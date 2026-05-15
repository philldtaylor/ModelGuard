from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from html import unescape
from typing import Any

from modelguard import __version__
from modelguard.garak.runner import GarakRunArtifacts
from modelguard.models import DetectorResult, ProbeResult, ScanConfig, ScanResult, ScanSummary, TargetResponse

STATUS_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _defcon_label(defcon: int | None) -> str:
    return f"DEFCON {defcon}" if defcon is not None else "Unknown"


def _derive_status(total_evaluated: int, passed_count: int, fails: int, nones: int) -> str:
    if total_evaluated <= 0:
        return "ERROR"
    if fails > 0:
        return "FAIL"
    if nones > 0:
        return "WARN"
    if passed_count == total_evaluated:
        return "PASS"
    return "WARN"


def _worst_status(detector_results: list[DetectorResult]) -> str:
    if not detector_results:
        return "ERROR"
    return max(detector_results, key=lambda item: STATUS_RANK.get(item.status, 3)).status


def _first_prompt_text(attempt: dict[str, Any]) -> str:
    prompt = attempt.get("prompt", {})
    turns = prompt.get("turns", []) if isinstance(prompt, dict) else []
    chunks = []
    for turn in turns:
        content = turn.get("content", {})
        text = content.get("text")
        if text:
            chunks.append(str(text))
    return "\n".join(chunks)


def _first_output_text(attempt: dict[str, Any]) -> str:
    outputs = attempt.get("outputs", [])
    if outputs and isinstance(outputs[0], dict):
        return str(outputs[0].get("text", ""))
    conversations = attempt.get("conversations", [])
    for conversation in conversations:
        for turn in conversation.get("turns", []):
            if turn.get("role") == "assistant":
                return str(turn.get("content", {}).get("text", ""))
    return ""


def _build_eval_index(eval_entries: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(entry.get("probe", "")), str(entry.get("detector", ""))): entry
        for entry in eval_entries
        if entry.get("probe") and entry.get("detector")
    }


def _build_attempt_index(attempts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        probe_name = str(attempt.get("probe_classname", ""))
        indexed.setdefault(probe_name, []).append(attempt)
    return indexed


def _build_detector_result(
    probe_name: str,
    detector_name: str,
    detector_summary: dict[str, Any],
    eval_entry: dict[str, Any] | None,
    sample_output: str,
) -> DetectorResult:
    total_evaluated = _safe_int(detector_summary.get("total_evaluated"))
    if total_evaluated is None and eval_entry is not None:
        total_evaluated = _safe_int(eval_entry.get("total_evaluated")) or 0
    passed_count = _safe_int(detector_summary.get("passed"))
    if passed_count is None and eval_entry is not None:
        passed_count = _safe_int(eval_entry.get("passed")) or 0
    total_evaluated = total_evaluated or 0
    passed_count = passed_count or 0
    fails = _safe_int((eval_entry or {}).get("fails")) or max(total_evaluated - passed_count, 0)
    nones = _safe_int((eval_entry or {}).get("nones")) or 0
    status = _derive_status(total_evaluated, passed_count, fails, nones)
    defcon = _safe_int(detector_summary.get("absolute_defcon") or detector_summary.get("detector_defcon"))
    score = _safe_float(detector_summary.get("absolute_score"))
    comment = detector_summary.get("absolute_comment") or detector_summary.get("relative_comment") or ""
    evidence = sample_output or comment or f"garak reported {passed_count}/{total_evaluated} passes for {probe_name}"
    rationale = (
        f"garak eval for {probe_name} / {detector_name}: passed={passed_count}, "
        f"failed={fails}, nones={nones}, total_evaluated={total_evaluated}"
    )
    confidence = _safe_float(detector_summary.get("confidence"))
    return DetectorResult(
        detector_id=detector_name,
        passed=status == "PASS",
        confidence=confidence or 0.0,
        evidence=str(evidence),
        rationale=rationale,
        status=status,
        triggered=status != "PASS",
        score=score,
        defcon=defcon,
        total_evaluated=total_evaluated,
        passed_count=passed_count,
        raw={"summary": detector_summary, "eval_entry": eval_entry or {}},
    )


def _build_findings(results: list[ProbeResult]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding_index, result in enumerate((item for item in results if item.status != "PASS"), start=1):
        ordered_detectors = sorted(
            result.detector_results,
            key=lambda item: (STATUS_RANK.get(item.status, 3), -(item.total_evaluated or 0)),
            reverse=True,
        )
        primary = ordered_detectors[0] if ordered_detectors else None
        findings.append(
            {
                "id": f"FIND-{finding_index:04d}",
                "title": f"{result.probe_id} / {primary.detector_id if primary else 'garak'}",
                "status": result.status,
                "severity": result.severity,
                "category": result.category,
                "probe_id": result.probe_id,
                "confidence": primary.confidence if primary else 0.0,
                "prompt": result.prompt,
                "response_excerpt": result.response.text[:1000],
                "primary_detector_id": primary.detector_id if primary else "",
                "primary_rationale": primary.rationale if primary else "No detector rationale recorded.",
                "primary_evidence": primary.evidence if primary else result.response.text[:1000],
                "recommendation": result.recommendation,
                "detectors": [asdict(detector) for detector in result.detector_results],
            }
        )
    return findings


def _local_time(iso_timestamp: str | None) -> str:
    if not iso_timestamp:
        return ""
    parsed = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    return parsed.astimezone().replace(microsecond=0).isoformat()


def normalize_garak_report(
    parsed_report: dict[str, Any],
    config: ScanConfig,
    run_artifacts: GarakRunArtifacts,
) -> ScanResult:
    metadata = parsed_report["metadata"]
    eval_index = _build_eval_index(parsed_report["eval_entries"])
    attempt_index = _build_attempt_index(parsed_report["attempts"])

    results: list[ProbeResult] = []
    seen_probe_ids: set[str] = set()
    for summary in parsed_report["eval_summaries"]:
        probe_name = str(summary["probe_name"])
        if probe_name in seen_probe_ids:
            continue
        seen_probe_ids.add(probe_name)
        group = str(summary["group"])
        probe_summary = summary["probe_summary"]
        attempts = attempt_index.get(probe_name, [])
        sample_attempt = attempts[0] if attempts else {}
        sample_prompt = _first_prompt_text(sample_attempt)
        sample_output = _first_output_text(sample_attempt)

        detector_results: list[DetectorResult] = []
        for detector in (item for item in parsed_report["eval_summaries"] if item["probe_name"] == probe_name):
            detector_name = str(detector["detector_name"])
            detector_results.append(
                _build_detector_result(
                    probe_name=probe_name,
                    detector_name=detector_name,
                    detector_summary=detector["detector_summary"],
                    eval_entry=eval_index.get((probe_name, detector_name)),
                    sample_output=sample_output,
                )
            )

        defcon = _safe_int(probe_summary.get("probe_severity"))
        total_evaluated = sum(detector.total_evaluated or 0 for detector in detector_results)
        passed_count = sum(detector.passed_count or 0 for detector in detector_results)
        score = _safe_float(probe_summary.get("probe_score"))
        results.append(
            ProbeResult(
                probe_id=probe_name,
                probe_name=probe_name,
                category=group,
                prompt=sample_prompt,
                response=TargetResponse(
                    text=sample_output,
                    raw={"attempt": sample_attempt},
                    latency_ms=None,
                    token_usage=None,
                    error=None,
                ),
                detector_results=detector_results,
                status=_worst_status(detector_results),
                severity=_defcon_label(defcon),
                title=unescape(str(probe_summary.get("probe_descr") or probe_name)),
                recommendation="Review the raw garak evidence for this probe and detector set before acting on the result.",
                score=score,
                defcon=defcon,
                total_evaluated=total_evaluated,
                passed_count=passed_count,
                raw={"probe_summary": probe_summary, "attempt_count": len(attempts)},
            )
        )

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "ERROR": 0}
    worst_defcon: int | None = None
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
        if result.defcon is not None:
            worst_defcon = result.defcon if worst_defcon is None else min(worst_defcon, result.defcon)

    summary = ScanSummary(
        total_probes=len(results),
        passed=counts.get("PASS", 0),
        warned=counts.get("WARN", 0),
        failed=counts.get("FAIL", 0),
        errors=counts.get("ERROR", 0),
        highest_severity=_defcon_label(worst_defcon),
    )
    started_at = str(metadata.get("start_time") or "")
    completed_at = str(metadata.get("end_time") or "")
    return ScanResult(
        scan_id=config.scan_id or str(metadata.get("run_uuid") or ""),
        started_at=started_at,
        completed_at=completed_at,
        started_at_local=_local_time(started_at),
        completed_at_local=_local_time(completed_at),
        elapsed_seconds=run_artifacts.runtime_seconds,
        scanner="garak",
        scanner_version=str(metadata.get("garak_version") or __version__),
        target={
            "type": config.target_type,
            "model": config.model,
            "base_url": config.base_url,
            "garak_target_type": metadata.get("target_type"),
            "garak_target_name": metadata.get("target_name"),
        },
        config={
            "name": config.scan_name,
            "description": config.description,
            "config_path": config.config_path,
            "probe_spec": config.probe_spec,
            "detector_spec": config.detector_spec,
            "generations": config.generations,
            "timeout_seconds": config.timeout_seconds,
            "thresholds": config.thresholds,
            "reporting": config.reporting,
        },
        summary=summary,
        findings=_build_findings(results),
        results=results,
        evidence={
            "garak_artifact_dir": run_artifacts.artifact_dir,
            "garak_report_prefix": run_artifacts.report_prefix,
            "jsonl_reports": run_artifacts.jsonl_reports,
            "html_reports": run_artifacts.html_reports,
            "hitlog_reports": run_artifacts.hitlog_reports,
            "stdout_log": run_artifacts.stdout_path,
            "stderr_log": run_artifacts.stderr_path,
            "command_used": run_artifacts.command_path,
            "runtime_metadata": run_artifacts.runtime_metadata_path,
            "environment": run_artifacts.environment_path,
        },
        raw={
            "garak_metadata": metadata,
            "eval_summaries": parsed_report["eval_summaries"],
        },
    )
