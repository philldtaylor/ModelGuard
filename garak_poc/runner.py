from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from garak_poc import __version__
from garak_poc.detectors import build_detector_registry
from garak_poc.models import ScanConfig, ScanResult, ScanSummary, utc_now_iso
from garak_poc.probes import resolve_probes
from garak_poc.reporting import write_json_report, write_markdown_report
from garak_poc.scoring import exceeds_threshold, score_probe, summarize_results
from garak_poc.targets import OllamaTarget


class TargetConnectionError(RuntimeError):
    pass


SECRET_REPLACEMENTS = [
    (
        __import__("re").compile(r"(sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY)", __import__("re").IGNORECASE),
        "[REDACTED_SECRET]",
    ),
    (
        __import__("re").compile(r"(bearer\s+)([A-Za-z0-9._-]{10,})", __import__("re").IGNORECASE),
        r"\1[REDACTED_TOKEN]",
    ),
    (
        __import__("re").compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", __import__("re").IGNORECASE),
        "[REDACTED_EMAIL]",
    ),
]


def redact_text(text: str) -> str:
    redacted = text
    for pattern, replacement in SECRET_REPLACEMENTS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _build_findings(results):
    findings = []
    finding_index = 1
    for result in results:
        if result.status == "PASS":
            continue
        confidence = max((detector.confidence for detector in result.detector_results), default=0.0)
        findings.append(
            {
                "id": f"FIND-{finding_index:04d}",
                "probe_id": result.probe_id,
                "category": result.category,
                "status": result.status,
                "severity": result.severity,
                "confidence": round(confidence, 2),
                "title": result.title,
                "prompt": result.prompt,
                "response_excerpt": result.response.text[:800],
                "detectors": [asdict(detector) for detector in result.detector_results],
                "recommendation": result.recommendation,
            }
        )
        finding_index += 1
    return findings


def _build_target(config: ScanConfig) -> OllamaTarget:
    if config.target_type == "ollama":
        return OllamaTarget(config)
    raise TargetConnectionError(f"Unsupported target type: {config.target_type}")


def _apply_redaction(scan_result: ScanResult, evidence_mode: str) -> ScanResult:
    if evidence_mode == "full":
        return scan_result
    for finding in scan_result.findings:
        finding["prompt"] = redact_text(finding["prompt"])
        finding["response_excerpt"] = redact_text(finding["response_excerpt"])
        for detector in finding["detectors"]:
            detector["evidence"] = redact_text(detector["evidence"])
    for result in scan_result.results:
        if evidence_mode in {"redacted", "summary"}:
            result.prompt = redact_text(result.prompt)
            result.response.text = redact_text(result.response.text)
            for detector in result.detector_results:
                detector.evidence = redact_text(detector.evidence)
    return scan_result


def run_scan(config: ScanConfig) -> int:
    started_at = utc_now_iso()
    target = _build_target(config)
    if not target.healthcheck():
        raise TargetConnectionError(f"Healthcheck failed for {config.base_url}")

    probes = resolve_probes(config.probes)
    if len(probes) > config.limits["max_probes"]:
        raise RuntimeError("Configured probe set exceeds max_probes limit")

    detector_registry = build_detector_registry()
    results = []
    for probe in probes:
        response = target.generate(probe.prompt)
        detector_results = []
        if response.error:
            detector_results = []
        else:
            for detector_id in probe.detectors:
                detector = detector_registry[detector_id]
                detector_results.append(detector.evaluate(probe.prompt, response.text))
        results.append(score_probe(probe, response, detector_results))

    summary = ScanSummary(**summarize_results(results))
    scan_id = f"{started_at.replace(':', '-').replace('.', '-')}-{config.model.replace(':', '-')}"
    scan_result = ScanResult(
        scan_id=scan_id,
        started_at=started_at,
        completed_at=utc_now_iso(),
        scanner="garak_poc",
        scanner_version=__version__,
        target=target.metadata(),
        config={
            "name": config.scan_name,
            "description": config.description,
            "probes": config.probes,
            "thresholds": config.thresholds,
            "generation": config.generation,
            "reporting": config.reporting,
        },
        summary=summary,
        findings=_build_findings(results),
        results=results,
    )
    scan_result = _apply_redaction(scan_result, config.reporting["evidence"])

    Path(config.output_markdown).parent.mkdir(parents=True, exist_ok=True)
    write_json_report(scan_result, config.output_json)
    write_markdown_report(scan_result, config.output_markdown)

    if summary.errors > config.thresholds["max_errors"]:
        return 4
    return 1 if exceeds_threshold(results, config.thresholds["fail_on"]) else 0
