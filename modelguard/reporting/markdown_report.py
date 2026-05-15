from __future__ import annotations

from pathlib import Path

from modelguard.models import ScanResult
from modelguard.reporting.common import format_elapsed_seconds, format_latency_ms


def _code_block(text: str) -> str:
    return f"```\n{text}\n```"


def _finding_rationale(finding: dict[str, object]) -> str:
    return str(finding.get("primary_rationale", "")).strip()


def _finding_evidence(finding: dict[str, object]) -> str:
    evidence = str(finding.get("primary_evidence", "")).strip()
    if evidence:
        return evidence
    rationale = _finding_rationale(finding)
    if rationale:
        return rationale
    excerpt = str(finding.get("response_excerpt", "")).strip()
    if excerpt:
        return excerpt
    return "No evidence captured."


def write_markdown_report(scan_result: ScanResult, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "# ModelGuard Scan Report",
        "",
        "**Classification:** Internal / Security Sensitive",
        "",
        "This report may contain raw model responses, prompts, system behaviour, and possible sensitive output.",
        "",
        "## Executive Summary",
        "",
        f"- Scan ID: `{scan_result.scan_id}`",
        f"- Scanner: `{scan_result.scanner}` `{scan_result.scanner_version}`",
        f"- Started: `{scan_result.started_at}`",
        f"- Completed: `{scan_result.completed_at}`",
        f"- Started (local): `{scan_result.started_at_local}`",
        f"- Completed (local): `{scan_result.completed_at_local}`",
        f"- Elapsed seconds: `{format_elapsed_seconds(scan_result.elapsed_seconds)}`",
        f"- Total probes: `{scan_result.summary.total_probes}`",
        f"- PASS/WARN/FAIL/ERROR: `{scan_result.summary.passed}/{scan_result.summary.warned}/{scan_result.summary.failed}/{scan_result.summary.errors}`",
        f"- Highest severity: `{scan_result.summary.highest_severity}`",
        "",
        "## Target",
        "",
        f"- Type: `{scan_result.target['type']}`",
        f"- Model: `{scan_result.target['model']}`",
        f"- Base URL: `{scan_result.target['base_url']}`",
        f"- garak target type: `{scan_result.target.get('garak_target_type', '')}`",
        f"- garak target name: `{scan_result.target.get('garak_target_name', '')}`",
        "",
        "## Evidence",
        "",
        f"- garak artefact dir: `{scan_result.evidence.get('garak_artifact_dir', '')}`",
        f"- JSONL reports: `{', '.join(scan_result.evidence.get('jsonl_reports', []))}`",
        f"- HTML reports: `{', '.join(scan_result.evidence.get('html_reports', []))}`",
        "",
        "## Findings",
        "",
    ]

    if not scan_result.findings:
        lines.extend(["No WARN, FAIL, or ERROR findings were produced.", ""])
    else:
        for finding in scan_result.findings:
            lines.extend(
                [
                    f"### {finding['id']}: {finding['title']}",
                    "",
                    f"- Status: `{finding['status']}`",
                    f"- Severity: `{finding['severity']}`",
                    f"- Category: `{finding['category']}`",
                    f"- Probe ID: `{finding['probe_id']}`",
                    f"- Confidence: `{finding['confidence']}`",
                    f"- Primary Detector: `{finding.get('primary_detector_id', '') or 'None'}`",
                    "",
                    f"Primary Rationale: {_finding_rationale(finding) or 'No detector rationale recorded.'}",
                    "",
                    "**Primary Evidence**",
                    "",
                    _code_block(_finding_evidence(finding)),
                    "",
                    f"Recommendation: {finding['recommendation']}",
                    "",
                ]
            )

    lines.extend(
        [
            "## Full Probe Results",
            "",
            "| Probe | Category | Status | Severity | Latency |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for result in scan_result.results:
        lines.append(
            f"| `{result.probe_id}` | `{result.category}` | `{result.status}` | `{result.severity}` | `{format_latency_ms(result.response.latency_ms)}` |"
        )
    lines.append("")

    for result in scan_result.results:
        lines.extend(
            [
                f"### {result.probe_id}",
                "",
                f"- Status: `{result.status}`",
                f"- Severity: `{result.severity}`",
                f"- Score: `{result.score if result.score is not None else 'n/a'}`",
                f"- Defcon: `{result.defcon if result.defcon is not None else 'n/a'}`",
                f"- Passed / Total: `{result.passed_count if result.passed_count is not None else 0}/{result.total_evaluated if result.total_evaluated is not None else 0}`",
                f"- Latency: `{format_latency_ms(result.response.latency_ms)}`",
                "",
                f"Prompt:\n{_code_block(result.prompt)}",
                "",
                f"Response:\n{_code_block(result.response.text)}",
                "",
                "Detectors:",
            ]
        )
        for detector in result.detector_results:
            lines.append(
                f"- `{detector.detector_id}` -> `{detector.status}` (confidence={detector.confidence}, score={detector.score if detector.score is not None else 'n/a'}, defcon={detector.defcon if detector.defcon is not None else 'n/a'}, passed={detector.passed_count if detector.passed_count is not None else 0}/{detector.total_evaluated if detector.total_evaluated is not None else 0}): {detector.evidence}"
            )
        lines.append("")

    with path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
