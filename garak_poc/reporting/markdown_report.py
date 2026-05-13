from __future__ import annotations

from pathlib import Path

from garak_poc.models import ScanResult


def _code_block(text: str) -> str:
    return f"```\n{text}\n```"


def _finding_evidence(finding: dict[str, object]) -> str:
    for detector in finding.get("detectors", []):
        rationale = str(detector.get("rationale", "")).strip()
        if rationale:
            return rationale
        evidence = str(detector.get("evidence", "")).strip()
        if evidence:
            return evidence
    excerpt = str(finding.get("response_excerpt", "")).strip()
    if excerpt:
        return excerpt
    return "No evidence captured."


def write_markdown_report(scan_result: ScanResult, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "# garak_poc Scan Report",
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
        f"- Total probes: `{scan_result.summary.total_probes}`",
        f"- PASS/WARN/FAIL/ERROR: `{scan_result.summary.passed}/{scan_result.summary.warned}/{scan_result.summary.failed}/{scan_result.summary.errors}`",
        f"- Highest severity: `{scan_result.summary.highest_severity}`",
        "",
        "## Target",
        "",
        f"- Type: `{scan_result.target['type']}`",
        f"- Model: `{scan_result.target['model']}`",
        f"- Base URL: `{scan_result.target['base_url']}`",
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
                    "",
                    "**Evidence**",
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
            "| Probe | Category | Status | Severity |",
            "| --- | --- | --- | --- |",
        ]
    )
    for result in scan_result.results:
        lines.append(f"| `{result.probe_id}` | `{result.category}` | `{result.status}` | `{result.severity}` |")
    lines.append("")

    for result in scan_result.results:
        lines.extend(
            [
                f"### {result.probe_id}",
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
                f"- `{detector.detector_id}` -> `{detector.status}` ({detector.confidence}): {detector.evidence}"
            )
        lines.append("")

    with path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
