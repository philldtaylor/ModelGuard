from __future__ import annotations

from pathlib import Path

from modelguard.config import _sanitize_filename_component
from modelguard.evidence.redaction import apply_redaction
from modelguard.garak.command_builder import build_garak_command
from modelguard.garak.normalizer import normalize_garak_report
from modelguard.garak.parser import parse_garak_report
from modelguard.garak.runner import run_garak
from modelguard.models import ScanConfig, ScanResult
from modelguard.reporting import write_html_report, write_json_report, write_markdown_report


class ScanExecutionError(RuntimeError):
    pass


class ScanTimeoutError(ScanExecutionError):
    pass


def _report_prefix(config: ScanConfig) -> str:
    artifact_dir = Path(config.garak_artifact_dir) / "garak-reports"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stem = _sanitize_filename_component(config.scan_id or config.model, "scan")
    return str(artifact_dir / stem)


def _print_start(config: ScanConfig, command: list[str]) -> None:
    print(f"Starting garak scan: {config.scan_id}")
    print(f"  Target: {config.target_type} / {config.model}")
    print(f"  Probe spec: {config.probe_spec}")
    print(f"  Evidence dir: {config.garak_artifact_dir}")
    print(f"  Timeout: {config.timeout_seconds}s")
    print(f"  Command: {' '.join(command)}")


def _print_complete(scan_result: ScanResult, config: ScanConfig) -> None:
    print("")
    print("Scan complete")
    print(f"  Markdown report: {config.output_markdown}")
    print(f"  JSON report: {config.output_json}")
    print(f"  HTML report: {config.output_html}")
    print(f"  garak artefacts: {config.garak_artifact_dir}")
    print(f"  Started (UTC): {scan_result.started_at}")
    print(f"  Completed (UTC): {scan_result.completed_at}")
    print(f"  PASS/WARN/FAIL/ERROR: {scan_result.summary.passed}/{scan_result.summary.warned}/{scan_result.summary.failed}/{scan_result.summary.errors}")
    print(f"  Highest severity: {scan_result.summary.highest_severity}")
    print(f"  Elapsed time: {scan_result.elapsed_seconds:.2f}s")


def run_scan(config: ScanConfig) -> int:
    Path(config.output_markdown).parent.mkdir(parents=True, exist_ok=True)
    Path(config.garak_artifact_dir).mkdir(parents=True, exist_ok=True)
    report_prefix = _report_prefix(config)
    command = build_garak_command(config, report_prefix)
    _print_start(config, command)

    run_artifacts = run_garak(
        command=command,
        artifact_dir=config.garak_artifact_dir,
        report_prefix=report_prefix,
        timeout_seconds=config.timeout_seconds,
    )
    if run_artifacts.timed_out:
        raise ScanTimeoutError(f"garak exceeded timeout of {config.timeout_seconds}s")
    if run_artifacts.exit_code not in {0}:
        raise ScanExecutionError(
            f"garak exited with code {run_artifacts.exit_code}. See {run_artifacts.stderr_path} and {run_artifacts.stdout_path}"
        )
    if not run_artifacts.jsonl_reports:
        raise ScanExecutionError(f"No garak JSONL report found under {config.garak_artifact_dir}")

    parsed = parse_garak_report(run_artifacts.jsonl_reports[0])
    scan_result = normalize_garak_report(parsed, config, run_artifacts)
    scan_result = apply_redaction(scan_result, config.reporting.get("evidence", "redacted"))

    write_json_report(scan_result, config.output_json)
    write_markdown_report(scan_result, config.output_markdown)
    write_html_report(scan_result, config.output_html)
    _print_complete(scan_result, config)
    return 0
