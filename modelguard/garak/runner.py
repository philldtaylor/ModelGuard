from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class GarakRunArtifacts:
    artifact_dir: str
    report_prefix: str
    command: list[str]
    exit_code: int | None
    runtime_seconds: float
    timed_out: bool
    stdout_path: str
    stderr_path: str
    command_path: str
    runtime_metadata_path: str
    environment_path: str
    jsonl_reports: list[str]
    html_reports: list[str]
    hitlog_reports: list[str]


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _locate_reports(report_prefix: str) -> tuple[list[str], list[str], list[str]]:
    prefix_path = Path(report_prefix)
    report_dir = prefix_path.parent
    stem = prefix_path.name
    jsonl = sorted(str(path) for path in report_dir.glob(f"{stem}*.report.jsonl"))
    html = sorted(str(path) for path in report_dir.glob(f"{stem}*.report.html"))
    hitlog = sorted(str(path) for path in report_dir.glob(f"{stem}*hitlog*.jsonl"))
    return jsonl, html, hitlog


def run_garak(
    command: list[str],
    artifact_dir: str | Path,
    report_prefix: str | Path,
    timeout_seconds: int,
    extra_env: dict[str, str] | None = None,
) -> GarakRunArtifacts:
    artifact_root = Path(artifact_dir)
    artifact_root.mkdir(parents=True, exist_ok=True)
    stdout_path = artifact_root / "stdout.log"
    stderr_path = artifact_root / "stderr.log"
    command_path = artifact_root / "command_used.txt"
    runtime_path = artifact_root / "runtime_metadata.json"
    environment_path = artifact_root / "environment.txt"

    _write_text(command_path, shlex.join(command) + "\n")

    effective_env = os.environ.copy()
    if extra_env:
        effective_env.update(extra_env)
    environment_lines = []
    for key in sorted({"PATH", "PYTHONPATH", "VIRTUAL_ENV", "OLLAMA_HOST"}):
        if key in effective_env:
            environment_lines.append(f"{key}={effective_env[key]}")
    _write_text(environment_path, "\n".join(environment_lines) + ("\n" if environment_lines else ""))

    started_at = _utc_now_iso()
    started_perf = perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=effective_env,
            timeout=timeout_seconds,
            check=False,
        )
        timed_out = False
        exit_code = completed.returncode
        stdout_text = completed.stdout or ""
        stderr_text = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = None
        stdout_text = exc.stdout or ""
        stderr_text = exc.stderr or ""
    runtime_seconds = perf_counter() - started_perf
    completed_at = _utc_now_iso()

    _write_text(stdout_path, stdout_text)
    _write_text(stderr_path, stderr_text)

    jsonl_reports, html_reports, hitlog_reports = _locate_reports(str(report_prefix))
    runtime_payload: dict[str, Any] = {
        "started_at": started_at,
        "completed_at": completed_at,
        "runtime_seconds": runtime_seconds,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "report_prefix": str(report_prefix),
        "jsonl_reports": jsonl_reports,
        "html_reports": html_reports,
        "hitlog_reports": hitlog_reports,
    }
    _write_text(runtime_path, json.dumps(runtime_payload, indent=2) + "\n")

    return GarakRunArtifacts(
        artifact_dir=str(artifact_root),
        report_prefix=str(report_prefix),
        command=command,
        exit_code=exit_code,
        runtime_seconds=runtime_seconds,
        timed_out=timed_out,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        command_path=str(command_path),
        runtime_metadata_path=str(runtime_path),
        environment_path=str(environment_path),
        jsonl_reports=jsonl_reports,
        html_reports=html_reports,
        hitlog_reports=hitlog_reports,
    )
