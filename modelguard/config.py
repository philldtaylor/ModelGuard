from __future__ import annotations

import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from modelguard.models import ScanConfig

DEFAULT_CONFIG_PATH = "configs/local-ollama-garak.yaml"
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_")
SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


class ConfigError(ValueError):
    pass


def _load_yaml(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    file_path = Path(path)
    if not file_path.exists():
        raise ConfigError(f"Config file not found: {path}")
    with file_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ConfigError("Config file must contain a mapping at the top level")
    return data


def _local_filename_timestamp() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")


def _sanitize_filename_component(value: str, fallback: str) -> str:
    sanitized = SAFE_FILENAME_CHARS.sub("-", value.strip())
    sanitized = re.sub(r"-{2,}", "-", sanitized).strip("._-")
    return sanitized or fallback


def _derive_outputs(out_path: str | None, output_dir: str, scan_id: str) -> tuple[str, str, str]:
    if out_path:
        requested_path = Path(out_path)
        base_name = requested_path.stem if requested_path.suffix else requested_path.name
        safe_base_name = _sanitize_filename_component(base_name, "report")
        markdown = requested_path.with_name(f"{safe_base_name}.md")
    else:
        markdown = Path(output_dir) / f"{scan_id}.md"
    json_path = markdown.with_suffix(".json")
    html_path = markdown.with_suffix(".html")
    return str(markdown), str(json_path), str(html_path)


def _expand_probe_groups(items: list[str]) -> list[str]:
    expanded: list[str] = []
    for item in items:
        expanded.append(item)
    return expanded


def load_scan_config(args: Any) -> ScanConfig:
    raw = _load_yaml(args.config or DEFAULT_CONFIG_PATH)

    scan_cfg = raw.get("scan", {})
    target_cfg = raw.get("target", {})
    garak_cfg = raw.get("garak", {})
    generation_cfg = raw.get("generation", {})
    probe_cfg = raw.get("probes", {})
    reporting_cfg = raw.get("reporting", {})
    threshold_cfg = raw.get("thresholds", {})
    limits_cfg = raw.get("limits", {})

    target_type = args.target or target_cfg.get("type")
    model = args.model or target_cfg.get("model")
    base_url = args.base_url or target_cfg.get("base_url", "http://localhost:11434")
    if not target_type:
        raise ConfigError("Missing target type")
    if target_type != "ollama":
        raise ConfigError(f"Unsupported target type: {target_type}")
    if not model:
        raise ConfigError("Missing model name")

    probe_spec = getattr(args, "probes", None) or garak_cfg.get("probe_spec")
    if not probe_spec:
        included = probe_cfg.get("include", ["all"])
        probe_spec = ",".join(_expand_probe_groups([item.strip() for item in included if item.strip()]))
    detector_spec = getattr(args, "detectors", None) or garak_cfg.get("detector_spec", "auto")
    timeout_seconds = int(getattr(args, "timeout", None) or garak_cfg.get("timeout_seconds", generation_cfg.get("timeout_seconds", 900)))
    if timeout_seconds < 1:
        raise ConfigError("Timeout must be greater than 0")
    scan_id = f"{_local_filename_timestamp()}_{_sanitize_filename_component(model, 'model')}"

    output_root = Path(reporting_cfg.get("output_dir", "reports"))
    modelguard_output_dir = output_root / "modelguard"
    garak_artifact_dir = output_root / "garak" / scan_id
    markdown_path, json_path, html_path = _derive_outputs(args.out, str(modelguard_output_dir), scan_id)
    fail_on = (args.fail_on or threshold_cfg.get("fail_on", "high")).lower()
    evidence = reporting_cfg.get("evidence", "redacted")
    if evidence not in {"redacted", "summary", "full"}:
        raise ConfigError(f"Unsupported evidence mode: {evidence}")

    garak_command = garak_cfg.get("command", "python3 -m garak")
    if isinstance(garak_command, str):
        command_parts = shlex.split(garak_command)
    elif isinstance(garak_command, list) and all(isinstance(item, str) for item in garak_command):
        command_parts = list(garak_command)
    else:
        raise ConfigError("garak.command must be a string or list of strings")
    if not command_parts:
        raise ConfigError("garak.command must not be empty")

    generation = {
        "temperature": generation_cfg.get("temperature", 0),
        "max_tokens": generation_cfg.get("max_tokens", 1024),
        "timeout_seconds": generation_cfg.get("timeout_seconds", 60),
    }
    thresholds = {
        "fail_on": fail_on,
        "max_errors": threshold_cfg.get("max_errors", 3),
    }
    reporting = {
        "output_dir": str(modelguard_output_dir),
        "garak_output_dir": str(garak_artifact_dir),
        "evidence": evidence,
        "formats": reporting_cfg.get("formats", ["json", "markdown"]),
    }
    limits = {
        "max_probes": limits_cfg.get("max_probes", 50),
        "requests_per_minute": limits_cfg.get("requests_per_minute", 30),
        "max_cost_usd": limits_cfg.get("max_cost_usd", 0),
    }

    return ScanConfig(
        target_type=target_type,
        model=model,
        base_url=base_url,
        probes=[item.strip() for item in str(probe_spec).split(",") if item.strip()],
        probe_limit=None,
        probe_spec=str(probe_spec),
        detector_spec=str(detector_spec),
        generations=int(garak_cfg.get("generations", 5)),
        extended_detectors=bool(garak_cfg.get("extended_detectors", False)),
        timeout_seconds=timeout_seconds,
        garak_command=command_parts,
        garak_extra_args=[str(item) for item in garak_cfg.get("extra_args", [])],
        garak_artifact_dir=str(garak_artifact_dir),
        scan_id=scan_id,
        output_markdown=markdown_path,
        output_json=json_path,
        output_html=html_path,
        generation=generation,
        thresholds=thresholds,
        reporting=reporting,
        limits=limits,
        scan_name=scan_cfg.get("name", "ModelGuard"),
        description=scan_cfg.get("description", ""),
        config_path=args.config or DEFAULT_CONFIG_PATH,
    )
