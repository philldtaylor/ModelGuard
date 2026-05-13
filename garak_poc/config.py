from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from garak_poc.models import ScanConfig

DEFAULT_CONFIG_PATH = "configs/local-ollama.yaml"


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


def _derive_outputs(out_path: str | None, output_dir: str, model: str) -> tuple[str, str]:
    if out_path:
        markdown = Path(out_path)
    else:
        safe_model = model.replace(":", "-").replace("/", "-")
        markdown = Path(output_dir) / f"{safe_model}.md"
    json_path = markdown.with_suffix(".json")
    return str(markdown), str(json_path)


def _expand_probe_groups(items: list[str]) -> list[str]:
    expanded: list[str] = []
    for item in items:
        expanded.append(item)
    return expanded


def load_scan_config(args: Any) -> ScanConfig:
    raw = _load_yaml(args.config or DEFAULT_CONFIG_PATH)

    scan_cfg = raw.get("scan", {})
    target_cfg = raw.get("target", {})
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

    included = probe_cfg.get("include", ["all"])
    probes = args.probes.split(",") if getattr(args, "probes", None) else included
    probes = [item.strip() for item in probes if item.strip()]
    probes = _expand_probe_groups(probes)
    probe_limit = getattr(args, "limit", None)
    if probe_limit is not None and probe_limit < 1:
        raise ConfigError("Probe limit must be greater than 0")

    output_dir = reporting_cfg.get("output_dir", "reports")
    markdown_path, json_path = _derive_outputs(args.out, output_dir, model)
    fail_on = (args.fail_on or threshold_cfg.get("fail_on", "high")).lower()
    evidence = reporting_cfg.get("evidence", "redacted")
    if evidence not in {"redacted", "summary", "full"}:
        raise ConfigError(f"Unsupported evidence mode: {evidence}")

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
        "output_dir": output_dir,
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
        probes=probes,
        probe_limit=probe_limit,
        output_markdown=markdown_path,
        output_json=json_path,
        generation=generation,
        thresholds=thresholds,
        reporting=reporting,
        limits=limits,
        scan_name=scan_cfg.get("name", "garak-poc"),
        description=scan_cfg.get("description", ""),
        config_path=args.config or DEFAULT_CONFIG_PATH,
    )
