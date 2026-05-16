from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from modelguard.models import ScanConfig


def _strip_scheme(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc
    return base_url.replace("http://", "").replace("https://", "").rstrip("/")


def build_generator_options(config: ScanConfig) -> dict[str, object]:
    host = _strip_scheme(config.base_url)
    options = {
        "host": host,
        "timeout": int(config.generation.get("timeout_seconds", config.timeout_seconds)),
        "max_tokens": int(config.generation.get("max_tokens", 150)),
    }
    temperature = config.generation.get("temperature")
    if temperature is not None:
        options["temperature"] = temperature
    return {
        "ollama": {
            "OllamaGenerator": options,
            "OllamaGeneratorChat": options,
        }
    }


def build_garak_command(config: ScanConfig, report_prefix: str | Path) -> list[str]:
    resolved_report_prefix = Path(report_prefix).resolve()
    command = list(config.garak_command)
    command.extend(
        [
            "--target_type",
            config.target_type,
            "--target_name",
            config.model,
            "--probes",
            config.probe_spec,
            "--report_prefix",
            str(resolved_report_prefix),
            "--generations",
            str(config.generations),
            "--generator_options",
            json.dumps(build_generator_options(config), separators=(",", ":")),
            "--skip_unknown",
        ]
    )
    if config.detector_spec and config.detector_spec.lower() != "auto":
        command.extend(["--detectors", config.detector_spec])
    if config.extended_detectors:
        command.append("--extended_detectors")
    if config.garak_extra_args:
        command.extend(config.garak_extra_args)
    return command
