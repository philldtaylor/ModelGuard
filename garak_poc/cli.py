from __future__ import annotations

import argparse

from garak_poc.config import ConfigError, load_scan_config
from garak_poc.runner import TargetConnectionError, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="garak_poc v0.1 AI vulnerability scanner")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--target", help="Target adapter type")
    parser.add_argument("--model", help="Target model name")
    parser.add_argument("--base-url", help="Target base URL")
    parser.add_argument("--probes", help="Comma-separated probe groups or probe ids")
    parser.add_argument("--limit", type=int, help="Run only the first N selected probes")
    parser.add_argument("--out", help="Markdown output path; JSON and HTML will be written beside it")
    parser.add_argument("--fail-on", help="Severity threshold: info|low|medium|high|critical")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_scan_config(args)
    except ConfigError as exc:
        print(f"Configuration error: {exc}")
        return 2
    try:
        return run_scan(config)
    except TargetConnectionError as exc:
        print(f"Target connection error: {exc}")
        return 3
    except Exception as exc:  # pragma: no cover
        print(f"Runtime error: {exc}")
        return 4
