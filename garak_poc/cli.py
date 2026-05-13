from __future__ import annotations

import argparse

from garak_poc import __version__
from garak_poc.config import ConfigError, load_scan_config
from garak_poc.runner import TargetConnectionError, run_scan


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "garak_poc is a lightweight Python AI vulnerability scanner inspired by "
            "garak. It runs a small, safe probe set against a target model, evaluates "
            "responses with simple detectors, and writes redacted reports."
        ),
        epilog=(
            "Authorised use only:\n"
            "  Use this tool only against systems and models you own, operate, or are\n"
            "  explicitly authorised to test. Do not use it for unauthorised scanning,\n"
            "  exploit development, credential harvesting, or offensive automation.\n"
            "\n"
            "Targets:\n"
            "  Only the local `ollama` target is supported today. Use `--target ollama`\n"
            "  with `--model` to scan a locally available Ollama model. Cloud targets are\n"
            "  intentionally not included yet.\n"
            "\n"
            "Report generation:\n"
            "  Each scan writes Markdown, JSON, and HTML reports together. `--out` sets the\n"
            "  Markdown filename, and the JSON and HTML reports are written beside it with\n"
            "  matching stems.\n"
            "\n"
            "Probe limiting:\n"
            "  `--limit` runs only the first N selected probes. Use this for quicker local\n"
            "  validation runs while tuning a target or prompt set.\n"
            "\n"
            "Timestamped filenames:\n"
            "  Output filenames are timestamped as `YYYY-MM-DD_HH-MM-SS_name.ext` to avoid\n"
            "  overwriting earlier scans. If your `--out` filename already starts with a\n"
            "  timestamp, it is preserved as-is.\n"
            "\n"
            "Examples:\n"
            "  python scanner.py --config configs/local-ollama.yaml\n"
            "  python scanner.py --target ollama --model deepseek-r1:14b\n"
            "  python scanner.py --target ollama --model llama3 --limit 2\n"
            "  python scanner.py --target ollama --model mistral --out reports/test.md\n"
            "\n"
            "Example Ollama scans:\n"
            "  python scanner.py --target ollama --model deepseek-r1:14b\n"
            "  python scanner.py --target ollama --model llama3 --limit 2\n"
            "  python scanner.py --target ollama --model mistral --out reports/test.md\n"
            "\n"
            "Exit codes:\n"
            "  0 = completed successfully\n"
            "  1 = findings exceeded threshold\n"
            "  2+ = scanner/runtime/configuration errors\n"
            "       2 configuration error\n"
            "       3 target connection error\n"
            "       4 runtime or scanner error"
        ),
        formatter_class=HelpFormatter,
        add_help=False,
    )
    general = parser.add_argument_group("General")
    general.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    general.add_argument("--version", action="version", version=f"garak_poc {__version__}", help="Show the scanner version and exit")

    target = parser.add_argument_group("Target Selection")
    target.add_argument("--config", default="configs/local-ollama.yaml", help="Path to YAML config file")
    target.add_argument("--target", help="Target adapter type")
    target.add_argument("--model", help="Target model name")
    target.add_argument("--base-url", default="http://localhost:11434", help="Target base URL")

    scan = parser.add_argument_group("Scan Behavior")
    scan.add_argument("--probes", help="Comma-separated probe groups or probe ids")
    scan.add_argument("--limit", type=int, help="Run only the first N selected probes")
    scan.add_argument("--fail-on", help="Severity threshold: info|low|medium|high|critical")

    reporting = parser.add_argument_group("Reporting")
    reporting.add_argument(
        "--out",
        help="Markdown output path; timestamped JSON and HTML reports are written beside it",
    )
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
