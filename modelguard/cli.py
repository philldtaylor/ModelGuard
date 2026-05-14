from __future__ import annotations

import argparse
import sys

from modelguard import __version__
from modelguard.config import ConfigError, load_scan_config
from modelguard.reporting.comparison_report import build_comparison_summary, load_scan_reports, write_comparison_report
from modelguard.runner import TargetConnectionError, run_scan


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "ModelGuard is a lightweight Python AI vulnerability scanner. Inspired by "
            "NVIDIA garak. It runs a small, safe probe set against a target model, evaluates "
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
    general.add_argument("--version", action="version", version=f"ModelGuard {__version__}", help="Show the scanner version and exit")

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


def build_compare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py compare",
        description="Compare multiple ModelGuard JSON scan reports and generate a single comparison report.",
    )
    parser.add_argument("report_paths", nargs="+", help="One or more JSON scan report paths")
    parser.add_argument("--out", default="reports/comparison.html", help="Comparison output path")
    parser.add_argument(
        "--format",
        choices=["html", "md", "json"],
        help="Comparison output format; inferred from --out when possible",
    )
    return parser


def _run_compare(argv: list[str]) -> int:
    parser = build_compare_parser()
    args = parser.parse_args(argv)
    try:
        reports = load_scan_reports(args.report_paths)
        comparison = build_comparison_summary(reports)
        format_name = write_comparison_report(comparison, args.out, args.format)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Comparison error: {exc}")
        return 2
    print(f"Comparison report ({format_name}): {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "compare":
        return _run_compare(argv[1:])

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
