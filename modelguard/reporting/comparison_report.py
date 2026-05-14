from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modelguard.reporting.common import escape_html, format_elapsed_seconds, format_latency_ms
from modelguard.scoring import SEVERITY_ORDER


STATUS_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2, "ERROR": 3, "MISSING": 4}


def _badge_class(prefix: str, value: str) -> str:
    normalized = value.lower().replace(" ", "-")
    return f"badge {prefix}-{normalized}"


def _detect_format(output_path: str, requested_format: str | None) -> str:
    if requested_format:
        return requested_format
    suffix = Path(output_path).suffix.lower()
    if suffix in {".html", ".htm"}:
        return "html"
    if suffix in {".md", ".markdown"}:
        return "md"
    if suffix == ".json":
        return "json"
    return "html"


def _mean_latency_ms(results: list[dict[str, Any]]) -> float | None:
    latencies = [
        result.get("response", {}).get("latency_ms")
        for result in results
        if result.get("response", {}).get("latency_ms") is not None
    ]
    if not latencies:
        return None
    return sum(latencies) / len(latencies)


def _model_display_names(reports: list[dict[str, Any]]) -> list[str]:
    model_counts: dict[str, int] = {}
    for report in reports:
        model = str(report["model_name"])
        model_counts[model] = model_counts.get(model, 0) + 1
    display_names: list[str] = []
    for report in reports:
        model = str(report["model_name"])
        if model_counts[model] > 1:
            display_names.append(f"{model} ({report['filename']})")
        else:
            display_names.append(model)
    return display_names


def load_scan_report(report_path: str) -> dict[str, Any]:
    path = Path(report_path)
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    scan = raw.get("scan", {})
    target = raw.get("target", {})
    summary = raw.get("summary", {})
    results = raw.get("results", [])
    return {
        "source_path": str(path),
        "filename": path.name,
        "model_name": str(target.get("model", "unknown")),
        "target_type": str(target.get("type", "unknown")),
        "started_at": str(scan.get("started_at", "")),
        "completed_at": str(scan.get("completed_at", "")),
        "elapsed_seconds": float(scan.get("elapsed_seconds", 0.0) or 0.0),
        "total_probes": int(summary.get("total_probes", len(results)) or 0),
        "counts": {
            "PASS": int(summary.get("passed", 0) or 0),
            "WARN": int(summary.get("warned", 0) or 0),
            "FAIL": int(summary.get("failed", 0) or 0),
            "ERROR": int(summary.get("errors", 0) or 0),
        },
        "highest_severity": str(summary.get("highest_severity", "Info")),
        "average_probe_latency_ms": _mean_latency_ms(results),
        "results": results,
    }


def load_scan_reports(report_paths: list[str]) -> list[dict[str, Any]]:
    return [load_scan_report(report_path) for report_path in report_paths]


def build_comparison_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    display_names = _model_display_names(reports)
    report_entries = []
    for report, display_name in zip(reports, display_names):
        report_entries.append(
            {
                "filename": report["filename"],
                "model_name": report["model_name"],
                "display_name": display_name,
                "target_type": report["target_type"],
                "started_at": report["started_at"],
                "completed_at": report["completed_at"],
                "elapsed_seconds": report["elapsed_seconds"],
                "elapsed_seconds_text": format_elapsed_seconds(report["elapsed_seconds"]),
                "total_probes": report["total_probes"],
                "counts": report["counts"],
                "highest_severity": report["highest_severity"],
                "average_probe_latency_ms": report["average_probe_latency_ms"],
                "average_probe_latency_text": (
                    f"{report['average_probe_latency_ms']:.2f}ms"
                    if report["average_probe_latency_ms"] is not None
                    else "n/a"
                ),
            }
        )

    all_probe_ids = sorted(
        {
            str(result.get("probe_id", ""))
            for report in reports
            for result in report["results"]
            if result.get("probe_id")
        }
    )
    probe_rows = []
    differing_rows = []
    for probe_id in all_probe_ids:
        by_model: dict[str, dict[str, Any]] = {}
        category = ""
        probe_name = probe_id
        statuses = []
        for report, display_name in zip(reports, display_names):
            matching = next((result for result in report["results"] if result.get("probe_id") == probe_id), None)
            if matching is None:
                by_model[display_name] = {
                    "status": "MISSING",
                    "severity": "",
                    "latency_ms": None,
                    "latency_text": "n/a",
                }
                statuses.append("MISSING")
                continue
            category = str(matching.get("category", category))
            probe_name = str(matching.get("probe_name", probe_name))
            latency_ms = matching.get("response", {}).get("latency_ms")
            by_model[display_name] = {
                "status": str(matching.get("status", "ERROR")),
                "severity": str(matching.get("severity", "")),
                "latency_ms": latency_ms,
                "latency_text": format_latency_ms(latency_ms),
            }
            statuses.append(by_model[display_name]["status"])

        row = {
            "probe_id": probe_id,
            "probe_name": probe_name,
            "category": category,
            "by_model": by_model,
        }
        probe_rows.append(row)
        if len(set(statuses)) > 1:
            differing_rows.append(row)

    def sort_key(entry: dict[str, Any], field: str) -> tuple[Any, str]:
        return (entry[field], entry["display_name"])

    latencies = [entry for entry in report_entries if entry["average_probe_latency_ms"] is not None]
    fastest_model = min(latencies, key=lambda entry: sort_key(entry, "average_probe_latency_ms"))["display_name"] if latencies else None
    fewest_fail_model = min(report_entries, key=lambda entry: (entry["counts"]["FAIL"], entry["display_name"]))["display_name"]
    fewest_warn_fail_model = min(
        report_entries,
        key=lambda entry: (entry["counts"]["WARN"] + entry["counts"]["FAIL"], entry["display_name"]),
    )["display_name"]

    return {
        "report_filenames": [entry["filename"] for entry in report_entries],
        "models": [entry["display_name"] for entry in report_entries],
        "reports": report_entries,
        "probe_results": probe_rows,
        "differing_probes": differing_rows,
        "highlights": {
            "fastest_model": fastest_model,
            "fewest_fail_model": fewest_fail_model,
            "fewest_warn_fail_model": fewest_warn_fail_model,
        },
    }


def _render_html(comparison: dict[str, Any]) -> str:
    report_headers = "".join(
        (
            "<section class=\"card\">"
            f"<h3>{escape_html(report['display_name'])}</h3>"
            f"<p><strong>Filename:</strong> {escape_html(report['filename'])}</p>"
            f"<p><strong>Target Type:</strong> {escape_html(report['target_type'])}</p>"
            f"<p><strong>Started:</strong> {escape_html(report['started_at'])}<br>"
            f"<strong>Completed:</strong> {escape_html(report['completed_at'])}</p>"
            f"<p><strong>Total Probes:</strong> {report['total_probes']}<br>"
            f"<strong>PASS/WARN/FAIL/ERROR:</strong> "
            f"{report['counts']['PASS']} / {report['counts']['WARN']} / {report['counts']['FAIL']} / {report['counts']['ERROR']}</p>"
            f"<p><strong>Highest Severity:</strong> "
            f"<span class=\"{_badge_class('severity', report['highest_severity'])}\">{escape_html(report['highest_severity'])}</span></p>"
            f"<p><strong>Elapsed Runtime:</strong> {escape_html(report['elapsed_seconds_text'])}s<br>"
            f"<strong>Average Probe Latency:</strong> {escape_html(report['average_probe_latency_text'])}</p>"
            "</section>"
        )
        for report in comparison["reports"]
    )

    model_headers = "".join(f"<th>{escape_html(model)}</th>" for model in comparison["models"])
    probe_rows = []
    for row in comparison["probe_results"]:
        cells = []
        for model in comparison["models"]:
            probe = row["by_model"][model]
            status = probe["status"]
            severity = probe["severity"] or "n/a"
            badge = f"<span class=\"{_badge_class('status', status)}\">{escape_html(status)}</span>"
            cells.append(
                "<td>"
                f"{badge}<br><span class=\"muted\">{escape_html(severity)} | {escape_html(probe['latency_text'])}</span>"
                "</td>"
            )
        probe_rows.append(
            "<tr>"
            f"<td>{escape_html(row['probe_id'])}</td>"
            f"<td>{escape_html(row['category'])}</td>"
            + "".join(cells)
            + "</tr>"
        )

    differing_items = "".join(
        (
            "<li>"
            f"<strong>{escape_html(row['probe_id'])}</strong>: "
            + ", ".join(
                f"{escape_html(model)}={escape_html(row['by_model'][model]['status'])}"
                for model in comparison["models"]
            )
            + "</li>"
        )
        for row in comparison["differing_probes"]
    )
    if not differing_items:
        differing_items = "<li>No differing probe outcomes.</li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ModelGuard Model Comparison Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f2efe8;
      --panel: #fffdf9;
      --ink: #1c2430;
      --muted: #5f6b79;
      --border: #d7cfbf;
      --pass: #2f855a;
      --warn: #b7791f;
      --fail: #c53030;
      --error: #6b46c1;
      --missing: #4a5568;
      --sev-critical: #742a2a;
      --sev-high: #c05621;
      --sev-medium: #b7791f;
      --sev-low: #2b6cb0;
      --sev-info: #4a5568;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(180deg, #ebe4d5 0%, var(--bg) 100%); color: var(--ink); }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 32px 20px 48px; }}
    h1, h2, h3 {{ font-family: "Trebuchet MS", Helvetica, sans-serif; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px; margin: 16px 0; box-shadow: 0 8px 24px rgba(28, 36, 48, 0.06); }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }}
    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; color: #fff; font: 600 0.8rem/1.4 "Trebuchet MS", Helvetica, sans-serif; }}
    .status-pass {{ background: var(--pass); }}
    .status-warn {{ background: var(--warn); }}
    .status-fail {{ background: var(--fail); }}
    .status-error {{ background: var(--error); }}
    .status-missing {{ background: var(--missing); }}
    .severity-critical {{ background: var(--sev-critical); }}
    .severity-high {{ background: var(--sev-high); }}
    .severity-medium {{ background: var(--sev-medium); }}
    .severity-low {{ background: var(--sev-low); }}
    .severity-info {{ background: var(--sev-info); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 12px; overflow: hidden; }}
    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ background: #efe7d6; font-family: "Trebuchet MS", Helvetica, sans-serif; }}
    ul {{ padding-left: 20px; }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
  <main>
    <header class="card">
      <h1>ModelGuard Model Comparison Report</h1>
      <p><strong>Compared Reports:</strong> {", ".join(escape_html(name) for name in comparison["report_filenames"])}</p>
      <p class="muted">Comparison data is derived from existing JSON scan reports. No new model scans were run.</p>
    </header>

    <section class="card">
      <h2>Highlights</h2>
      <p><strong>Fastest Model:</strong> {escape_html(comparison['highlights']['fastest_model'] or 'n/a')}</p>
      <p><strong>Fewest FAIL Results:</strong> {escape_html(comparison['highlights']['fewest_fail_model'] or 'n/a')}</p>
      <p><strong>Fewest WARN+FAIL Results:</strong> {escape_html(comparison['highlights']['fewest_warn_fail_model'] or 'n/a')}</p>
    </section>

    <section>
      <h2>Per-Model Summary</h2>
      <div class="meta-grid">
        {report_headers}
      </div>
    </section>

    <section>
      <h2>Probe Results By Model</h2>
      <table>
        <thead>
          <tr>
            <th>Probe</th>
            <th>Category</th>
            {model_headers}
          </tr>
        </thead>
        <tbody>
          {"".join(probe_rows)}
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Differing Probe Outcomes</h2>
      <ul>{differing_items}</ul>
    </section>
  </main>
</body>
</html>
"""


def _render_markdown(comparison: dict[str, Any]) -> str:
    lines = [
        "# ModelGuard Model Comparison Report",
        "",
        f"Compared reports: {', '.join(f'`{name}`' for name in comparison['report_filenames'])}",
        "",
        "## Highlights",
        "",
        f"- Fastest model: `{comparison['highlights']['fastest_model'] or 'n/a'}`",
        f"- Fewest FAIL results: `{comparison['highlights']['fewest_fail_model'] or 'n/a'}`",
        f"- Fewest WARN+FAIL results: `{comparison['highlights']['fewest_warn_fail_model'] or 'n/a'}`",
        "",
        "## Per-Model Summary",
        "",
    ]
    for report in comparison["reports"]:
        lines.extend(
            [
                f"### {report['display_name']}",
                "",
                f"- Filename: `{report['filename']}`",
                f"- Target type: `{report['target_type']}`",
                f"- Started: `{report['started_at']}`",
                f"- Completed: `{report['completed_at']}`",
                f"- Total probes: `{report['total_probes']}`",
                f"- PASS/WARN/FAIL/ERROR: `{report['counts']['PASS']}/{report['counts']['WARN']}/{report['counts']['FAIL']}/{report['counts']['ERROR']}`",
                f"- Highest severity: `{report['highest_severity']}`",
                f"- Elapsed runtime: `{report['elapsed_seconds_text']}s`",
                f"- Average probe latency: `{report['average_probe_latency_text']}`",
                "",
            ]
        )

    header = "| Probe | Category | " + " | ".join(comparison["models"]) + " |"
    divider = "| --- | --- | " + " | ".join("---" for _ in comparison["models"]) + " |"
    lines.extend(["## Probe Results By Model", "", header, divider])
    for row in comparison["probe_results"]:
        model_values = []
        for model in comparison["models"]:
            probe = row["by_model"][model]
            model_values.append(f"`{probe['status']}` / `{probe['latency_text']}`")
        lines.append(f"| `{row['probe_id']}` | `{row['category']}` | " + " | ".join(model_values) + " |")

    lines.extend(["", "## Differing Probe Outcomes", ""])
    if comparison["differing_probes"]:
        for row in comparison["differing_probes"]:
            outcome_text = ", ".join(f"`{model}`=`{row['by_model'][model]['status']}`" for model in comparison["models"])
            lines.append(f"- `{row['probe_id']}`: {outcome_text}")
    else:
        lines.append("- No differing probe outcomes.")
    lines.append("")
    return "\n".join(lines)


def _json_ready_comparison(comparison: dict[str, Any]) -> dict[str, Any]:
    payload = json.loads(json.dumps(comparison))
    for row in payload["probe_results"]:
        row["highest_observed_severity"] = max(
            (entry["severity"] for entry in row["by_model"].values() if entry["severity"]),
            default="Info",
            key=lambda severity: SEVERITY_ORDER.get(severity, -1),
        )
    return payload


def write_comparison_report(comparison: dict[str, Any], output_path: str, requested_format: str | None = None) -> str:
    format_name = _detect_format(output_path, requested_format)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if format_name == "html":
        content = _render_html(comparison)
    elif format_name == "md":
        content = _render_markdown(comparison)
    elif format_name == "json":
        content = json.dumps(_json_ready_comparison(comparison), indent=2)
    else:
        raise ValueError(f"Unsupported comparison format: {format_name}")

    with path.open("w", encoding="utf-8") as handle:
        handle.write(content)
    return format_name
