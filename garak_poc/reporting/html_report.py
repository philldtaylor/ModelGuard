from __future__ import annotations

from pathlib import Path

from garak_poc.models import ScanResult
from garak_poc.reporting.common import escape_html, format_elapsed_seconds, format_latency_ms


def _badge_class(prefix: str, value: str) -> str:
    normalized = value.lower().replace(" ", "-")
    return f"badge {prefix}-{normalized}"


def _render_detector_list(scan_result: ScanResult) -> str:
    sections: list[str] = []
    for result in scan_result.results:
        latency = format_latency_ms(result.response.latency_ms)
        detectors = "".join(
            (
                "<li>"
                f"<span class=\"{_badge_class('status', detector.status)}\">{escape_html(detector.status)}</span> "
                f"<strong>{escape_html(detector.detector_id)}</strong> "
                f"(confidence: {detector.confidence:.2f}, triggered: {str(detector.triggered).lower()})"
                f"<div class=\"detail\"><div><strong>Evidence</strong><pre>{escape_html(detector.evidence)}</pre></div>"
                f"<div><strong>Rationale</strong><pre>{escape_html(detector.rationale)}</pre></div></div>"
                "</li>"
            )
            for detector in result.detector_results
        )
        if not detectors:
            detectors = "<li>No detector results recorded.</li>"
        sections.append(
            "<section class=\"card\">"
            f"<h3>{escape_html(result.probe_id)} <span class=\"{_badge_class('status', result.status)}\">{escape_html(result.status)}</span> "
            f"<span class=\"{_badge_class('severity', result.severity)}\">{escape_html(result.severity)}</span></h3>"
            f"<p><strong>Category:</strong> {escape_html(result.category)} | <strong>Latency:</strong> {escape_html(latency)}</p>"
            f"<p><strong>Recommendation:</strong> {escape_html(result.recommendation)}</p>"
            f"<div class=\"detail\"><div><strong>Prompt</strong><pre>{escape_html(result.prompt)}</pre></div>"
            f"<div><strong>Response</strong><pre>{escape_html(result.response.text)}</pre></div></div>"
            f"<div class=\"detail\"><div><strong>Target Error</strong><pre>{escape_html(result.response.error or '')}</pre></div></div>"
            f"<h4>Detector Results</h4><ul class=\"detector-list\">{detectors}</ul>"
            "</section>"
        )
    return "".join(sections)


def _render_findings(scan_result: ScanResult) -> str:
    if not scan_result.findings:
        return "<section class=\"card\"><p>No WARN, FAIL, or ERROR findings were produced.</p></section>"

    items: list[str] = []
    for finding in scan_result.findings:
        items.append(
            "<section class=\"card\">"
            f"<h3>{escape_html(str(finding['id']))}: {escape_html(str(finding['title']))}</h3>"
            f"<p><span class=\"{_badge_class('status', str(finding['status']))}\">{escape_html(str(finding['status']))}</span> "
            f"<span class=\"{_badge_class('severity', str(finding['severity']))}\">{escape_html(str(finding['severity']))}</span></p>"
            f"<p><strong>Category:</strong> {escape_html(str(finding['category']))} | "
            f"<strong>Probe ID:</strong> {escape_html(str(finding['probe_id']))} | "
            f"<strong>Confidence:</strong> {escape_html(str(finding['confidence']))}</p>"
            f"<div class=\"detail\"><div><strong>Response Excerpt</strong><pre>{escape_html(str(finding['response_excerpt']))}</pre></div></div>"
            f"<p><strong>Recommendation:</strong> {escape_html(str(finding['recommendation']))}</p>"
            "</section>"
        )
    return "".join(items)


def write_html_report(scan_result: ScanResult, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    summary = scan_result.summary
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>garak_poc Scan Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f1e8;
      --panel: #fffdf8;
      --ink: #1f2933;
      --muted: #5b6672;
      --border: #d7cbb5;
      --pass: #2f855a;
      --warn: #b7791f;
      --fail: #c53030;
      --error: #805ad5;
      --sev-critical: #742a2a;
      --sev-high: #c05621;
      --sev-medium: #b7791f;
      --sev-low: #2b6cb0;
      --sev-info: #4a5568;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Georgia, "Times New Roman", serif; background: linear-gradient(180deg, #efe7d6 0%, var(--bg) 100%); color: var(--ink); }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 48px; }}
    h1, h2, h3, h4 {{ font-family: "Trebuchet MS", Helvetica, sans-serif; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px; margin: 16px 0; box-shadow: 0 8px 24px rgba(31, 41, 51, 0.06); }}
    .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }}
    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; color: #fff; font: 600 0.8rem/1.4 "Trebuchet MS", Helvetica, sans-serif; }}
    .status-pass {{ background: var(--pass); }}
    .status-warn {{ background: var(--warn); }}
    .status-fail {{ background: var(--fail); }}
    .status-error {{ background: var(--error); }}
    .severity-critical {{ background: var(--sev-critical); }}
    .severity-high {{ background: var(--sev-high); }}
    .severity-medium {{ background: var(--sev-medium); }}
    .severity-low {{ background: var(--sev-low); }}
    .severity-info {{ background: var(--sev-info); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 12px; overflow: hidden; }}
    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ font-family: "Trebuchet MS", Helvetica, sans-serif; background: #efe7d6; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #f8f4ea; border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin: 8px 0 0; }}
    .detail {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }}
    .detector-list {{ padding-left: 20px; }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
  <main>
    <header class="card">
      <h1>garak_poc Scan Report</h1>
      <p><strong>Classification:</strong> Internal / Security Sensitive</p>
      <p class="muted">This report may contain raw model responses, prompts, system behaviour, and possible sensitive output.</p>
    </header>

    <section class="card">
      <h2>Executive Summary</h2>
      <div class="meta">
        <div><strong>Scan ID</strong><br>{escape_html(scan_result.scan_id)}</div>
        <div><strong>Scanner</strong><br>{escape_html(scan_result.scanner)} {escape_html(scan_result.scanner_version)}</div>
        <div><strong>Total Probes</strong><br>{summary.total_probes}</div>
        <div><strong>Highest Severity</strong><br><span class="{_badge_class('severity', summary.highest_severity)}">{escape_html(summary.highest_severity)}</span></div>
      </div>
      <div class="meta">
        <div><strong>Started (UTC)</strong><br>{escape_html(scan_result.started_at)}</div>
        <div><strong>Completed (UTC)</strong><br>{escape_html(scan_result.completed_at)}</div>
        <div><strong>Started (Local)</strong><br>{escape_html(scan_result.started_at_local)}</div>
        <div><strong>Completed (Local)</strong><br>{escape_html(scan_result.completed_at_local)}</div>
        <div><strong>Elapsed Seconds</strong><br>{escape_html(format_elapsed_seconds(scan_result.elapsed_seconds))}</div>
        <div><strong>PASS / WARN / FAIL / ERROR</strong><br>{summary.passed} / {summary.warned} / {summary.failed} / {summary.errors}</div>
      </div>
    </section>

    <section class="card">
      <h2>Target Details</h2>
      <div class="meta">
        <div><strong>Type</strong><br>{escape_html(str(scan_result.target['type']))}</div>
        <div><strong>Model</strong><br>{escape_html(str(scan_result.target['model']))}</div>
        <div><strong>Base URL</strong><br>{escape_html(str(scan_result.target['base_url']))}</div>
      </div>
    </section>

    <section>
      <h2>Findings</h2>
      {_render_findings(scan_result)}
    </section>

    <section>
      <h2>Full Probe Results</h2>
      <table>
        <thead>
          <tr>
            <th>Probe</th>
            <th>Category</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          {"".join(
              f"<tr><td>{escape_html(result.probe_id)}</td><td>{escape_html(result.category)}</td>"
              f"<td><span class=\"{_badge_class('status', result.status)}\">{escape_html(result.status)}</span></td>"
              f"<td><span class=\"{_badge_class('severity', result.severity)}\">{escape_html(result.severity)}</span></td>"
              f"<td>{escape_html(format_latency_ms(result.response.latency_ms))}</td></tr>"
              for result in scan_result.results
          )}
        </tbody>
      </table>
    </section>

    <section>
      <h2>Prompts, Responses, and Detector Results</h2>
      {_render_detector_list(scan_result)}
    </section>

    <section class="card">
      <h2>Recommendations</h2>
      <ul>
        {"".join(f"<li><strong>{escape_html(result.probe_id)}</strong>: {escape_html(result.recommendation)}</li>" for result in scan_result.results)}
      </ul>
    </section>
  </main>
</body>
</html>
"""

    with path.open("w", encoding="utf-8") as handle:
        handle.write(html)
