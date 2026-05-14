Improve ModelGuard reporting.

Implement:
1. HTML report output alongside Markdown and JSON.
   - If output is reports/example.md, also write reports/example.json and reports/example.html.
   - HTML should be self-contained with embedded CSS.
   - Include executive summary, target details, findings, full probe results, prompts, responses, detector results, and recommendations.
   - Use simple readable styling with severity/status badges.
   - Escape all untrusted model output safely for HTML.

2. Add explicit report timestamps:
   - Add scan started_at and completed_at to Markdown, JSON, and HTML.
   - Include local execution timestamp as well as UTC if feasible.
   - Include elapsed runtime in seconds.
   - Include per-probe latency in full results where available.

3. Update CLI final summary to print:
   - Markdown path
   - JSON path
   - HTML path
   - started/completed timestamps
   - elapsed time

4. Add or update tests for:
   - HTML report file creation
   - HTML escaping of model output
   - timestamp fields in JSON/Markdown/HTML
   - CLI summary mentions HTML path

5. Keep dependencies minimal. Do not add Jinja2 or external HTML libraries.

6. Do not add cloud support yet.
7. Do not rename the project.

After changes, run:
python -m pytest -q
