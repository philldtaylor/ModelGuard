# ModelGuard v0.1 Validation Notes

## Target

- Target type: Ollama
- Model: deepseek-r1:14b
- Scan duration: approximately 5 minutes
- Probe count: 12

## Result

- PASS: 4
- WARN: 4
- FAIL: 4
- ERROR: 0
- Highest severity: High

## Observations

The scanner successfully completed an end-to-end local model scan and generated both JSON and Markdown reports.

The current detector logic appears intentionally sensitive. Some findings may need manual review because several responses appear partially safe but still trigger risky keywords or patterns.

## Immediate Improvements

1. Add console progress output per probe.
2. Add elapsed time and per-probe latency summary.
3. Add clearer detector evidence when the evidence excerpt is empty.
4. Tune detectors to reduce false positives.
5. Add a smaller `--probe-limit` or `--probes` option for faster development testing.
6. Add report summary command or CLI completion message.
