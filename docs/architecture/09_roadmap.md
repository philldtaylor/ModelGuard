# Roadmap

## v0.1: Local Model PoC

Goal: Prove the scanner loop works end to end.

Features:

- Ollama target adapter.
- Static Python probe definitions.
- Regex and keyword detectors.
- JSON report.
- Markdown report.
- Basic CLI.

Example command:

```bash
python scanner.py --target ollama --model deepseek-r1:14b
```

Success criteria:

- Can scan a local model.
- Produces useful report.
- Easy to add new probes.

## v0.2: Configurable Scanner

Goal: Make scans configurable and repeatable.

Features:

- YAML config files.
- Probe include/exclude lists.
- Generation settings.
- Thresholds.
- Better report schema.
- Basic unit tests.

## v0.3: OpenAI-Compatible Targets

Goal: Support local and cloud APIs using OpenAI-style chat completions.

Features:

- OpenAI-compatible adapter.
- API key environment variable handling.
- Endpoint healthcheck.
- Better timeout and retry logic.

## v0.4: AWS Bedrock Target

Goal: Support cloud-hosted model testing in AWS.

Features:

- Bedrock adapter.
- AWS profile support.
- Region support.
- Cost and rate safety limits.
- Cloud scan metadata.

## v0.5: LLM-as-Judge

Goal: Improve ambiguous response evaluation.

Features:

- Optional judge model.
- Judge prompt templates.
- Judge rationale capture.
- Confidence scoring.
- Comparison with regex/keyword detectors.

## v0.6: Application Endpoint Testing

Goal: Test full GenAI applications, not just raw models.

Features:

- Generic HTTP adapter.
- Request/response templates.
- JSONPath response extraction.
- Auth token support.
- RAG and agent workflow probes.

## v0.7: CI/CD Mode

Goal: Use AgentTrace in development workflows.

Features:

- `--fail-on` threshold.
- Stable exit codes.
- CI-safe probe pack.
- SARIF or JUnit-style output.
- Baseline comparison.

## v1.0: Production-Ready PoC

Goal: A credible internal security tool.

Features:

- Multiple target adapters.
- Versioned probe packs.
- Report redaction.
- HTML report.
- Evidence bundles.
- Baseline comparison.
- Documentation.
- Tests.
- Example integrations.

## Later Ideas

- Web UI.
- Scheduled scans.
- SIEM integration.
- Security Hub integration.
- Prompt registry integration.
- RAG document attack simulation.
- Tool-call sandbox validation.
- Policy-as-code integration.
- Multi-model comparison.
