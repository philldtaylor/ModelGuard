# Engineering Notes for Codex

## Objective

Build a Python PoC called AgentTrace: a lightweight AI vulnerability scanner inspired by garak.

The scanner should run probes against a target model, evaluate the responses with detectors, and write JSON and Markdown reports.

## Initial Implementation Target

Implement v0.1 only.

Required features:

- CLI entry point.
- Ollama target adapter.
- Simple probe classes or static probe registry.
- Regex and keyword detectors.
- JSON report output.
- Markdown report output.
- Example scan against `deepseek-r1:14b`.

## Preferred Repository Structure

```text
agentrace/
  scanner.py
  agentrace/
    __init__.py
    cli.py
    config.py
    runner.py
    models.py
    targets/
      __init__.py
      base.py
      ollama.py
    probes/
      __init__.py
      base.py
      registry.py
    detectors/
      __init__.py
      base.py
      regex.py
      keywords.py
    reporting/
      __init__.py
      json_report.py
      markdown_report.py
    scoring.py
  reports/
  tests/
  README.md
  requirements.txt
```

## Implementation Requirements

Use Python 3.11+.

Keep dependencies minimal:

```text
requests
pyyaml
rich optional
```

The scanner should support:

```bash
python scanner.py --target ollama --model deepseek-r1:14b --out reports/scan.md
```

Also support:

```bash
python scanner.py --config configs/local-ollama.yaml
```

## Ollama API

Use the Ollama local API at:

```text
POST http://localhost:11434/api/generate
```

Payload shape:

```json
{
  "model": "deepseek-r1:14b",
  "prompt": "test prompt",
  "stream": false,
  "options": {
    "temperature": 0
  }
}
```

Expected response includes a `response` field.

## Initial Probe Registry

Create around 12 safe probes across:

- Prompt injection.
- Jailbreak resistance.
- Data leakage.
- Insecure code generation.

Each probe should include:

- `id`
- `name`
- `category`
- `severity`
- `prompt`
- `detectors`
- `description`
- `safe_expectation`

## Detector Behaviour

Implement:

- Keyword match detector.
- Regex detector.
- Refusal detector.

A detector should return:

```python
DetectorResult(
    detector_id="...",
    passed=True,
    confidence=0.8,
    evidence="...",
    rationale="..."
)
```

## Scoring

A probe result should be:

```text
PASS
WARN
FAIL
ERROR
```

Simple logic:

- If target call errors, result is ERROR.
- If any high-confidence risky detector triggers, result is FAIL.
- If weak or ambiguous detector triggers, result is WARN.
- Otherwise PASS.

## Report Output

JSON report should include full structured evidence.

Markdown report should include:

- Executive summary.
- Target details.
- Results table.
- Findings.
- Evidence excerpts.
- Recommendations.

## Safety Requirements

- Do not execute model output.
- Do not include offensive automation.
- Redact obvious secrets in reports.
- Treat all model responses as untrusted.
- Add clear authorised-use wording to README.

## Acceptance Test

The following command should work against a running Ollama instance:

```bash
python scanner.py --target ollama --model deepseek-r1:14b --out reports/ollama-deepseek-r1-14b.md
```

It should create:

```text
reports/ollama-deepseek-r1-14b.json
reports/ollama-deepseek-r1-14b.md
```
