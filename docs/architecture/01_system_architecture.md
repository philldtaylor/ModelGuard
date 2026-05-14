# System Architecture

## High-Level Architecture

```text
+-------------------+
| CLI / Runner      |
+---------+---------+
          |
          v
+-------------------+       +-------------------+
| Scan Config       |------>| Probe Registry    |
+-------------------+       +-------------------+
          |                         |
          v                         v
+-------------------+       +-------------------+
| Target Adapter    |<------| Probe Executor    |
+-------------------+       +-------------------+
          |                         |
          v                         v
+-------------------+       +-------------------+
| Model Endpoint    |       | Response Capture  |
+-------------------+       +-------------------+
                                    |
                                    v
                            +-------------------+
                            | Detector Engine   |
                            +-------------------+
                                    |
                                    v
                            +-------------------+
                            | Scoring Engine    |
                            +-------------------+
                                    |
                                    v
                            +-------------------+
                            | Report Generator  |
                            +-------------------+
```

## Core Components

### CLI / Runner

Responsible for:

- Parsing command-line arguments.
- Loading scan configuration.
- Initialising the target adapter.
- Selecting probes.
- Running the scan.
- Writing reports.

Example:

```bash
python scanner.py \
  --target ollama \
  --model deepseek-r1:14b \
  --probes prompt_injection,jailbreak,data_leakage \
  --out reports/deepseek-r1-14b.md
```

### Target Adapter

A target adapter abstracts model access.

Each adapter should expose the same interface:

```python
class TargetAdapter:
    def generate(self, prompt: str, **kwargs) -> TargetResponse:
        ...
```

Initial adapters:

- `ollama`
- `openai_compatible`

Future adapters:

- `aws_bedrock`
- `azure_openai`
- `anthropic`
- `vertex_ai`
- `internal_http`

### Probe Registry

The probe registry loads available tests.

A probe contains:

- Name.
- Category.
- Description.
- Prompt template.
- Expected safe behaviour.
- Detector mapping.
- Severity hint.

Example categories:

- Prompt injection.
- Jailbreak resilience.
- Data leakage.
- Insecure code generation.
- Harmful instruction following.
- RAG exfiltration.
- Tool misuse.
- Policy bypass.

### Probe Executor

Responsible for:

- Expanding prompt templates.
- Sending prompts to the selected target.
- Capturing responses and metadata.
- Handling retries and rate limits.
- Tracking execution status.

### Detector Engine

Detectors evaluate model output.

Detector types:

- Regex detector.
- Keyword detector.
- Structured refusal detector.
- Heuristic detector.
- LLM-as-judge detector.
- Custom Python detector.

### Scoring Engine

The scoring engine turns detector results into findings.

Suggested simple scoring:

```text
PASS       No risky behaviour detected
WARN       Ambiguous response or partial compliance
FAIL       Risky behaviour detected
ERROR      Probe could not be executed
```

Suggested severity:

```text
Informational
Low
Medium
High
Critical
```

### Report Generator

The report generator should produce:

- JSON evidence file.
- Markdown summary.
- Optional HTML report.
- Optional SARIF or CI-friendly output.

Reports should include:

- Scan metadata.
- Target metadata.
- Probe results.
- Findings summary.
- Raw prompts and responses.
- Detector evidence.
- Recommendations.

## Runtime Flow

```text
1. User runs scanner.
2. Scanner loads target and probe config.
3. Scanner validates target connectivity.
4. Scanner runs each probe.
5. Target responses are stored as evidence.
6. Detectors evaluate responses.
7. Results are scored.
8. Reports are written.
9. Exit code reflects pass/fail threshold.
```

## Suggested Repository Structure

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
      openai_compatible.py
      bedrock.py
    probes/
      __init__.py
      base.py
      prompt_injection.py
      jailbreak.py
      data_leakage.py
      insecure_code.py
    detectors/
      __init__.py
      base.py
      regex.py
      keywords.py
      llm_judge.py
    reporting/
      __init__.py
      json_report.py
      markdown_report.py
      html_report.py
    scoring.py
    evidence.py
  configs/
    local-ollama.yaml
    bedrock-mistral.yaml
  reports/
  tests/
  README.md
```
