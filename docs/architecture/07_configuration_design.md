# Configuration Design

## Design Goals

The scanner should be configurable without code changes.

Configuration should control:

- Target model.
- Endpoint details.
- Probe selection.
- Generation parameters.
- Detector settings.
- Report output.
- Thresholds.
- Safety limits.

## Example Local Ollama Config

```yaml
scan:
  name: local-deepseek-baseline
  description: Baseline scan against local DeepSeek R1 14B via Ollama

target:
  type: ollama
  base_url: http://localhost:11434
  model: deepseek-r1:14b

generation:
  temperature: 0
  max_tokens: 1024
  timeout_seconds: 60

probes:
  include:
    - prompt_injection
    - jailbreak
    - data_leakage
    - insecure_code
  exclude: []

detectors:
  enabled:
    - regex
    - keyword
  llm_judge:
    enabled: false

reporting:
  output_dir: reports
  formats:
    - json
    - markdown
  evidence: redacted

thresholds:
  fail_on: high
  max_errors: 3

limits:
  max_probes: 50
  requests_per_minute: 30
  max_cost_usd: 0
```

## Example AWS Bedrock Config

```yaml
scan:
  name: bedrock-mistral-baseline

target:
  type: bedrock
  region: eu-west-2
  model: mistral.mistral-large-2402-v1:0
  profile: security-lab

generation:
  temperature: 0
  max_tokens: 1024
  timeout_seconds: 60

probes:
  include:
    - prompt_injection
    - jailbreak
    - data_leakage

reporting:
  output_dir: reports
  formats:
    - json
    - markdown
  evidence: redacted

thresholds:
  fail_on: high

limits:
  max_probes: 30
  requests_per_minute: 10
  max_cost_usd: 5
```

## Environment Variables

Suggested environment variables:

```text
AGENTRACE_CONFIG
AGENTRACE_OUTPUT_DIR
OPENAI_API_KEY
AZURE_OPENAI_API_KEY
AWS_PROFILE
AWS_REGION
```

## CLI Overrides

CLI arguments should override config file values.

Example:

```bash
python scanner.py \
  --config configs/local-ollama.yaml \
  --model qwen2.5-coder:14b \
  --out reports/qwen-baseline.md
```

## Validation

The config loader should validate:

- Target type is supported.
- Required target fields are present.
- Probe names exist.
- Detector names exist.
- Output directory is writable.
- Safety limits are sane.
- Cloud scans have an explicit budget or max probe limit.
