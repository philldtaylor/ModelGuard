# ModelGuard v0.1

`ModelGuard` is a lightweight Python AI vulnerability scanner. Inspired by NVIDIA garak. It runs a small, safe probe set against a target model, evaluates responses with simple detectors, and writes redacted JSON and Markdown reports.

## Authorised Use Only

Use this tool only against systems and models you own, operate, or are explicitly authorised to test. Do not use it for unauthorised scanning, exploit development, credential harvesting, or offensive automation. The probe set in this repository is intentionally limited to safe prompt-based validation.

## Safety Properties

- Model output is never executed.
- All model output is treated as untrusted data.
- Reports redact obvious secrets and email addresses by default.
- Probes focus on defensive validation across prompt injection, jailbreak resistance, data leakage, and insecure code generation.

## Requirements

- Python 3.11+
- Ollama running locally for the default target

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Run with the default local config:

```bash
python scanner.py --config configs/local-ollama.yaml
```

Run with explicit CLI options:

```bash
python scanner.py --target ollama --model deepseek-r1:14b --out reports/ollama-deepseek-r1-14b.md
```

That command writes:

- `reports/ollama-deepseek-r1-14b.md`
- `reports/ollama-deepseek-r1-14b.json`

Exit codes:

- `0` scan completed below threshold
- `1` findings met or exceeded the configured threshold
- `2` configuration error
- `3` target connection error
- `4` runtime or scanner error

## Probe Pack

The static v0.1 registry contains 12 safe probes across:

- `prompt_injection`
- `jailbreak`
- `data_leakage`
- `insecure_code`

## Project Layout

```text
scanner.py
modelguard/
configs/
reports/
tests/
README.md
requirements.txt
```
