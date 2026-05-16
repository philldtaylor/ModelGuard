# ModelGuard

ModelGuard is an enterprise orchestration and governance wrapper for NVIDIA garak.

It runs garak against configured AI targets, preserves raw scan evidence, normalises garak output, and generates governance-friendly reports for AI security assurance, CI/CD workflows, and model comparison.

ModelGuard is not a replacement for garak. It is designed to make garak easier to operate, evidence, and explain in enterprise environments.

## Relationship to garak

ModelGuard uses NVIDIA garak as its LLM vulnerability scanning engine.

Garak provides the probes, detectors, and model safety evaluation logic. ModelGuard does not implement custom probes, custom detectors, custom scoring, or LLM-as-judge evaluation.

### ModelGuard adds

- Scan orchestration
- Target configuration
- Evidence preservation
- JSONL normalisation
- Markdown/JSON/HTML governance reports
- Comparison-ready output
- CI/CD and scheduling integration paths

### garak project

https://github.com/NVIDIA/garak

## What ModelGuard does not do

ModelGuard does not:

- Replace garak
- Implement custom vulnerability probes
- Implement custom detector logic
- Independently classify model responses
- Provide exploit tooling
- Claim that a scan result is a full security assessment

All security findings originate from garak output and should be reviewed as security test signals.

## MVP status

This repository is an MVP demonstrating:

- Local Ollama target support
- garak subprocess orchestration
- Raw garak artefact preservation
- garak JSONL parsing
- Normalised ModelGuard JSON reports
- Markdown and HTML governance reporting
- Basic automated tests for parser, normaliser, and smoke flow

### Validated command

```bash
python scanner.py scan --config configs/local-ollama-garak.yaml
```

## Example output

```text
reports/
├── garak/<scan_id>/
│   ├── command_used.txt
│   ├── environment.txt
│   ├── runtime_metadata.json
│   ├── stdout.log
│   ├── stderr.log
│   └── garak-reports/
│       ├── <scan_id>.report.jsonl
│       └── <scan_id>.report.html
└── modelguard/
    ├── <scan_id>.json
    ├── <scan_id>.md
    └── <scan_id>.html
```

## Quick start

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install garak
```

Run a scan:

```bash
python scanner.py scan --config configs/local-ollama-garak.yaml
```

## Testing

```bash
ruff check .
python -m pytest
```

## Roadmap

Planned next steps:

- Add curated garak scan profiles for CI and assurance workflows
- Improve comparison reports across multiple model runs
- Add AWS Bedrock target profiles
- Add GitHub Actions examples
- Add optional S3 evidence storage pattern
- Add SARIF or CSV export for security tooling integration

## Licence and attribution

ModelGuard is an independent wrapper around NVIDIA garak. It invokes garak as the scanning engine and normalises its output for governance reporting.

See the garak project for garak licensing and usage terms:

https://github.com/NVIDIA/garak
