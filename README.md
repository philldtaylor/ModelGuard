# ModelGuard

ModelGuard is a garak orchestration, evidence capture, and governance reporting wrapper for LLM security scans.

## Overview

ModelGuard orchestrates NVIDIA garak and adds the enterprise wrapper around it:

- target profile resolution
- subprocess execution and timeout handling
- raw evidence capture
- normalized JSON, Markdown, and HTML reporting
- comparison-ready JSON outputs
- CI and scheduling-friendly exit codes

garak is the only scan engine. ModelGuard does not implement custom probes, custom detectors, custom scoring, a native prompt catalogue, or LLM-as-judge evaluation.

## Current Scope

Available now:

- local Ollama target profile
- garak execution from the ModelGuard CLI
- raw artefact storage under `reports/garak/<scan_id>/`
- normalized ModelGuard reports under `reports/modelguard/`
- report comparison from existing JSON outputs

Planned later:

- AWS Bedrock target profiles
- OpenAI-compatible target profiles
- CI/CD and scheduler integrations
- future AWS deployment support

## Installation

Requirements:

- Python 3.11+
- a running Ollama instance for local scans
- `garak` and the Ollama Python dependency installed in the same environment

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Quick Start

Run the local Ollama garak profile:

```bash
python3 scanner.py scan --config configs/local-ollama-garak.yaml
```

Run an explicit local scan:

```bash
python3 scanner.py scan --target ollama --model deepseek-r1:14b
```

Override the garak probe spec:

```bash
python3 scanner.py scan --target ollama --model deepseek-r1:14b --probes test.Test
```

Write reports with a custom stem:

```bash
python3 scanner.py scan --config configs/local-ollama-garak.yaml --out reports/local-deepseek.md
```

Compare normalized reports:

```bash
python3 scanner.py compare reports/modelguard/*.json --out reports/comparison.html
```

## Output Layout

Each scan writes:

- ModelGuard-normalized reports:
  - `reports/modelguard/<scan_id>.json`
  - `reports/modelguard/<scan_id>.md`
  - `reports/modelguard/<scan_id>.html`
- Raw garak evidence:
  - `reports/garak/<scan_id>/stdout.log`
  - `reports/garak/<scan_id>/stderr.log`
  - `reports/garak/<scan_id>/command_used.txt`
  - `reports/garak/<scan_id>/runtime_metadata.json`
  - `reports/garak/<scan_id>/garak-reports/*.report.jsonl`
  - `reports/garak/<scan_id>/garak-reports/*.report.html`
  - `reports/garak/<scan_id>/garak-reports/*hitlog*.jsonl` when garak produces them

The garak JSONL report is the source of truth for normalization.

## Architecture

```text
CLI / Scheduler / CI
        |
        v
Scan Orchestrator
        |
        v
Target Profile Resolver
        |
        v
garak Command Builder
        |
        v
garak Runner
        |
        v
garak JSONL Parser
        |
        v
ModelGuard Normalized Reports
        |
        v
Governance Reporting / Comparison
```

## Safety

Use ModelGuard only against systems and models you own, operate, or are explicitly authorised to test.

- garak outputs should be treated as internal security artefacts
- model output is treated as untrusted data
- normalized reports redact obvious secrets and email addresses by default
- raw evidence may still contain sensitive content and should be handled accordingly
