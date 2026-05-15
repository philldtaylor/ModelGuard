# Architecture Decision: ModelGuard as a garak Orchestration Layer

## Decision

ModelGuard will orchestrate NVIDIA garak rather than implement its own probe, detector, or scoring engine.

ModelGuard is an enterprise orchestration, reporting, comparison, and deployment layer around garak.

## Confirmed Architecture

```text
ModelGuard
├── Scan orchestration
├── Target abstraction
├── Governance reporting
├── Comparison engine
├── AWS deployment
├── Scheduling / CI
└── garak execution engine
```

## Explicit Non-Goals

ModelGuard will not implement:

- Custom probes
- Custom detectors
- Custom scoring logic
- A native prompt test catalogue
- LLM-as-judge evaluation for model responses
- A replacement scanner competing with garak

Any previous ModelGuard or AgentTrace design notes that describe custom probes, detector registries, regex scoring, keyword scoring, or native vulnerability classification are superseded by this decision.

## Rationale

The project originally explored a lightweight scanner with native probes and detectors. That direction created false-positive risk and reduced enterprise credibility because the tool would be judged as a home-grown scanner.

The revised model is stronger for regulated and enterprise environments:

- garak provides the recognised LLM vulnerability scanning engine.
- ModelGuard provides the operational wrapper needed by enterprises.
- Governance reports can be built from garak evidence without reinterpreting findings using brittle custom logic.
- CI/CD, scheduling, AWS deployment, target profiles, evidence handling, and comparison are all valuable enterprise capabilities outside garak's core purpose.

## Target Operating Model

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
garak Command / Config Builder
        |
        v
garak Execution Engine
        |
        v
garak Output Collector
        |
        v
garak JSONL Parser
        |
        v
ModelGuard Normalised Result Schema
        |
        v
Governance Reports / Comparison / Evidence Bundle
```

## ModelGuard Responsibilities

### Scan orchestration

- Accept scan requests from CLI, CI, or scheduler.
- Resolve target profiles.
- Build safe garak command/config invocations.
- Execute garak in a controlled subprocess.
- Capture stdout, stderr, exit code, runtime metadata, and report paths.
- Enforce timeouts, output directories, and safe defaults.

### Target abstraction

- Represent model/application targets as ModelGuard target profiles.
- Translate target profiles into garak generator/model settings.
- Support local Ollama first.
- Add AWS Bedrock and other enterprise targets later.

### garak execution engine

- Invoke garak as the scanning engine.
- Store raw garak outputs as evidence.
- Avoid modifying garak probe/detector semantics.
- Avoid introducing ModelGuard-owned model safety classification.

### Result normalisation

- Parse garak JSONL output.
- Extract run metadata, generator information, probes, detectors, attempts, outputs, and eval summaries.
- Map garak entries into a ModelGuard report schema for consistent enterprise reporting.
- Preserve links back to raw garak evidence.

### Governance reporting

- Produce Markdown, JSON, and HTML reports suitable for review.
- Summarise findings by model, probe, detector, severity/score, and scan profile.
- Include caveats that garak results are security test signals requiring review.
- Add report classification and evidence sensitivity warnings.
- Redact obvious secrets in exported reports while preserving raw evidence internally where configured.

### Comparison engine

- Compare multiple ModelGuard-normalised garak runs.
- Support model selection, regression testing, and assurance checkpoints.
- Compare by model, generator, probe family, detector, score, runtime, and scan profile.

### AWS deployment

- Provide deployment patterns for running scans from CI runners, security test runners, or scheduled jobs.
- Use least-privilege IAM roles.
- Store evidence and reports in controlled S3 paths.
- Support future integration with Security Hub, ticketing, or SIEM workflows.

### Scheduling / CI

- Support repeatable scans in CI/CD pipelines.
- Produce stable exit codes for policy gates.
- Keep scan volume and probe selection explicit.
- Allow scheduled assurance scans for approved non-production targets.

## First Implementation Target

Refactor the current ModelGuard codebase into a garak orchestration wrapper.

Initial scope:

1. Remove or bypass native probe execution.
2. Remove or deprecate native detector/scoring logic.
3. Add a garak runner module.
4. Add a garak output parser for JSONL reports.
5. Add a normalised ModelGuard result schema.
6. Reuse reporting and comparison where practical.
7. Provide an Ollama target profile that runs garak against a local Ollama model.
8. Preserve raw garak outputs under `reports/garak/` or equivalent.

## Suggested Repository Direction

```text
modelguard/
  cli.py
  config.py
  orchestration/
    scan_orchestrator.py
  targets/
    profiles.py
    ollama.py
    bedrock.py
  garak/
    command_builder.py
    runner.py
    parser.py
    normalizer.py
  reporting/
    json_report.py
    markdown_report.py
    html_report.py
    comparison_report.py
  evidence/
    redaction.py
    bundle.py
  ci/
    exit_codes.py
configs/
  local-ollama-garak.yaml
reports/
  garak/
  modelguard/
tests/
```

## Migration Principle

Do not extend the custom scanner.

Refactor toward this shape:

```text
Old: ModelGuard probes -> ModelGuard detectors -> ModelGuard scoring -> reports
New: garak probes -> garak detectors -> garak output -> ModelGuard governance reports
```

## Status

Accepted.
