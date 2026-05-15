# ModelGuard Target Use Cases

## Purpose

This file defines the enterprise use cases ModelGuard should support as a garak orchestration and governance layer.

ModelGuard should be designed around realistic assurance workflows rather than as a toy wrapper around a command-line scanner.

## Primary Use Cases

### 1. Local model assurance

A security engineer runs garak through ModelGuard against a local Ollama model before using it in a lab, prototype, or internal workflow.

Example targets:

- `deepseek-r1:14b` via Ollama
- `llama3` via Ollama
- `mistral` via Ollama

Value from ModelGuard:

- Repeatable target profiles
- Report normalisation
- Evidence bundles
- Comparison across local models

### 2. Model selection checkpoint

A team compares several candidate models before selecting one for an internal GenAI workload.

Example question:

> Which candidate model has the best garak scan profile for our intended use case?

Value from ModelGuard:

- Multi-run comparison
- Governance-friendly summary
- Consistent evidence format
- Historical scan preservation

### 3. CI/CD prompt or model regression gate

A development team changes model configuration, system prompts, or application guardrails. ModelGuard runs a controlled garak scan as part of CI/CD.

Value from ModelGuard:

- Stable exit codes
- Safe scan profiles
- Build artefacts
- Regression comparison against a baseline

### 4. AWS Bedrock assurance

A cloud security or platform team tests approved AWS Bedrock model configurations from a controlled security runner.

Value from ModelGuard:

- AWS target profiles
- Least-privilege IAM guidance
- S3 evidence storage
- Cloud scan metadata
- Cost and rate safety controls

### 5. Scheduled assurance scans

A security team schedules recurring scans of approved non-production AI endpoints.

Value from ModelGuard:

- Scan scheduling
- Trend reporting
- Evidence retention
- Drift detection

### 6. Governance and audit evidence

An AI governance committee, model risk team, or security assurance function needs evidence that model safety testing occurred.

Value from ModelGuard:

- Executive summaries
- Raw evidence preservation
- Report classification banners
- Scan metadata
- Target metadata
- Comparison history

### 7. GenAI application endpoint testing

Later, ModelGuard may orchestrate garak or compatible testing against an application endpoint rather than a raw base model.

Example applications:

- Internal RAG assistant
- SOC analyst copilot
- Developer code assistant
- Customer service chatbot
- Agentic workflow with tool access

Value from ModelGuard:

- Application target profiles
- Auth and request templating
- Controlled evidence handling
- Environment separation

## Out of Scope

ModelGuard should not become:

- A custom vulnerability scanner
- A custom probe library
- A custom detector framework
- An offensive exploitation toolkit
- A replacement for garak

## Design Implication

Every feature should answer one of these enterprise questions:

1. How do we run garak consistently?
2. How do we target the right model or endpoint safely?
3. How do we preserve useful evidence?
4. How do we explain results to governance stakeholders?
5. How do we compare runs over time?
6. How do we integrate scans into AWS and CI/CD workflows?
