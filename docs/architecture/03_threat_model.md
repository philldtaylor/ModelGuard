# Threat Model

## Scope

This threat model covers the AgentTrace scanner and the GenAI workloads it tests.

The scanner is intended for authorised testing only against local models, owned cloud accounts, internal applications, or explicitly approved systems.

## Assets

### Scanner Assets

- Scan configuration files.
- API keys and cloud credentials.
- Probe corpus.
- Raw prompts and responses.
- Reports and evidence bundles.
- CI/CD secrets.
- Local model endpoints.

### Target Assets

- Model endpoint.
- System prompts.
- RAG data sources.
- Tool/function interfaces.
- Application secrets.
- User data.
- Agent execution permissions.

## Trust Boundaries

```text
User CLI
  -> Scanner runtime
  -> Target adapter
  -> Model provider or local endpoint
  -> Optional tools / RAG / downstream APIs
  -> Report storage
```

## Primary Risks

### Credential Exposure

Risk: API keys or cloud credentials are exposed through logs, reports, prompts, or exceptions.

Mitigations:

- Never print credentials.
- Redact known secret patterns.
- Support `.env` but never write it into reports.
- Add secret scanning for generated reports.
- Keep raw evidence access controlled.

### Unsafe Probe Content

Risk: Probes contain offensive or sensitive content that creates operational or policy issues.

Mitigations:

- Keep probes focused on defensive validation.
- Avoid providing operational exploitation instructions.
- Keep test prompts configurable by risk tier.
- Add a safe-mode probe pack for CI.

### Target Abuse

Risk: Scanner accidentally sends high-volume traffic to paid or production endpoints.

Mitigations:

- Rate limiting.
- Max probe count.
- Dry-run mode.
- Explicit cloud target confirmation.
- Budget and token controls.
- Per-run cost estimate where available.

### Report Sensitivity

Risk: Reports contain sensitive model output, internal prompts, or leaked data.

Mitigations:

- Mark reports as sensitive.
- Redact secrets by default.
- Provide `--include-raw` only when explicitly requested.
- Store raw evidence separately from summary reports.

### False Positives and False Negatives

Risk: Scanner incorrectly classifies model behaviour.

Mitigations:

- Use confidence scores.
- Preserve evidence.
- Label findings as potential unless manually verified.
- Use multiple detector types.
- Add manual review workflow.

### Prompt Injection Against the Scanner

Risk: A model response attempts to influence scanner behaviour, especially if LLM-as-judge or agentic remediation is added.

Mitigations:

- Treat model output as untrusted data.
- Never execute model output.
- Do not let model output modify scanner config.
- Isolate judge prompts from execution logic.
- Disable tools for judge models unless explicitly needed.

### Cloud Misconfiguration

Risk: Scanner integration with AWS, Azure, or other providers uses excessive permissions.

Mitigations:

- Use least-privilege IAM.
- Separate read/test role from deployment role.
- Avoid wildcard permissions.
- Log scan activity.
- Use dedicated test accounts where possible.

## Abuse-Resistance Principles

- Do not include exploit automation against third-party systems.
- Do not include credential harvesting workflows.
- Do not include stealth or evasion features.
- Do not automatically execute generated code.
- Do not scan systems without authorisation.

## Defensive Use Cases

- Pre-deployment model validation.
- Regression testing after prompt or model changes.
- CI/CD security gate for GenAI workflows.
- Internal red-team support.
- RAG prompt-injection testing.
- Agent tool-use safety testing.
- Evidence collection for AI governance.
