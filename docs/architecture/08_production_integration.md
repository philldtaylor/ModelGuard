# Production Integration Architecture

## Production Use Cases

AgentTrace can support several production security workflows:

1. Pre-deployment model validation.
2. Prompt template regression testing.
3. RAG application security checks.
4. Agent tool-use safety testing.
5. CI/CD security gates.
6. Scheduled assurance scans.
7. Evidence generation for governance and audit.

## CI/CD Integration

Example pipeline:

```text
Developer changes prompt/model/app config
        |
        v
Pull request opened
        |
        v
AgentTrace safe probe pack runs
        |
        v
Report uploaded as build artefact
        |
        v
Pipeline fails if severity threshold exceeded
```

## Example GitHub Actions Flow

```yaml
name: AgentTrace AI Security Scan

on:
  pull_request:
    paths:
      - prompts/**
      - app/ai/**
      - configs/model/**

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python scanner.py --config configs/ci-safe.yaml --fail-on high
      - uses: actions/upload-artifact@v4
        with:
          name: agentrace-report
          path: reports/
```

## AWS Integration

For AWS-hosted GenAI workloads, AgentTrace could integrate with:

- AWS Bedrock for direct model testing.
- API Gateway endpoints for application testing.
- Lambda-based GenAI workflows.
- ECS/EKS-hosted inference services.
- CloudWatch logs for scan audit events.
- S3 for report storage.
- Security Hub for findings ingestion.

## Recommended AWS Deployment Pattern

```text
CI/CD runner or security test runner
        |
        v
Dedicated IAM role with least privilege
        |
        v
Approved Bedrock model or internal AI endpoint
        |
        v
Reports written to controlled S3 bucket
        |
        v
Optional ticket / Security Hub / SIEM integration
```

## IAM Guidance

Use a dedicated scanner role.

The role should only be able to:

- Invoke approved model endpoints.
- Write reports to a specific bucket or path.
- Emit logs to a specific log group.

The role should not be able to:

- Manage IAM.
- Read arbitrary secrets.
- Modify production infrastructure.
- Invoke unrelated tools or agents.

## Environment Separation

Recommended environments:

```text
Local development  -> Local models and mock apps
Dev cloud          -> Non-production model endpoints
Staging            -> Production-like GenAI workflows
Production         -> Restricted, low-risk validation only
```

## Scan Tiers

### Tier 1: Safe CI Pack

- Low-risk probes.
- Low volume.
- No aggressive jailbreak corpus.
- Runs on pull requests.

### Tier 2: Staging Security Pack

- Broader prompt injection and jailbreak testing.
- RAG-specific tests.
- Agent tool-use tests.
- Runs before release.

### Tier 3: Manual Red-Team Pack

- Deeper adversarial testing.
- Human-supervised.
- Evidence review required.
- Not suitable for automatic production execution.

## Operational Controls

Production usage should include:

- Rate limits.
- Cost limits.
- Logging.
- Clear ownership.
- Report retention policy.
- Secret redaction.
- Approval for high-risk probe packs.
- Manual review for high-severity findings.

## Metrics

Useful metrics:

- Findings by severity.
- Findings by model.
- Findings by application.
- Pass/fail trend over time.
- Prompt injection regression count.
- Unsafe code generation rate.
- Tool misuse failure rate.
- Mean time to remediate.
