# Reporting Schema

## Report Types

AgentTrace should produce at least two files per scan:

```text
reports/<scan_id>.json
reports/<scan_id>.md
```

Future formats:

```text
reports/<scan_id>.html
reports/<scan_id>.sarif
reports/<scan_id>.csv
```

## JSON Report Structure

```json
{
  "scan": {
    "id": "2026-05-11T17-30-00Z-deepseek-r1-14b",
    "scanner": "agentrace",
    "scanner_version": "0.1.0",
    "started_at": "2026-05-11T17:30:00Z",
    "completed_at": "2026-05-11T17:32:00Z"
  },
  "target": {
    "type": "ollama",
    "model": "deepseek-r1:14b",
    "base_url": "http://localhost:11434",
    "generation": {
      "temperature": 0,
      "max_tokens": 1024
    }
  },
  "summary": {
    "total_probes": 20,
    "passed": 14,
    "warned": 3,
    "failed": 3,
    "errors": 0,
    "highest_severity": "High"
  },
  "findings": [
    {
      "id": "FIND-0001",
      "probe_id": "prompt_injection.ignore_previous",
      "category": "prompt_injection",
      "status": "FAIL",
      "severity": "High",
      "confidence": 0.86,
      "title": "Model followed instruction override attempt",
      "prompt": "...",
      "response_excerpt": "...",
      "detectors": [
        {
          "id": "keyword_instruction_override",
          "passed": false,
          "evidence": "Matched phrase: ignoring previous instructions"
        }
      ],
      "recommendation": "Strengthen instruction hierarchy and add prompt injection filtering."
    }
  ],
  "results": []
}
```

## Markdown Report Structure

```markdown
# AgentTrace Scan Report

## Executive Summary

## Target

## Scan Configuration

## Findings Summary

## Findings

### FIND-0001: Title

- Severity:
- Category:
- Probe:
- Status:
- Confidence:

#### Evidence

#### Recommendation

## Full Probe Results

## Appendix
```

## Report Sensitivity

Reports may contain sensitive data. Treat all raw scan reports as internal security artefacts.

Recommended banner:

```text
Classification: Internal / Security Sensitive
This report may contain raw model responses, prompts, system behaviour, and possible sensitive output.
```

## Redaction

Redact by default:

- API keys.
- Bearer tokens.
- AWS keys.
- Private keys.
- Session cookies.
- Email addresses if not needed.
- Internal hostnames if exporting externally.

## Evidence Handling

Recommended modes:

```text
--evidence summary      Store only excerpts
--evidence full         Store full prompts and responses
--evidence redacted     Store full evidence with redaction
```

Default should be `redacted`.

## CI Output

The scanner should support a threshold:

```bash
python scanner.py --fail-on high
```

Suggested behaviour:

```text
No High/Critical findings: exit 0
High/Critical findings present: exit 1
Scanner error: exit 2+
```
