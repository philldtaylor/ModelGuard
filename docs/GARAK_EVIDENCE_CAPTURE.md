# garak Evidence Capture for ModelGuard

## Purpose

This guide produces the garak output bundle needed to design ModelGuard's garak parser, normalisation layer, reporting, and comparison engine.

## Expected Output Bundle

The final zip should contain:

```text
garak-evidence/
  command_used.txt
  environment.txt
  garak-stdout.log
  garak-stderr.log
  garak-version.txt
  garak-reports/
    *.report.jsonl
    *.report.html
    *hitlog*.jsonl
```

## Recommended First Target

Use a local Ollama model because it is cheap, controlled, and suitable for parser development.

Example:

```text
deepseek-r1:14b
```

## Safety Notes

- Run only against models and systems you own or are authorised to test.
- Treat garak reports as internal security artefacts.
- garak JSONL reports may contain prompts, responses, model metadata, detector outcomes, and potentially sensitive output.
- Do not publish raw reports without review and redaction.

## Why This Bundle Matters

ModelGuard needs real garak output so it can:

- Parse garak JSONL correctly.
- Preserve raw evidence.
- Build governance summaries.
- Compare runs across models.
- Avoid guessing the report schema.
