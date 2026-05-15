# ModelGuard Project Pinned Files Guide

## Goal

Keep the project context clean and authoritative so future ChatGPT and Codex work does not drift back toward the superseded custom scanner design.

## Recommended Pinned Files

Pin the following files to the project:

```text
ARCHITECTURE_DECISION.md
TARGET_USE_CASES.md
PINNED_FILES_GUIDE.md
modelguard-source.zip
garak-sample-output.zip
README.md
deepseek-fp-report.md
```

## Required Files

### ARCHITECTURE_DECISION.md

Single source of truth for the architecture.

Confirms:

- ModelGuard orchestrates garak.
- No custom probes.
- No custom detectors.
- No custom scoring.
- ModelGuard owns orchestration, target abstraction, reporting, comparison, AWS deployment, scheduling, CI, and evidence handling.

### TARGET_USE_CASES.md

Defines the enterprise workflows the product should serve.

Use this to keep implementation grounded in real assurance and governance needs.

### modelguard-source.zip

Zip of the current working codebase.

Should include:

```text
modelguard/
scanner.py
requirements.txt
configs/
tests/
README.md
```

Do not rely on individually pinned Python files unless investigating a very specific bug.

### garak-sample-output.zip

Evidence bundle from a real garak run.

Should include:

```text
garak stdout log
garak stderr log, if any
garak JSONL report
garak HTML report, if generated
garak hit log, if generated
command_used.txt
environment.txt
```

This is essential for designing the parser and normalisation layer without guessing garak's schema.

### README.md

Current project README.

Should be updated after the architecture pivot to describe ModelGuard as a garak orchestration layer.

### deepseek-fp-report.md

The report that triggered the rethink away from custom detectors.

Keep it as rationale/evidence for why ModelGuard should not classify model responses itself.

## Files to Unpin or Archive

Unpin or archive old files that describe the superseded custom scanner model, especially files focused on:

- Custom probes
- Detector registries
- Regex/keyword scoring
- LLM-as-judge scoring
- Native probe catalogues
- Replacing garak

Suggested archive folder in Git:

```text
archive/pre-garak-pivot/
```

The files can remain in Git history, but they should not be pinned as project source-of-truth material.

## Practical Rule

If a pinned file says “build probes” or “build detectors”, it is probably obsolete.

If a pinned file says “orchestrate garak and report the results”, it is probably current.
