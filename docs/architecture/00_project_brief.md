# Garak PoC / AgentTrace Project Brief

## Purpose

Build a lightweight AI vulnerability scanner inspired by garak that can test local and cloud-hosted LLMs and produce a repeatable security report.

The end state is a Python CLI tool that can be pointed at a model endpoint, execute a configured set of probes, evaluate the responses, and generate JSON, Markdown, and eventually HTML reports.

## Working Name

**AgentTrace**

## Goal

Create a practical proof of concept for testing GenAI workloads, especially:

- Local models running through Ollama, LM Studio, llama.cpp, or OpenAI-compatible APIs.
- Cloud-hosted models such as AWS Bedrock, Azure OpenAI, OpenAI-compatible gateways, or internal inference APIs.
- Future production GenAI workloads with prompt templates, tools, agents, RAG pipelines, and workflow-specific policies.

## Non-Goals for the PoC

The PoC is not intended to be a full garak replacement.

It will not initially include:

- Full benchmark coverage.
- Highly sophisticated statistical scoring.
- A large curated attack corpus.
- Enterprise-grade dashboarding.
- Multi-user access control.
- Persistent scan database.
- Automated exploitation beyond safe prompt-based testing.

## Initial Success Criteria

Version 0.1 is successful if it can:

1. Connect to a local Ollama model.
2. Run a small set of probes.
3. Capture model responses.
4. Detect obvious risky outputs using simple detectors.
5. Produce a Markdown report and JSON evidence file.
6. Be extended without redesigning the whole codebase.

## Guiding Principles

- Keep the scanner modular.
- Separate targets, probes, detectors, scoring, and reporting.
- Preserve raw evidence for later review.
- Prefer simple, inspectable logic before using LLM-as-judge.
- Treat findings as potential vulnerabilities unless manually confirmed.
- Make cloud integration explicit and controlled.
- Avoid any design that accidentally turns the tool into an offensive automation framework.
