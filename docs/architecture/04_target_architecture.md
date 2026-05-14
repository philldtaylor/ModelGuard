# Target Architecture

## Target Abstraction

A target is anything that accepts a prompt and returns model output.

Examples:

- Local Ollama model.
- LM Studio OpenAI-compatible endpoint.
- llama.cpp server.
- AWS Bedrock model.
- Azure OpenAI deployment.
- Internal inference API.
- GenAI application endpoint.

## Adapter Contract

Every adapter should implement:

```python
healthcheck() -> bool
metadata() -> dict
generate(prompt: str, **kwargs) -> TargetResponse
```

## Local Target: Ollama

### Example Config

```yaml
target:
  type: ollama
  base_url: http://localhost:11434
  model: deepseek-r1:14b

generation:
  temperature: 0
  max_tokens: 1024
  timeout_seconds: 60
```

### Benefits

- Easy local testing.
- No cloud cost.
- Good first adapter.
- Useful for scanner development.

### Considerations

- Model behaviour may differ from hosted models.
- Local hardware affects latency.
- Some models include reasoning traces that need report handling.

## OpenAI-Compatible Target

### Example Config

```yaml
target:
  type: openai_compatible
  base_url: http://localhost:1234/v1
  api_key_env: OPENAI_API_KEY
  model: local-model

generation:
  temperature: 0
  max_tokens: 1024
```

### Benefits

- Works with many gateways.
- Useful for LM Studio, vLLM, LiteLLM, local proxies, and internal APIs.
- Good bridge between local and cloud testing.

## AWS Bedrock Target

### Example Config

```yaml
target:
  type: bedrock
  region: eu-west-2
  model: mistral.mistral-large-2402-v1:0
  profile: security-lab

generation:
  temperature: 0
  max_tokens: 1024
```

### IAM Principle

Use a dedicated scanner role with the narrowest possible model invocation permissions.

Example conceptual permission:

```text
Allow bedrock:InvokeModel only for approved model ARNs.
Deny access to unrelated AWS services.
```

## Azure OpenAI Target

### Example Config

```yaml
target:
  type: azure_openai
  endpoint: https://example.openai.azure.com
  deployment: gpt-4o-mini-security-test
  api_key_env: AZURE_OPENAI_API_KEY
  api_version: 2024-xx-xx

generation:
  temperature: 0
  max_tokens: 1024
```

## Application Target

Eventually, the scanner should test full applications, not just raw models.

An application target might include:

```yaml
target:
  type: http_app
  url: https://internal-ai-app.example/api/chat
  auth:
    type: bearer
    token_env: APP_TEST_TOKEN
  request_template:
    method: POST
    json:
      message: "{{ prompt }}"
  response_path: $.answer
```

This allows testing:

- Prompt templates.
- RAG layers.
- Tool controls.
- Guardrails.
- Business logic.
- End-to-end application behaviour.

## Target Metadata

Each scan should record:

- Target type.
- Model name.
- Endpoint host, with sensitive details redacted.
- Generation parameters.
- Timestamp.
- Scanner version.
- Probe set version.

## Safety Controls

All target adapters should support:

- Timeout.
- Retry limit.
- Rate limit.
- Max tokens.
- Redaction.
- Dry run.
- Explicit cloud mode.
