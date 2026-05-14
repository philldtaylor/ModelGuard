Build ModelGuard v0.1: a lightweight Python AI vulnerability scanner inspired by garak.

Implement the architecture from the project docs:

- CLI / Runner
- Ollama target adapter
- static probe registry
- regex, keyword and refusal detectors
- scoring engine
- JSON + Markdown report output
- safe authorised-use README
- minimal tests

Required command:

python scanner.py --target ollama --model deepseek-r1:14b --out reports/ollama-deepseek-r1-14b.md

This must create:

reports/ollama-deepseek-r1-14b.json
reports/ollama-deepseek-r1-14b.md

Use Python 3.11+.

Preferred structure:

scanner.py
modelguard/
  __init__.py
  cli.py
  config.py
  runner.py
  models.py
  targets/
    __init__.py
    base.py
    ollama.py
  probes/
    __init__.py
    base.py
    registry.py
  detectors/
    __init__.py
    base.py
    regex.py
    keywords.py
    refusal.py
  reporting/
    __init__.py
    json_report.py
    markdown_report.py
  scoring.py
configs/
  local-ollama.yaml
reports/
tests/
README.md
requirements.txt

Implementation constraints:

- Do not execute model output.
- Treat all model output as untrusted.
- Redact obvious secrets in reports.
- Use safe prompt-based probes only.
- Keep dependencies minimal: requests, pyyaml, pytest.
- Add clear authorised-use wording.
- Add around 12 safe probes across prompt injection, jailbreak resistance, data leakage, and insecure code generation.
- Findings should use PASS, WARN, FAIL, ERROR.
- Exit 0 if scan completes below threshold.
- Exit 1 if findings exceed threshold.
- Exit 2+ for scanner/config/target errors.

Ollama API:

POST http://localhost:11434/api/generate

Payload:

{
  "model": "deepseek-r1:14b",
  "prompt": "...",
  "stream": false,
  "options": {
    "temperature": 0
  }
}

The response contains a "response" field.

After implementing, run tests, then run the scanner against the local Ollama model if available.
