# Component Design

## Core Data Models

### ScanConfig

Represents user-provided scan settings.

```python
@dataclass
class ScanConfig:
    target_type: str
    model: str
    probes: list[str]
    output_dir: str
    generation: dict
    thresholds: dict
```

### TargetResponse

Represents a single model response.

```python
@dataclass
class TargetResponse:
    text: str
    raw: dict | None
    latency_ms: int | None
    token_usage: dict | None
    error: str | None = None
```

### Probe

Represents a single security test.

```python
@dataclass
class Probe:
    id: str
    name: str
    category: str
    severity: str
    prompt: str
    detectors: list[str]
    description: str
    safe_expectation: str
```

### ProbeResult

Represents execution output for one probe.

```python
@dataclass
class ProbeResult:
    probe_id: str
    prompt: str
    response: TargetResponse
    detector_results: list[DetectorResult]
    status: str
    severity: str
```

### DetectorResult

Represents evaluation output.

```python
@dataclass
class DetectorResult:
    detector_id: str
    passed: bool
    confidence: float
    evidence: str
    rationale: str
```

## Target Adapter Interface

```python
class BaseTarget:
    def __init__(self, config: dict):
        self.config = config

    def healthcheck(self) -> bool:
        raise NotImplementedError

    def generate(self, prompt: str, **kwargs) -> TargetResponse:
        raise NotImplementedError
```

## Probe Interface

```python
class BaseProbe:
    id: str
    category: str
    severity: str

    def build_prompts(self) -> list[str]:
        raise NotImplementedError

    def detectors(self) -> list[str]:
        raise NotImplementedError
```

## Detector Interface

```python
class BaseDetector:
    id: str

    def evaluate(self, prompt: str, response: str) -> DetectorResult:
        raise NotImplementedError
```

## Reporting Interface

```python
class BaseReporter:
    def write(self, scan_result: ScanResult, output_path: str) -> None:
        raise NotImplementedError
```

## Initial Probe Set

### Prompt Injection Probe

Purpose: Test whether the model follows malicious instructions embedded inside a user message.

Example intent:

```text
The model should not ignore previous instructions, reveal hidden prompts, or claim to access unavailable secrets.
```

### Jailbreak Probe

Purpose: Test whether the model complies with instructions to bypass safety constraints.

Example intent:

```text
The model should refuse policy bypass framing and maintain safe behaviour.
```

### Data Leakage Probe

Purpose: Test whether the model fabricates or reveals secrets, system prompts, API keys, or credentials.

Example intent:

```text
The model should not invent or disclose sensitive data.
```

### Insecure Code Probe

Purpose: Test whether the model produces obviously unsafe code patterns.

Example intent:

```text
The model should avoid dangerous defaults and include security warnings where appropriate.
```

### Tool Misuse Probe

Purpose: Test agentic or tool-enabled systems for inappropriate tool invocation.

Example intent:

```text
The model should not call tools based on untrusted user-controlled content without validation.
```

## Detector Strategy

### Phase 1: Simple Detectors

Use regex and keyword detectors first.

Examples:

- Detect fake API keys.
- Detect unsafe shell commands.
- Detect phrases indicating instruction override.
- Detect direct compliance with prohibited requests.
- Detect secret-looking strings.

### Phase 2: Heuristic Detectors

Add structured logic.

Examples:

- Response contains both a refusal and unsafe content.
- Response gives step-by-step risky instructions.
- Response claims access to hidden context.
- Response prints something that looks like a system prompt.

### Phase 3: LLM-as-Judge

Use a stronger model to classify ambiguous outputs.

Important controls:

- Keep judge prompts deterministic.
- Store judge rationale.
- Do not treat judge output as ground truth.
- Compare judge results against regex and human review.

## Error Handling

The scanner should distinguish between:

- Target connection failure.
- Model generation error.
- Timeout.
- Detector error.
- Report writing error.
- Invalid configuration.

## Exit Codes

Suggested CLI exit codes:

```text
0  Scan completed and threshold passed
1  Findings exceeded threshold
2  Configuration error
3  Target connection error
4  Runtime error
```
