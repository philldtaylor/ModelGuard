from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class ScanConfig:
    target_type: str
    model: str
    base_url: str
    probes: list[str]
    probe_limit: int | None
    output_markdown: str
    output_json: str
    output_html: str
    generation: dict[str, Any]
    thresholds: dict[str, Any]
    reporting: dict[str, Any]
    limits: dict[str, Any]
    scan_name: str = "garak-poc"
    description: str = ""
    config_path: str | None = None


@dataclass(slots=True)
class TargetResponse:
    text: str
    raw: dict[str, Any] | None
    latency_ms: int | None
    token_usage: dict[str, Any] | None
    error: str | None = None


@dataclass(slots=True)
class Probe:
    id: str
    name: str
    category: str
    severity: str
    prompt: str
    detectors: list[str]
    description: str
    safe_expectation: str
    recommendation: str


@dataclass(slots=True)
class DetectorResult:
    detector_id: str
    passed: bool
    confidence: float
    evidence: str
    rationale: str
    status: str
    triggered: bool = False


@dataclass(slots=True)
class ProbeResult:
    probe_id: str
    probe_name: str
    category: str
    prompt: str
    response: TargetResponse
    detector_results: list[DetectorResult]
    status: str
    severity: str
    title: str
    recommendation: str


@dataclass(slots=True)
class ScanSummary:
    total_probes: int
    passed: int
    warned: int
    failed: int
    errors: int
    highest_severity: str


@dataclass(slots=True)
class ScanResult:
    scan_id: str
    started_at: str
    completed_at: str
    started_at_local: str
    completed_at_local: str
    elapsed_seconds: float
    scanner: str
    scanner_version: str
    target: dict[str, Any]
    config: dict[str, Any]
    summary: ScanSummary
    findings: list[dict[str, Any]]
    results: list[ProbeResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan": {
                "id": self.scan_id,
                "scanner": self.scanner,
                "scanner_version": self.scanner_version,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "started_at_local": self.started_at_local,
                "completed_at_local": self.completed_at_local,
                "elapsed_seconds": self.elapsed_seconds,
            },
            "target": self.target,
            "config": self.config,
            "summary": asdict(self.summary),
            "findings": self.findings,
            "results": [asdict(result) for result in self.results],
        }
