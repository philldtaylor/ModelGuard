from __future__ import annotations

import re

from modelguard.models import ScanResult

SECRET_REPLACEMENTS = [
    (re.compile(r"(sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY)", re.IGNORECASE), "[REDACTED_SECRET]"),
    (re.compile(r"(bearer\s+)([A-Za-z0-9._-]{10,})", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[REDACTED_EMAIL]"),
]


def redact_text(text: str) -> str:
    redacted = text
    for pattern, replacement in SECRET_REPLACEMENTS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def apply_redaction(scan_result: ScanResult, evidence_mode: str) -> ScanResult:
    if evidence_mode == "full":
        return scan_result
    for finding in scan_result.findings:
        finding["prompt"] = redact_text(str(finding.get("prompt", "")))
        finding["response_excerpt"] = redact_text(str(finding.get("response_excerpt", "")))
        finding["primary_evidence"] = redact_text(str(finding.get("primary_evidence", "")))
        for detector in finding.get("detectors", []):
            detector["evidence"] = redact_text(str(detector.get("evidence", "")))
    for result in scan_result.results:
        result.prompt = redact_text(result.prompt)
        result.response.text = redact_text(result.response.text)
        for detector in result.detector_results:
            detector.evidence = redact_text(detector.evidence)
    return scan_result
