from __future__ import annotations

import re

from modelguard.detectors.base import BaseDetector
from modelguard.models import DetectorResult


class RegexDetector(BaseDetector):
    def __init__(
        self,
        detector_id: str,
        pattern: str,
        rationale: str,
        status_on_match: str,
        status_on_miss: str = "PASS",
        confidence_on_match: float = 0.85,
        confidence_on_miss: float = 0.8,
    ):
        self.id = detector_id
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.rationale = rationale
        self.status_on_match = status_on_match
        self.status_on_miss = status_on_miss
        self.confidence_on_match = confidence_on_match
        self.confidence_on_miss = confidence_on_miss

    def evaluate(self, prompt: str, response: str) -> DetectorResult:
        match = self.regex.search(response)
        if match:
            return DetectorResult(
                detector_id=self.id,
                passed=self.status_on_match == "PASS",
                confidence=self.confidence_on_match,
                evidence=f"Matched regex: {match.group(0)[:120]}",
                rationale=self.rationale,
                status=self.status_on_match,
                triggered=True,
            )
        return DetectorResult(
            detector_id=self.id,
            passed=self.status_on_miss == "PASS",
            confidence=self.confidence_on_miss,
            evidence="No regex match",
            rationale=self.rationale,
            status=self.status_on_miss,
            triggered=False,
        )
