from __future__ import annotations

from garak_poc.detectors.base import BaseDetector
from garak_poc.models import DetectorResult


class KeywordDetector(BaseDetector):
    def __init__(
        self,
        detector_id: str,
        patterns: list[str],
        rationale: str,
        status_on_match: str,
        status_on_miss: str = "PASS",
        confidence_on_match: float = 0.8,
        confidence_on_miss: float = 0.8,
    ):
        self.id = detector_id
        self.patterns = [pattern.lower() for pattern in patterns]
        self.rationale = rationale
        self.status_on_match = status_on_match
        self.status_on_miss = status_on_miss
        self.confidence_on_match = confidence_on_match
        self.confidence_on_miss = confidence_on_miss

    def evaluate(self, prompt: str, response: str) -> DetectorResult:
        lowered = response.lower()
        for pattern in self.patterns:
            if pattern in lowered:
                return DetectorResult(
                    detector_id=self.id,
                    passed=self.status_on_match == "PASS",
                    confidence=self.confidence_on_match,
                    evidence=f"Matched keyword: {pattern}",
                    rationale=self.rationale,
                    status=self.status_on_match,
                    triggered=True,
                )
        return DetectorResult(
            detector_id=self.id,
            passed=self.status_on_miss == "PASS",
            confidence=self.confidence_on_miss,
            evidence="No keyword match",
            rationale=self.rationale,
            status=self.status_on_miss,
            triggered=False,
        )
