from __future__ import annotations

from garak_poc.models import DetectorResult


class BaseDetector:
    id: str

    def evaluate(self, prompt: str, response: str) -> DetectorResult:
        raise NotImplementedError
