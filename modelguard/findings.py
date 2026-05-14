from __future__ import annotations

from dataclasses import asdict

from modelguard.models import DetectorResult, ProbeResult


def select_primary_detector(result_status: str, detector_results: list[DetectorResult]) -> dict[str, object] | None:
    preferred_statuses = [result_status] if result_status in {"WARN", "FAIL"} else []
    preferred_statuses.append("PASS")

    for status in preferred_statuses:
        for detector in detector_results:
            if detector.status == status:
                return asdict(detector)
    return asdict(detector_results[0]) if detector_results else None


def build_finding(result: ProbeResult, finding_index: int) -> dict[str, object]:
    confidence = max((detector.confidence for detector in result.detector_results), default=0.0)
    primary_detector = select_primary_detector(result.status, result.detector_results)

    return {
        "id": f"FIND-{finding_index:04d}",
        "probe_id": result.probe_id,
        "category": result.category,
        "status": result.status,
        "severity": result.severity,
        "confidence": round(confidence, 2),
        "title": result.title,
        "prompt": result.prompt,
        "response_excerpt": _build_response_excerpt(result.response.text, result.response.error),
        "primary_detector_id": str(primary_detector.get("detector_id", "")) if primary_detector else "",
        "primary_rationale": str(primary_detector.get("rationale", "")) if primary_detector else "",
        "primary_evidence": str(primary_detector.get("evidence", "")) if primary_detector else "",
        "detectors": [asdict(detector) for detector in result.detector_results],
        "recommendation": result.recommendation,
    }


def _build_response_excerpt(response_text: str, response_error: str | None) -> str:
    excerpt = response_text.strip()[:800]
    if excerpt:
        return excerpt
    if response_error:
        return f"Target error: {response_error}"
    return ""
