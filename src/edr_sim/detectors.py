from __future__ import annotations

from statistics import mean

from .models import DetectionResult, EndpointEvent, EventType


class BehavioralEDRDetector:
    """Simple AI-aware behavioral detector for synthetic endpoint telemetry."""

    def __init__(self, threshold: float = 4.0) -> None:
        self.threshold = threshold

    def score(self, events: list[EndpointEvent]) -> DetectionResult:
        if not events:
            return DetectionResult(False, 0.0, [])

        score = 0.0
        reasons: list[str] = []
        event_types = [event.event_type for event in events]
        deltas = [
            later.timestamp - earlier.timestamp
            for earlier, later in zip(events, events[1:], strict=False)
        ]

        if deltas and mean(deltas) < 10.0:
            score += 1.25
            reasons.append("high action tempo")

        if deltas and len(set(round(delta, 1) for delta in deltas)) <= max(2, len(deltas) // 8):
            score += 1.0
            reasons.append("regular timing pattern")

        if EventType.LATERAL_MOVEMENT in event_types:
            score += 1.25
            reasons.append("lateral movement sequence")

        if EventType.SENSITIVE_ACCESS in event_types and EventType.EXFIL_ATTEMPT in event_types:
            score += 1.5
            reasons.append("sensitive access followed by exfiltration attempt")

        endpoint_hops = len({event.endpoint_id for event in events})
        if endpoint_hops >= 3:
            score += 1.0
            reasons.append("multi-endpoint path")

        rare_admin_tools = {"wmic", "certutil", "powershell"}
        if sum(event.tool in rare_admin_tools for event in events) >= 3:
            score += 1.0
            reasons.append("repeated high-risk administration tools")

        suspicious = score >= self.threshold
        detected_at = events[-1].timestamp if suspicious else None
        return DetectionResult(suspicious, score, reasons, detected_at)

