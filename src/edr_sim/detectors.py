from __future__ import annotations

from collections import Counter
from statistics import mean, pstdev

from .models import ArchitectureMode, DetectionFeatures, DetectionResult, EndpointEvent, EventType


class BehavioralEDRDetector:
    """Simple AI-aware behavioral detector for synthetic endpoint telemetry."""

    def __init__(
        self,
        threshold: float = 4.0,
        architecture: ArchitectureMode = ArchitectureMode.CENTRALIZED,
    ) -> None:
        self.threshold = threshold
        self.architecture = architecture

    def score(self, events: list[EndpointEvent]) -> DetectionResult:
        if not events:
            features = DetectionFeatures(
                event_count=0,
                duration=0.0,
                mean_delta=0.0,
                delta_variation=0.0,
                endpoint_hops=0,
                high_risk_tool_count=0,
                lateral_movement_count=0,
                sensitive_to_exfil=False,
                role_mismatch_count=0,
                repeated_tool_ratio=0.0,
                goal_directedness=0.0,
                human_noise_score=0.0,
                alert_adaptation_score=0.0,
            )
            return DetectionResult(False, 0.0, (), features)

        score = 0.0
        reasons: list[str] = []
        features = extract_features(events)
        event_types = [event.event_type for event in events]

        if features.mean_delta and features.mean_delta < 10.0:
            score += 1.25
            reasons.append("high action tempo")

        if features.delta_variation and features.delta_variation < 4.0:
            score += 1.0
            reasons.append("regular timing pattern")

        if features.lateral_movement_count:
            score += 1.25
            reasons.append("lateral movement sequence")

        if features.sensitive_to_exfil:
            score += 1.5
            reasons.append("sensitive access followed by exfiltration attempt")

        if features.endpoint_hops >= 3:
            score += 1.0
            reasons.append("multi-endpoint path")

        if features.high_risk_tool_count >= 3:
            score += 1.0
            reasons.append("repeated high-risk administration tools")

        if features.role_mismatch_count >= 2:
            score += 0.75
            reasons.append("role and target mismatch")

        if features.goal_directedness >= 0.35:
            score += 1.0
            reasons.append("high goal-directedness")

        if features.human_noise_score <= 0.08:
            score += 0.75
            reasons.append("low human-noise signal")

        score = apply_architecture_adjustment(score, reasons, features, self.architecture)
        suspicious = score >= self.threshold
        detected_at = estimate_detection_time(events, event_types, suspicious)
        return DetectionResult(suspicious, score, tuple(reasons), features, detected_at)


def extract_features(events: list[EndpointEvent]) -> DetectionFeatures:
    ordered = sorted(events, key=lambda event: event.timestamp)
    event_types = [event.event_type for event in ordered]
    deltas = [
        later.timestamp - earlier.timestamp
        for earlier, later in zip(ordered, ordered[1:], strict=False)
    ]
    duration = ordered[-1].timestamp - ordered[0].timestamp if len(ordered) > 1 else 0.0
    mean_delta = mean(deltas) if deltas else 0.0
    delta_variation = pstdev(deltas) if len(deltas) > 1 else 0.0
    tools = [event.tool for event in ordered]
    tool_counts = Counter(tools)
    repeated_tool_ratio = max(tool_counts.values()) / len(tools) if tools else 0.0
    high_risk_tools = {"wmic", "certutil", "powershell", "net"}
    high_value_targets = {"domain-controller", "database", "file-share", "admin-host"}
    human_noise_values = {"mistyped", "abandoned", "corrected"}

    sensitive_index = _first_index(event_types, EventType.SENSITIVE_ACCESS)
    exfil_index = _first_index(event_types, EventType.EXFIL_ATTEMPT)
    sensitive_to_exfil = (
        sensitive_index is not None
        and exfil_index is not None
        and sensitive_index < exfil_index
    )

    attack_stage_count = sum(
        event_type
        in {
            EventType.DISCOVERY,
            EventType.LATERAL_MOVEMENT,
            EventType.SENSITIVE_ACCESS,
            EventType.EXFIL_ATTEMPT,
        }
        for event_type in event_types
    )
    goal_directedness = attack_stage_count / len(ordered)
    human_noise_score = sum(
        event.metadata.get("command_quality") in human_noise_values for event in ordered
    ) / len(ordered)
    role_mismatch_count = sum(
        event.role in {"developer", "analyst", "unknown"} and event.target in high_value_targets
        for event in ordered
    )
    alert_adaptation_score = max(
        int(event.metadata.get("adaptation_level", 0)) for event in ordered
    )

    return DetectionFeatures(
        event_count=len(ordered),
        duration=duration,
        mean_delta=mean_delta,
        delta_variation=delta_variation,
        endpoint_hops=len({event.endpoint_id for event in ordered}),
        high_risk_tool_count=sum(event.tool in high_risk_tools for event in ordered),
        lateral_movement_count=sum(event.event_type == EventType.LATERAL_MOVEMENT for event in ordered),
        sensitive_to_exfil=sensitive_to_exfil,
        role_mismatch_count=role_mismatch_count,
        repeated_tool_ratio=repeated_tool_ratio,
        goal_directedness=goal_directedness,
        human_noise_score=human_noise_score,
        alert_adaptation_score=float(alert_adaptation_score),
    )


def apply_architecture_adjustment(
    score: float,
    reasons: list[str],
    features: DetectionFeatures,
    architecture: ArchitectureMode,
) -> float:
    """Approximate how EDR architecture changes visibility and correlation."""

    if architecture == ArchitectureMode.LOCAL:
        if features.endpoint_hops >= 3:
            score -= 0.75
            reasons.append("local mode loses cross-endpoint context")
        return max(score, 0.0)

    if architecture == ArchitectureMode.CENTRALIZED:
        if features.event_count >= 30 and features.mean_delta < 8.0:
            score -= 0.5
            reasons.append("central queue pressure")
        elif features.endpoint_hops >= 3:
            score += 0.5
            reasons.append("central cross-endpoint correlation")
        return max(score, 0.0)

    if architecture == ArchitectureMode.FEDERATED:
        if features.endpoint_hops >= 2:
            score += 0.75
            reasons.append("shared behavioral indicator correlation")
        if features.alert_adaptation_score >= 2:
            score += 0.25
            reasons.append("federated memory of adapted behavior")
        return score

    if architecture == ArchitectureMode.HYBRID:
        if features.endpoint_hops >= 2:
            score += 0.5
            reasons.append("hybrid local response plus central context")
        if features.mean_delta < 8.0:
            score += 0.25
            reasons.append("fast local containment path")
        return score

    return score


def estimate_detection_time(
    events: list[EndpointEvent],
    event_types: list[EventType],
    suspicious: bool,
) -> float | None:
    if not suspicious:
        return None
    for event in events:
        if event.event_type in {
            EventType.LATERAL_MOVEMENT,
            EventType.SENSITIVE_ACCESS,
            EventType.EXFIL_ATTEMPT,
        }:
            return event.timestamp
    return events[-1].timestamp


def _first_index(values: list[EventType], target: EventType) -> int | None:
    try:
        return values.index(target)
    except ValueError:
        return None
