from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    PROCESS_START = "process_start"
    COMMAND_EXEC = "command_exec"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECT = "network_connect"
    AUTH = "auth"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    SENSITIVE_ACCESS = "sensitive_access"
    EXFIL_ATTEMPT = "exfil_attempt"


class TrafficClass(str, Enum):
    BENIGN_ADMIN = "benign_admin"
    SCRIPTED_ATTACKER = "scripted_attacker"
    AI_AGENT_ATTACKER = "ai_agent_attacker"


class ActorProfile(str, Enum):
    OFFICE_WORKER = "office_worker"
    DEVELOPER = "developer"
    SYSADMIN = "sysadmin"
    HELPDESK = "helpdesk"
    SERVICE_ACCOUNT = "service_account"
    SCRIPTED_ATTACKER = "scripted_attacker"
    AI_AGENT_ATTACKER = "ai_agent_attacker"


class ArchitectureMode(str, Enum):
    LOCAL = "local"
    CENTRALIZED = "centralized"
    FEDERATED = "federated"
    HYBRID = "hybrid"


@dataclass(frozen=True)
class EndpointEvent:
    """One safe, abstract EDR-style telemetry event."""

    timestamp: float
    endpoint_id: str
    user: str
    role: str
    event_type: EventType
    tool: str
    target: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionProfile:
    traffic_class: TrafficClass
    seed: int
    session_id: str
    actor_profile: ActorProfile
    endpoint_count: int = 5
    length: int = 32
    adaptation_level: int = 0


@dataclass(frozen=True)
class DetectionFeatures:
    event_count: int
    duration: float
    mean_delta: float
    delta_variation: float
    endpoint_hops: int
    high_risk_tool_count: int
    lateral_movement_count: int
    sensitive_to_exfil: bool
    role_mismatch_count: int
    repeated_tool_ratio: float
    goal_directedness: float
    human_noise_score: float
    alert_adaptation_score: float


@dataclass(frozen=True)
class DetectionResult:
    suspicious: bool
    score: float
    reasons: tuple[str, ...]
    features: DetectionFeatures
    detected_at: float | None = None


@dataclass(frozen=True)
class SimulationRun:
    traffic_class: TrafficClass
    actor_profile: ActorProfile
    architecture: ArchitectureMode
    seed: int
    session_id: str
    detected: bool
    score: float
    reasons: tuple[str, ...]
    time_to_detection: float | None
    attack_success: bool
    false_positive: bool
    true_positive: bool
    event_count: int
