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


@dataclass
class DetectionResult:
    suspicious: bool
    score: float
    reasons: list[str]
    detected_at: float | None = None

