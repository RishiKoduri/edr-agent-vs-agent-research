from __future__ import annotations

import random
from collections.abc import Iterable

from .models import EndpointEvent, EventType, TrafficClass


TOOLS_BY_CLASS = {
    TrafficClass.BENIGN_ADMIN: ["ssh", "bash", "python", "browser", "scp"],
    TrafficClass.SCRIPTED_ATTACKER: ["powershell", "net", "wmic", "curl", "certutil"],
    TrafficClass.AI_AGENT_ATTACKER: ["powershell", "net", "wmic", "python", "curl"],
}


ATTACK_CHAIN = [
    EventType.DISCOVERY,
    EventType.AUTH,
    EventType.PROCESS_START,
    EventType.COMMAND_EXEC,
    EventType.NETWORK_CONNECT,
    EventType.LATERAL_MOVEMENT,
    EventType.SENSITIVE_ACCESS,
    EventType.EXFIL_ATTEMPT,
]


BENIGN_CHAIN = [
    EventType.AUTH,
    EventType.PROCESS_START,
    EventType.COMMAND_EXEC,
    EventType.FILE_ACCESS,
    EventType.NETWORK_CONNECT,
]


def generate_session(
    traffic_class: TrafficClass,
    *,
    seed: int,
    endpoint_ids: Iterable[str] = ("host-1", "host-2", "host-3", "host-4", "host-5"),
    length: int = 24,
) -> list[EndpointEvent]:
    """Generate one abstract endpoint session for a traffic class.

    This intentionally does not execute real commands or touch real systems.
    It only creates synthetic telemetry records for detection experiments.
    """

    rng = random.Random(seed)
    endpoints = list(endpoint_ids)
    timestamp = 0.0
    events: list[EndpointEvent] = []
    chain = BENIGN_CHAIN if traffic_class == TrafficClass.BENIGN_ADMIN else ATTACK_CHAIN

    for step in range(length):
        if traffic_class == TrafficClass.BENIGN_ADMIN:
            timestamp += rng.uniform(8.0, 90.0)
            event_type = rng.choice(chain)
            endpoint = rng.choice(endpoints[:2])
            role = rng.choice(["admin", "developer", "analyst"])
            target = rng.choice(["ticket-system", "logs", "repo", "internal-wiki"])
        elif traffic_class == TrafficClass.SCRIPTED_ATTACKER:
            timestamp += rng.uniform(0.5, 4.0)
            event_type = chain[step % len(chain)]
            endpoint = endpoints[min(step // 6, len(endpoints) - 1)]
            role = "unknown"
            target = rng.choice(["domain-controller", "database", "file-share", "admin-host"])
        else:
            timestamp += rng.uniform(2.0, 18.0)
            event_type = chain[(step + rng.choice([0, 0, 1])) % len(chain)]
            endpoint = endpoints[min(step // 7, len(endpoints) - 1)]
            role = rng.choice(["admin", "developer"])
            target = rng.choice(["database", "file-share", "admin-host", "logs"])

        events.append(
            EndpointEvent(
                timestamp=timestamp,
                endpoint_id=endpoint,
                user=f"{traffic_class.value}-user",
                role=role,
                event_type=event_type,
                tool=rng.choice(TOOLS_BY_CLASS[traffic_class]),
                target=target,
                metadata={"traffic_class": traffic_class.value, "step": step},
            )
        )

    return events

