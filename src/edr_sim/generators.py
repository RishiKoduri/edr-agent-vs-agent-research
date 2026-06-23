from __future__ import annotations

import random
from collections.abc import Iterable

from .models import EndpointEvent, EventType, SessionProfile, TrafficClass


TOOLS_BY_CLASS = {
    TrafficClass.BENIGN_ADMIN: ["ssh", "bash", "python", "browser", "scp", "git", "vim"],
    TrafficClass.SCRIPTED_ATTACKER: ["powershell", "net", "wmic", "curl", "certutil"],
    TrafficClass.AI_AGENT_ATTACKER: ["powershell", "net", "wmic", "python", "curl", "bash"],
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


HUMAN_NOISE_EVENTS = [EventType.FILE_ACCESS, EventType.COMMAND_EXEC, EventType.PROCESS_START]


def generate_session(
    traffic_class: TrafficClass,
    *,
    seed: int,
    endpoint_ids: Iterable[str] = ("host-1", "host-2", "host-3", "host-4", "host-5"),
    length: int = 24,
    adaptation_level: int = 0,
) -> list[EndpointEvent]:
    """Generate one abstract endpoint session for a traffic class.

    This intentionally does not execute real commands or touch real systems.
    It only creates synthetic telemetry records for detection experiments.
    """

    profile = SessionProfile(
        traffic_class=traffic_class,
        seed=seed,
        session_id=f"{traffic_class.value}-{seed}",
        endpoint_count=len(tuple(endpoint_ids)),
        length=length,
        adaptation_level=adaptation_level,
    )
    return generate_session_from_profile(profile, endpoint_ids=endpoint_ids)


def generate_session_from_profile(
    profile: SessionProfile,
    *,
    endpoint_ids: Iterable[str] | None = None,
) -> list[EndpointEvent]:
    """Generate safe, abstract endpoint telemetry for one session.

    The generated events are synthetic records. The simulator never executes
    real commands, probes systems, or creates exploit payloads.
    """

    rng = random.Random(profile.seed)
    if endpoint_ids is None:
        endpoint_ids = tuple(f"host-{index}" for index in range(1, profile.endpoint_count + 1))
    endpoints = list(endpoint_ids)
    timestamp = 0.0
    events: list[EndpointEvent] = []
    chain = BENIGN_CHAIN if profile.traffic_class == TrafficClass.BENIGN_ADMIN else ATTACK_CHAIN

    for step in range(profile.length):
        if profile.traffic_class == TrafficClass.BENIGN_ADMIN:
            timestamp += rng.uniform(8.0, 90.0)
            event_type = rng.choice(chain + HUMAN_NOISE_EVENTS)
            endpoint = rng.choice(endpoints[:2])
            role = rng.choice(["admin", "developer", "analyst"])
            target = rng.choice(["ticket-system", "logs", "repo", "internal-wiki"])
            command_quality = rng.choice(["normal", "mistyped", "abandoned", "corrected"])
        elif profile.traffic_class == TrafficClass.SCRIPTED_ATTACKER:
            timestamp += rng.uniform(0.5, 4.0)
            event_type = chain[step % len(chain)]
            endpoint = endpoints[min(step // 6, len(endpoints) - 1)]
            role = "unknown"
            target = rng.choice(["domain-controller", "database", "file-share", "admin-host"])
            command_quality = "scripted"
        else:
            timing_floor = 2.0 + (profile.adaptation_level * 2.0)
            timing_ceiling = 18.0 + (profile.adaptation_level * 15.0)
            timestamp += rng.uniform(timing_floor, timing_ceiling)
            jitter = rng.choice([0, 0, 1, -1 if profile.adaptation_level else 0])
            event_type = chain[(step + jitter) % len(chain)]
            endpoint = endpoints[min(step // max(7, 7 + profile.adaptation_level), len(endpoints) - 1)]
            role = rng.choice(["admin", "developer"])
            target = rng.choice(["database", "file-share", "admin-host", "logs"])
            command_quality = rng.choices(
                ["normal", "scripted", "corrected", "abandoned"],
                weights=[
                    2 + profile.adaptation_level,
                    max(1, 5 - profile.adaptation_level),
                    profile.adaptation_level,
                    profile.adaptation_level,
                ],
                k=1,
            )[0]

        if (
            profile.traffic_class == TrafficClass.AI_AGENT_ATTACKER
            and profile.adaptation_level >= 2
            and event_type in {EventType.LATERAL_MOVEMENT, EventType.EXFIL_ATTEMPT}
            and rng.random() < 0.35
        ):
            event_type = rng.choice([EventType.FILE_ACCESS, EventType.NETWORK_CONNECT])

        events.append(
            EndpointEvent(
                timestamp=timestamp,
                endpoint_id=endpoint,
                user=f"{profile.traffic_class.value}-user",
                role=role,
                event_type=event_type,
                tool=rng.choice(TOOLS_BY_CLASS[profile.traffic_class]),
                target=target,
                metadata={
                    "traffic_class": profile.traffic_class.value,
                    "session_id": profile.session_id,
                    "step": step,
                    "adaptation_level": profile.adaptation_level,
                    "command_quality": command_quality,
                },
            )
        )

    return events
