from __future__ import annotations

import random
from collections.abc import Iterable

from .models import ActorProfile, EndpointEvent, EventType, SessionProfile, TrafficClass


TOOLS_BY_CLASS = {
    TrafficClass.BENIGN_ADMIN: ["ssh", "bash", "python", "browser", "scp", "git", "vim"],
    TrafficClass.SCRIPTED_ATTACKER: ["powershell", "net", "wmic", "curl", "certutil"],
    TrafficClass.AI_AGENT_ATTACKER: ["powershell", "net", "wmic", "python", "curl", "bash"],
}

TOOLS_BY_ACTOR_PROFILE = {
    ActorProfile.OFFICE_WORKER: ["browser", "email", "office", "slack", "teams"],
    ActorProfile.DEVELOPER: ["bash", "python", "git", "vim", "docker"],
    ActorProfile.SYSADMIN: ["ssh", "bash", "powershell", "scp", "systemctl"],
    ActorProfile.HELPDESK: ["browser", "remote_assist", "powershell", "installer", "ticket_tool"],
    ActorProfile.SERVICE_ACCOUNT: ["backup_agent", "sync_agent", "python", "curl"],
    ActorProfile.SCRIPTED_ATTACKER: TOOLS_BY_CLASS[TrafficClass.SCRIPTED_ATTACKER],
    ActorProfile.NOISY_SCRIPTED_ATTACKER: ["powershell", "net", "wmic", "curl", "certutil"],
    ActorProfile.STEALTH_SCRIPTED_ATTACKER: ["powershell", "net", "python", "curl", "ssh"],
    ActorProfile.AI_AGENT_ATTACKER: TOOLS_BY_CLASS[TrafficClass.AI_AGENT_ATTACKER],
    ActorProfile.CAUTIOUS_AI_AGENT: ["powershell", "python", "curl", "bash", "ssh"],
    ActorProfile.HUMAN_MIMICKING_AI_AGENT: ["bash", "python", "git", "ssh", "browser"],
    ActorProfile.ADAPTIVE_AI_AGENT: ["powershell", "python", "curl", "bash", "ssh", "net"],
}

BENIGN_PROFILES = (
    ActorProfile.OFFICE_WORKER,
    ActorProfile.DEVELOPER,
    ActorProfile.SYSADMIN,
    ActorProfile.HELPDESK,
    ActorProfile.SERVICE_ACCOUNT,
)

SCRIPTED_ATTACKER_PROFILES = (
    ActorProfile.NOISY_SCRIPTED_ATTACKER,
    ActorProfile.STEALTH_SCRIPTED_ATTACKER,
)

AI_ATTACKER_PROFILES = (
    ActorProfile.CAUTIOUS_AI_AGENT,
    ActorProfile.HUMAN_MIMICKING_AI_AGENT,
    ActorProfile.ADAPTIVE_AI_AGENT,
)


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
    actor_profile: ActorProfile | None = None,
) -> list[EndpointEvent]:
    """Generate one abstract endpoint session for a traffic class.

    This intentionally does not execute real commands or touch real systems.
    It only creates synthetic telemetry records for detection experiments.
    """

    if actor_profile is None:
        actor_profile = default_actor_profile(traffic_class)
    profile = SessionProfile(
        traffic_class=traffic_class,
        seed=seed,
        session_id=f"{traffic_class.value}-{seed}",
        actor_profile=actor_profile,
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
            event_type, endpoint, role, target, command_quality, delta = benign_event_fields(
                profile.actor_profile,
                rng,
                chain,
                endpoints,
                step,
            )
            timestamp += delta
        elif profile.traffic_class == TrafficClass.SCRIPTED_ATTACKER:
            event_type, endpoint, role, target, command_quality, delta = scripted_attacker_event_fields(
                profile.actor_profile,
                rng,
                chain,
                endpoints,
                step,
            )
            timestamp += delta
        else:
            event_type, endpoint, role, target, command_quality, delta = ai_attacker_event_fields(
                profile.actor_profile,
                profile.adaptation_level,
                rng,
                chain,
                endpoints,
                step,
            )
            timestamp += delta

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
                tool=rng.choice(TOOLS_BY_ACTOR_PROFILE[profile.actor_profile]),
                target=target,
                metadata={
                    "traffic_class": profile.traffic_class.value,
                    "actor_profile": profile.actor_profile.value,
                    "session_id": profile.session_id,
                    "step": step,
                    "adaptation_level": profile.adaptation_level,
                    "command_quality": command_quality,
                },
            )
        )

    return events


def default_actor_profile(traffic_class: TrafficClass) -> ActorProfile:
    if traffic_class == TrafficClass.SCRIPTED_ATTACKER:
        return ActorProfile.NOISY_SCRIPTED_ATTACKER
    if traffic_class == TrafficClass.AI_AGENT_ATTACKER:
        return ActorProfile.CAUTIOUS_AI_AGENT
    return ActorProfile.SYSADMIN


def adaptation_level_for_profile(actor_profile: ActorProfile) -> int:
    if actor_profile == ActorProfile.CAUTIOUS_AI_AGENT:
        return 1
    if actor_profile == ActorProfile.HUMAN_MIMICKING_AI_AGENT:
        return 3
    if actor_profile == ActorProfile.ADAPTIVE_AI_AGENT:
        return 4
    return 0


def benign_event_fields(
    actor_profile: ActorProfile,
    rng: random.Random,
    chain: list[EventType],
    endpoints: list[str],
    step: int,
) -> tuple[EventType, str, str, str, str, float]:
    if actor_profile == ActorProfile.OFFICE_WORKER:
        return (
            rng.choice([EventType.AUTH, EventType.FILE_ACCESS, EventType.NETWORK_CONNECT, EventType.PROCESS_START]),
            rng.choice(endpoints[:2]),
            "employee",
            rng.choice(["email", "shared-drive", "calendar", "internal-wiki"]),
            rng.choice(["normal", "mistyped", "abandoned", "corrected"]),
            rng.uniform(20.0, 180.0),
        )

    if actor_profile == ActorProfile.DEVELOPER:
        return (
            rng.choice(chain + [EventType.FILE_ACCESS, EventType.COMMAND_EXEC]),
            rng.choice(endpoints[:2]),
            "developer",
            rng.choice(["repo", "build-server", "logs", "dev-database"]),
            rng.choice(["normal", "corrected", "abandoned"]),
            rng.uniform(10.0, 75.0),
        )

    if actor_profile == ActorProfile.SYSADMIN:
        return (
            rng.choice(chain + [EventType.DISCOVERY, EventType.FILE_ACCESS]),
            rng.choice(endpoints[:3]),
            "admin",
            rng.choice(["logs", "admin-host", "file-share", "service-console"]),
            rng.choice(["normal", "corrected", "abandoned"]),
            rng.uniform(8.0, 65.0),
        )

    if actor_profile == ActorProfile.HELPDESK:
        return (
            rng.choice([EventType.AUTH, EventType.PROCESS_START, EventType.COMMAND_EXEC, EventType.NETWORK_CONNECT]),
            rng.choice(endpoints[:4]),
            "helpdesk",
            rng.choice(["ticket-system", "user-workstation", "software-catalog", "device-inventory"]),
            rng.choice(["normal", "mistyped", "corrected"]),
            rng.uniform(12.0, 90.0),
        )

    if actor_profile == ActorProfile.SERVICE_ACCOUNT:
        return (
            rng.choice([EventType.AUTH, EventType.FILE_ACCESS, EventType.NETWORK_CONNECT, EventType.PROCESS_START]),
            endpoints[step % min(2, len(endpoints))],
            "service_account",
            rng.choice(["backup-share", "sync-endpoint", "monitoring-api", "logs"]),
            "scheduled",
            rng.uniform(25.0, 35.0),
        )

    return (
        rng.choice(chain + HUMAN_NOISE_EVENTS),
        rng.choice(endpoints[:2]),
        "admin",
        rng.choice(["ticket-system", "logs", "repo", "internal-wiki"]),
        rng.choice(["normal", "mistyped", "abandoned", "corrected"]),
        rng.uniform(8.0, 90.0),
    )


def scripted_attacker_event_fields(
    actor_profile: ActorProfile,
    rng: random.Random,
    chain: list[EventType],
    endpoints: list[str],
    step: int,
) -> tuple[EventType, str, str, str, str, float]:
    if actor_profile == ActorProfile.STEALTH_SCRIPTED_ATTACKER:
        event_type = chain[(step + rng.choice([0, 0, 1])) % len(chain)]
        if event_type in {EventType.LATERAL_MOVEMENT, EventType.EXFIL_ATTEMPT} and rng.random() < 0.25:
            event_type = rng.choice([EventType.NETWORK_CONNECT, EventType.FILE_ACCESS])
        return (
            event_type,
            endpoints[min(step // 8, len(endpoints) - 1)],
            rng.choice(["developer", "admin"]),
            rng.choice(["database", "file-share", "admin-host", "logs"]),
            rng.choice(["scripted", "normal", "corrected"]),
            rng.uniform(4.0, 20.0),
        )

    return (
        chain[step % len(chain)],
        endpoints[min(step // 6, len(endpoints) - 1)],
        "unknown",
        rng.choice(["domain-controller", "database", "file-share", "admin-host"]),
        "scripted",
        rng.uniform(0.5, 4.0),
    )


def ai_attacker_event_fields(
    actor_profile: ActorProfile,
    adaptation_level: int,
    rng: random.Random,
    chain: list[EventType],
    endpoints: list[str],
    step: int,
) -> tuple[EventType, str, str, str, str, float]:
    if actor_profile == ActorProfile.HUMAN_MIMICKING_AI_AGENT:
        timing_floor = 12.0
        timing_ceiling = 90.0
        endpoint_window = 10
        command_weights = [5, 1, 3, 3]
        role_choices = ["developer", "admin"]
    elif actor_profile == ActorProfile.ADAPTIVE_AI_AGENT:
        timing_floor = 8.0
        timing_ceiling = 80.0
        endpoint_window = 11
        command_weights = [5, 1, 4, 3]
        role_choices = ["admin", "developer"]
    else:
        timing_floor = 2.0 + (adaptation_level * 2.0)
        timing_ceiling = 18.0 + (adaptation_level * 15.0)
        endpoint_window = max(7, 7 + adaptation_level)
        command_weights = [
            2 + adaptation_level,
            max(1, 5 - adaptation_level),
            adaptation_level,
            adaptation_level,
        ]
        role_choices = ["admin", "developer"]

    jitter = rng.choice([0, 0, 1, -1 if adaptation_level else 0])
    event_type = chain[(step + jitter) % len(chain)]
    if actor_profile in {ActorProfile.HUMAN_MIMICKING_AI_AGENT, ActorProfile.ADAPTIVE_AI_AGENT}:
        if event_type in {EventType.LATERAL_MOVEMENT, EventType.EXFIL_ATTEMPT} and rng.random() < 0.45:
            event_type = rng.choice([EventType.FILE_ACCESS, EventType.NETWORK_CONNECT, EventType.COMMAND_EXEC])

    return (
        event_type,
        endpoints[min(step // endpoint_window, len(endpoints) - 1)],
        rng.choice(role_choices),
        rng.choice(["database", "file-share", "admin-host", "logs", "repo"]),
        rng.choices(
            ["normal", "scripted", "corrected", "abandoned"],
            weights=command_weights,
            k=1,
        )[0],
        rng.uniform(timing_floor, timing_ceiling),
    )
