from __future__ import annotations

from .detectors import BehavioralEDRDetector
from .generators import (
    AI_ATTACKER_PROFILES,
    BENIGN_PROFILES,
    SCRIPTED_ATTACKER_PROFILES,
    adaptation_level_for_profile,
    generate_session,
)
from .models import ActorProfile, ArchitectureMode, EventType, SimulationRun, TrafficClass


def run_trial(
    traffic_class: TrafficClass,
    seed: int,
    *,
    architecture: ArchitectureMode = ArchitectureMode.CENTRALIZED,
    length: int = 32,
    adaptation_level: int = 0,
    actor_profile: ActorProfile | None = None,
) -> SimulationRun:
    events = generate_session(
        traffic_class,
        seed=seed,
        length=length,
        adaptation_level=adaptation_level,
        actor_profile=actor_profile,
    )
    actor_profile = ActorProfile(events[0].metadata["actor_profile"])
    result = BehavioralEDRDetector(architecture=architecture).score(events)
    attack_success = infer_attack_success(events, detected=result.suspicious)
    is_attack = traffic_class != TrafficClass.BENIGN_ADMIN
    return SimulationRun(
        traffic_class=traffic_class,
        actor_profile=actor_profile,
        architecture=architecture,
        seed=seed,
        session_id=f"{actor_profile.value}-{architecture.value}-{seed}",
        detected=result.suspicious,
        score=result.score,
        reasons=result.reasons,
        time_to_detection=result.detected_at,
        attack_success=attack_success,
        false_positive=traffic_class == TrafficClass.BENIGN_ADMIN and result.suspicious,
        true_positive=is_attack and result.suspicious,
        event_count=len(events),
    )


def run_experiment(
    seeds: range = range(50),
    architectures: tuple[ArchitectureMode, ...] = (
        ArchitectureMode.LOCAL,
        ArchitectureMode.CENTRALIZED,
        ArchitectureMode.FEDERATED,
        ArchitectureMode.HYBRID,
    ),
) -> list[SimulationRun]:
    runs: list[SimulationRun] = []
    for seed in seeds:
        for architecture in architectures:
            for benign_profile in BENIGN_PROFILES:
                runs.append(
                    run_trial(
                        TrafficClass.BENIGN_ADMIN,
                        seed,
                        architecture=architecture,
                        actor_profile=benign_profile,
                    )
                )
            for scripted_profile in SCRIPTED_ATTACKER_PROFILES:
                runs.append(
                    run_trial(
                        TrafficClass.SCRIPTED_ATTACKER,
                        seed,
                        architecture=architecture,
                        actor_profile=scripted_profile,
                    )
                )
            for ai_profile in AI_ATTACKER_PROFILES:
                runs.append(
                    run_trial(
                        TrafficClass.AI_AGENT_ATTACKER,
                        seed,
                        architecture=architecture,
                        adaptation_level=adaptation_level_for_profile(ai_profile),
                        actor_profile=ai_profile,
                    )
                )
    return runs


def infer_attack_success(events, *, detected: bool) -> bool:
    event_types = {event.event_type for event in events}
    reached_objective = EventType.EXFIL_ATTEMPT in event_types or EventType.SENSITIVE_ACCESS in event_types
    return reached_objective and not detected
