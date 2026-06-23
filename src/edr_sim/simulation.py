from __future__ import annotations

from .detectors import BehavioralEDRDetector
from .generators import generate_session
from .models import ArchitectureMode, EventType, SimulationRun, TrafficClass


def run_trial(
    traffic_class: TrafficClass,
    seed: int,
    *,
    architecture: ArchitectureMode = ArchitectureMode.CENTRALIZED,
    length: int = 32,
    adaptation_level: int = 0,
) -> SimulationRun:
    events = generate_session(
        traffic_class,
        seed=seed,
        length=length,
        adaptation_level=adaptation_level,
    )
    result = BehavioralEDRDetector(architecture=architecture).score(events)
    attack_success = infer_attack_success(events, detected=result.suspicious)
    is_attack = traffic_class != TrafficClass.BENIGN_ADMIN
    return SimulationRun(
        traffic_class=traffic_class,
        architecture=architecture,
        seed=seed,
        session_id=f"{traffic_class.value}-{architecture.value}-{seed}",
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
            for traffic_class in TrafficClass:
                adaptation_level = 2 if traffic_class == TrafficClass.AI_AGENT_ATTACKER else 0
                runs.append(
                    run_trial(
                        traffic_class,
                        seed,
                        architecture=architecture,
                        adaptation_level=adaptation_level,
                    )
                )
    return runs


def infer_attack_success(events, *, detected: bool) -> bool:
    event_types = {event.event_type for event in events}
    reached_objective = EventType.EXFIL_ATTEMPT in event_types or EventType.SENSITIVE_ACCESS in event_types
    return reached_objective and not detected
