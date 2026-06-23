from __future__ import annotations

from dataclasses import dataclass

from .detectors import BehavioralEDRDetector
from .generators import generate_session
from .models import TrafficClass


@dataclass(frozen=True)
class SimulationRun:
    traffic_class: TrafficClass
    seed: int
    detected: bool
    score: float
    reasons: tuple[str, ...]
    time_to_detection: float | None


def run_trial(traffic_class: TrafficClass, seed: int) -> SimulationRun:
    events = generate_session(traffic_class, seed=seed)
    result = BehavioralEDRDetector().score(events)
    return SimulationRun(
        traffic_class=traffic_class,
        seed=seed,
        detected=result.suspicious,
        score=result.score,
        reasons=tuple(result.reasons),
        time_to_detection=result.detected_at,
    )


def run_experiment(seeds: range = range(30)) -> list[SimulationRun]:
    runs: list[SimulationRun] = []
    for seed in seeds:
        for traffic_class in TrafficClass:
            runs.append(run_trial(traffic_class, seed))
    return runs

