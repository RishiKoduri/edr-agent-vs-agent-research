from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .detectors import BehavioralEDRDetector
from .generators import BENIGN_PROFILES, generate_session
from .models import ActorProfile, ArchitectureMode, TrafficClass
from .simulation import infer_attack_success


CORE_ARCHITECTURES = (
    ArchitectureMode.LOCAL,
    ArchitectureMode.CENTRALIZED,
    ArchitectureMode.FEDERATED,
)
PRESSURE_LEVELS = (1, 2, 4, 8, 16, 32)
BACKGROUND_BENIGN_SESSIONS = len(BENIGN_PROFILES)
DEFAULT_SEEDS = range(20)
DETECTOR_THRESHOLD = 4.0

# These are explicit synthetic assumptions for a first stress experiment. They
# represent the number of concurrent sessions an architecture can process
# during the observation window before a queue forms.
SESSION_CAPACITY = {
    ArchitectureMode.LOCAL: 8,
    ArchitectureMode.CENTRALIZED: 12,
    ArchitectureMode.FEDERATED: 16,
}


@dataclass(frozen=True)
class StressRun:
    architecture: ArchitectureMode
    seed: int
    pressure_level: int
    attacker_sessions: int
    background_sessions: int
    total_sessions: int
    capacity_sessions: int
    backlog_sessions: int
    overload_ratio: float
    raw_attack_detection_rate: float
    attack_detection_rate: float
    attack_success_rate: float
    false_positive_rate: float
    raw_alert_volume: int
    effective_alert_volume: int
    alert_queue_backlog: int
    operator_burden_index: float
    total_events: int
    collapse: bool


def run_stress_experiment(
    seeds=DEFAULT_SEEDS,
    pressure_levels: tuple[int, ...] = PRESSURE_LEVELS,
    architectures: tuple[ArchitectureMode, ...] = CORE_ARCHITECTURES,
    detector_threshold: float = DETECTOR_THRESHOLD,
) -> list[StressRun]:
    """Run a safe synthetic coordinated-pressure stress experiment.

    Each row represents one architecture, attacker pressure level, and random
    seed. The attacker sessions are adaptive AI-agent sessions. Five benign
    sessions, one for each benign persona, run in the same observation window.
    No commands execute and no real systems are contacted.
    """

    results: list[StressRun] = []
    for seed in seeds:
        for architecture in architectures:
            for pressure_level in pressure_levels:
                results.append(
                    run_stress_trial(
                        seed,
                        pressure_level,
                        architecture=architecture,
                        detector_threshold=detector_threshold,
                    )
                )
    return results


def run_stress_trial(
    seed: int,
    pressure_level: int,
    *,
    architecture: ArchitectureMode,
    detector_threshold: float = DETECTOR_THRESHOLD,
    background_profiles: tuple[ActorProfile, ...] = BENIGN_PROFILES,
) -> StressRun:
    if pressure_level < 1:
        raise ValueError("pressure_level must be at least 1")
    if architecture not in SESSION_CAPACITY:
        raise ValueError("stress experiment supports local, centralized, and federated modes")

    capacity = SESSION_CAPACITY[architecture]
    background_sessions = len(background_profiles)
    total_sessions = pressure_level + background_sessions
    backlog_sessions = max(0, total_sessions - capacity)
    overload_ratio = backlog_sessions / capacity

    # Queue pressure reduces the score available for timely detection. This
    # is a transparent stress assumption, not a claim about a vendor product.
    overload_penalty = overload_ratio
    detector = BehavioralEDRDetector(
        threshold=detector_threshold,
        architecture=architecture,
    )

    raw_attack_detections = 0
    attack_detections = 0
    attack_successes = 0
    raw_alert_volume = 0
    effective_alert_volume = 0
    false_positive_alerts = 0
    total_events = 0

    for index in range(pressure_level):
        events = generate_session(
            TrafficClass.AI_AGENT_ATTACKER,
            seed=stress_seed(seed, pressure_level, index),
            length=32,
            adaptation_level=4,
            actor_profile=ActorProfile.ADAPTIVE_AI_AGENT,
        )
        result = detector.score(events)
        raw_detected = result.suspicious
        effective_detected = result.score - overload_penalty >= detector_threshold
        raw_attack_detections += raw_detected
        attack_detections += effective_detected
        attack_successes += infer_attack_success(events, detected=effective_detected)
        raw_alert_volume += raw_detected
        effective_alert_volume += effective_detected
        total_events += len(events)

    for index, profile in enumerate(background_profiles):
        events = generate_session(
            TrafficClass.BENIGN_ADMIN,
            seed=stress_seed(seed, pressure_level, pressure_level + index),
            length=32,
            actor_profile=profile,
        )
        result = detector.score(events)
        raw_detected = result.suspicious
        effective_detected = result.score - overload_penalty >= detector_threshold
        raw_alert_volume += raw_detected
        effective_alert_volume += effective_detected
        false_positive_alerts += effective_detected
        total_events += len(events)

    attack_detection_rate = safe_div(attack_detections, pressure_level)
    raw_attack_detection_rate = safe_div(raw_attack_detections, pressure_level)
    attack_success_rate = safe_div(attack_successes, pressure_level)
    false_positive_rate = safe_div(false_positive_alerts, background_sessions)
    alert_queue_backlog = max(0, raw_alert_volume - capacity)

    # This index combines session backlog and raw alert backlog. It is used as
    # a comparative operator-workload measure, not as a universal unit.
    operator_burden_index = float(backlog_sessions + alert_queue_backlog)
    collapse = overload_ratio >= 1.0 or attack_success_rate >= 0.75

    return StressRun(
        architecture=architecture,
        seed=seed,
        pressure_level=pressure_level,
        attacker_sessions=pressure_level,
        background_sessions=background_sessions,
        total_sessions=total_sessions,
        capacity_sessions=capacity,
        backlog_sessions=backlog_sessions,
        overload_ratio=overload_ratio,
        raw_attack_detection_rate=raw_attack_detection_rate,
        attack_detection_rate=attack_detection_rate,
        attack_success_rate=attack_success_rate,
        false_positive_rate=false_positive_rate,
        raw_alert_volume=raw_alert_volume,
        effective_alert_volume=effective_alert_volume,
        alert_queue_backlog=alert_queue_backlog,
        operator_burden_index=operator_burden_index,
        total_events=total_events,
        collapse=collapse,
    )


def stress_seed(seed: int, pressure_level: int, session_index: int) -> int:
    return seed * 100_000 + pressure_level * 1_000 + session_index


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def write_stress_csv(results: list[StressRun], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "architecture",
        "seed",
        "pressure_level",
        "attacker_sessions",
        "background_sessions",
        "total_sessions",
        "capacity_sessions",
        "backlog_sessions",
        "overload_ratio",
        "raw_attack_detection_rate",
        "attack_detection_rate",
        "attack_success_rate",
        "false_positive_rate",
        "raw_alert_volume",
        "effective_alert_volume",
        "alert_queue_backlog",
        "operator_burden_index",
        "total_events",
        "collapse",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "architecture": result.architecture.value,
                    "seed": result.seed,
                    "pressure_level": result.pressure_level,
                    "attacker_sessions": result.attacker_sessions,
                    "background_sessions": result.background_sessions,
                    "total_sessions": result.total_sessions,
                    "capacity_sessions": result.capacity_sessions,
                    "backlog_sessions": result.backlog_sessions,
                    "overload_ratio": f"{result.overload_ratio:.4f}",
                    "raw_attack_detection_rate": f"{result.raw_attack_detection_rate:.4f}",
                    "attack_detection_rate": f"{result.attack_detection_rate:.4f}",
                    "attack_success_rate": f"{result.attack_success_rate:.4f}",
                    "false_positive_rate": f"{result.false_positive_rate:.4f}",
                    "raw_alert_volume": result.raw_alert_volume,
                    "effective_alert_volume": result.effective_alert_volume,
                    "alert_queue_backlog": result.alert_queue_backlog,
                    "operator_burden_index": f"{result.operator_burden_index:.4f}",
                    "total_events": result.total_events,
                    "collapse": result.collapse,
                }
            )


def write_stress_report(results: list[StressRun], path: Path) -> None:
    grouped: dict[tuple[ArchitectureMode, int], list[StressRun]] = defaultdict(list)
    for result in results:
        grouped[(result.architecture, result.pressure_level)].append(result)

    lines = [
        "# Coordinated-Pressure Stress Test",
        "",
        "This experiment increases simultaneous adaptive AI-agent attacker sessions while five benign personas remain active.",
        "It compares local, centralized, and federated EDR-style architectures using synthetic telemetry only.",
        "",
        "## Assumptions",
        "",
        "- Session capacity is a transparent synthetic queue assumption: local 8, centralized 12, and federated 16 sessions per observation window.",
        "- Queue pressure subtracts `overload_ratio` from each raw detector score before applying the 4.0 threshold.",
        "- Collapse is flagged when overload reaches capacity or attack success reaches 75 percent or more.",
        "- Operator burden index is a comparative index equal to session backlog plus raw alert queue backlog. It is not a production staffing unit.",
        "",
        "## Mean results by pressure",
        "",
        "| Architecture | Attack sessions | Attack detection | Attack success | False positive rate | Backlog | Operator burden | Collapse rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for architecture in CORE_ARCHITECTURES:
        for pressure in PRESSURE_LEVELS:
            rows = grouped.get((architecture, pressure), [])
            if not rows:
                continue
            lines.append(
                f"| {architecture.value} | {pressure} | "
                f"{mean(row.attack_detection_rate for row in rows):.3f} | "
                f"{mean(row.attack_success_rate for row in rows):.3f} | "
                f"{mean(row.false_positive_rate for row in rows):.3f} | "
                f"{mean(row.backlog_sessions for row in rows):.1f} | "
                f"{mean(row.operator_burden_index for row in rows):.1f} | "
                f"{mean(row.collapse for row in rows):.3f} |"
            )

    lines.extend(
        [
            "",
            "## Interpretation questions",
            "",
            "- At what pressure does each architecture show a meaningful increase in attack success?",
            "- Does added federation capacity delay the collapse point under coordinated pressure?",
            "- Does operator burden grow before detection quality collapses?",
            "- Are the results sensitive to the capacity and overload assumptions?",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def write_attack_success_chart(results: list[StressRun], path: Path) -> None:
    grouped: dict[tuple[ArchitectureMode, int], list[StressRun]] = defaultdict(list)
    for result in results:
        grouped[(result.architecture, result.pressure_level)].append(result)

    width = 980
    height = 560
    left = 80
    right = 35
    top = 75
    bottom = 75
    chart_width = width - left - right
    chart_height = height - top - bottom
    max_pressure = max(PRESSURE_LEVELS)
    colors = {
        ArchitectureMode.LOCAL: "#6B7280",
        ArchitectureMode.CENTRALIZED: "#2563EB",
        ArchitectureMode.FEDERATED: "#059669",
    }
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="30" y="38" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#111827">Attack success under coordinated pressure</text>',
    ]
    for tick in range(0, 6):
        y = top + chart_height - (tick / 5) * chart_height
        value = tick / 5
        lines.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#E5E7EB"/>')
        lines.append(f'<text x="45" y="{y + 4:.1f}" text-anchor="end" font-family="Arial, sans-serif" font-size="12" fill="#4B5563">{value:.1f}</text>')

    for architecture in CORE_ARCHITECTURES:
        points = []
        for pressure in PRESSURE_LEVELS:
            rows = grouped.get((architecture, pressure), [])
            if not rows:
                continue
            rate = sum(row.attack_success_rate for row in rows) / len(rows)
            x = left + (pressure / max_pressure) * chart_width
            y = top + chart_height - rate * chart_height
            points.append(f"{x:.1f},{y:.1f}")
        lines.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{colors[architecture]}" stroke-width="3"/>')

    lines.append(f'<line x1="{left}" y1="{top + chart_height}" x2="{width - right}" y2="{top + chart_height}" stroke="#111827"/>')
    lines.append(f'<text x="{left + chart_width / 2:.1f}" y="{height - 25}" text-anchor="middle" font-family="Arial, sans-serif" font-size="13" fill="#111827">Simultaneous attacker sessions</text>')
    for index, architecture in enumerate(CORE_ARCHITECTURES):
        x = left + index * 180
        lines.append(f'<rect x="{x}" y="{height - 55}" width="14" height="14" fill="{colors[architecture]}"/>')
        lines.append(f'<text x="{x + 20}" y="{height - 43}" font-family="Arial, sans-serif" font-size="12" fill="#111827">{architecture.value}</text>')
    lines.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def main() -> int:
    results = run_stress_experiment()
    write_stress_csv(results, Path("data/stress_results.csv"))
    write_stress_report(results, Path("data/stress_summary.md"))
    write_attack_success_chart(results, Path("analysis/figures/stress_attack_success.svg"))
    print(f"Wrote {len(results)} stress-test rows to data/stress_results.csv")
    print("Wrote stress-test report to data/stress_summary.md")
    print("Wrote stress-test chart to analysis/figures/stress_attack_success.svg")
    return 0


def mean(values):
    values = list(values)
    return sum(values) / len(values) if values else 0.0


if __name__ == "__main__":
    raise SystemExit(main())
