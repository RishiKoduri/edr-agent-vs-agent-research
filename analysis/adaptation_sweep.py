from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from edr_sim.models import ActorProfile, ArchitectureMode, TrafficClass
from edr_sim.simulation import run_trial


CORE_ARCHITECTURES = (
    ArchitectureMode.LOCAL,
    ArchitectureMode.CENTRALIZED,
    ArchitectureMode.FEDERATED,
)
ADAPTATION_LEVELS = (0, 1, 2, 3, 4)
SEEDS = range(20)


@dataclass(frozen=True)
class AdaptationRun:
    architecture: ArchitectureMode
    adaptation_level: int
    seed: int
    detected: bool
    score: float
    attack_success: bool
    time_to_detection: float | None
    event_count: int


def run_adaptation_sweep(
    seeds=SEEDS,
    adaptation_levels: tuple[int, ...] = ADAPTATION_LEVELS,
    architectures: tuple[ArchitectureMode, ...] = CORE_ARCHITECTURES,
) -> list[AdaptationRun]:
    """Evaluate the adaptive AI-agent proxy across controlled adaptation levels.

    The current model uses an explicit adaptation parameter in the synthetic
    event generator. It is a controlled proxy for learned attacker behavior,
    not a claim that a reinforcement-learning agent has already been trained.
    """

    results: list[AdaptationRun] = []
    for seed in seeds:
        for architecture in architectures:
            for adaptation_level in adaptation_levels:
                run = run_trial(
                    TrafficClass.AI_AGENT_ATTACKER,
                    seed,
                    architecture=architecture,
                    adaptation_level=adaptation_level,
                    actor_profile=ActorProfile.ADAPTIVE_AI_AGENT,
                )
                results.append(
                    AdaptationRun(
                        architecture=architecture,
                        adaptation_level=adaptation_level,
                        seed=seed,
                        detected=run.detected,
                        score=run.score,
                        attack_success=run.attack_success,
                        time_to_detection=run.time_to_detection,
                        event_count=run.event_count,
                    )
                )
    return results


def write_csv(results: list[AdaptationRun], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "architecture",
        "adaptation_level",
        "seed",
        "detected",
        "score",
        "attack_success",
        "time_to_detection",
        "event_count",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "architecture": result.architecture.value,
                    "adaptation_level": result.adaptation_level,
                    "seed": result.seed,
                    "detected": result.detected,
                    "score": f"{result.score:.4f}",
                    "attack_success": result.attack_success,
                    "time_to_detection": (
                        f"{result.time_to_detection:.4f}"
                        if result.time_to_detection is not None
                        else ""
                    ),
                    "event_count": result.event_count,
                }
            )


def write_report(results: list[AdaptationRun], path: Path) -> None:
    grouped: dict[tuple[ArchitectureMode, int], list[AdaptationRun]] = defaultdict(list)
    for result in results:
        grouped[(result.architecture, result.adaptation_level)].append(result)

    lines = [
        "# Adaptive Attacker Evasion Analysis",
        "",
        "This experiment increases the adaptation parameter of the synthetic adaptive AI-agent attacker and measures detection quality across local, centralized, and federated EDR-style architectures.",
        "",
        "The adaptation parameter is a controlled proxy for learned attacker behavior. It changes event timing and hides selected attack-stage events at higher levels. It is not a trained reinforcement-learning or language-model agent.",
        "",
        "## Mean results",
        "",
        "| Architecture | Adaptation level | Detection rate | Attack success rate | Mean score | Mean time to detection |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for architecture in CORE_ARCHITECTURES:
        for level in ADAPTATION_LEVELS:
            rows = grouped.get((architecture, level), [])
            if not rows:
                continue
            detection_rate = mean(row.detected for row in rows)
            attack_success_rate = mean(row.attack_success for row in rows)
            detected_times = [
                row.time_to_detection for row in rows if row.time_to_detection is not None
            ]
            lines.append(
                f"| {architecture.value} | {level} | {detection_rate:.3f} | "
                f"{attack_success_rate:.3f} | {mean(row.score for row in rows):.3f} | "
                f"{mean(detected_times):.2f} |"
            )

    lines.extend(
        [
            "",
            "## Findings to investigate",
            "",
            "- Does increasing adaptation reduce detection rate or increase attack success?",
            "- Does cross-endpoint correlation preserve detection quality as the attacker becomes less regular?",
            "- Does the adaptation curve plateau, suggesting the detector has reached a blind spot?",
            "- Which results change when the detector threshold is varied?",
            "",
            "## Model note",
            "",
            "The levels are graduated synthetic behavior changes, not a trained reinforcement-learning or language-model policy. A later version should replace this proxy with a learned attacker policy and compare the learned policy against these controlled levels.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def write_attack_success_chart(results: list[AdaptationRun], path: Path) -> None:
    grouped: dict[tuple[ArchitectureMode, int], list[AdaptationRun]] = defaultdict(list)
    for result in results:
        grouped[(result.architecture, result.adaptation_level)].append(result)

    width = 980
    height = 560
    left = 80
    right = 35
    top = 75
    bottom = 75
    chart_width = width - left - right
    chart_height = height - top - bottom
    colors = {
        ArchitectureMode.LOCAL: "#6B7280",
        ArchitectureMode.CENTRALIZED: "#2563EB",
        ArchitectureMode.FEDERATED: "#059669",
    }
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="30" y="38" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#111827">Attack success as attacker adaptation increases</text>',
    ]
    for tick in range(0, 6):
        y = top + chart_height - (tick / 5) * chart_height
        value = tick / 5
        lines.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#E5E7EB"/>')
        lines.append(f'<text x="45" y="{y + 4:.1f}" text-anchor="end" font-family="Arial, sans-serif" font-size="12" fill="#4B5563">{value:.1f}</text>')

    for architecture in CORE_ARCHITECTURES:
        points = []
        for level in ADAPTATION_LEVELS:
            rows = grouped.get((architecture, level), [])
            if not rows:
                continue
            rate = mean(row.attack_success for row in rows)
            x = left + (level / max(ADAPTATION_LEVELS)) * chart_width
            y = top + chart_height - rate * chart_height
            points.append(f"{x:.1f},{y:.1f}")
        lines.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{colors[architecture]}" stroke-width="3"/>')

    lines.append(f'<line x1="{left}" y1="{top + chart_height}" x2="{width - right}" y2="{top + chart_height}" stroke="#111827"/>')
    lines.append(f'<text x="{left + chart_width / 2:.1f}" y="{height - 25}" text-anchor="middle" font-family="Arial, sans-serif" font-size="13" fill="#111827">Attacker adaptation level</text>')
    for index, architecture in enumerate(CORE_ARCHITECTURES):
        x = left + index * 180
        lines.append(f'<rect x="{x}" y="{height - 55}" width="14" height="14" fill="{colors[architecture]}"/>')
        lines.append(f'<text x="{x + 20}" y="{height - 43}" font-family="Arial, sans-serif" font-size="12" fill="#111827">{architecture.value}</text>')
    lines.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def mean(values) -> float:
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def main() -> int:
    results = run_adaptation_sweep()
    write_csv(results, Path("data/adaptation_results.csv"))
    write_report(results, Path("data/adaptation_summary.md"))
    write_attack_success_chart(results, Path("analysis/figures/adaptation_attack_success.svg"))
    print(f"Wrote {len(results)} adaptation rows to data/adaptation_results.csv")
    print("Wrote adaptation report to data/adaptation_summary.md")
    print("Wrote adaptation chart to analysis/figures/adaptation_attack_success.svg")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
