from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from statistics import mean

from .models import ArchitectureMode, SimulationRun, TrafficClass


@dataclass(frozen=True)
class MetricRow:
    architecture: ArchitectureMode
    traffic_class: TrafficClass
    runs: int
    detection_rate: float
    attack_success_rate: float
    average_score: float
    average_time_to_detection: float | None


@dataclass(frozen=True)
class ArchitectureMetricRow:
    architecture: ArchitectureMode
    precision: float
    recall: float
    false_positive_rate: float
    attack_success_rate: float
    average_time_to_detection: float | None


def summarize_by_class(runs: list[SimulationRun]) -> list[MetricRow]:
    grouped: dict[tuple[ArchitectureMode, TrafficClass], list[SimulationRun]] = defaultdict(list)
    for run in runs:
        grouped[(run.architecture, run.traffic_class)].append(run)

    rows: list[MetricRow] = []
    for (architecture, traffic_class), group in sorted(
        grouped.items(), key=lambda item: (item[0][0].value, item[0][1].value)
    ):
        detection_times = [
            run.time_to_detection for run in group if run.time_to_detection is not None
        ]
        rows.append(
            MetricRow(
                architecture=architecture,
                traffic_class=traffic_class,
                runs=len(group),
                detection_rate=_rate(run.detected for run in group),
                attack_success_rate=_rate(run.attack_success for run in group),
                average_score=mean(run.score for run in group),
                average_time_to_detection=mean(detection_times) if detection_times else None,
            )
        )
    return rows


def summarize_by_architecture(runs: list[SimulationRun]) -> list[ArchitectureMetricRow]:
    grouped: dict[ArchitectureMode, list[SimulationRun]] = defaultdict(list)
    for run in runs:
        grouped[run.architecture].append(run)

    rows: list[ArchitectureMetricRow] = []
    for architecture, group in sorted(grouped.items(), key=lambda item: item[0].value):
        true_positive = sum(run.true_positive for run in group)
        false_positive = sum(run.false_positive for run in group)
        false_negative = sum(
            run.traffic_class != TrafficClass.BENIGN_ADMIN and not run.detected for run in group
        )
        benign = [run for run in group if run.traffic_class == TrafficClass.BENIGN_ADMIN]
        attacks = [run for run in group if run.traffic_class != TrafficClass.BENIGN_ADMIN]
        detection_times = [
            run.time_to_detection for run in group if run.time_to_detection is not None
        ]
        rows.append(
            ArchitectureMetricRow(
                architecture=architecture,
                precision=_safe_div(true_positive, true_positive + false_positive),
                recall=_safe_div(true_positive, true_positive + false_negative),
                false_positive_rate=_rate(run.false_positive for run in benign),
                attack_success_rate=_rate(run.attack_success for run in attacks),
                average_time_to_detection=mean(detection_times) if detection_times else None,
            )
        )
    return rows


def render_markdown_summary(runs: list[SimulationRun]) -> str:
    by_architecture = summarize_by_architecture(runs)
    by_class = summarize_by_class(runs)
    lines = [
        "# Baseline EDR Agent-vs-Agent Experiment Summary",
        "",
        "This report is generated from the safe synthetic endpoint-telemetry simulator.",
        "No real exploit code, malware, scanning, or external system interaction is performed.",
        "",
        "## Architecture-level results",
        "",
        "| Architecture | Precision | Recall | False positive rate | Attack success rate | Avg. time to detection |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in by_architecture:
        lines.append(
            "| "
            f"{row.architecture.value} | "
            f"{row.precision:.2f} | "
            f"{row.recall:.2f} | "
            f"{row.false_positive_rate:.2f} | "
            f"{row.attack_success_rate:.2f} | "
            f"{_fmt_optional(row.average_time_to_detection)} |"
        )

    lines.extend(
        [
            "",
            "## Traffic-class results",
            "",
            "| Architecture | Traffic class | Runs | Detection rate | Attack success rate | Avg. score | Avg. time to detection |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in by_class:
        lines.append(
            "| "
            f"{row.architecture.value} | "
            f"{row.traffic_class.value} | "
            f"{row.runs} | "
            f"{row.detection_rate:.2f} | "
            f"{row.attack_success_rate:.2f} | "
            f"{row.average_score:.2f} | "
            f"{_fmt_optional(row.average_time_to_detection)} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `precision` measures how often alerts correspond to attacker sessions rather than benign admin activity.",
            "- `recall` measures how often attacker sessions are detected.",
            "- `attack_success_rate` means the simulated attacker reached sensitive access or exfiltration before detection.",
            "- Local EDR intentionally has weaker cross-endpoint visibility; federated and hybrid modes receive correlation benefits.",
            "",
        ]
    )
    return "\n".join(lines)


def _rate(values) -> float:
    values = list(values)
    return _safe_div(sum(bool(value) for value in values), len(values))


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _fmt_optional(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.1f}"
