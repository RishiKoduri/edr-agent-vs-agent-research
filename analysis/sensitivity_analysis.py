from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


CORE_ARCHITECTURES = ("local", "centralized", "federated")
ALL_ARCHITECTURES = (*CORE_ARCHITECTURES, "hybrid")


@dataclass(frozen=True)
class ThresholdMetrics:
    architecture: str
    threshold: float
    precision: float
    recall: float
    f2_score: float
    false_positive_rate: float
    attack_success_rate: float


def main() -> int:
    rows = read_rows(Path("data/baseline_results.csv"))
    thresholds = [round(value * 0.25, 2) for value in range(0, 49)]
    metrics = evaluate_thresholds(rows, thresholds)

    write_threshold_csv(metrics, Path("data/threshold_sensitivity.csv"))
    write_markdown_report(rows, metrics, Path("data/threshold_sensitivity.md"))
    write_f2_chart(metrics, Path("analysis/figures/threshold_f2.svg"))

    print("Wrote threshold sensitivity results to data/threshold_sensitivity.csv")
    print("Wrote threshold sensitivity report to data/threshold_sensitivity.md")
    print("Wrote threshold F2 chart to analysis/figures/threshold_f2.svg")
    return 0


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def evaluate_thresholds(
    rows: list[dict[str, str]], thresholds: list[float]
) -> list[ThresholdMetrics]:
    results: list[ThresholdMetrics] = []
    for architecture in ALL_ARCHITECTURES:
        group = [row for row in rows if row["architecture"] == architecture]
        for threshold in thresholds:
            results.append(calculate_metrics(group, architecture, threshold))
    return results


def calculate_metrics(
    rows: list[dict[str, str]], architecture: str, threshold: float
) -> ThresholdMetrics:
    labels = [row["traffic_class"] != "benign_admin" for row in rows]
    predictions = [float(row["score"]) >= threshold for row in rows]

    true_positive = sum(label and prediction for label, prediction in zip(labels, predictions, strict=False))
    false_positive = sum(not label and prediction for label, prediction in zip(labels, predictions, strict=False))
    false_negative = sum(label and not prediction for label, prediction in zip(labels, predictions, strict=False))
    benign_count = sum(not label for label in labels)
    attack_count = sum(labels)

    precision = safe_div(true_positive, true_positive + false_positive)
    recall = safe_div(true_positive, true_positive + false_negative)
    f2_score = safe_div(5 * true_positive, 5 * true_positive + false_positive + 4 * false_negative)
    false_positive_rate = safe_div(false_positive, benign_count)
    attack_success_rate = safe_div(false_negative, attack_count)

    return ThresholdMetrics(
        architecture=architecture,
        threshold=threshold,
        precision=precision,
        recall=recall,
        f2_score=f2_score,
        false_positive_rate=false_positive_rate,
        attack_success_rate=attack_success_rate,
    )


def ranking_metrics(rows: list[dict[str, str]]) -> tuple[float, float]:
    labels = [row["traffic_class"] != "benign_admin" for row in rows]
    scores = [float(row["score"]) for row in rows]
    return roc_auc(labels, scores), pr_auc(labels, scores)


def roc_auc(labels: list[bool], scores: list[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return 0.0

    ordered = sorted(zip(scores, labels, strict=False), key=lambda item: item[0], reverse=True)
    true_positive = 0
    false_positive = 0
    points = [(0.0, 0.0)]
    previous_score: float | None = None
    for score, label in ordered:
        if previous_score is not None and score != previous_score:
            points.append((false_positive / negatives, true_positive / positives))
        if label:
            true_positive += 1
        else:
            false_positive += 1
        previous_score = score
    points.append((1.0, 1.0))

    return trapezoid_area(points)


def pr_auc(labels: list[bool], scores: list[float]) -> float:
    positives = sum(labels)
    if positives == 0:
        return 0.0

    ordered = sorted(zip(scores, labels, strict=False), key=lambda item: item[0], reverse=True)
    true_positive = 0
    false_positive = 0
    points = [(0.0, 1.0)]
    previous_score: float | None = None
    for score, label in ordered:
        if previous_score is not None and score != previous_score:
            recall = true_positive / positives
            precision = safe_div(true_positive, true_positive + false_positive)
            points.append((recall, precision))
        if label:
            true_positive += 1
        else:
            false_positive += 1
        previous_score = score
    points.append((1.0, safe_div(true_positive, true_positive + false_positive)))

    return trapezoid_area(sorted(points))


def write_threshold_csv(metrics: list[ThresholdMetrics], path: Path) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "architecture",
                "threshold",
                "precision",
                "recall",
                "f2_score",
                "false_positive_rate",
                "attack_success_rate",
            ]
        )
        for row in metrics:
            writer.writerow(
                [
                    row.architecture,
                    f"{row.threshold:.2f}",
                    f"{row.precision:.4f}",
                    f"{row.recall:.4f}",
                    f"{row.f2_score:.4f}",
                    f"{row.false_positive_rate:.4f}",
                    f"{row.attack_success_rate:.4f}",
                ]
            )


def write_markdown_report(
    rows: list[dict[str, str]], metrics: list[ThresholdMetrics], path: Path
) -> None:
    lines = [
        "# Detection Threshold Sensitivity Analysis",
        "",
        "This analysis evaluates the detector across thresholds from 0.00 to 12.00.",
        "The core comparison uses local, centralized, and federated architectures. Hybrid is included as an optional reference.",
        "",
        "## Ranking metrics",
        "",
        "| Architecture | ROC-AUC | PR-AUC | Best F2 threshold | Best F2 | Recall at best F2 | False positive rate at best F2 | Attack success at best F2 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for architecture in ALL_ARCHITECTURES:
        group = [row for row in rows if row["architecture"] == architecture]
        architecture_metrics = [row for row in metrics if row.architecture == architecture]
        best = max(architecture_metrics, key=lambda row: (row.f2_score, -row.threshold))
        roc, pr = ranking_metrics(group)
        lines.append(
            f"| {architecture} | {roc:.3f} | {pr:.3f} | {best.threshold:.2f} | "
            f"{best.f2_score:.3f} | {best.recall:.3f} | {best.false_positive_rate:.3f} | "
            f"{best.attack_success_rate:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- F2 weights recall more heavily than precision, reflecting the higher cost of missed attacks.",
            "- ROC-AUC measures ranking quality across thresholds and can look optimistic when classes are balanced.",
            "- PR-AUC emphasizes performance on the positive attacker class and is useful when alerts are uncommon.",
            "- The selected threshold is a research comparison point, not a production calibration recommendation.",
            "",
        ]
    )
    path.write_text("\n".join(lines))


def write_f2_chart(metrics: list[ThresholdMetrics], path: Path) -> None:
    width = 980
    height = 560
    left = 80
    right = 35
    top = 75
    bottom = 75
    chart_width = width - left - right
    chart_height = height - top - bottom
    thresholds = sorted({row.threshold for row in metrics})
    max_threshold = max(thresholds) if thresholds else 1.0
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="30" y="38" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#111827">F2 score across detection thresholds</text>',
    ]
    for tick in range(0, 6):
        y = top + chart_height - (tick / 5) * chart_height
        value = tick / 5
        lines.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#E5E7EB"/>')
        lines.append(f'<text x="45" y="{y + 4:.1f}" text-anchor="end" font-family="Arial, sans-serif" font-size="12" fill="#4B5563">{value:.1f}</text>')

    colors = {"local": "#6B7280", "centralized": "#2563EB", "federated": "#059669", "hybrid": "#7C3AED"}
    for architecture in ALL_ARCHITECTURES:
        group = [row for row in metrics if row.architecture == architecture]
        points = []
        for row in group:
            x = left + (row.threshold / max_threshold) * chart_width
            y = top + chart_height - row.f2_score * chart_height
            points.append(f"{x:.1f},{y:.1f}")
        lines.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{colors[architecture]}" stroke-width="3"/>')

    lines.append(f'<line x1="{left}" y1="{top + chart_height}" x2="{width - right}" y2="{top + chart_height}" stroke="#111827"/>')
    lines.append(f'<text x="{left + chart_width / 2:.1f}" y="{height - 25}" text-anchor="middle" font-family="Arial, sans-serif" font-size="13" fill="#111827">Detection threshold</text>')
    legend_x = left
    for index, architecture in enumerate(ALL_ARCHITECTURES):
        x = legend_x + index * 180
        lines.append(f'<rect x="{x}" y="{height - 55}" width="14" height="14" fill="{colors[architecture]}"/>')
        lines.append(f'<text x="{x + 20}" y="{height - 43}" font-family="Arial, sans-serif" font-size="12" fill="#111827">{architecture}</text>')
    lines.append("</svg>")
    path.write_text("\n".join(lines))


def trapezoid_area(points: list[tuple[float, float]]) -> float:
    return sum((x2 - x1) * (y1 + y2) / 2 for (x1, y1), (x2, y2) in zip(points, points[1:], strict=False))


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


if __name__ == "__main__":
    raise SystemExit(main())
