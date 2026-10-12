from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path


ARCHITECTURES = ["local", "centralized", "federated", "hybrid"]
AI_PROFILES = ["cautious_ai_agent", "human_mimicking_ai_agent", "adaptive_ai_agent"]
ATTACKER_CLASSES = {"scripted_attacker", "ai_agent_attacker"}
COLORS = {
    "local": "#6B7280",
    "centralized": "#2563EB",
    "federated": "#059669",
    "hybrid": "#7C3AED",
    "detection": "#2563EB",
    "attack_success": "#DC2626",
    "false_positive": "#F59E0B",
}


def main() -> int:
    source = Path("data/baseline_results.csv")
    output_dir = Path("analysis/figures")
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = read_rows(source)
    write_architecture_metrics(rows, output_dir / "architecture_metrics.svg")
    write_ai_profile_detection(rows, output_dir / "ai_profile_detection.svg")
    write_profile_scores(rows, output_dir / "average_score_by_profile.svg")

    print(f"Wrote charts to {output_dir}")
    return 0


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_architecture_metrics(rows: list[dict[str, str]], path: Path) -> None:
    metrics = []
    for architecture in ARCHITECTURES:
        group = [row for row in rows if row["architecture"] == architecture]
        attackers = [row for row in group if row["traffic_class"] in ATTACKER_CLASSES]
        benign = [row for row in group if row["traffic_class"] == "benign_admin"]
        metrics.append(
            {
                "architecture": architecture,
                "Detection rate": rate(row["detected"] == "True" for row in attackers),
                "Attack success": rate(row["attack_success"] == "True" for row in attackers),
                "False positive": rate(row["false_positive"] == "True" for row in benign),
            }
        )

    series = ["Detection rate", "Attack success", "False positive"]
    draw_grouped_bar_chart(
        path,
        title="EDR architecture comparison",
        categories=[item["architecture"] for item in metrics],
        series=series,
        values={
            name: [item[name] for item in metrics]
            for name in series
        },
        colors={
            "Detection rate": COLORS["detection"],
            "Attack success": COLORS["attack_success"],
            "False positive": COLORS["false_positive"],
        },
        value_format="{:.0%}",
    )


def write_ai_profile_detection(rows: list[dict[str, str]], path: Path) -> None:
    series = ARCHITECTURES
    values = {architecture: [] for architecture in ARCHITECTURES}
    for profile in AI_PROFILES:
        for architecture in ARCHITECTURES:
            group = [
                row for row in rows
                if row["architecture"] == architecture and row["actor_profile"] == profile
            ]
            values[architecture].append(rate(row["detected"] == "True" for row in group))

    draw_grouped_bar_chart(
        path,
        title="AI attacker detection by profile",
        categories=AI_PROFILES,
        series=series,
        values=values,
        colors={architecture: COLORS[architecture] for architecture in ARCHITECTURES},
        value_format="{:.0%}",
    )


def write_profile_scores(rows: list[dict[str, str]], path: Path) -> None:
    grouped: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        grouped[row["actor_profile"]].append(float(row["score"]))

    profiles = sorted(grouped)
    values = [sum(grouped[profile]) / len(grouped[profile]) for profile in profiles]
    draw_horizontal_bar_chart(
        path,
        title="Average suspicion score by profile",
        categories=profiles,
        values=values,
        max_value=max(values) if values else 1.0,
        color="#2563EB",
        value_format="{:.2f}",
    )


def rate(values) -> float:
    values = list(values)
    if not values:
        return 0.0
    return sum(bool(value) for value in values) / len(values)


def draw_grouped_bar_chart(
    path: Path,
    *,
    title: str,
    categories: list[str],
    series: list[str],
    values: dict[str, list[float]],
    colors: dict[str, str],
    value_format: str,
) -> None:
    width = 980
    height = 560
    margin_left = 90
    margin_right = 30
    margin_top = 80
    margin_bottom = 120
    chart_width = width - margin_left - margin_right
    chart_height = height - margin_top - margin_bottom
    group_width = chart_width / len(categories)
    bar_width = min(34, group_width / (len(series) + 1))

    parts = svg_header(width, height, title)
    parts.append(axis_lines(margin_left, margin_top, chart_width, chart_height))
    for tick in range(0, 6):
        y = margin_top + chart_height - (tick / 5) * chart_height
        value = tick / 5
        parts.append(f'<line x1="{margin_left}" y1="{y:.1f}" x2="{width - margin_right}" y2="{y:.1f}" stroke="#E5E7EB"/>')
        parts.append(text(50, y + 4, f"{value:.0%}", size=12, anchor="start", fill="#4B5563"))

    for category_index, category in enumerate(categories):
        group_start = margin_left + category_index * group_width
        center = group_start + group_width / 2
        for series_index, name in enumerate(series):
            value = values[name][category_index]
            x = center - (len(series) * bar_width) / 2 + series_index * bar_width
            bar_height = value * chart_height
            y = margin_top + chart_height - bar_height
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width - 4:.1f}" height="{bar_height:.1f}" fill="{colors[name]}"/>')
            if value >= 0.08:
                parts.append(text(x + (bar_width - 4) / 2, y - 6, value_format.format(value), size=10, anchor="middle", fill="#111827"))
        parts.append(text(center, height - 72, category.replace("_", " "), size=12, anchor="middle", fill="#111827", rotate=-20))

    legend_x = margin_left
    legend_y = height - 35
    for index, name in enumerate(series):
        x = legend_x + index * 190
        parts.append(f'<rect x="{x}" y="{legend_y - 12}" width="14" height="14" fill="{colors[name]}"/>')
        parts.append(text(x + 20, legend_y, name, size=12, anchor="start", fill="#111827"))

    parts.append("</svg>")
    path.write_text("\n".join(parts))


def draw_horizontal_bar_chart(
    path: Path,
    *,
    title: str,
    categories: list[str],
    values: list[float],
    max_value: float,
    color: str,
    value_format: str,
) -> None:
    width = 980
    row_height = 42
    margin_left = 250
    margin_right = 80
    margin_top = 80
    margin_bottom = 40
    height = margin_top + margin_bottom + row_height * len(categories)
    chart_width = width - margin_left - margin_right

    parts = svg_header(width, height, title)
    for index, category in enumerate(categories):
        y = margin_top + index * row_height
        bar_width = 0 if max_value == 0 else values[index] / max_value * chart_width
        parts.append(text(margin_left - 14, y + 22, category.replace("_", " "), size=12, anchor="end", fill="#111827"))
        parts.append(f'<rect x="{margin_left}" y="{y + 7}" width="{bar_width:.1f}" height="22" fill="{color}"/>')
        parts.append(text(margin_left + bar_width + 8, y + 24, value_format.format(values[index]), size=12, anchor="start", fill="#111827"))
    parts.append("</svg>")
    path.write_text("\n".join(parts))


def svg_header(width: int, height: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        text(30, 40, title, size=24, anchor="start", fill="#111827", weight="700"),
    ]


def axis_lines(margin_left: int, margin_top: int, chart_width: int, chart_height: int) -> str:
    return (
        f'<line x1="{margin_left}" y1="{margin_top + chart_height}" '
        f'x2="{margin_left + chart_width}" y2="{margin_top + chart_height}" stroke="#111827"/>'
    )


def text(
    x: float,
    y: float,
    content: str,
    *,
    size: int,
    anchor: str,
    fill: str,
    weight: str = "400",
    rotate: int | None = None,
) -> str:
    escaped = (
        content.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    transform = f' transform="rotate({rotate} {x:.1f} {y:.1f})"' if rotate is not None else ""
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" fill="{fill}"'
        f' font-family="Arial, sans-serif" font-size="{size}" font-weight="{weight}"{transform}>'
        f"{escaped}</text>"
    )


if __name__ == "__main__":
    raise SystemExit(main())
