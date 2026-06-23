from __future__ import annotations

import csv
from pathlib import Path

from .metrics import render_markdown_summary
from .simulation import run_experiment


def main() -> int:
    data_dir = Path("data")
    data_dir.mkdir(parents=True, exist_ok=True)
    output = data_dir / "baseline_results.csv"
    summary_output = data_dir / "baseline_summary.md"

    runs = run_experiment()
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "session_id",
                "architecture",
                "traffic_class",
                "seed",
                "detected",
                "score",
                "reasons",
                "time_to_detection",
                "attack_success",
                "false_positive",
                "true_positive",
                "event_count",
            ],
        )
        writer.writeheader()
        for run in runs:
            writer.writerow(
                {
                    "session_id": run.session_id,
                    "architecture": run.architecture.value,
                    "traffic_class": run.traffic_class.value,
                    "seed": run.seed,
                    "detected": run.detected,
                    "score": f"{run.score:.2f}",
                    "reasons": "; ".join(run.reasons),
                    "time_to_detection": run.time_to_detection or "",
                    "attack_success": run.attack_success,
                    "false_positive": run.false_positive,
                    "true_positive": run.true_positive,
                    "event_count": run.event_count,
                }
            )

    summary_output.write_text(render_markdown_summary(runs))

    print(f"Wrote {len(runs)} simulation rows to {output}")
    print(f"Wrote summary report to {summary_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
