from __future__ import annotations

import csv
import sys
from pathlib import Path

from .simulation import run_experiment


def main() -> int:
    output = Path("data/baseline_results.csv")
    output.parent.mkdir(parents=True, exist_ok=True)

    runs = run_experiment()
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "traffic_class",
                "seed",
                "detected",
                "score",
                "reasons",
                "time_to_detection",
            ],
        )
        writer.writeheader()
        for run in runs:
            writer.writerow(
                {
                    "traffic_class": run.traffic_class.value,
                    "seed": run.seed,
                    "detected": run.detected,
                    "score": f"{run.score:.2f}",
                    "reasons": "; ".join(run.reasons),
                    "time_to_detection": run.time_to_detection or "",
                }
            )

    print(f"Wrote {len(runs)} simulation rows to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

