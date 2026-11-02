# Osquery Bridge Protocol

## Purpose

This bridge allows osquery-style endpoint observations to be scored by the same behavioral detector used in the synthetic EDR experiments. It creates a path for later validation with real benign endpoint telemetry without changing the controlled simulator.

## Important limitation

Osquery is primarily an endpoint instrumentation and visibility tool. A table snapshot is not automatically a behavioral event stream. The bridge therefore prefers records with an explicit `event_type`, `timestamp`, and `session_id`. When those fields are missing, it uses conservative field-based inference for exploratory analysis. Results from inferred events must be labeled as provisional.

## Supported input

The input can be newline-delimited JSON or the JSON array returned by an osquery shell query. Each row can include:

- `event_type`
- `timestamp` or `time`
- `host_identifier`
- `username`
- `role`
- `name` or `process_name`
- `target`
- `session_id`
- `command_quality`

The adapter also accepts osquery-style rows with a nested `columns` object.

## Smoke test

Generate safe synthetic osquery-shaped data:

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
from edr_sim.osquery_bridge import write_synthetic_fixture

write_synthetic_fixture(Path("data/osquery_bridge_fixture.jsonl"))
PY
```

Score the fixture:

```bash
PYTHONPATH=src python3 -m edr_sim.osquery_bridge \
  data/osquery_bridge_fixture.jsonl \
  --architecture centralized \
  --output data/osquery_bridge_results.csv
```

This smoke test is safe and does not execute commands or contact an endpoint.
