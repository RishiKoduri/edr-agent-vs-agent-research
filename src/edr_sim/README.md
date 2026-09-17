# edr_sim

This package implements the safe synthetic EDR simulation.

Module map:

- `models.py`: shared event, session, detection, and result models
- `generators.py`: benign and attacker telemetry generators
- `detectors.py`: AI-BIoC-style behavioral detector
- `simulation.py`: experiment execution logic
- `metrics.py`: summary metrics and Markdown report rendering
- `cli.py`: command-line entry point

