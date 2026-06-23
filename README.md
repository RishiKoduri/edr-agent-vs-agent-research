# EDR Agent-vs-Agent Research Testbed

Research workspace for Step 1 of the project: building a safe Python testbed for studying AI attacker-agent behavior against AI-aware Endpoint Detection and Response (EDR) logic.

## Step 1 objective

Build a safe, reproducible simulation that generates synthetic endpoint telemetry and measures whether EDR-style behavioral detection can distinguish:

- benign human/admin activity
- traditional scripted attacker activity
- adaptive AI-agent attacker activity

The simulator does not execute real commands, exploit systems, scan networks, or generate malware. It only creates abstract event records for research experiments.

## Required December 2026 outputs

- Reproducible simulation environment
- Baseline benign, scripted-attacker, and AI-agent traffic generators
- AI-aware EDR behavioral detector
- Local, centralized, federated, and hybrid EDR configurations
- Instrumentation and experiment runner
- Pilot and main experiment datasets
- Statistical and visual analysis
- Technical report and Step 2 model-parameter handoff

## Repository structure

```text
docs/          Research design, decisions, protocols, and reporting
src/           Simulation and agent implementation
tests/         Automated verification
experiments/   Versioned experiment configurations
analysis/      Analysis code and figures
data/          Local generated data (raw outputs should not be committed)
```

## Quick start

Run the baseline simulator:

```bash
PYTHONPATH=src python3 -m edr_sim.cli
```

This writes:

```text
data/baseline_results.csv
data/baseline_summary.md
```

Run the current verification tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Version 1 experiment

The current V1 experiment runs all three traffic classes across four EDR architecture modes:

- `local`
- `centralized`
- `federated`
- `hybrid`

It reports detection rate, precision, recall, false-positive rate, attack-success rate, and time-to-detection.

## Current phase

Phase 1: EDR-focused Step 1 prototype and experimental design.

See [docs/edr-agent-vs-agent-plan.md](docs/edr-agent-vs-agent-plan.md), [docs/step-1-charter.md](docs/step-1-charter.md), and [docs/roadmap.md](docs/roadmap.md).
