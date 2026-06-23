# Multi-Agent Adversarial Architectures and Cyber Risk Dynamics

Research workspace for Step 1 of the project: developing and evaluating multi-agent attacker and defender architectures under concentrated adversarial pressure.

## Step 1 objective

Build a safe, reproducible simulation that measures when different defensive coordination architectures remain resilient, degrade, collapse, and recover as coordinated attacker pressure increases.

## Required December 2026 outputs

- Reproducible simulation environment
- Baseline attacker and defender agents
- Centralized, decentralized, federated, and hybrid defensive configurations
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

Run the current verification tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Current phase

Phase 1: scope, definitions, hypotheses, platform selection, and experimental design.

See [docs/step-1-charter.md](docs/step-1-charter.md) and [docs/roadmap.md](docs/roadmap.md).
