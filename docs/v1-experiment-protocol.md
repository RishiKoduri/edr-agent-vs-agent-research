# V1 Experiment Protocol

## Purpose

Version 1 tests whether synthetic endpoint-telemetry features can separate benign administrative activity from scripted attacker activity and adaptive AI-agent attacker activity.

This is not a live cyber range. It is a safe simulation layer for developing the research design, metrics, and EDR-agent logic before any realistic lab integration.

## Traffic classes

1. Benign admin
   - Includes office worker, developer, sysadmin, helpdesk, and service account profiles
   - Slower timing for human users
   - More idle gaps and human-noise events for human users
   - Regular scheduled behavior for service accounts
   - Mostly routine administrative or business targets

2. Scripted attacker
   - Includes noisy scripted and stealth scripted profiles
   - Fast or moderately paced action tempo
   - Repetitive attack-chain ordering
   - High-risk administration tools
   - Clear or partially obscured lateral movement and sensitive-access path

3. Adaptive AI-agent attacker
   - Includes cautious AI, human-mimicking AI, and adaptive AI profiles
   - More variable timing than the scripted attacker
   - Partial human-noise mimicry
   - Some avoidance of obviously suspicious event types
   - Goal-directed movement toward high-value targets

## EDR architecture modes

1. Local
   - Endpoint-level detection with weak cross-endpoint context.

2. Centralized
   - Central correlation across endpoints, with a small queue-pressure penalty under fast event bursts.

3. Federated
   - Shared behavioral indicators across endpoints, with improved recognition of adapted behavior.

4. Hybrid
   - Local fast response plus central context.

## AI-BIoC feature families

The V1 detector scores:

- action tempo
- timing regularity
- endpoint hops
- repeated high-risk administration tools
- lateral movement
- sensitive-access-to-exfiltration sequence
- role/target mismatch
- goal-directedness
- absence of human-noise signals
- adaptation level

## V1 outputs

Running:

```bash
PYTHONPATH=src python3 -m edr_sim.cli
```

produces:

- `data/baseline_results.csv` — one row per simulated session
- `data/baseline_summary.md` — architecture-level and traffic-class metrics

## Metrics

- precision
- recall
- false-positive rate
- detection rate
- attack-success rate
- average score
- average time-to-detection

## Current limitations

- The event stream is synthetic and abstract.
- The detector is rule-weighted rather than machine-learned.
- Benign administrative behavior is still simplified.
- The attacker adaptation model is heuristic, not a learned red agent.
- The architecture effects are modeled as scoring adjustments, not full distributed systems.

These limitations are intentional for V1. The goal is to create a reproducible research scaffold before increasing realism.

## Next improvements

1. Add configurable experiment files under `experiments/`.
2. Add richer benign-user personas.
3. Add adaptive attacker rounds that learn from prior detector reasons.
4. Add per-endpoint event timelines.
5. Add plots for detection rate and false-positive tradeoffs.
6. Add a Wazuh/Sysmon mapping document showing how each synthetic field maps to realistic telemetry.
