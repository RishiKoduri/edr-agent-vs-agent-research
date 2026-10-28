# Coordinated-Pressure Stress Test Protocol

## Research purpose

This experiment tests how EDR architecture behaves when several adaptive AI-agent attacker sessions occur at the same time. It extends the baseline detector comparison with two operational outcomes:

- attack success under pressure
- alert and processing burden under pressure

The experiment is synthetic and safe. It generates abstract telemetry only. It does not execute commands, scan a network, contact endpoints, or create malware.

## Experimental design

- Attacker profile: `adaptive_ai_agent`
- Adaptation level: 4
- Benign background: one session for each of the five benign personas
- Core architectures: local, centralized, federated
- Attacker pressure: 1, 2, 4, 8, 16, and 32 simultaneous sessions
- Random seeds: 20 seeds per architecture and pressure level
- Detector threshold: 4.0

## Stress assumptions

The first stress model needs an explicit capacity assumption so the experiment can measure overload. The assumed session capacities are:

| Architecture | Concurrent session capacity |
|---|---:|
| Local | 8 |
| Centralized | 12 |
| Federated | 16 |

When total sessions exceed capacity, the experiment computes an overload ratio. That ratio is subtracted from each raw detector score to represent loss of timely processing under queue pressure. This is a research model assumption, not a claim about a specific EDR vendor.

Collapse is flagged when the overload ratio reaches 1.0 or when attack success reaches 75 percent or more. The higher cutoff separates ordinary baseline misses from a stress-induced collapse signal in this first model.

## Measures

- `attack_detection_rate`: proportion of attacker sessions detected after pressure adjustment
- `attack_success_rate`: proportion of attacker sessions that reach a sensitive objective without detection
- `false_positive_rate`: benign sessions incorrectly flagged after pressure adjustment
- `backlog_sessions`: sessions beyond the assumed architecture capacity
- `raw_alert_volume`: alerts before pressure adjustment
- `alert_queue_backlog`: raw alerts beyond the assumed processing capacity
- `operator_burden_index`: session backlog plus alert queue backlog, used only for relative comparison
- `collapse`: binary indicator for the predefined collapse rule

## Run command

```bash
PYTHONPATH=src python3 -m edr_sim.stress_testing
```

Outputs:

- `data/stress_results.csv`
- `data/stress_summary.md`
- `analysis/figures/stress_attack_success.svg`

## Interpretation

The result should be interpreted as a controlled sensitivity experiment. If an architecture appears more resilient, the next step is to test whether that result remains after changing capacity, overload penalty, threshold, attacker profile, and seed count.
