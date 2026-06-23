# Baseline EDR Agent-vs-Agent Experiment Summary

This report is generated from the safe synthetic endpoint-telemetry simulator.
No real exploit code, malware, scanning, or external system interaction is performed.

## Architecture-level results

| Architecture | Precision | Recall | False positive rate | Attack success rate | Avg. time to detection |
|---|---:|---:|---:|---:|---:|
| centralized | 1.00 | 1.00 | 0.00 | 0.00 | 77.6 |
| federated | 1.00 | 1.00 | 0.00 | 0.00 | 77.6 |
| hybrid | 1.00 | 1.00 | 0.00 | 0.00 | 77.6 |
| local | 1.00 | 0.97 | 0.00 | 0.03 | 77.5 |

## Traffic-class results

| Architecture | Traffic class | Runs | Detection rate | Attack success rate | Avg. score | Avg. time to detection |
|---|---|---:|---:|---:|---:|---:|
| centralized | ai_agent_attacker | 50 | 1.00 | 0.00 | 6.24 | 142.2 |
| centralized | benign_admin | 50 | 0.00 | 0.00 | 0.00 | n/a |
| centralized | scripted_attacker | 50 | 1.00 | 0.00 | 9.00 | 12.9 |
| federated | ai_agent_attacker | 50 | 1.00 | 0.00 | 6.74 | 142.2 |
| federated | benign_admin | 50 | 0.00 | 0.00 | 0.75 | n/a |
| federated | scripted_attacker | 50 | 1.00 | 0.00 | 10.25 | 12.9 |
| hybrid | ai_agent_attacker | 50 | 1.00 | 0.00 | 6.24 | 142.2 |
| hybrid | benign_admin | 50 | 0.00 | 0.00 | 0.50 | n/a |
| hybrid | scripted_attacker | 50 | 1.00 | 0.00 | 10.25 | 12.9 |
| local | ai_agent_attacker | 50 | 0.94 | 0.06 | 4.99 | 146.2 |
| local | benign_admin | 50 | 0.00 | 0.00 | 0.00 | n/a |
| local | scripted_attacker | 50 | 1.00 | 0.00 | 8.75 | 12.9 |

## Interpretation

- `precision` measures how often alerts correspond to attacker sessions rather than benign admin activity.
- `recall` measures how often attacker sessions are detected.
- `attack_success_rate` means the simulated attacker reached sensitive access or exfiltration before detection.
- Local EDR intentionally has weaker cross-endpoint visibility; federated and hybrid modes receive correlation benefits.
