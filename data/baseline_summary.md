# Baseline EDR Agent-vs-Agent Experiment Summary

This report is generated from the safe synthetic endpoint-telemetry simulator.
No real exploit code, malware, scanning, or external system interaction is performed.

## Architecture-level results

| Architecture | Precision | Recall | False positive rate | Attack success rate | Avg. time to detection |
|---|---:|---:|---:|---:|---:|
| centralized | 1.00 | 0.89 | 0.00 | 0.11 | 127.5 |
| federated | 1.00 | 0.96 | 0.00 | 0.04 | 146.4 |
| hybrid | 1.00 | 0.89 | 0.00 | 0.11 | 127.5 |
| local | 1.00 | 0.74 | 0.00 | 0.26 | 98.1 |

## Traffic-class results

| Architecture | Traffic class and profile | Runs | Detection rate | Attack success rate | Avg. score | Avg. time to detection |
|---|---|---:|---:|---:|---:|---:|
| centralized | ai_agent_attacker / adaptive_ai_agent | 50 | 0.90 | 0.10 | 5.23 | 249.2 |
| centralized | ai_agent_attacker / cautious_ai_agent | 50 | 1.00 | 0.00 | 6.16 | 85.4 |
| centralized | ai_agent_attacker / human_mimicking_ai_agent | 50 | 0.54 | 0.46 | 4.42 | 324.9 |
| centralized | benign_admin / developer | 50 | 0.00 | 0.00 | 0.00 | n/a |
| centralized | benign_admin / helpdesk | 50 | 0.00 | 0.00 | 2.46 | n/a |
| centralized | benign_admin / office_worker | 50 | 0.00 | 0.00 | 0.00 | n/a |
| centralized | benign_admin / service_account | 50 | 0.00 | 0.00 | 1.75 | n/a |
| centralized | benign_admin / sysadmin | 50 | 0.00 | 0.00 | 2.46 | n/a |
| centralized | scripted_attacker / noisy_scripted_attacker | 50 | 1.00 | 0.00 | 9.00 | 13.3 |
| centralized | scripted_attacker / stealth_scripted_attacker | 50 | 1.00 | 0.00 | 6.78 | 67.9 |
| federated | ai_agent_attacker / adaptive_ai_agent | 50 | 0.90 | 0.10 | 5.73 | 249.2 |
| federated | ai_agent_attacker / cautious_ai_agent | 50 | 1.00 | 0.00 | 6.41 | 85.4 |
| federated | ai_agent_attacker / human_mimicking_ai_agent | 50 | 0.88 | 0.12 | 4.92 | 351.0 |
| federated | benign_admin / developer | 50 | 0.00 | 0.00 | 0.75 | n/a |
| federated | benign_admin / helpdesk | 50 | 0.00 | 0.00 | 2.71 | n/a |
| federated | benign_admin / office_worker | 50 | 0.00 | 0.00 | 0.75 | n/a |
| federated | benign_admin / service_account | 50 | 0.00 | 0.00 | 2.50 | n/a |
| federated | benign_admin / sysadmin | 50 | 0.00 | 0.00 | 2.71 | n/a |
| federated | scripted_attacker / noisy_scripted_attacker | 50 | 1.00 | 0.00 | 10.25 | 13.3 |
| federated | scripted_attacker / stealth_scripted_attacker | 50 | 1.00 | 0.00 | 7.03 | 67.9 |
| hybrid | ai_agent_attacker / adaptive_ai_agent | 50 | 0.90 | 0.10 | 5.23 | 249.2 |
| hybrid | ai_agent_attacker / cautious_ai_agent | 50 | 1.00 | 0.00 | 6.16 | 85.4 |
| hybrid | ai_agent_attacker / human_mimicking_ai_agent | 50 | 0.54 | 0.46 | 4.42 | 324.9 |
| hybrid | benign_admin / developer | 50 | 0.00 | 0.00 | 0.50 | n/a |
| hybrid | benign_admin / helpdesk | 50 | 0.00 | 0.00 | 2.46 | n/a |
| hybrid | benign_admin / office_worker | 50 | 0.00 | 0.00 | 0.50 | n/a |
| hybrid | benign_admin / service_account | 50 | 0.00 | 0.00 | 2.25 | n/a |
| hybrid | benign_admin / sysadmin | 50 | 0.00 | 0.00 | 2.46 | n/a |
| hybrid | scripted_attacker / noisy_scripted_attacker | 50 | 1.00 | 0.00 | 10.25 | 13.3 |
| hybrid | scripted_attacker / stealth_scripted_attacker | 50 | 1.00 | 0.00 | 6.78 | 67.9 |
| local | ai_agent_attacker / adaptive_ai_agent | 50 | 0.50 | 0.50 | 3.98 | 244.4 |
| local | ai_agent_attacker / cautious_ai_agent | 50 | 1.00 | 0.00 | 4.91 | 85.4 |
| local | ai_agent_attacker / human_mimicking_ai_agent | 50 | 0.24 | 0.76 | 3.17 | 324.1 |
| local | benign_admin / developer | 50 | 0.00 | 0.00 | 0.00 | n/a |
| local | benign_admin / helpdesk | 50 | 0.00 | 0.00 | 1.21 | n/a |
| local | benign_admin / office_worker | 50 | 0.00 | 0.00 | 0.00 | n/a |
| local | benign_admin / service_account | 50 | 0.00 | 0.00 | 1.75 | n/a |
| local | benign_admin / sysadmin | 50 | 0.00 | 0.00 | 1.21 | n/a |
| local | scripted_attacker / noisy_scripted_attacker | 50 | 1.00 | 0.00 | 8.75 | 13.3 |
| local | scripted_attacker / stealth_scripted_attacker | 50 | 0.96 | 0.04 | 5.53 | 66.9 |

## Interpretation

- `precision` measures how often alerts correspond to attacker sessions rather than benign admin activity.
- `recall` measures how often attacker sessions are detected.
- `attack_success_rate` means the simulated attacker reached sensitive access or exfiltration before detection.
- Local EDR intentionally has weaker cross-endpoint visibility; federated and hybrid modes receive correlation benefits.
