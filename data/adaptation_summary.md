# Adaptive Attacker Evasion Analysis

This experiment increases the adaptation parameter of the synthetic adaptive AI-agent attacker and measures detection quality across local, centralized, and federated EDR-style architectures.

The adaptation parameter is a controlled proxy for learned attacker behavior. It changes event timing and hides selected attack-stage events at higher levels. It is not a trained reinforcement-learning or language-model agent.

## Mean results

| Architecture | Adaptation level | Detection rate | Attack success rate | Mean score | Mean time to detection |
|---|---:|---:|---:|---:|---:|
| local | 0 | 0.800 | 0.200 | 5.025 | 257.65 |
| local | 1 | 0.650 | 0.350 | 4.263 | 187.66 |
| local | 2 | 0.450 | 0.550 | 3.837 | 239.16 |
| local | 3 | 0.450 | 0.550 | 3.837 | 239.16 |
| local | 4 | 0.450 | 0.550 | 3.837 | 239.16 |
| centralized | 0 | 1.000 | 0.000 | 6.275 | 259.62 |
| centralized | 1 | 0.950 | 0.050 | 5.513 | 240.49 |
| centralized | 2 | 0.900 | 0.100 | 5.088 | 275.60 |
| centralized | 3 | 0.900 | 0.100 | 5.088 | 275.60 |
| centralized | 4 | 0.900 | 0.100 | 5.088 | 275.60 |
| federated | 0 | 1.000 | 0.000 | 6.525 | 259.62 |
| federated | 1 | 0.950 | 0.050 | 5.763 | 240.49 |
| federated | 2 | 0.900 | 0.100 | 5.588 | 275.60 |
| federated | 3 | 0.900 | 0.100 | 5.588 | 275.60 |
| federated | 4 | 0.900 | 0.100 | 5.588 | 275.60 |

## Findings to investigate

- Does increasing adaptation reduce detection rate or increase attack success?
- Does cross-endpoint correlation preserve detection quality as the attacker becomes less regular?
- Does the adaptation curve plateau, suggesting the detector has reached a blind spot?
- Which results change when the detector threshold is varied?

## Limitation

Levels 2 through 4 currently share the same event-obfuscation branch in the generator. A later version should replace this proxy with a learned attacker policy or add more graduated behavior changes.
