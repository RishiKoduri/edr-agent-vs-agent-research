# Adaptive Attacker Evasion Analysis

This experiment increases the adaptation parameter of the synthetic adaptive AI-agent attacker and measures detection quality across local, centralized, and federated EDR-style architectures.

The adaptation parameter is a controlled proxy for learned attacker behavior. It changes event timing and hides selected attack-stage events at higher levels. It is not a trained reinforcement-learning or language-model agent.

## Mean results

| Architecture | Adaptation level | Detection rate | Attack success rate | Mean score | Mean time to detection |
|---|---:|---:|---:|---:|---:|
| local | 0 | 1.000 | 0.000 | 6.700 | 54.90 |
| local | 1 | 0.950 | 0.050 | 4.925 | 87.97 |
| local | 2 | 0.800 | 0.200 | 4.487 | 138.66 |
| local | 3 | 0.650 | 0.350 | 4.263 | 151.42 |
| local | 4 | 0.550 | 0.450 | 4.100 | 254.39 |
| centralized | 0 | 1.000 | 0.000 | 7.900 | 54.90 |
| centralized | 1 | 1.000 | 0.000 | 6.175 | 88.71 |
| centralized | 2 | 1.000 | 0.000 | 5.737 | 148.16 |
| centralized | 3 | 0.950 | 0.050 | 5.513 | 194.05 |
| centralized | 4 | 0.900 | 0.100 | 5.350 | 275.48 |
| federated | 0 | 1.000 | 0.000 | 8.200 | 54.90 |
| federated | 1 | 1.000 | 0.000 | 6.425 | 88.71 |
| federated | 2 | 1.000 | 0.000 | 6.237 | 148.16 |
| federated | 3 | 0.950 | 0.050 | 6.013 | 194.05 |
| federated | 4 | 0.900 | 0.100 | 5.850 | 275.48 |

## Findings to investigate

- Does increasing adaptation reduce detection rate or increase attack success?
- Does cross-endpoint correlation preserve detection quality as the attacker becomes less regular?
- Does the adaptation curve plateau, suggesting the detector has reached a blind spot?
- Which results change when the detector threshold is varied?

## Model note

The levels are graduated synthetic behavior changes, not a trained reinforcement-learning or language-model policy. A later version should replace this proxy with a learned attacker policy and compare the learned policy against these controlled levels.
