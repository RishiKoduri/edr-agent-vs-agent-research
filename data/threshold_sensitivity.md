# Detection Threshold Sensitivity Analysis

This analysis evaluates the detector across thresholds from 0.00 to 12.00.
The core comparison uses local, centralized, and federated architectures. Hybrid is included as an optional reference.

## Ranking metrics

| Architecture | ROC-AUC | PR-AUC | Best F2 threshold | Best F2 | Recall at best F2 | False positive rate at best F2 | Attack success at best F2 |
|---|---:|---:|---:|---:|---:|---:|---:|
| local | 0.988 | 0.991 | 2.00 | 0.984 | 0.980 | 0.000 | 0.020 |
| centralized | 0.992 | 0.992 | 2.75 | 0.984 | 0.980 | 0.000 | 0.020 |
| federated | 0.996 | 0.995 | 3.00 | 0.984 | 0.980 | 0.000 | 0.020 |
| hybrid | 0.990 | 0.992 | 2.75 | 0.984 | 0.980 | 0.000 | 0.020 |

## Interpretation

- F2 weights recall more heavily than precision, reflecting the higher cost of missed attacks.
- ROC-AUC measures ranking quality across thresholds and can look optimistic when classes are balanced.
- PR-AUC emphasizes performance on the positive attacker class and is useful when alerts are uncommon.
- The selected threshold is a research comparison point, not a production calibration recommendation.
