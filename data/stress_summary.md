# Coordinated-Pressure Stress Test

This experiment increases simultaneous adaptive AI-agent attacker sessions while five benign personas remain active.
It compares local, centralized, and federated EDR-style architectures using synthetic telemetry only.

## Assumptions

- Session capacity is a transparent synthetic queue assumption: local 8, centralized 12, and federated 16 sessions per observation window.
- Queue pressure subtracts `overload_ratio` from each raw detector score before applying the 4.0 threshold.
- Collapse is flagged when overload reaches capacity or attack success reaches 75 percent or more.
- Operator burden index is a comparative index equal to session backlog plus raw alert queue backlog. It is not a production staffing unit.

## Mean results by pressure

| Architecture | Attack sessions | Attack detection | Attack success | False positive rate | Backlog | Operator burden | Collapse rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| local | 1 | 0.650 | 0.350 | 0.000 | 0.0 | 0.0 | 0.350 |
| local | 2 | 0.525 | 0.475 | 0.000 | 0.0 | 0.0 | 0.300 |
| local | 4 | 0.500 | 0.500 | 0.000 | 1.0 | 1.0 | 0.400 |
| local | 8 | 0.425 | 0.575 | 0.000 | 5.0 | 5.0 | 0.200 |
| local | 16 | 0.188 | 0.809 | 0.000 | 13.0 | 14.4 | 1.000 |
| local | 32 | 0.000 | 1.000 | 0.000 | 29.0 | 39.7 | 1.000 |
| centralized | 1 | 0.900 | 0.100 | 0.000 | 0.0 | 0.0 | 0.100 |
| centralized | 2 | 0.875 | 0.125 | 0.000 | 0.0 | 0.0 | 0.050 |
| centralized | 4 | 0.875 | 0.125 | 0.000 | 0.0 | 0.0 | 0.000 |
| centralized | 8 | 0.944 | 0.056 | 0.000 | 1.0 | 1.0 | 0.000 |
| centralized | 16 | 0.650 | 0.347 | 0.000 | 9.0 | 11.6 | 0.000 |
| centralized | 32 | 0.188 | 0.812 | 0.000 | 25.0 | 42.4 | 1.000 |
| federated | 1 | 0.900 | 0.100 | 0.000 | 0.0 | 0.0 | 0.100 |
| federated | 2 | 0.875 | 0.125 | 0.000 | 0.0 | 0.0 | 0.050 |
| federated | 4 | 0.875 | 0.125 | 0.000 | 0.0 | 0.0 | 0.000 |
| federated | 8 | 0.944 | 0.056 | 0.000 | 0.0 | 0.0 | 0.000 |
| federated | 16 | 0.912 | 0.087 | 0.000 | 5.0 | 5.0 | 0.000 |
| federated | 32 | 0.584 | 0.416 | 0.000 | 21.0 | 34.4 | 1.000 |

## Interpretation questions

- At what pressure does each architecture show a meaningful increase in attack success?
- Does added federation capacity delay the collapse point under coordinated pressure?
- Does operator burden grow before detection quality collapses?
- Are the results sensitive to the capacity and overload assumptions?
