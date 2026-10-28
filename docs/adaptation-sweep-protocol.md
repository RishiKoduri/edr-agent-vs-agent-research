# Adaptive Attacker Evasion Protocol

## Research purpose

This experiment isolates the relationship between attacker adaptation and EDR detection quality. It extends the baseline and stress experiments by changing one attacker behavior parameter while holding the architecture, detector threshold, session length, and random-seed design constant.

## Design

- Attacker profile: `adaptive_ai_agent`
- Adaptation levels: 0 through 4
- Architectures: local, centralized, federated
- Seeds: 20 per architecture and adaptation level
- Detector threshold: 4.0
- Session length: 32 synthetic events

The adaptation parameter changes the timing and event-obfuscation behavior of the synthetic attacker. The current implementation is a controlled proxy for learned behavior. It does not execute an AI model or claim that a trained reinforcement-learning policy is present.

## Measures

- Detection rate
- Attack success rate
- Mean suspicion score
- Mean time to detection among detected sessions

## Run command

```bash
PYTHONPATH=src:. python3 analysis/adaptation_sweep.py
```

Outputs:

- `data/adaptation_results.csv`
- `data/adaptation_summary.md`
- `analysis/figures/adaptation_attack_success.svg`

## Limitation and next refinement

The levels now use graduated timing, endpoint movement, command-quality, and event-obfuscation changes. They remain a controlled proxy rather than a trained reinforcement-learning or language-model policy. The next refinement should compare this proxy against a learned attacker policy.
