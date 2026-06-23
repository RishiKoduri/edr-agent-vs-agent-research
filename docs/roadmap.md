# Step 1 Roadmap

The schedule uses December 15, 2026 as the working completion date and reserves the remainder of December for correction and submission risk.

| Dates | Phase | Exit gate |
|---|---|---|
| Jun 22–Jul 3 | Scope and research design | Charter, hypotheses, definitions, exclusions, and acceptance criteria agreed |
| Jul 6–17 | Literature and platform selection | Literature matrix and architecture decision record completed |
| Jul 20–31 | Experimental design | Variables, baselines, scenarios, metrics, replication, and analysis plan frozen |
| Aug 3–14 | Testbed construction | Reproducible environment, reset, logging, and seed controls verified |
| Aug 17–28 | Baseline agents | Single-attacker and single-defender baseline runs pass automated tests |
| Aug 31–Sep 18 | Attacker coordination | Coordinated attacker population and concentration policies operational |
| Sep 21–Oct 9 | Defender coordination | Multi-agent defensive coordination and recovery operational |
| Oct 12–23 | Architecture variants | Centralized, decentralized, federated, and hybrid variants comparable |
| Oct 26–Nov 6 | Pilot study | End-to-end pilots completed; thresholds and protocol frozen |
| Nov 9–20 | Main experiments | Registered runs complete with quality-control report |
| Nov 23–Dec 4 | Analysis | Clean dataset, principal figures, uncertainty, and threshold estimates complete |
| Dec 7–15 | Final package | Report, repository, data dictionary, reproduction guide, and Step 2 handoff complete |
| Dec 16–31 | Contingency | Reruns, corrections, packaging, and submission buffer |

## Weekly operating rhythm

- Monday: select a small deliverable with a testable exit condition.
- Midweek: integrate and run automated checks.
- Friday: record results, decisions, risks, and next week's target.
- Every two weeks: review scope and remove work that does not advance the December completion gate.

## Immediate work queue

1. Choose the simulation platform using explicit selection criteria.
2. Build the literature and prior-work matrix.
3. Specify the minimum environment topology.
4. Convert hypotheses into a draft experiment matrix.
5. Define the event schema and run-manifest format before writing agent logic.
