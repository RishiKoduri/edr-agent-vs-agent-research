# Step 1 Research Charter

**Project deadline:** December 2026  
**Working completion target:** December 15, 2026  
**Status:** Initial working charter; decisions marked TBD must be frozen before implementation.

## Research claim

Coordinated autonomous attackers can create nonlinear defensive overload by concentrating activity against limited defensive resources. Defensive coordination architecture changes the location and severity of the resulting degradation and collapse thresholds.

## Primary research question

How do attacker concentration, defender coordination architecture, and adaptation latency interact to produce defensive resilience, degradation, collapse, and recovery?

## Initial hypotheses

### H1 — Concentration effect

At a fixed total attack volume, coordinated concentration against a small number of targets produces lower time-to-compromise and earlier defensive collapse than distributed pressure.

### H2 — Centralization bottleneck

Centralized defense performs efficiently at low pressure but exhibits a sharper collapse threshold as coordination demand approaches the orchestrator's processing or communication capacity.

### H3 — Federation resilience

Federated defense tolerates higher concentrated pressure than centralized defense when local agents can share capabilities and act without waiting for global authorization.

### H4 — Coordination cost

Federated and decentralized defense incur higher communication or duplicated-work costs at low pressure, creating conditions under which centralization remains preferable.

### H5 — Adaptation latency

Defensive outcome is driven more strongly by relative adaptation latency than by raw agent count once both populations exceed the environment's basic workload capacity.

### H6 — Recovery hysteresis

After overload, reducing attack pressure to its pre-collapse level is not sufficient for immediate recovery because incident backlog and impaired defensive capacity persist.

## Operational definitions

- **Agent:** A bounded software decision process with an assigned role, observable state, action set, and communication policy. Parallel tasks alone do not count as separate agents.
- **Attacker swarm:** Multiple attacker agents coordinating target selection, timing, or tactic allocation toward a shared objective.
- **Federated defense:** Local defensive units retain decision authority while exchanging selected observations, models, alerts, or response capacity through a defined federation protocol.
- **Concentrated pressure:** A high proportion of attacker actions directed at a small subset of targets or defensive decision points during a defined interval.
- **Resilience:** The ability to maintain required defensive service levels and restore affected services within specified bounds.
- **Degradation:** Sustained failure of one or more service-level metrics without meeting the collapse criterion.
- **Collapse:** A preregistered combination of compromise rate, unresolved backlog, and response latency exceeding acceptable bounds for a sustained interval.
- **Recovery:** Return of all required service-level metrics below their recovery thresholds for a sustained interval.

Exact numeric thresholds remain TBD and must be set from baseline and pilot results before the main experiments.

## Step 1 scope

### Included

- One abstract enterprise or cyber-range-style environment
- Safe simulation of reconnaissance, access attempts, lateral movement, detection, response, and recovery
- Centralized, decentralized, federated, and hybrid defensive coordination
- Independent and coordinated attacker configurations
- Static and adaptive policy variants where feasible
- Repeated controlled experiments with deterministic seed management
- Measurement of technical behavior needed for Step 2 system-dynamics modeling

### Excluded from the minimum viable study

- Deployment against live external systems
- Development of operational malware, persistence, evasion, or destructive payloads
- Simultaneous modeling of water, energy, and healthcare domains
- Human-subject studies
- Production autonomous response
- Unbounded online learning during main experiments

Domain-specific cyber-physical validation and sophisticated coevolution are stretch work or Step 3 work.

## Independent variables

- Defender architecture
- Attacker population size
- Defender population or resource capacity
- Attacker coordination policy
- Pressure concentration level
- Attacker and defender adaptation latency
- Communication latency, bandwidth, and failure rate
- Environment topology and target criticality

## Primary dependent variables

- Successful compromise rate
- Time to first compromise
- Attack propagation rate
- Detection latency
- Response latency
- Recovery time
- Unresolved incident backlog
- Defender utilization and coordination overhead
- Defensive service-level attainment
- Probability and time of degradation or collapse
- Time and trajectory of recovery

## Experimental principles

- Compare architectures under identical workloads and random seeds.
- Separate agent-count effects from total action-rate effects.
- Include simple non-agent baselines.
- Record configuration, code revision, seed, event trace, and summary metrics for every run.
- Calibrate thresholds during pilots and freeze them before main data collection.
- Preserve failed runs and document exclusion rules.
- Use enough replications to report uncertainty, not only mean outcomes.

## Completion gate

Step 1 is complete only when another researcher can reproduce the environment, execute the registered experiment matrix, regenerate the principal figures, and map the measured parameters into the Step 2 strategic model.

## Decisions to freeze

1. Primary simulation platform and programming language
2. Primary environment and topology
3. Exact agent action and observation spaces
4. Federation protocol and shared information/capabilities
5. Baseline policies
6. Numeric degradation, collapse, and recovery thresholds
7. Main experiment matrix and replication count
8. Statistical analysis method
