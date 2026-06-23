# EDR-Focused Agent-vs-Agent Research Plan

## Core idea

This project studies whether endpoint security systems can detect autonomous AI attacker behavior when the attacker uses legitimate credentials, normal operating-system tools, and authenticated sessions.

The focused research frame is:

> Can an AI-aware EDR defender detect and contain an AI attacker agent using endpoint telemetry alone, especially when the attacker avoids obvious malware-like behavior?

This is narrower and more testable than a broad multi-agent critical-infrastructure architecture study. It still fits the larger theme of adversarial AI dynamics, but the experimental object becomes endpoint telemetry, behavioral detection, and attacker adaptation.

## Why the EDR angle is strong

Traditional EDR detection is built around known malicious indicators, suspicious process behavior, anomalous command usage, privilege escalation, lateral movement, and endpoint telemetry correlations.

AI attacker agents create a different problem:

- They may operate through legitimate accounts.
- They may use standard tools such as shells, scripting interfaces, remote administration utilities, and APIs.
- They may avoid static signatures.
- Their behavior may look operationally valid but mechanically non-human.
- They can adapt timing, command order, and tool choices between rounds.

That creates the central detection gap: the difference between malicious code and malicious agency.

## Research questions

1. Can an AI-aware defender detect an AI attacker using only endpoint-style telemetry?
2. Which behavioral signals distinguish AI-agent activity from normal human administrative activity?
3. How does attacker adaptation reduce detection performance over repeated rounds?
4. Which detection features remain useful when the attacker mimics human timing and tool use?
5. How much improvement does an AI-aware behavioral layer provide over conventional rule-based detection?

## Proposed Python testbed

The first version should be a safe Python simulation, not a live malware lab.

The simulator will model endpoint activity as event streams. Each event represents an observable action that a real EDR might collect:

- process creation
- command-line execution
- parent-child process relationships
- file access
- network connection
- authentication event
- privilege-sensitive action
- lateral movement attempt
- data access or staged exfiltration event
- response action such as alert, containment, quarantine, or recovery

The attacker agent generates sequences of endpoint events that represent a simplified attack chain. The defender agent observes those events and decides whether to alert, escalate, contain, or ignore.

## Red agent

The red agent represents an autonomous attacker.

Initial behaviors:

- reconnaissance
- local discovery
- credential access attempt, modeled safely as an abstract event
- lateral movement attempt, modeled safely as an abstract event
- sensitive-data access
- staged exfiltration attempt, modeled safely as an abstract event

Adaptation knobs:

- slower timing
- more human-like pauses
- randomized command ordering
- reduced burstiness
- use of more common administrative tools
- lower-risk path selection
- avoidance of actions that previously caused alerts

## Blue agent

The blue agent represents an AI-aware EDR layer.

It does not need to replace EDR. It acts as a behavioral detection module that sits on top of endpoint telemetry.

Initial detection logic:

- event burstiness
- unusual command/tool sequencing
- repeated retries without human-like correction
- low typing/noise variation
- high goal-directedness across steps
- suspicious parent-child process chains
- unusual access path to sensitive resources
- suspicious lateral movement sequence
- mismatch between user role and action pattern

Defensive actions:

- ignore
- low-confidence alert
- high-confidence alert
- request more telemetry
- contain endpoint
- block action
- begin recovery

## Human baseline

The project needs a benign comparison group.

Instead of comparing only attacker versus defender, the simulator should generate three traffic classes:

1. normal human/admin activity
2. traditional scripted attacker activity
3. adaptive AI-agent attacker activity

This allows the project to measure whether AI-aware detection catches agentic attackers without simply flagging all automation as malicious.

## Detection feature families

The proposed AI-BIoC taxonomy can be structured around six families:

1. Timing features
   - action spacing
   - burstiness
   - session duration
   - pause distribution

2. Sequence features
   - tool order
   - repeated command patterns
   - recon-to-access-to-movement chains
   - rare transitions between event types

3. Human-noise features
   - corrections
   - abandoned commands
   - backtracking
   - idle gaps
   - exploration before decisive action

4. Goal-directedness features
   - rapid movement toward high-value assets
   - low wasted motion
   - repeated narrowing toward privilege or data access

5. Context features
   - user role mismatch
   - time-of-day mismatch
   - endpoint mismatch
   - unusual target selection

6. Defensive-interaction features
   - adaptation after alert
   - changing tactics after containment
   - probing the detection boundary

## Architecture variants

This EDR version still supports architecture comparisons:

1. Local EDR only
   - Each endpoint detects independently.

2. Centralized EDR
   - All telemetry goes to a central correlation engine.

3. Federated EDR
   - Endpoints keep local models but share summarized behavioral indicators.

4. Hybrid EDR
   - Local fast containment plus central strategic correlation.

The first build should compare local EDR versus centralized EDR versus federated EDR.

## Main metrics

Detection metrics:

- true positive rate
- false positive rate
- precision
- recall
- F1 score
- time to detection
- time to containment

Attacker metrics:

- attack success rate
- time to objective
- number of steps before alert
- number of adaptations required
- evasion rate

Defender workload metrics:

- alert volume
- analyst-equivalent workload
- containment count
- false containment count
- telemetry processing backlog

Resilience metrics:

- compromised endpoints
- critical asset access
- recovery time
- degradation threshold
- collapse threshold

## Minimal December 2026 deliverables

By December 2026, Step 1 should produce:

1. A reproducible Python EDR simulation testbed.
2. A red-agent event generator with adaptive attacker profiles.
3. A blue-agent detection layer with AI-aware behavioral features.
4. A benign human/admin baseline generator.
5. At least three defensive architecture variants.
6. A documented AI-BIoC taxonomy.
7. Experiment scripts and generated datasets.
8. Detection and resilience analysis.
9. A written report explaining the EDR detection gap and experimental results.

## First implementation target

Build a minimal simulator that answers:

> Can behavioral features distinguish benign admin activity, scripted attacker activity, and adaptive AI-agent attacker activity?

The first prototype only needs:

- 5 endpoints
- 3 user roles
- 3 traffic classes
- 8-12 event types
- local and centralized defender modes
- basic metrics for detection rate, false positives, time to detection, and attacker success

Once this works, add federated EDR and adaptive red-agent learning.

