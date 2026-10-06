# Research Contribution Statement

This document fixes, *before implementation*, what is existing research, what is our
implementation work, and what is our proposed contribution. It is the reference for the
report and the viva. We never present Category A as original work.

## A. Existing research (NOT our contribution)

| Item | Source |
|---|---|
| D2DAP protocol (Setup, Registration, MAKA, GenSign/VerifySign) | Parai et al., IEEE TVT 2026 |
| PUF-based device authentication concept, CRPs | Herder et al. 2014, cited by D2DAP |
| (t, n) threshold secret sharing / Lagrange reconstruction | Shamir 1979 |
| STRIDE threat modelling, and the D2D STRIDE report (Table II of D2DAP) | Microsoft STRIDE; D2DAP Sec. III-A |
| XOR-Arbiter PUF additive-delay model | Standard PUF literature (as used by `pypuf`, which D2DAP used) |
| ML-based IDS for IoD; taxonomy; datasets; metrics | Ogab et al., IEEE Access 2025 (review) and the studies it cites |
| Logistic Regression, Decision Tree, Random Forest, XGBoost | Standard ML |
| Beta reputation and the expectation of a Beta distribution as trust | Jøsang & Ismail, 2002 (Beta Reputation System) |
| Standard IDS evaluation metrics (P/R/F1/FPR/ROC) | Standard; SLR Eqs. 1–11 |

## B. Our implementation (engineering work, not novelty)

- Discrete-time **drone swarm simulator** (mobility, links, battery model, join/leave).
- **Software PUF** abstraction (XOR-Arbiter model + ideal keyed-hash model) behind an interface that could be swapped for real hardware.
- A **D2DAP implementation** with real ECC, SHA-3 and AES-CTR, instrumented to count operations and bytes.
- **Traffic simulator** (periodic telemetry, bursty video, Poisson commands, auth/RL traffic).
- **Attack simulator** that operates on the real protocol messages (spoofing, replay, tampering, DoS, impersonation and cloning, unauthorized access, elevation of privilege, abnormal traffic, flooding).
- **ML pipeline** with leakage checks; four baseline models; full evaluation.
- **Benchmarking framework** (repeated trials, percentiles, CPU, memory, bytes).
- **Experiment automation**, **dashboard** and **demo**.

## C. Our proposed contribution

**An adaptive, trust-aware security layer that fuses D2DAP authentication outcomes with ML-IDS evidence into a
continuous per-drone trust score, and drives a graded, explainable response policy.**

1. **Continuous trust evaluation.** Trust is re-evaluated every observation window, not only at authentication time.
2. **Evidence fusion (authentication + ML).** Trust combines:
   - D2DAP outcomes (success, and failure with its reason, such as a signature, freshness or secret-reconstruction failure),
   - ML attack probability, used as *soft* evidence,
   - protocol violations (integrity failure, replay indicators, unauthorized privileged commands),
   - statistical abnormal-behaviour evidence,
   - normal behaviour (positive evidence),
   - history, time decay (forgetting) and escalation for repeat offenders.
3. **Transparent trust model.** A decayed Beta-reputation model, `T = α/(α+β)`, with documented, configurable
   evidence weights. Every update records `(previous, new, evidence, reason, timestamp)`.
4. **Adaptive policy engine.** NORMAL → MONITOR → RESTRICT → RE-AUTHENTICATE → QUARANTINE. Thresholds are configurable,
   hysteresis prevents oscillation, and hard rules apply (for example, a failed re-authentication leads to quarantine).
   Every decision includes a human-readable explanation.
5. **Re-authentication as an ambiguity resolver.** When behavioural evidence is suspicious, we force a *fresh D2DAP MAKA*.
   A legitimate drone, for instance one framed by a replayer, passes and recovers trust. A clone without the PUF fails and is quarantined.
   This couples the ML layer back into the authentication layer.
6. **Trust recovery.** Time decay plus probation lets wrongly penalised drones recover. Quarantine exit requires successful re-authentication.
7. **Evaluation of the adaptive layer.** Baseline comparison (Systems A–D), an ablation study, threshold and weight sensitivity,
   and scalability. All are measured in simulation with keyed seeds.

### Claims we will NOT make

- No physical PUF, hardware timing or energy results.
- No new formal security proof. D2DAP's proofs are the authors' proofs. We did not re-run AVISPA.
- No claim that our simulated-traffic IDS accuracy transfers to real drone networks.
- The trust formula is not claimed to be optimal. We report the sensitivity of the thresholds and weights.

### Research questions for our contribution

- **RQ-C1:** Does fusing authentication evidence with ML evidence (System C/D) reduce false positives or response latency
  compared with acting on raw ML alerts (System B)?
- **RQ-C2:** Does graded adaptive policy (System D) increase attack mitigation while limiting collateral damage to benign drones?
- **RQ-C3:** Does forced re-authentication correctly separate framed legitimate drones from clones and impersonators?
- **RQ-C4:** What computational and communication overhead does the adaptive layer add, and how does it scale with swarm size?
