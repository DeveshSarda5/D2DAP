# Final Project Audit

**Project:** Adaptive Trust-Aware Drone Security Framework Using D2DAP Authentication and ML-Based Intrusion Detection. Team: Kapil and Devesh.
**Final experiment run:** `python scripts/run_experiments.py` at seed 42, recorded in `results/reports/run_experiments.log.jsonl` with one manifest per experiment in `results/raw/*/manifest.json`.
**Compiled tables:** [`results/reports/final_tables.md`](../results/reports/final_tables.md). **Figures:** [`results/reports/figures_index.md`](../results/reports/figures_index.md).

> **Result types.** Unless marked *Literature* (copied from the D2DAP paper) or *ESTIMATED*, every number below is **Our Experimental Result** from a software simulation on one Windows laptop (Python 3.10).
> No physical drones, PUF hardware or energy measurements are involved. ML results are on simulated data (D2D-SIM).

---

## 1. What was implemented

| Phase | Deliverable | Location |
|---|---|---|
| 0 | Research understanding, contribution statement, D2DAP→implementation mapping (32 items) | `docs/` |
| 1 | Project foundation: venv, pyproject, ruff (incl. security rules), `mypy --strict`, pytest, YAML/Pydantic config, JSON logging, named RNG streams | repo root, `backend/app/core` |
| 2 | Deterministic drone-swarm simulator (mobility, channel, network, traffic sources, join/leave, battery model) | `backend/app/simulation` |
| 3 | Software PUF (XOR-Arbiter model, ideal PUF, device binding) and quality metrics | `backend/app/security/puf.py` |
| 4 | D2DAP: Setup, Registration, MAKA with real ECC/SHA-3/AES-CTR, Shamir, GenSign/VerifySign, service API | `backend/app/security/` |
| 5 | Authentication benchmarking (micro-ops, 200-trial MAKA, CPU, memory, bytes, PUF-noise study) | `backend/app/benchmarks` |
| 6 | Packet-level D2DAP, AES-GCM data plane, traffic log and profile | `backend/app/services`, `simulation/traffic_log.py` |
| 7 | 10 attacks on real packets (7 external, 3 insider), STRIDE-mapped, measurable evidence | `backend/app/attacks` |
| 8 | STRIDE evaluation from simulated attacks (4 systems × 12 scenarios × 3 seeds) and repudiation analysis | `experiments/stride_eval.py` |
| 9–11 | ML IDS: window features, D2D-SIM dataset (124 runs), leakage checks, LR/DT/RF/XGBoost, full evaluation, NSL-KDD loader | `backend/app/ids`, `experiments/ids_eval.py` |
| 12 | **TrustEngine** (attribution-aware decayed Beta) | `backend/app/trust` |
| 13 | **Adaptive PolicyEngine** + enforcement (verify-then-drop) | `backend/app/policy` |
| 14 | Integrated SecurityMonitor, framework variants, end-to-end showcase | `services/monitor.py`, `services/framework.py` |
| 15–17 | Baseline comparison A–D, ablation, sensitivity, detector-noise stress test, scalability 5–100 drones | `experiments/` |
| 18 | `scripts/run_experiments.py` (12 suites, provenance sidecars) | `scripts/` |
| 19 | Live dashboard (FastAPI + SVG frontend, state of a real running simulation) | `backend/app/api`, `frontend/` |
| 20 | Narrated professor demo | `scripts/run_demo.py` |
| 21–22 | 7 main tables, 13 supplementary tables, 30+ figures with source sidecars | `results/` |
| 23 | Final tests, static checks, reproducibility verification | `scripts/check_all.py`, `scripts/verify_reproducibility.py` |

## 2. What was reproduced from the literature (not our contribution)

- **D2DAP protocol** (Parai et al., IEEE TVT 2026): every Fig. 3 step and abort check is implemented; deviations are listed in `docs/d2dap-implementation-mapping.md`.
  We **reproduced**:
  - Mutual authentication with a common session key at 128/192/256-bit security.
  - Resistance to clones holding extracted credentials (`secret_mismatch`, the paper's GM4).
  - Rejection of forged, tampered and stale messages.
- We **did not reproduce** the RoR proof, the AVISPA runs or the Raspberry Pi cycle and energy measurements.
- **ML-IDS methodology** from the review by Ogab et al. (metrics in Eqs. 1–11; common models; dataset criticisms).
- **Standard components:** Shamir secret sharing, STRIDE, the Beta reputation basis, LR/DT/RF/XGBoost.

## 3. Our contribution

A continuous, **attribution-aware trust** layer fusing D2DAP outcomes with ML-IDS evidence, plus a **graded adaptive policy**:
- states NORMAL → MONITOR → RESTRICT → RE-AUTHENTICATE → QUARANTINE;
- hysteresis, hard rules, recovery and plain-language explanations;
- **forced re-authentication** to separate framed honest drones from impostors.

The key design idea is that evidence counts against an identity only in proportion to how much of that drone's traffic is cryptographically bound to it. Behaviour classes (insider vs. external) are taken from the multiclass IDS.
Requirements R1–R6 are executable tests. See `docs/architecture/trust-model.md`.

## 4. Test results

- **Final test pass (Phase 23): 234 passed, 0 failed** (`python scripts/check_all.py`, including slow end-to-end tests, about 2.8 min).
- Coverage spans unit tests (core, simulator, PUF, crypto, D2DAP, IDS, trust, policy), integration tests (data plane, attacks, STRIDE, comparison, dataset, API) and end-to-end tests (framework variants, reproducibility).
- Static checks: ruff format, ruff lint (pycodestyle, pyflakes, bugbear, bandit `S`, pylint subset, …) and `mypy --strict`. All pass; no rule was disabled to hide a problem.
  Documented exceptions: N802/N803/N806 for paper notation such as `H`, `A`, `Y_i`, and three justified inline `noqa`s.

## 5. ML results (Tables 4–5; D2D-SIM, held-out runs, split by run)

Dataset: 56,694 window samples from 124 simulated runs (9 attacks × 3 intensities × 4 seeds, plus 16 benign runs). The imbalance between benign and the smallest attack class is about 249:1.
**Leakage checks:**
- 0 runs shared between train and test.
- 98 exact cross-split duplicate windows (0.52 % of the test set, 1 label conflict).
- No single feature separates the classes on its own (AUC ≥ 0.99 scan was empty).
- Scaling is fitted on the training split only (asserted by a test).

| Model | Accuracy | Macro-F1 | Weighted-F1 | Binary F1 | FPR | FNR | ROC-AUC | Single-row inference |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.968 | 0.839 | 0.977 | 0.819 | 3.29 % | 0.53 % | 0.9986 | 6.1 ms |
| Decision Tree | 0.992 | 0.896 | 0.992 | 0.959 | 0.18 % | 5.66 % | 0.9708 | 5.9 ms |
| Random Forest | 0.996 | 0.936 | 0.995 | 0.983 | 0.03 % | 2.95 % | 0.9994 | 24.9 ms |
| **XGBoost** (operational; selected by CV macro-F1 0.9535, not by test score) | 0.996 | **0.944** | 0.996 | 0.986 | 0.08 % | 1.81 % | 0.9998 | 7.9 ms |

- **Per class (XGBoost):** F1 is ≥ 0.98 for privilege escalation, tampering, impersonation, unauthorized access and DoS. It is **0.80 for `abnormal`** (recall 0.68, confused with benign) and 0.90 for replay and flooding.
- **Robustness:**
  - Removing train-duplicated test windows changes macro-F1 by less than 0.002, so the results are not inflated by duplicates.
  - **At an unseen low attack intensity (3 pkt/s), macro-F1 drops to 0.77–0.83.** This is a generalisation gap.
- **Detection latency** (attack start to end of first detected window): median 0.83 s for XGBoost; every attack run was detected.
- **Public benchmark (NSL-KDD): not run.** The files require registration and were not provided. No numbers are claimed.

## 6. STRIDE results (Table 3; attack success = accepted / attempted packets, mean of 3 seeds)

| Threat | Scenario | No auth | D2DAP | D2DAP+IDS (B) | Adaptive (D) | Adaptive response |
|---|---|---|---|---|---|---|
| S | Spoofing | 100 % | **0 %** | 0 % | 0 % | victim MONITOR only |
| S | In-window M1 replay (O1) | 100 % | **7.9 %** | 1.9 % | 8.7 % | MONITOR |
| S | Stale replay | 100 % | 0 % | 0 % | 0 % | MONITOR |
| S/E | Node capture + clone | 100 % | 0 % | 0 % | 0 % | MONITOR |
| T | On-path tampering | 100 % | 0 % | 0 % | 0 % | MONITOR |
| R | Repudiation | repudiable | M1/M2 judge-verifiable; receiver cannot forge M1; **data plane repudiable** | n/a | audit log only | n/a |
| I | Eavesdropping (plaintext share) | 100 % | 0 % | 0 % | 0 % | n/a (passive, undetectable) |
| I | Insider scan/exfiltration | 100 % | **92.7 %** | 9.8 % | 10.5 % | QUARANTINE |
| D | Auth-request flood (DoS) | 100 % | 0 % (but **923 ms/s of victim CPU**) | 0 % | 0 % | MONITOR |
| D | Insider flooding | 100 % | **87.3 %** | 17.6 % | 14.2 % | QUARANTINE |
| E | Unregistered drone | 100 % | 0 % | 0 % | 0 % | QUARANTINE (rogue address) |
| E | Privilege escalation | 100 % | **98.6 %** | 10.3 % | 7.2 % | QUARANTINE |

D2DAP stops all external S/T/I/E attacks. Authentication alone cannot touch insider behaviour (87–99 % success), and the detection-plus-response layers cut it to 7–18 %.
**The computational DoS is not mitigated by any layer.** Requests are rejected, but verification costs about 92 % of a CPU core on the victim.

## 7. Computational results (Table 1; 200 MAKA trials per configuration, compute only)

| Config | Mean | Median | P95 | P99 | CPU/auth | Ops/auth | Throughput |
|---|---|---|---|---|---|---|---|
| P-256, hint | 32.1 ms | 31.5 ms | 37.8 ms | 45.5 ms | 30.6 ms | 44 | 31.1 auth/s |
| P-384, hint | 68.2 ms | 65.8 ms | 82.4 ms | 85.7 ms | 66.9 ms | 44 | 14.6 auth/s |
| P-521, hint | 130.8 ms | 131.3 ms | 138.6 ms | 146.9 ms | 126.2 ms | 44 | 7.6 auth/s |
| P-256, trial decryption | 49.6 ms | 49.6 ms | 66.8 ms | 78.1 ms | 48.3 ms | 56.3 | 20.1 auth/s |

- Point multiplication takes about 95 % of compute time.
- Instrumented counts show 5 point multiplications per drone. The paper's own Table IX/VIII implies about 4.6.
  Our counts multiplied by the paper's per-op cycles is an *ESTIMATE* about 22 % above the paper's Table IX. We do not claim Raspberry Pi cycles.

## 8. Communication results (Table 2)

| Level | Measured on the wire | Literature (paper Table VII) |
|---|---|---|
| 128-bit | 304 B = **2432 bits** + 256-bit RL broadcast | 1024 bits |
| 192-bit | 3456 bits | 1536 bits |
| 256-bit | 4576 bits | 2008 bits (not consistent with the paper's own progression) |

Framework overhead (Table 6) is about 1.8 kB/s for 10 drones, covering authentication, RL broadcasts, sealed trust reports and notices. D2DAP alone is about 0.63 kB/s.

## 9. Scalability results (Table 7; sequential; area scaled to keep density constant)

| Drones | D2DAP hint | D2DAP trial | Point mults (trial, responder) | Monitor per window | Trust update | Security B/s per drone | Detection |
|---|---|---|---|---|---|---|---|
| 5 | 31.9 ms | 37.5 ms | 6.6 | 76 ms | 216 µs | 88 | 1.0 s |
| 10 | 29.9 ms | 47.6 ms | 9.0 | 82 ms | 128 µs | 151 | 1.0 s |
| 25 | 31.1 ms | 84.0 ms | 18.1 | 90 ms | 90 µs | 211 | 1.0 s |
| 50 | 29.3 ms | 144.7 ms | 31.6 | 105 ms | 74 µs | 238 | 1.0 s |
| 100 | 35.3 ms | **293.5 ms** | 58.3 | 134 ms | 67 µs | 279 | 1.0 s |

- Trial-decryption peer resolution, which preserves D2DAP's anonymity claim, grows **linearly** with swarm size (O4).
- Most monitor time is feature extraction. IDS inference is 21–31 ms per window and trust plus policy 1–7 ms.

## 10. Comparison, ablation, sensitivity and stress results (our contribution)

**Table 6 (3 seeds × 9 attacks + benign):**

| System | Detection | Mitigation | Response (median) | Honest-drone disruption | **Forged identity framed** |
|---|---|---|---|---|---|
| A: D2DAP only | 0.67 (misses all insiders) | 0.68 | n/a | 0 | 0 |
| B: D2DAP + IDS (alert → block) | 1.00 | 0.956 | **1.1 s** | 0.07 % | **100 %** |
| C: + trust, binary block | 1.00 | 0.778 | 2.6 s | 0 | 0 |
| **D: full adaptive** | 1.00 | **0.955** | 2.2 s | **0** | **0 %** |

**Ablation:**

| Variant | Mitigation | Disruption | Framed | Note |
|---|---|---|---|---|
| Full | 0.955 | 0 | 0 % | |
| − Trust engine | 0.986 | 0.11 % | **100 %** | faster, but frames innocent identities |
| − ML IDS | 0.909 | **8.6 %** | 25 % | heuristic only, with false positives |
| − Policy engine | 0.681 | 0 | 0 % | detection without response equals auth only |
| − Attribution-aware fusion | 0.963 | 0 | **100 %** | |

**Detector-noise stress test (SYNTHETIC false alarms injected into the IDS):**
- At 0 / 1 / 5 % false alarms, B's honest-drone disruption grows **0.09 % → 1.1 % → 4.0 %**, with 3.2 % of benign packets lost.
- D stays at **0 % disruption at every level**, with 93–94 % mitigation.
- C stays at 0 % but mitigates only about 62–65 %.

**Sensitivity (one at a time):**
- The default bands and weights are not optimal: `w_ml_attack = 4.5` gives better mitigation (0.941 vs 0.919) with no disruption.
- Shifting the bands up (+0.1) raises mitigation but introduces disruption (0.18 %).
- We report this and **did not re-tune** on the evaluation scenarios.

**Answers to our research questions:**
- **RQ-C1** (does fusion reduce false positives under an imperfect detector?): yes in this simulation, per the stress test and the −ML ablation.
- **RQ-C2** (more mitigation with limited collateral?): D matches B's mitigation with no disruption and no framing. It responds about 1 s slower.
- **RQ-C3** (does re-authentication separate framed from compromised drones?):
  - Framed identities stay below RESTRICT, so re-authentication is not needed for them.
  - Compromised insiders pass re-authentication, because they hold genuine credentials, and are then quarantined by the repeat-offender rule (showcase and demo).
  - Clones fail at D2DAP itself.
- **RQ-C4** (overhead and scaling): about 1.2 kB/s of extra traffic for 10 drones; trust updates under 0.25 ms; monitor 76–134 ms per 1 s window up to 100 drones.

## 11. Limitations

1. **Simulation only.** Drones, mobility, the radio channel (range, latency, loss) and traffic are software models. There is no multi-hop routing, no interference model and no RF-level attacks (jamming, GPS spoofing).
2. **Software PUF.** The PUF is a numerical model (XOR-Arbiter additive delay model or HMAC). Its "unclonability" is enforced by the simulation's model boundary, not by physics. ML modelling attacks on arbiter PUFs are not evaluated.
3. **IDS trained and tested on simulated traffic.** High scores on D2D-SIM say nothing about real IoD traffic. The unseen-intensity split already shows a generalisation drop.
4. **Trust and policy parameters are design choices.** They are derived from requirements R1–R6 and studied for sensitivity, but not optimised and not validated on real deployments.
5. **The monitor is centralised on the leader and assumed honest.** A compromised leader, report suppression and collusion are out of scope. Cooperative monitoring is abstracted: the monitor reads the reception log directly, and the TRUST_REPORT packets account only for the communication overhead.
6. **Attribution relies on claimed link addresses.** On-path tampering and replay cannot be attributed to the real attacker (only rejected).
7. **Repudiation.** The AEAD data plane is repudiable. The trust audit log is not cryptographic non-repudiation.
8. **Computational DoS is not prevented.** Bogus AUTH_REQUESTs with spoofed sources still cost the victim verification work. The adaptive layer cannot block per-source when sources are forged.
9. **Wall-clock measurements** (latency, CPU, memory, inference time) come from one Windows laptop running Python with pure-Python ECC. Absolute values are not representative of embedded drones.

## 12. Hardware limitations

- No physical drones, PUF, embedded board or radio were used.
- **Not measured and not claimed:** energy consumption, Raspberry Pi CPU cycles, hardware PUF latency or reliability, real RF behaviour.
- The paper's Table VIII–X values appear only as clearly labelled *Literature* or *ESTIMATED* columns. They are never presented as our measurements.

## 13. Dataset limitations

- D2D-SIM is generated by our own simulator, so its realism is bounded by the traffic and attack models.
- Class imbalance is about 249:1 (benign : smallest attack class). It is handled with balanced weights and reported per class.
- Labels are window-level and attributed to the claimed source. Windows mixing a victim's benign traffic with spoofed packets carry the attack label.
- The public NSL-KDD benchmark was **not run**: the official download requires registration and the files were not provided. The loader and pipeline are implemented and tested on a format fixture only.

## 14. Reproducibility status

**PASSED.** `python scripts/verify_reproducibility.py` (output in `results/reports/reproducibility_check.txt`): two runs with the same seed produce byte-identical packets, trust updates, policy decisions and IDS alerts, and parallel dataset generation equals sequential generation.

- Simulated time never depends on wall-clock time. A bug where measured D2DAP compute time advanced the simulation clock was found and fixed; `test_full_pipeline_is_reproducible` now asserts this.
- Every experiment saves its seed, full configuration, environment (package versions, platform), git commit, raw data, processed data, metrics and a structured log.
- Every table and figure has a provenance sidecar (`*.source.json`).
- Wall-clock measurements (latency, CPU, inference time) vary between runs and machines by nature. They are reported with distributions (mean/median/P95/P99) and are never fed back into the simulation.
- **Demo:** `python scripts/run_demo.py` runs end to end (transcript in `results/reports/demo_transcript.txt`): the insider is detected after 1.0 s and escalated through the policy states, honest drones stay NORMAL, and the insider recovers after the attack ends.

## 15. Known weaknesses (found and documented, not hidden)

- **O1 – in-window replay** is accepted by the D2DAP responder (no replay cache) and consumes a CRP. Measured in STRIDE (Table 3).
- **O2 – CRP exhaustion** through replays and through routine re-keying (CRP-budget note).
- **O3 – insider recovery of master secret `A`** from two own shares (tested).
- **O4 – peer resolution** by trial decryption costs O(n) point multiplications (Table 7).
- **Noisy PUFs break D2DAP** because it has no fuzzy extractor (PUF-noise table).
- The communication-cost figures in the paper (1024 bits at 128-bit security) could not be reproduced from the message contents; we measure 2432 bits.
- Weak IDS classes (`abnormal` and `replay` recall) and the generalisation drop at unseen attack intensity.
- The naive IDS-block baseline (System B) responds faster than the adaptive framework. The trust layer trades response latency for stability (Table 6).
- Detection latency of the trust layer is bounded below by the 1 s window and by evidence accumulation.
- While a drone is quarantined its traffic is blocked, so evidence fades and trust decays back toward the prior *during* quarantine (showcase figure).
  Release is still gated by the policy (minimum duration plus successful re-authentication), but trust alone is not a "still guilty" signal.
- Framing through identity abuse is prevented by design here (0 %). However, spoofed DoS requests still cost the victim CPU, and System B's 100 % framing shows how easily naive IPS designs fail.

## 16. Future work

1. Hardware validation: a real PUF (e.g. SRAM or arbiter on FPGA) with a fuzzy extractor added to D2DAP, and Raspberry Pi or companion-computer timing and energy measurements.
2. Protocol hardening: a responder replay cache, CRP-free re-keying for already-authenticated peers, and a signed revocation list.
3. Real or emulated IoD traffic (PX4/Gazebo plus network emulation) and public IoD datasets for the IDS. Run NSL-KDD and UNSW-NB15 as external validity checks.
4. Distributed and collaborative monitoring with Byzantine-robust aggregation of trust reports (no single trusted leader).
5. Learned or optimised trust weights with robustness guarantees against adversarial evidence (e.g. adversarial-ML evasion of the IDS).
6. Formal verification of the adaptive policy (e.g. model checking of the state machine) and of protocol extensions (Tamarin/ProVerif).
