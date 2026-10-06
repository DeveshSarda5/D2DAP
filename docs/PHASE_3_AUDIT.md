# Phase 3 Audit

## A. Already experimentally valid

- ExperimentRecorder writes seed, configuration, package environment, platform, commit,
  raw/processed files, and provenance sidecars.
- IDS training uses run-level grouped split and grouped CV; leakage checks are executable.
- IDS reports per-class metrics, confusion matrices, binary FPR/FNR, timing, dedup
  robustness, and unseen-rate robustness.
- Authentication reports distributions, P95/P99, bytes, messages, operation counts,
  CRP/Puf studies, and separates compute measurements from simulation time.
- A-D baseline and ablation runners exist with fixed scenario seeds and common metrics.
- STRIDE scenarios, attack evidence, repudiation analysis, and scalability studies are
  recorded.
- `verify_reproducibility.py` and the recorded `reproducibility_check.txt` report seeded
  simulation and sequential/parallel dataset equivalence.

## B. Missing or not rerun on this laptop

- Fresh full validation at current HEAD `64b9b7f`.
- Three repeated current-HEAD runs for a stronger reproducibility record.
- Fresh independent trust validation CSV produced by executable tests.
- Fresh current-HEAD ML metrics/confusion exports.
- Fresh attack-detection, attribution, and quarantine runs at current HEAD.
- Public NSL-KDD evaluation; the required files are absent.
- External IoD traffic validation.

Reruns are currently blocked by the copied virtual environment pointing to the previous
owner's Python path. The system Python also fails to import pandas because an Application
Control policy blocks a native DLL. Recreate `.venv` and install dependencies before
running suites.

## C. Weak points and research risks

1. Existing artefacts span multiple commits; mixing them without commit labels risks
   claiming current-code validity.
2. The dataset is synthetic and highly imbalanced; overall accuracy is not sufficient.
3. There are 98 exact train/test feature duplicates and one label conflict; the project
   reports deduplicated robustness, but this must be discussed.
4. Unseen low-rate performance drops substantially.
5. The monitor is leader-hosted and assumed honest.
6. Software PUF results cannot establish physical unclonability.
7. Communication cost is serialized simulator/message cost, not a socket capture.
8. Wall-clock timing is host-dependent.
9. Mitigation is an experimental metric based on accepted/attempted simulated packets,
   not a production incident metric.
10. Passive eavesdropping is not detectable through current traffic evidence.

## D. What should be fixed later

Before final thesis submission, pin or rerun all results at one commit; preserve a fresh
environment lock; add executable independent trust validation; add a dedicated
attribution experiment table; and make the report automatically print manifest commit
and metric definitions beside every table. These are validation/documentation changes,
not permission to silently change formulas or architecture.

## E. Recommended experiments

1. Rerun all suites at current HEAD after environment repair.
2. Repeat the key IDS, baseline, ablation, and attribution suites three times; compare
   deterministic artefacts and separately report timing variance.
3. Run an explicit external-spoofing versus verified-insider matched scenario with the
   same seed/configuration and report attribution, trust penalty, and state transition.
4. Run controlled policy-threshold/hysteresis traces around 0.20/0.40/0.60/0.80.
5. Run controlled quarantine/re-authentication recovery and record every transition.
6. If permitted, add NSL-KDD only as an external validity experiment, with a clear
   feature-mapping caveat.

## F. Available metrics

IDS: accuracy, macro/weighted precision/recall/F1, per-class metrics, confusion,
binary FPR/FNR, ROC/PR AUC, inference timing, detection latency, CV score, duplicates,
group overlap. Authentication: success, latency distributions, messages, bytes,
operations, CRP consumption, memory/timing. Framework: detection, mitigation, response,
false flags, disruption, collateral, framing, monitor cost, security bytes, policy
states. Network: sent/delivered/dropped/bytes, topology and channel outcomes.

## G. Metrics impossible or unsafe to claim currently

Physical PUF unclonability/reliability, real RF packet loss, energy efficiency, real
hardware cycles, real drone throughput, real-world IDS generalization, formal protocol
proof, and distributed-monitor resilience are not established by this simulator.

## H. Phase 4 recommendations

Only after review: repair/recreate the environment, rerun at a pinned commit, add the
independent validation harness and explicit experiment reports, then decide whether any
implementation correction is justified. Do not change trust formulas, ML labels, or
results merely to improve scores.
