# Research Claim Matrix

This matrix separates prior concepts, implementation work, and the proposed contribution.
The recorded results are software-simulation results and must be cited with their
experiment manifest and commit. They are not hardware or real-network measurements.

| Claim | Source/origin | Implemented? | Evidence | Contribution? | Safe wording |
|---|---|---:|---|---:|---|
| D2DAP mutual authentication/key agreement | Reference D2DAP paper | Yes, with documented deviations | `security/d2dap/`, D2DAP tests, authentication results | No | “We implemented and evaluated a software D2DAP implementation.” |
| PUF-based credential binding | D2DAP paper/PUF literature | Software model only | `security/puf.py`, PUF tests | No | “We model PUF behaviour with a seeded XOR-Arbiter software PUF.” |
| ECC/SHA-3/AES cryptography | Standard cryptography and reference protocol | Yes | `security/crypto.py`, `secure_transport.py`, protocol tests | No | “The simulation uses real cryptographic primitives.” |
| Shamir threshold sharing | Shamir literature and D2DAP | Yes | `security/secret_sharing.py`, D2DAP implementation | No | “We use a degree-one, two-share reconstruction in the protocol model.” |
| STRIDE threat categories | Microsoft STRIDE/security literature | Yes as classification | `attacks/base.py`, `stride_eval.py` | No | “Attacks are mapped to STRIDE categories for evaluation.” |
| ML IDS classifiers | Standard ML/IDS literature | Yes | `ids/models.py`, IDS manifests/results | No | “We compare four standard classifiers on D2D-SIM.” |
| Beta reputation basis | Jøsang/Ismail reputation literature | Yes | `trust/engine.py` | No | “Our trust engine uses a decayed Beta-reputation basis.” |
| Deterministic drone-swarm simulator | This project | Yes | `simulation/`, seeded tests and reproducibility report | Partly | “We built a deterministic software simulator for the evaluation.” |
| Packet-level authenticated data plane | This project integration | Yes | `services/secure_transport.py`, data-plane tests | Yes as implementation | “We integrated D2DAP sessions with AES-GCM data traffic.” |
| Ten real-packet attack behaviours | This project | Yes | `attacks/`, STRIDE raw runs | Yes as implementation | “We implemented measurable simulated external and insider attacks.” |
| Leakage-checked simulated IDS dataset | This project methodology | Yes | `ids/validation.py`, `validation_report.json` | Yes as methodology | “We generated D2D-SIM and split by run with leakage checks.” |
| Attribution-aware evidence fusion | This project | Yes | `trust/engine.py:update`, attribution/ablation results | Yes | “Our contribution is attribution-aware trust evidence fusion.” |
| Decayed, history-aware trust | Beta basis plus project design | Yes | `TrustEngine.update`, sensitivity/ablation results | Yes in design | “We add decayed evidence, attribution, anomaly, and repeat-offender handling.” |
| Graded adaptive policy | This project design | Yes | `policy/engine.py`, policy tests/results | Yes | “We propose a graded policy with hysteresis and hard rules.” |
| Forced re-authentication as response | This project integration | Yes | `policy/enforcement.py`, coordinator, showcase | Yes | “Policy can revoke sessions and force fresh MAKA.” |
| Receiver-side enforcement | This project design | Yes | `PolicyEnforcer` network filter | Yes | “Restrictions are enforced at ingress because senders may be malicious.” |
| Framing resistance | Experimental design goal | Partly supported in simulation | `framed_rate`, attribution ablation | Not a universal security proof | “In these simulations, attribution-aware fusion reduced identity framing.” |
| Real-time security | Runtime property of simulation UI | Limited | 1-second windows/polling | Do not overclaim | “The simulator processes one-second windows and exposes live snapshots.” |
| Real drone security | Not established | No | No hardware/RF deployment | No | Do not claim real deployment security. |
| Physical PUF unclonability | Not established | No | Software PUF limitation | No | Do not claim physical unclonability. |
| Energy efficiency | Not established | No | No power measurement | No | Do not claim energy efficiency. |
| Formal D2DAP proof/AVISPA reproduction | Not established | No | No formal tool artifacts | No | Say empirical protocol testing only. |
| Generalisation to real IoD traffic | Not established | No | D2D-SIM; NSL-KDD not run | No | Say real-world generalisation requires external validation. |

## Defensible contribution statement

“The project contribution is a software-evaluated adaptive security layer that fuses
D2DAP authentication outcomes, receiver-observable ML IDS evidence, and attribution
into a decayed trust state, then applies a graded receiver-side policy with hysteresis,
forced re-authentication, and quarantine. The contribution is evaluated in a seeded
drone-swarm simulation; it is not a claim that D2DAP, PUFs, STRIDE, standard ML models,
or Beta reputation were invented here.”

## Provenance warning

The current repository HEAD is `64b9b7f`. Existing manifests identify older generating
commits: IDS/authentication at `1004505e04...`, and STRIDE/baseline/scalability at
`ad3ae5e95b...`. Those results remain useful recorded experiments, but a final thesis
should either pin the cited commit or rerun the suites at the current HEAD.
