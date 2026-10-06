# Architecture Overview

```
                ┌───────────────────── Control Server (Setup, Registration, RL) ─────────┐
                │                      (not involved in D2D authentication)               │
Drone simulator │  D2DAP agents (software PUF, ECC, Shamir, GenSign/VerifySign)           │
(mobility,      ├─ AuthCoordinator: on-demand packet-level MAKA, re-keying, revocation,   │
 channel,       │  forced re-authentication, AuthEvents                                   │
 traffic)       ├─ SecureTransport: AES-GCM data plane over SK, replay window,            │
   │            │  verify-then-drop inspection                                            │
   ▼            └──────────────────────────────────────────────────────────────────────────┘
DroneNetwork (event queue) ── ingress filters (PolicyEnforcer) ── handlers ── observers
   │                                                                             │
   ▼                                                                             ▼
Attack simulator (10 attacks on real packets)                       TrafficLog (observable + ground truth)
                                                                                 │
SecurityMonitor (leader-hosted, every 1 s window) ◄──────────────────────────────┘
   features → ML IDS → Evidence (+AuthEvents) → TrustEngine → PolicyEngine → PolicyEnforcer
   (TRUST_REPORT packets sealed over D2DAP sessions are sent for overhead accounting)
```

| Layer | Module | Notes |
|---|---|---|
| Simulation | `simulation/` | Deterministic discrete-time engine. Sim time never depends on wall-clock time |
| Authentication | `security/d2dap/` | Faithful MAKA; deviations listed in `d2dap-implementation-mapping.md` |
| Session & data plane | `services/secure_transport.py`, `services/auth_coordinator.py` | Our addition: AES-GCM over SK; receive-side session index |
| Attacks | `attacks/` | Ground-truth labels are used only for evaluation |
| Detection | `ids/` | Window features from observable fields only; 4 models |
| Trust & policy | `trust/`, `policy/` | Our contribution (see `trust-model.md`) |
| Integration | `services/monitor.py`, `services/framework.py` | System variants A–D and ablations |
| Experiments | `experiments/`, `benchmarks/` | `ExperimentRecorder`: manifest + provenance |
| API & dashboard | `api/main.py`, `services/live.py`, `frontend/` | Live state of a real running simulation |

**Trust boundary assumptions.**
- The Control Server and the registration channel are trusted, as in the paper.
- The security monitor runs on the leader and is assumed honest; a compromised leader is out of scope.
- Receivers enforce policy at ingress, since a malicious sender does not cooperate.
- Ground truth (`true_src`, `label`, `attack_id`) never reaches detectors; this is tested.
