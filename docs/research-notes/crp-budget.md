# CRP Budget: an Operational Limit of D2DAP (finding)

**Observation (our simulation).** D2DAP consumes one challenge-response pair (CRP) on *each* side of every MAKA. The pair `(C_ik, b_ik)` is deleted after use, as the paper specifies.
The paper provisions `m` CRPs per drone at registration and says nothing about re-provisioning.

A hub drone (the leader) with `k` session peers that re-keys every `R` seconds therefore consumes about `k / R` CRPs per second, and is exhausted after

```
t_exhaust ≈ m · R / k
```

In the live dashboard with `m = 64`, `k = 9` and `R = 10 s`, the leader ran out after about 90 s. Exhaustion then cascades:
- Every new MAKA with the leader fails with `crp_exhausted` (and timeouts follow).
- Data is held for missing sessions.
- The IDS sees the resulting authentication failures and unauthenticated or no-session verdicts, and fires spurious alerts on honest drones.

In-window replays (observation O1) accelerate the depletion: each accepted replay costs the victim one CRP.

**What we changed (documented, configurable):**

| Setting | Where | Value |
|---|---|---|
| CRPs per drone `m` | `ScenarioConfig.crp_count` | 256 for experiments (covers 60 s runs with 10 s re-keying) |
| CS top-up re-provisioning (models a return-to-base refresh over the secure registration channel) | `AuthCoordinator(reprovision_below=…)` | off in experiments; on (below 8) in the long-running dashboard |

Re-provisioning is a **top-up**: new pairs are appended, so pairs reserved by an in-flight MAKA stay valid. A first implementation that replaced the list broke concurrent sessions; this was caught by `TestCRPBudget`.

**Tests:** `tests/integration/test_secure_traffic.py::TestCRPBudget` covers exhaustion without re-provisioning and its prevention with it.

**Implication for the report.** A deployable D2DAP needs either a large `m` (which increases registration cost and CS storage), periodic secure re-provisioning, or a CRP-free re-keying step for already-authenticated peers. This is a practical gap in the protocol as published.
