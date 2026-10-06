# Trust Engine and Adaptive Policy (Phases 12–14): Our Proposed Contribution

Code: `backend/app/trust/`, `backend/app/policy/`, `backend/app/services/monitor.py`, `backend/app/services/framework.py`.
Tests: `tests/unit/test_trust.py` (requirements R1–R5), `tests/unit/test_policy.py`, `tests/e2e/test_framework.py`.

## 1. Pipeline (runs every 1 s window on the leader)

```
traffic log -> window features (observable only) -> ML IDS: P(attack), class probabilities
            + D2DAP AuthEvents (MAKA successes / failures / forced re-authentications)
  -> attribution-aware Evidence -> TrustEngine (decayed Beta) -> PolicyEngine (graded, hysteresis,
     hard rules) -> PolicyEnforcer (receiver-side: rate limit, command block, session revocation,
     forced MAKA, quarantine, notice broadcast)
```

## 2. Trust model

Decayed Beta reputation. The Beta-distribution basis is from Jøsang & Ismail (2002) and is *not* our contribution:

```
alpha_k = λ·alpha_{k−1} + positive_k        beta_k = λ·beta_{k−1} + negative_k
T_k     = (alpha_k + a0) / (alpha_k + beta_k + a0 + b0)
```

| Evidence (per drone, per window) | Contribution | Reasoning for the weight |
|---|---|---|
| IDS benign mass `1−p` | `+w_normal·(1−p)`, with `w_normal = 1` | Unit of evidence = one window |
| IDS **insider-class** mass `p_ins` | `−w_ml·p_ins·(c·m + (1−c)·u)`, with `w_ml = 3` | "Easy to lose, hard to gain". 3 is the smallest integer meeting R2 while keeping R1 |
| IDS **external-class** mass `p_ext` | `−w_ml·p_ext·u` | The identity is being *used*, and D2DAP already drops those packets |
| D2DAP MAKA success | `+0.5` each (max 3) | Weak: proves credential possession, not behaviour |
| D2DAP failures (claimed initiator) | `−2·sat(n)·u` | Anyone can claim the identity, so it is unattributed |
| Receiver verdicts (integrity / replay / unauthenticated / no-session) | `−2·sat(n)·u` | Unverified packets cannot be bound to the identity |
| **Verified** privileged command from a non-leader | `−2·sat(n)·m` | Role violation, cryptographically bound to the identity |
| Rate anomaly of **verified** packets (EWMA z) | `−1·clip((z−3)/3)·c·max(p, 0.2)` with ML (no escalation); `·m·c` without ML | Heuristic: corroborates the IDS, primary only when there is no ML |
| Passed a policy-forced re-authentication | `+4` (once per forced re-auth) | Proves genuine PUF and credentials (separates framed drones from clones) |

Parameters: `λ = 0.85` (half-life ≈ 4.3 windows); prior `a0 = 4, b0 = 0.5` (mean 0.89) for registered drones, and `1, 1` for unknown addresses.
Count evidence uses `sat(n) = 1 − e^{−n/3}`. The repeat-offender multiplier is `m = min(3, 1 + 0.15·bad_windows_in_last_30)`.

**Attribution-aware fusion** is the key design idea. `c` is the fraction of the window's receptions that were cryptographically verified (AEAD under a D2DAP session, or an accepted M1/M2). `u = 0.05` is the weight of unattributable evidence.
A spoofer can therefore not frame an honest drone. Unregistered addresses have no honest owner, so `c = 1, u = 1` for them.

### Design requirements (verified by tests with the default bands)

| | Requirement | Test |
|---|---|---|
| R1 | One confident false-positive window never RESTRICTs a benign drone; NORMAL again within 10 windows | `test_r1_…` |
| R2 | A sustained insider attack reaches RESTRICT in ≤ 3 windows, RE-AUTH in ≤ 6, QUARANTINE in ≤ 15 | `test_r2_…` |
| R3 | After a short attack burst, trust returns to NORMAL in < 25 windows | `test_r3_…` |
| R4 | Sustained spoofing of an honest drone leaves it in MONITOR at worst. **Without attribution it is quarantined** (ablation test) | `test_r4_…` |
| R5 | An unregistered rogue address is quarantined within 10 windows | `test_r5_…` |
| R6 | A legitimate burst that the IDS rates benign never RESTRICTs a drone. Without ML the heuristic can (documented limitation) | `test_r6_…` |

The weights are **not claimed optimal**. Phase 16 reports threshold and weight sensitivity.

## 3. Policy

| Trust | State | Entry actions |
|---|---|---|
| ≥ 0.80 | NORMAL | lift restrictions |
| ≥ 0.60 | MONITOR | increased monitoring (no service impact) |
| ≥ 0.40 | RESTRICT | rate limit (5 pkt/s, burst 10), block privileged commands |
| ≥ 0.20 | RE-AUTHENTICATE | as RESTRICT, plus revoke all sessions and force fresh D2DAP MAKA |
| < 0.20 | QUARANTINE | revoke sessions, drop all traffic, block new sessions, broadcast notice |

- **Hysteresis of 0.05** applies to relaxation only; escalation is immediate.
- **Hard rules:**
  - The drone's own forced re-authentication fails, so it goes to QUARANTINE.
  - Three RE-AUTH entries within 60 s means a repeat offender, so it goes to QUARANTINE.
  - Quarantine exit needs at least 20 s, a successful re-authentication and trust ≥ 0.45, and leads to RESTRICT (probation).
- Every decision carries a plain-language explanation (trust before and after, IDS probability and class, authentication failures, verified share, evidence and rule).

## 4. Design issues found and fixed while integrating (kept for the report)

1. **Framing through spoofed traffic.** Unweighted fusion let an outsider drive an honest drone into quarantine. Fixed by attribution-aware fusion (R4 test and ablation).
2. **Anomaly on spoofed volume.** The rate anomaly was computed on all packets claiming the address. It is now computed on *verified* packets.
3. **Enforcement feedback loop.** Rate-limited packets were dropped before verification, so the anomaly vanished and trust oscillated. Fixed with **verify-then-drop**.
4. **Framing through the hard rule.** Responder-side failures of spoofed M1s would have triggered "failed re-authentication". Only the drone's own initiator-side failures count now.
5. **Reward farming.** A drone in RE-AUTH earned the re-authentication bonus for every new session. Now one reward per forced re-authentication.
6. **Heuristic overriding the learned detector.** In the showcase run, an honest drone was RESTRICTed during a video burst that the IDS correctly rated benign (P ≈ 0.003), because the rate anomaly escalated.
   With ML present, the anomaly heuristic now only *corroborates*: it is weighted by `max(P(attack), 0.2)` and does not escalate (R6).
7. **Known limitation (measured, not hidden).** Without ML, the rate-anomaly heuristic briefly RESTRICTs drones during legitimate video bursts. The `no_ml` ablation quantifies this.
