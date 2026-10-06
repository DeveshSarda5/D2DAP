# D2DAP Paper → Implementation Mapping

Legend for **Status**:

- **Exact**: implemented as written in the paper.
- **Interpreted**: the paper is ambiguous or underspecified; we chose the standard, correct reading (reason given).
- **Substituted**: a different but equivalent-purpose primitive (reason given).
- **Simplified**: implemented with reduced fidelity.
- **Abstracted**: replaced by a software model of a physical or system component.
- **Added**: not in the paper; we added it because an implementation needs it. It can be switched off where possible.
- **Not Implemented**: out of scope, with the reason.

We never silently change the protocol. Every deviation is listed here and in code docstrings.
Code locations refer to `backend/app/security/` (filled in during Phase 4).

| # | Paper component | Our implementation | Status | Reason |
|---|---|---|---|---|
| 1 | Setup: ℓ-bit prime `q`, curve `E(Z_q)`, generator `P` | NIST P-256 / P-384 / P-521 for the 128/192/256-bit security levels (`curves.py`) | Substituted | The paper's evaluation used a Type-A (pairing-friendly, supersingular) curve, but D2DAP uses no pairings. Standard prime-order NIST curves give the stated security level with well-audited parameters. P-521 is used for the "512-bit ECC" level (Table VI) because no 512-bit NIST curve exists. |
| 2 | Scalars and shares "mod q" | All scalar arithmetic (keys, `r`, `σ2`, `β`, `γ`, `F(x)`, Lagrange) is done modulo the **group order `n`** | Interpreted | The paper uses `q` both as field prime and group order. Signature algebra and Shamir sharing are only correct modulo the prime group order. |
| 3 | `F(x) = A + Bx mod q`, (2, n) threshold | `ShamirScheme(threshold=2)`, a general (t, n) implementation used with t = 2 | Exact | — |
| 4 | Lagrange reconstruction, Eq. (2) | `ShamirScheme.reconstruct` | Exact | — |
| 5 | Hash `H` | SHA3-256 / SHA3-384 / SHA3-512 per security level, with length-prefixed concatenation for `‖` | Exact (H) / Added (encoding) | The paper's footnote points to SHA-3. Length-prefixing prevents ambiguous concatenations; the paper's `‖` encoding is not specified. |
| 6 | `a_ik = H(R_ik ‖ ID_i)` used as polynomial abscissa | Hash output interpreted as a big-endian integer mod `n` | Interpreted | Needed to evaluate `F` over `Z_n`. |
| 7 | Symmetric `Enc_K / Dec_K` (AES-CTR) | AES-CTR (128/192/256-bit key) with a random 128-bit initial counter block sent with the ciphertext | Exact (cipher) / Added (IV) | CTR mode requires a unique nonce; the paper does not list it in the message size. |
| 8 | Key `K = x_i·Y_j` (an EC point) used as an AES key | AES key = `H("D2DAP-K" ‖ K_x)` truncated to the AES key length | Added (KDF) | An EC point is not an AES key. Hashing the x-coordinate is the standard ECDH key derivation. |
| 9 | Registration over a secure channel | Direct in-process call between `ControlServer` and `Drone` objects | Abstracted | Secure provisioning is assumed by the paper as well. |
| 10 | `C_i`: m distinct 128-bit challenges | `m` configurable (default 32), drawn from the seeded CSPRNG stream of the CS | Exact (m is configurable) | The paper does not fix `m`. |
| 11 | `R = PUF(C)` | `SoftwarePUF` interface; default `XORArbiterPUF` (k = 4 chains, 128 stages to match the paper's 128-bit challenge, 128-bit response from 128 derived sub-challenges, optional noise + majority vote); also `IdealPUF` (HMAC-SHA3) | **Abstracted** | **No physical PUF is available. This is a SOFTWARE PUF SIMULATION.** The paper's own demo also used a software PUF model (`pypuf` 128-bit XOR Arbiter). See `docs/research-notes/software-puf.md` (Phase 3). |
| 12 | `x_i ←R Z*_q`, `Y_i = x_i·P` | Same, using the `ecdsa` library's point arithmetic | Exact | — |
| 13 | CS stores `{a_i, Y_i}`, gives `{b_i, RL, V_i}`; drone stores `{ID_i, x_i, b_i, C_i, RL, V_i}` | `DroneCredentials` holds exactly these fields. `a_i` and `R_i` are not stored on the drone. | Exact | Lets the cloning experiment `Extract` exactly what the paper says is stored. |
| 14 | Revocation list `RL`, append-only, broadcast | `RevocationList` (append-only set, insert-only API). Each insertion is broadcast to the other drones, and the broadcast bytes and messages are counted. | Abstracted | No distributed ledger or real broadcast. Dissemination is assumed immediate and reliable, as in the paper. |
| 15 | Timestamps `T_i`, `T_j`, window `ΔT` | 64-bit millisecond timestamps from the simulation clock; `ΔT` configurable (default 2000 ms) | Abstracted | Deterministic virtual time gives reproducible freshness experiments. |
| 16 | `GenSign` (Algorithm 1) | Implemented literally: `α = (r·h mod n)·P`, `σ1 = α_x mod n`, `σ2 = (M + x·σ1)·r⁻¹ mod n` | Exact (with item 2) | We reduce `σ1 = α_x` mod `n`, as in ECDSA. |
| 17 | `VerifySign` (Algorithm 2) | `β = M·σ2⁻¹`, `γ = σ1·σ2⁻¹`, `α = h·(β·P + γ·Y)`; accept iff `α_x mod n = σ1` | Exact | — |
| 18 | MAKA M1/V1/M2/V2 including all abort conditions and their order | `MAKA` initiator/responder state machines, with abort reasons as enum values (`FRESHNESS`, `SIGNATURE`, `REVOKED_PAIR`, `SECRET_MISMATCH`, `NOT_IN_RL`, `CRP_EXHAUSTED`, `UNKNOWN_PEER`, `MALFORMED`) | Exact | The order of checks follows Fig. 3. |
| 19 | How the responder knows the initiator's `Y_i` | Configurable `peer_resolution`: **`trial`** (default; the responder tries every published `Y` and accepts only when freshness and signature verify; no identity on the wire) or `hint` (the transport passes the claimed sender address) | Added | Underspecified in the paper. `trial` preserves the anonymity claim at O(n) cost, which we measure in the scalability study. `hint` is cheaper but leaks the link-layer identity. |
| 20 | Session key `SK = H(a_ik‖a_jk‖T_i‖T_j)` | Exact | Exact | — |
| 21 | Removing used `(C_ik, b_ik)` | Removed from the drone's credential store after a successful session (both sides) | Exact | The responder removes its pair when it sends M2, as in the paper. |
| 22 | Data protection *after* MAKA | AES-GCM with a key derived from `SK`, plus per-packet sequence numbers | Added | The paper ends at key agreement. Post-auth traffic must be protected for the tampering and replay experiments. |
| 23 | CRP exhaustion handling | When `C_i` is empty, MAKA fails with `CRP_EXHAUSTED`. Re-provisioning requires CS re-registration (`ControlServer.reprovision`). | Added | Not discussed in the paper but unavoidable with one-time CRPs. |
| 24 | Replay cache at the responder | Optional `replay_cache` (OFF by default to stay faithful) | Added (optional hardening) | Used only to *evaluate* observation O1. All D2DAP-faithful results use OFF. |
| 25 | Security levels 128/192/256 | All three supported; P-256/SHA3-256/AES-128 is the default for experiments | Exact | — |
| 26 | Communication cost (Table VII) | *Measured* serialized bytes per message, reported next to the paper's theoretical bits | Exact (method differs) | The paper counts parameter lengths; we count real serialized bytes. Both are shown, labelled. |
| 27 | Computation cost in CPU cycles on Raspberry Pi 3 (Tables VIII–IX) | Wall-clock and CPU time on the development machine, plus instrumented operation counts | **Not Implemented** (hardware cycles) | No Raspberry Pi. We report operation counts, which are comparable, and our own machine's timings, which are not hardware results. |
| 28 | Energy consumption (Table X, Eq. 10) | — | **Not Implemented** | It would need real power measurements. We do not estimate or claim energy. |
| 29 | RoR provable security (Theorem 1) | — | **Not Implemented** | We did not re-derive or mechanise the proof. We cite it as the authors' result. |
| 30 | AVISPA validation (OFMC / CL-AtSe) | — | **Not Implemented** | No HLPSL model was re-run. Our security evaluation is empirical (simulated attacks). |
| 31 | MTMT STRIDE report (Table II) | Used as the threat list for our attack simulator and STRIDE evaluation | Exact (as input) | — |
| 32 | Hardware demo (RPi + laptop) | Software-only simulation | Abstracted | No hardware. |

## Code locations (Phase 4)

| Paper element | Module |
|---|---|
| Curve, hash, AES-CTR, KDF, op counting | `backend/app/security/crypto.py` |
| `F(x)`, Lagrange (Eqs. 1–2) | `backend/app/security/secret_sharing.py` |
| GenSign / VerifySign (Alg. 1–2) | `backend/app/security/signature.py` |
| Setup + Registration (CS) | `backend/app/security/d2dap/control_server.py` |
| MAKA initiator / responder (Fig. 3) | `backend/app/security/d2dap/agent.py` |
| Wire format `{CM, σ1, σ2}` / `{DM, σ3, σ4}` | `backend/app/security/d2dap/messages.py` |
| `RL` | `backend/app/security/d2dap/revocation.py` |
| Service interface (`authenticate`) | `backend/app/security/d2dap/service.py` |
| Software PUF | `backend/app/security/puf.py` |

## Verified operation counts per MAKA (instrumented; `peer_resolution = hint`)

| Side | T_PM | T_PA | T_H | T_ED | T_PUF | T_SSR | T_R | mod-inv |
|---|---|---|---|---|---|---|---|---|
| Initiator D_i | 5 | 1 | 9 | 2 | 1 | 1 | 1 | 2 |
| Responder D_j | 5 | 1 | 9 | 2 | 1 | 1 | 1 | 2 |

T_H = 9 is: `a`, `H(CM)`, `H(a‖T)` (sign), `H(a_ik‖a_jk)` (RL), `H(A‖ID)`, `H(DM)`, `H(a‖T)` (verify), `SK`, plus 1 for the KDF of `K` (mapping item 8).
In `trial` mode the responder needs on average about (n−1)/2 extra T_PM and T_ED for key search.
This is asserted by `test_hint_mode_exact_operation_counts` and `test_trial_mode_costs_more_at_responder`.
