# Research Understanding (Phase 0)

Project: **Adaptive Trust-Aware Drone Security Framework Using D2DAP Authentication and
Machine Learning-Based Intrusion Detection** (Kapil and Devesh).

This document records our reading of the two reference papers *before* any implementation.
The goal is to separate clearly what the literature proposes from what we build and what we add.
Every literature number quoted here is copied from the paper and labelled **[Literature]**.

---

## 1. Reference paper 1: D2DAP

> K. Parai, P. K. Roy, P. Kumar, SK H. Islam, "D2DAP: Provably Secure and Efficient
> Drone-to-Drone Authentication Protocol Using Threshold Cryptography and PUF",
> *IEEE Transactions on Vehicular Technology*, 2026, DOI 10.1109/TVT.2026.3674144 (accepted author version).

### 1.1 Problem the paper solves

Drone-to-drone (D2D) mutual authentication and key agreement (MAKA) **without** a trusted third
party (control server / ground station) in the authentication path. The paper names four requirements:

1. a system-specific threat model (STRIDE, produced with the Microsoft Threat Modeling Tool);
2. single-hop D2D authentication, so no intermediate server adds a hop;
3. physical security against cloning and node capture, achieved with a PUF;
4. low key storage: one network-wide secret `A`, of which each drone stores only *shares*
   rather than `n-1` pairwise keys. This is the (2, n) threshold scheme.

### 1.2 Entities

| Entity | Role |
|---|---|
| Control Server `CS` | Runs Setup and Registration (offline, secure channel). **Not** involved in MAKA. Maintains the revocation list `RL`. |
| Drone `D_i`, `D_j` | Homogeneous drones, each with built-in PUF circuitry. They run MAKA over a public (Dolev-Yao) channel. |
| Adversary `A` | Controls the public channel (eavesdrop, modify, replay). Can physically capture a drone and extract stored data (`Extract` query). Can query a PUF only on the device itself. |

### 1.3 Protocol workflow (exactly as in Sec. IV and Fig. 3 of the paper)

**Setup (by CS)**
- Choose an ℓ-bit prime `q`, curve `E(Z_q)`, generator `P`.
- Pick `A, B ←R Z*_q`; polynomial `F(x) = A + B·x mod q` (degree 1, hence a **(2, n)** threshold). Keep `A` secret.
- Initialise the revocation list `RL = ∅`. Drones may insert into `RL` but may not delete from it.
- Choose a hash `H: {0,1}* → {0,1}^ℓ` and symmetric `Enc/Dec`. Publish `{q, E, P, H, Enc/Dec}`.

**Registration (per drone, secure channel)**
- CS assigns `ID_i` and `m` distinct 128-bit challenges `C_i = {C_i1..C_im}`.
- `D_i` computes `R_ik = PUF(C_ik)` and picks `x_i`. It computes `Y_i = x_i·P` and `a_ik = H(R_ik || ID_i)`, then sends `{a_i, Y_i}` to CS.
- CS computes `b_ik = F(a_ik)` and `V_i = H(A || ID_i)`. It stores `{a_i, Y_i}`, gives `{b_i, RL, V_i}` to `D_i` and publishes `Y_i`.
- `D_i` stores `{ID_i, x_i, b_i, C_i, RL, V_i}`. It does **not** store `a_i` or `R_i`; these are regenerated from the PUF.

**MAKA (D_i initiates; 2 messages)**

| Step | D_i (initiator) | D_j (responder) |
|---|---|---|
| M1 | `T_i`; `K = x_i·Y_j`; pick `(C_ik, b_ik)`; `R_ik = PUF(C_ik)`; `a_ik = H(R_ik‖ID_i)`; `CM = Enc_K(a_ik‖b_ik‖T_i)`; `(σ1,σ2) = GenSign(CM, a_ik, T_i, x_i)`. Send `{CM, σ1, σ2}` | |
| V1 | | `K = x_j·Y_i`; decrypt `CM`; abort if `|T_j − T_i| > ΔT`; abort if `VerifySign ≠ σ1`; pick `(C_jk, b_jk)`; `a_jk = H(PUF(C_jk)‖ID_j)`; abort if `H(a_ik‖a_jk) ∈ RL`; reconstruct `A` by Lagrange from `(a_ik,b_ik)`, `(a_jk,b_jk)`; abort if `H(A‖ID_j) ≠ V_j`; `RL ← RL ∪ {H(a_ik‖a_jk)}` and broadcast |
| M2 | | `DM = Enc_K(a_jk‖b_jk‖T_j)`; `(σ3,σ4) = GenSign(DM, a_jk, T_j, x_j)`; `SK = H(a_ik‖a_jk‖T_i‖T_j)`; delete `C_jk, b_jk`. Send `{DM, σ3, σ4}` |
| V2 | decrypt `DM`; abort if `|T'_i − T_j| > ΔT`; abort if `H(a_ik‖a_jk) ∉ RL`; reconstruct `A`; abort if `H(A‖ID_i) ≠ V_i`; abort if `VerifySign(DM,…) ≠ σ3`; `SK = H(a_ik‖a_jk‖T_i‖T_j)`; delete `C_ik, b_ik` | |

**GenSign (Algorithm 1):** `r ←R Z*_q`, `M = H(CM)`, `α = r·H(a_ik‖T_i)·P`, `σ1 = α_x`, `σ2 = (M + x_i·α_x)·r⁻¹ mod q`.
**VerifySign (Algorithm 2):** `β = M·σ2⁻¹`, `γ = σ2⁻¹·σ1`, `α = (β·P + γ·Y_i)·H(a_ik‖T_i)`; accept iff `α_x = σ1`.
This is an ECDSA variant in which the nonce point is additionally multiplied by `H(a_ik‖T_i)`.

### 1.4 Cryptographic operations per MAKA

These counts come from our own reading of the protocol and are verified later by the
instrumented implementation in Phase 4.

| Operation | D_i | D_j |
|---|---|---|
| EC point multiplication (T_PM) | K, α, βP, γY, ×H → 5 | K, βP, γY, ×H, α → 5 |
| EC point addition (T_PA) | 1 | 1 |
| Hash (T_H) | a_ik, H(CM), H(a‖T) (sign), H(DM), H(a‖T) (verify), H(a_ik‖a_jk), H(A‖ID), SK | symmetric set + RL insertion |
| Sym. enc/dec (T_ED) | 1 enc + 1 dec | 1 dec + 1 enc |
| PUF evaluation (T_PUF) | 1 | 1 |
| Secret reconstruction (T_SSR) | 1 | 1 |
| Random number (T_R) | 1 (r) | 1 (r) |

### 1.5 What the paper claims and how it supports the claims

| Claim | Evidence used in the paper |
|---|---|
| Mutual authentication + session-key agreement | Algebraic correctness proof (Sec. V-A) |
| Resistance to all six STRIDE threats | Informal argument (Sec. V-B, Table IV) |
| Semantic security of SK | Real-or-Random (RoR) game-based proof (Theorem 1) |
| SAFE under Dolev-Yao | AVISPA (OFMC, CL-AtSe) |
| Communication cost **[Literature]** | 1024 / 1536 / 2008 bits for 128/192/256-bit security, 2 rounds (Table VII). The value 2008 does not scale like the other two (2048 would be expected), so it may be a typo in the paper. |
| Computation cost **[Literature]** | 108,654,520 CPU cycles per drone at 128-bit on a Raspberry Pi 3 (Table IX), from per-operation cycle counts (Table VIII) |
| Energy **[Literature]** | 0.931 mJ per drone at 128-bit (Table X), *derived* from cycles × assumed power (Eq. 10) |
| Hardware demo | Raspberry Pi 3 + laptop, `tinyec`, `pycryptodome`, `pypuf` 128-bit XOR-Arbiter PUF |

### 1.6 Assumptions (explicit and implicit)

1. Registration runs over a secure channel. CS is trusted and honest.
2. Each drone has a PUF that is unclonable, unpredictable, robust (noise-free) and indistinguishable from random (Sec. V-D definitions).
3. Clocks are loosely synchronised so that a fixed `ΔT` freshness window works.
4. All drones' public keys `Y_i` are published, and a responder somehow knows **which** `Y_i` to use.
   *Implicit:* the message `{CM, σ1, σ2}` carries no identity, and the paper does not say how `D_j` selects `Y_i`.
5. `RL` broadcasts reach all drones "as soon as the new list becomes available". This assumes reliable, immediate dissemination.
6. Each drone has `m` one-time CRPs. After `m` sessions the drone can no longer authenticate (implicit; the paper does not discuss re-provisioning).
7. The paper uses `mod q` for both the field prime and the scalar group order. A correct implementation needs scalars and shares modulo the **group order** `n`.

### 1.7 Hardware-dependent components

| Component | Hardware dependency | Can we reproduce it? |
|---|---|---|
| PUF responses | Silicon manufacturing variation | **No.** We simulate it in software (a seeded XOR-Arbiter additive-delay model plus an ideal keyed-hash model). A software PUF is *not* unclonable: its "secret" is a seed in memory. |
| CPU-cycle costs on Raspberry Pi 3 | ARM SoC | **No.** We measure wall-clock and CPU time on our own development machine and label it as such. |
| Energy (mJ) | Power measurements / assumed wattage | **No.** We do not measure or estimate energy. |
| Physical capture / side channels | Real device | Only *modelled*, as an `Extract` of stored credentials. |
| Wireless channel | Radio | Modelled (distance-based range, latency, loss). |

### 1.8 Our critical observations (to be tested in simulation, not asserted)

These are hypotheses drawn from the protocol text. Each is turned into a measurable
experiment (Phases 7–8). They are **not** claims that the paper's formal proof is wrong. They concern
properties outside what the RoR proof and AVISPA model cover.

- **O1 Replay inside the freshness window.** `D_j` keeps no cache of seen `(CM, T_i)`. A replay of
  `{CM, σ1, σ2}` that arrives within `ΔT` passes the timestamp and signature checks. `D_j` then consumes
  a fresh CRP and inserts an RL entry. The attacker cannot derive `SK`, because `a_ik` is encrypted under `K`.
  However, `D_j` may be left with an orphan half-session and one fewer CRP. *Testable:* replay at `t < ΔT` vs. `t > ΔT`.
- **O2 CRP exhaustion as a DoS vector.** Following from O1, a burst of in-window replays can drain `D_j`'s `m` CRPs. *Testable.*
- **O3 Insider recovery of `A`.** All of a drone's shares lie on the same line `F`. A drone (or a captured but functioning drone)
  that can evaluate its own PUF on two of its challenges can solve for `A` (and `B`). This is also inherent by design:
  every responder reconstructs `A` during MAKA. Impact appears limited, because signatures still bind to the insider's own `x_i`.
  But the threshold scheme does not protect against a *functioning* insider. *Testable.*
- **O4 Peer resolution.** Without an identity in the message, the responder must either trial-decrypt against every published `Y`
  (O(n) EC multiplications) or rely on a link-layer hint that weakens the anonymity claim. *Measurable in the scalability study.*
- **O5 Insider misbehaviour.** A legitimately registered drone passes MAKA. D2DAP authenticates identity, not behaviour,
  so flooding, false data or privilege abuse by an authenticated drone is out of scope for D2DAP. This is the main gap our contribution targets.

---

## 2. Reference paper 2: ML-based IDS for the Internet of Drones (SLR)

> M. Ogab, S. Zaidi, A. Bourouis, C. T. Calafate, "Machine Learning-Based Intrusion Detection Systems for the
> Internet of Drones: A Systematic Literature Review", *IEEE Access*, vol. 13, pp. 96681–96717, 2025,
> DOI 10.1109/ACCESS.2025.3575236 (CC BY-NC-ND 4.0).

### 2.1 What it is

A PRISMA systematic review of 62 studies (2014–2024, from 1,909 records). It is a **review**: it proposes no new detector.
It provides a taxonomy, dataset analysis, metric definitions, challenges and future directions.

### 2.2 Concepts we take from it

- **IDS taxonomy** (Fig. 2): deployment (centralised/distributed/hybrid), data source (network traffic, host and flight logs),
  detection methodology (anomaly/signature/specification), timeliness (online/offline, passive vs. active response).
- **IDS types in the surveyed studies** **[Literature]**: network-based 35, host-based 19, collaborative 4, hybrid 2, distributed 1.
- **Datasets** **[Literature]**: CIC-IDS2017 (13 studies), UAV Attack Dataset (9), NSL-KDD (8), KDD Cup 99 (6), flight logs (6),
  UNSW-NB15 (5), ToN-IoT (4), CSE-CIC-IDS2018 (4). Its key criticism: none of them are IoD-specific network datasets.
- **Algorithms** **[Literature]**: LSTM variants dominate (11). Others: CNN (8), DT (6), SVM (5), MLP (5), AE (5), RF (4), XGBoost (1).
- **Metrics** (Eqs. 1–11): accuracy, precision, recall/DR, F1, specificity, FPR/FAR, FNR, error rate, AUC/ROC, training time, prediction time.
- **Classification setting** **[Literature]**: multi-class in 30 studies, binary in 22.

### 2.3 Challenges and gaps the SLR identifies (RQ4/RQ5)

1. Resource constraints. Lightweight models are needed.
2. High false-positive rates and the accuracy versus false-alarm trade-off.
3. Real-time detection and latency.
4. Scarcity of datasets and their lack of IoD specificity.
5. Generalisation to novel attacks.
6. Inconsistent evaluation. Accuracy is reported without efficiency or real-time metrics.
7. **Intrusion *prevention* gap:** the review states there is a critical gap in proactive, real-time *decision mechanisms*
   that act on detections, as opposed to only raising alerts.

### 2.4 What the SLR does **not** provide

- No integration of IDS output with authentication state.
- No response policy (what to do after a detection).
- No benchmark code, models or numbers that we could reproduce directly.

---

## 3. What can be simulated vs. what cannot

| Aspect | Simulated? | How |
|---|---|---|
| Drones, mobility, battery (model only) | Yes | Discrete-time simulator, random-waypoint mobility, seeded RNG |
| D2D wireless links | Yes (abstracted) | Range-limited neighbour graph, distance-based latency, packet loss |
| PUF | Yes (software model) | XOR-Arbiter additive-delay model (numpy) and an ideal keyed-hash PUF |
| D2DAP cryptography | **Yes (real cryptography)** | Real ECC (NIST P-256/384/521), SHA-3, AES-CTR. Only the PUF is simulated. |
| Attacks | Yes | Packet- and protocol-level adversary that operates on the real protocol messages |
| Network traffic | Yes | Telemetry (periodic), video (burst), command (Poisson), auth and RL broadcast |
| ML IDS | Yes | Trained on features from simulated traffic. Optionally validated on a public benchmark dataset. |
| Hardware timing / energy | **No** | Not claimed |
| Formal verification (RoR, AVISPA) | **No** | We did not re-run AVISPA or re-prove Theorem 1. Our security evidence is empirical (attack simulation). |

## 4. Research gap (the motivation for our contribution)

D2DAP answers *"is this drone who it claims to be?"* once per session. The ML-IDS literature answers
*"does this traffic look malicious?"* per sample. **Neither answers *"how much should we trust this
authenticated drone right now, and what should the network do about it?"*** The SLR explicitly lists the missing
prevention and response layer as a gap (Sec. 2.3, item 7). Observations O1–O5 show that authentication alone leaves
behavioural, insider and availability threats unaddressed. Our contribution is a continuous trust and adaptive-policy
layer that joins the two (see `research-contribution.md`).
