# Attack Simulator (Phase 7)

Package: `backend/app/attacks/` (`base.py`, `external.py`, `insider.py`, `manager.py`).

Every attack acts on **real packets and real D2DAP protocol bytes** inside the simulator. It writes a ground-truth `label` and `attack_id` on every packet it creates or alters. These fields are used for evaluation only and are never used as IDS features.
Each attack also produces `AttackEvidence`: packets sent, accepted and dropped by reason; auth attempts, acceptances and failures by reason; crypto work forced on victims; CRPs consumed; and attack-specific extras.

| Attack (`kind`) | Adversary | Mechanism | STRIDE | Key evidence |
|---|---|---|---|---|
| `spoofing` | external radio | Data packets claiming the victim's address: some unauthenticated, some carrying a sniffed session id with a forged payload. Also forged `AUTH_REQUEST`s. | S | drops: `unauthenticated` / `no_session` / `integrity`; auth failures |
| `replay` | external radio | Captures the victim's `AUTH_REQUEST`s and sealed data, then replays them. `window=in` replays M1 within ΔT (O1), `window=stale` after ΔT. | S, D | data drops `replay`; `auth_replays_accepted`; `crp_consumed` (O2) |
| `tampering` | on-path | Flips ciphertext bits of the victim's packets (data and auth) | T | drops `integrity`; auth failures |
| `dos` | external radio | Floods the victim with bogus `AUTH_REQUEST`s that carry spoofed sources | D | `victim_compute_ms` (forced verification work) |
| `impersonation` | node capture + clone | The victim is captured (leaves). A clone holding the extracted `{ID, x, b, C, V}` but a *different* PUF claims its identity. | S, E | auth failures `secret_mismatch` (paper GM4) |
| `unauthorized_access` | rogue drone | An unregistered drone with its own keys tries MAKA and sends commands | S, E | auth failures; drops `unauthenticated` |
| `eavesdropping` | passive | Captures everything in range and sends nothing | I | plaintext fraction, identities in auth messages, link-layer exposure |
| `flooding` | **insider** | A compromised registered drone sends a high-rate stream of large, validly sealed packets | D | accepted packets and bytes |
| `privilege_escalation` | **insider** | A compromised WORKER issues leader-only `COMMAND`s, and recovers master secret `A` from its own shares (O3) | E | accepted commands; `master_secret_recovered` |
| `abnormal` | **insider** | Scanning (tiny packets to every member) plus exfiltration bursts | I, D | accepted packets; new sessions (CRPs) |

**Repudiation (R)** is not a packet attack. It is analysed in Phase 8: M1 signatures can be verified by a judge, while AEAD data packets can be forged by the receiver.

## Smoke-run observations (D2DAP enabled, 8 drones, 15 s attacks; integration tests assert these)

- **All external attacks are blocked by D2DAP plus the authenticated data plane**: 0 accepted packets for spoofing, tampering, impersonation and unauthorized access.
- **The clone fails with `secret_mismatch`**, as the paper's GM4 predicts, because the clone's PUF gives a different `a_ik`.
- **The auth-flood DoS cost the victim about 9 s of CPU in 15 s**. Every request is rejected, but each one still costs about 30 ms of verification. D2DAP cannot avoid this work.
- **In-window replay (O1/O2) reproduced at network level** when sessions are re-keyed: the responder accepts the replayed M1, consumes a CRP, and installs a half-open session.
- **Insider attacks pass D2DAP**: more than 98 % of flooding, privilege-escalation and abnormal packets were accepted and validly sealed. The insider also recovered `A`.
  This gap motivates the trust and adaptive-policy layer.

## Fixes found while building the attacks

- Attackers now derive the M1 size from *public* parameters rather than from victim agents.
- Responder acceptance of M1 is now emitted as an `AuthEvent` (`stage=respond, success=True`). Without this, O1 replays were invisible to monitoring.
- Auth events carry the ground-truth `attack_id` for evaluation-only attribution, so a victim's legitimate re-key is not counted as an attack success.
- Registered drones refuse to send data to destinations without a published key. Before this fix, a leader had sent a few plaintext commands to an attacker radio that looked like a worker.
- Optional `rekey_interval_ms` (our addition; D2DAP does not specify session lifetimes). It is off by default.
