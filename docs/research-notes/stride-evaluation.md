# STRIDE Evaluation (Phase 8)

Code: `backend/app/experiments/stride_eval.py` (scenario runner: `scenario.py`).
Final table: `results/tables/stride_table.md`, also Table 3 in `results/reports/final_tables.md`. Raw runs: `results/raw/stride/stride_runs.csv`.

**Method.** Every cell is measured, not argued.
- Each threat scenario is simulated in a 10-drone swarm for 60 s, with the attack running from 15 s to 45 s at 20 pkt/s and re-keying every 10 s.
- It is repeated over 3 seeds for each of the four systems: no authentication, D2DAP, D2DAP + IDS (System B) and the full adaptive framework (System D).
- *Attack success* = accepted / attempted attack packets (attempted includes packets that a policy prevented from ever being sent; channel losses are excluded). For eavesdropping it is the share of captured data packets that were plaintext.
- **Detected:** D2DAP rejects at least 10 % of the attack's packets or reports authentication failures, and/or the IDS alerted on the attack's claimed sources.
- **Trust impact / policy response:** minimum trust and most severe state of the attack's claimed sources under System D.
- **Mitigated?:** Yes if success ≤ 1 %, No if ≥ 90 %, Partial otherwise.
- Repudiation is evaluated with executable checks (`repudiation_analysis`).

## Findings (Our Experimental Result, simulation, mean of 3 seeds)

| Threat | Scenario | No auth | D2DAP | + IDS (B) | Adaptive (D) |
|---|---|---|---|---|---|
| S | Spoofing | 100 % | 0 % | 0 % | 0 % (victim MONITOR only) |
| S | In-window M1 replay | 100 % | **7.9 %** (O1) | 1.9 % | 8.7 % |
| S | Stale replay | 100 % | 0 % | 0 % | 0 % |
| S/E | Clone with extracted credentials | 100 % | 0 % | 0 % | 0 % |
| T | Tampering | 100 % | 0 % | 0 % | 0 % |
| R | Repudiation | repudiable | M1/M2 non-repudiable; AEAD data repudiable | n/a | audit log only |
| I | Eavesdropping | 100 % plaintext | 0 % | 0 % | 0 % |
| I | Insider scan/exfiltration | 100 % | **92.7 %** | 9.8 % | 10.5 % |
| D | Auth-request flood | 100 % | 0 %, but **923 ms/s victim CPU** | 0 % | 0 % |
| D | Insider flooding | 100 % | **87.3 %** | 17.6 % | 14.2 % |
| E | Unregistered drone | 100 % | 0 % | 0 % | 0 % |
| E | Privilege escalation | 100 % | **98.6 %** | 10.3 % | 7.2 % |

**Conclusion.**
- D2DAP fully stops external S/T/I/E attacks, but leaves in-window replay, computational DoS and every authenticated-insider attack open.
- The detection-plus-response layers reduce insider attack success from 87–99 % to 7–18 %.
- The adaptive framework does this **without** sanctioning the honest identities that outsiders forge. System B blocks them (Table 6, `framed_rate`).
- Computational DoS remains unmitigated: rejecting requests still costs the victim verification work.
