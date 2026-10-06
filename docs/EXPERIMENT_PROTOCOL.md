# Experiment Protocol

This protocol is intended to reproduce the existing recorded results. It distinguishes
virtual simulation metrics from host-dependent timing metrics.

## Environment

- Repository root: `D:\Projects\Gulabi` (use the equivalent path elsewhere).
- Python: >=3.10; recorded runs used Python 3.10.11.
- Install: `python -m pip install -e ".[dev]"` in a fresh virtual environment.
- Seed: 42 unless a suite specifies derived seeds.
- Results: `results/raw`, `results/processed`, `results/tables`, `results/figures`,
  `results/reports`.
- Model path: `results/models/ids_operational.joblib`, or `ADS_IDS_MODEL` override.

## Suite commands

```powershell
python scripts\run_experiments.py --suite ids
python scripts\run_experiments.py --suite puf,auth,traffic
python scripts\run_experiments.py --suite stride,comparison,ablation
python scripts\run_experiments.py --suite sensitivity,stress,scalability
python scripts\run_experiments.py --suite diagrams,report
python scripts\verify_reproducibility.py
```

The complete suite is `python scripts\run_experiments.py`; it is potentially long.
The IDS suite must run before framework suites because it creates the operational model.

## Main recorded configurations

| Experiment | Configuration |
|---|---|
| IDS | 4 dataset seeds, 9 attack kinds, rates 3/10/30, 4 benign runs/seed, 8/10/12 drones, 45 s, 30% test by run |
| Authentication | 200 MAKA trials per P-256/P-384/P-521 hint and P-256 trial configuration; warmup 10; compute-only latency |
| STRIDE | 10 drones, 60 s, attack at 15 s for 30 s, 3 seeds 42/43/44, baseline/D2DAP/IDS/adaptive |
| Baseline comparison | Same 10-drone/60 s scenario and 3 seeds; A-D variants |
| Ablation | Same comparison scenarios; full, no trust, no ML, no policy, no attribution |
| Scalability | Sequential 5/10/25/50/100 drones, 30 auth trials, 30 s framework run |
| Stress | Synthetic IDS false-alarm rates 0%, 1%, 5%; explicitly not real detector noise |

## Metrics and definitions

- IDS accuracy/precision/recall/F1: multiclass held-out windows.
- Macro-F1: unweighted mean class F1; preferred under imbalance.
- Binary `P(attack)`: `1-P(benign)`; alert threshold 0.5.
- FPR/FNR: binary confusion rates at threshold 0.5.
- Detection latency: attack start to end of first flagged window.
- Mitigation: 1 - accepted attack packets / attempted attack packets in comparison runs.
- Response latency: attack start to first policy-caused attack drop.
- Disruption: benign drone-windows in RESTRICT or worse.
- Collateral rate: policy-dropped benign packets / benign packets received.
- Authentication latency: measured Python compute plus configured/simulated network delay;
  it is not hardware timing.
- Communication cost: serialized protocol/message byte model and counted simulated
  control/data packets; not a socket capture.
- Delivery ratio: delivered / (delivered+dropped) finalized simulated packet attempts.
- Monitor cost: measured host processing time per monitor window.

## Reproducibility procedure

1. Create a fresh environment and record package versions.
2. Run the suite at a pinned Git commit.
3. Keep each manifest and source sidecar.
4. Run `verify_reproducibility.py` at least once; for a thesis claim, repeat the same
   deterministic suite three times and compare non-timing artifacts.
5. Exclude wall-clock latency/CPU/RSS from byte-identical comparisons; retain them as
   distributions with environment metadata.

## Current provenance warning

Existing IDS/authentication outputs were generated at commit `1004505e04...`; existing
STRIDE/comparison/scalability outputs at `ad3ae5e95b...`. Current HEAD is `64b9b7f`.
Use the manifest commit as part of every citation, or rerun at HEAD before claiming
current-code equivalence.
