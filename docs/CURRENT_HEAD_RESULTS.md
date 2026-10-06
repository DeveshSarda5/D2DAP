# Current-head results

Date: 2026-10-06  
Commit: `64b9b7f7768467f0a0fa8476104ec4dde74b9e32`

These are fresh runs from the current checkout. They are separate from historical
results and must not be mixed with them. The generated manifests under
`results/current_head/raw/*/manifest.json` are the source of run configuration and
environment metadata.

## What completed

- IDS: all four model families, validation, predictions, confusion matrices, latency,
  and current-head operational XGBoost artifact completed.
- Authentication: D2DAP 128/192/256 hint configurations and 128 trial configuration
  completed with 100% success in the measured trials.
- STRIDE: 132 scenario runs completed.
- Baseline comparison: 120 runs completed across the four system variants.
- Ablation: 180 runs completed across the full framework and four ablations.
- Scalability: 5, 10, 25, 50, and 100-drone cases completed.
- Trust/policy: executable current-head checks generated in
  `results/current_head/trust_validation.csv` and `policy_validation.csv`; the normal
  unit tests also cover attribution, decay, hysteresis, re-authentication, quarantine,
  and receiver-side policy behaviour.
- Targeted trust/policy reproducibility: three executions produced identical SHA-256
  hashes; the hashes are recorded in `results/current_head/reproducibility_validation.txt`.
- Figures, tables, and report indexes were generated under `results/current_head`.

## Current-head headline values

The selected XGBoost model reports test accuracy `0.9960`, macro-F1 `0.9439`,
weighted-F1 `0.9959`, binary-F1 `0.9856`, FPR `0.000803`, FNR `0.01813`, and grouped
CV macro-F1 `0.9535`. The unseen-rate-3 stress row reports macro-F1 `0.8288` and
binary-F1 `0.8937`; this is the more conservative stress result.

Current authentication means are approximately 32.77 ms (128-bit hint), 68.77 ms
(192-bit hint), 129.23 ms (256-bit hint), and 49.08 ms (128-bit trial), with all
reported success rates equal to 1.0. These are measured software compute timings on
this host; they are not hardware or RF timings.

The current full adaptive comparison reports detection rate `1.0`, layer detection
rate `0.9259`, mitigation rate `0.9549`, and median response `2200 ms` for 30 runs.
The current ablation table is in
`results/current_head/processed/ablation/summary.csv`; scalability values are in
`results/current_head/raw/scalability/scalability.csv`.

## Historical-results boundary

The older IDS/authentication artifacts were produced at earlier commit
`1004505e04...`; older STRIDE/framework artifacts were produced at
`ad3ae5e95b...`. Current HEAD changes `backend/app/services/monitor.py` by adding
deterministic IDS false-alarm controls and changes `backend/app/trust/engine.py` so
anomaly corroboration uses insider probability for attributed sources. Therefore old
framework/ablation numbers are historical context, not current-HEAD evidence. The
fresh current-head tables above should be cited for present claims.

## Validation status and blockers

`169` unit tests, `44` selected integration tests, `9` E2E tests, and compilation
passed. The aggregate check was not fully green because the host Application Control
policy blocked Ruff, mypy native components, and matplotlib's `_path` extension during
format/lint/type/full-collection checks. Details and remediation are in
`docs/ENVIRONMENT_AUDIT.md` and `results/test_run_current_head.txt`.

The optional NSL-KDD public benchmark was not run because its dataset files were not
present. This leaves the simulator IDS evaluation as the reproducible primary result;
it does not establish generalization to real drone or public benchmark traffic.

## Re-run commands

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests\unit -q
.\.venv\Scripts\python.exe -m pytest backend\tests\e2e -q
.\.venv\Scripts\python.exe scripts\run_experiments.py --suite ids --results-dir results\current_head_rerun
.\.venv\Scripts\python.exe scripts\run_experiments.py --suite auth --results-dir results\current_head_rerun
```

For a clean comparison rerun, use a new results directory rather than overwriting
`results/current_head`.
