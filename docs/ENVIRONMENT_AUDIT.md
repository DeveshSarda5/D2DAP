# Environment audit — current HEAD

Date: 2026-10-06  
Commit: `64b9b7f7768467f0a0fa8476104ec4dde74b9e32`

## Repaired environment

The project is run from `.venv`, not from the system interpreter. Its interpreter is
Python 3.11.9 and `pyvenv.cfg` points to the installed Python 3.11 runtime. The
previous stale-environment symptom was a pandas native DLL/import failure; the current
virtual environment now imports pandas and the application successfully.

Verified imports include numpy 2.4.6, pandas 2.3.3, scikit-learn 1.7.2,
xgboost 3.2.0, joblib 1.6.0, FastAPI 0.142.2, uvicorn 0.54.0, pydantic 2.13.5,
cryptography 50.0.2, ecdsa 0.19.2, matplotlib 3.11.2, pytest 9.1.1, ruff 0.16.10,
and mypy 2.4.0. Application imports and `compileall` pass.

## Verification commands

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m compileall -q backend scripts
.\.venv\Scripts\python.exe -m pytest backend\tests\unit -q
.\.venv\Scripts\python.exe -m pytest backend\tests\e2e -q
python scripts\run_experiments.py --suite ids,auth --results-dir results\current_head
```

The exact test results are recorded in `results/test_run_current_head.txt`.

## Host-policy blocker

The Windows host Application Control policy blocks some native executables/DLLs.
Consequently, Ruff's subprocess, mypy's native component, and matplotlib's
`_path` extension cannot run reliably. This blocked the repository's aggregate
`scripts/check_all.py` command and full pytest collection. It is not evidence of an
application assertion failure. The runnable unit, selected integration, and E2E tests
passed.

To obtain a completely green aggregate check on this laptop, the host administrator
must allow the relevant `.venv` executables and compiled extensions, or the checks must
be run in an approved Python environment/container. No application logic was changed
to work around this policy.

## Reproducibility notes

Current-head experiment manifests record the interpreter, package versions, machine,
commit, seed, configuration, and elapsed time. Results are isolated in
`results/current_head`; historical directories were not overwritten. The current IDS
run retrained the models using the existing generated simulator dataset
`data/generated/d2dsim_6a739e9552.csv.gz` (56,694 rows, 124 runs), whose simulation
generators are unchanged between its original artifact commit and current HEAD.
The current-head manifest therefore identifies this as a retrained current-head model
on an existing versioned dataset, not a claim that a new dataset was regenerated.
