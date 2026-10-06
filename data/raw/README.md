# data/raw

Place externally obtained datasets here (they are git-ignored).

## NSL-KDD (optional public benchmark)

1. Download from the official source: https://www.unb.ca/cic/datasets/nsl.html (registration form).
2. Copy `KDDTrain+.txt` and `KDDTest+.txt` into `data/raw/nsl-kdd/`.
3. Run `python scripts/run_experiments.py --suite ids`.

The loader (`backend/app/ids/public.py`) uses the official train/test split and the standard 5-category label mapping (normal, dos, probe, r2l, u2r).
If the files are absent, the public benchmark is reported as "not run". No numbers are produced or claimed for it.

## Simulated data

The simulator-generated IoD dataset (D2D-SIM) is written to `data/generated/` by the IDS experiment.
It is regenerated automatically: the cache key includes the dataset configuration, seed, feature list and simulator version.
