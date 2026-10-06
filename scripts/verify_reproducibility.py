"""Phase 23 reproducibility check: same seed -> identical (non-timing) results.

Runs seeded experiments twice into separate temporary directories and compares their
artefacts. Columns that are wall-clock *measurements* (latency, CPU, ms) legitimately
differ between runs and are excluded; everything simulated must be identical.

    python scripts/verify_reproducibility.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pandas as pd

from app.experiments import system_eval, traffic_profile
from app.ids.dataset import DatasetConfig, generate

TIMING_MARKERS = ("_ms", "ms_", "seconds", "cpu", "wall", "latency", "throughput", "_us",
                  "duration", "compute")  # fmt: skip


def _comparable(df: pd.DataFrame) -> pd.DataFrame:
    keep = [c for c in df.columns if not any(m in c.lower() for m in TIMING_MARKERS)
            or c in ("timestamp_ms", "delivered_ms", "t_ms", "start_ms", "end_ms",
                     "attack_start_ms", "attack_end_ms", "t_start_ms")]  # fmt: skip
    return df[keep].reset_index(drop=True)


def compare(a: Path, b: Path, rel: str) -> bool:
    da, db = pd.read_csv(a / rel), pd.read_csv(b / rel)
    ok = _comparable(da).equals(_comparable(db))
    print(f"  {'IDENTICAL' if ok else 'DIFFERENT':<10} {rel}  ({len(da)} rows)")
    return ok


def main() -> int:
    results = []
    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        d1, d2 = Path(t1), Path(t2)
        print("1) traffic profile (quick) twice, seed 7")
        for d in (d1, d2):
            traffic_profile.run(seed=7, quick=True, results_dir=d)
        results.append(compare(d1, d2, "raw/traffic_profile/packets.csv"))
        print("2) adaptive-framework showcase (quick) twice, seed 7")
        for d in (d1, d2):
            system_eval.showcase(seed=7, quick=True, results_dir=d)
        for rel in ("raw/showcase/trust_updates.csv", "raw/showcase/policy_decisions.csv",
                    "raw/showcase/ids_alerts.csv", "raw/showcase/packets.csv"):  # fmt: skip
            results.append(compare(d1, d2, rel))
        print("3) IDS dataset generation: sequential vs parallel, seed 3")
        tiny = DatasetConfig(seeds=(5,), kinds=("flooding", "replay", "spoofing"),
                             rates_pps=(10.0,), benign_runs_per_seed=1, duration_ms=15_000,
                             drone_counts=(6,))  # fmt: skip
        a = generate(tiny, base_seed=3, workers=1)
        b = generate(tiny, base_seed=3, workers=3)
        same = a.equals(b)
        print(f"  {'IDENTICAL' if same else 'DIFFERENT':<10} dataset ({len(a)} windows)")
        results.append(same)
    ok = all(results)
    print("\nREPRODUCIBILITY: " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
