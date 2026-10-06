"""Run the experiment suite and produce results/{raw,processed,tables,figures,reports}.

    python scripts/run_experiments.py                    # everything (several hours)
    python scripts/run_experiments.py --suite ids,showcase
    python scripts/run_experiments.py --quick            # fast smoke run -> results_quick/

Suites run in dependency order (the IDS suite trains the model used by the framework
suites). Every experiment saves its seed, configuration, environment, raw data,
processed data, metrics and a structured log; every table/figure has a provenance
sidecar naming its source data.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

from app.core.logging import configure_logging, get_logger
from app.experiments import (
    diagrams,
    final_report,
    ids_eval,
    puf_quality,
    scalability,
    stride_eval,
    system_eval,
    traffic_profile,
)
from app.experiments.recorder import REPO_ROOT
from app.experiments.scenario import Variant
from app.services.framework import MODEL_ENV

ORDER = ("puf", "auth", "traffic", "ids", "showcase", "stride", "comparison", "ablation",
         "sensitivity", "stress", "scalability", "diagrams", "report")  # fmt: skip
log = get_logger("run_experiments")


def suites(workers: int) -> dict[str, Callable[[int, bool, Path], object]]:
    from app.benchmarks import auth_benchmark  # noqa: PLC0415 - heavy import, only if needed

    stride_variants = [Variant.BASELINE, Variant.D2DAP, Variant.D2DAP_IDS, Variant.ADAPTIVE]

    def ids(s: int, q: bool, r: Path) -> object:
        return ids_eval.run(s, q, r, log=lambda m: log.info("ids.progress", msg=m))

    def stride(s: int, q: bool, r: Path) -> object:
        return stride_eval.run(s, q, r, variants=stride_variants, workers=1 if q else workers)

    def report(s: int, q: bool, r: Path) -> object:
        return final_report.build(r)

    return {
        "puf": puf_quality.run,
        "auth": auth_benchmark.run,
        "traffic": traffic_profile.run,
        "ids": ids,
        "showcase": system_eval.showcase,
        "stride": stride,
        "comparison": system_eval.baseline_comparison,
        "ablation": system_eval.ablation,
        "sensitivity": system_eval.sensitivity,
        "stress": system_eval.stress,
        "scalability": scalability.run,
        "diagrams": diagrams.run,
        "report": report,
    }  # fmt: skip


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--suite", default="all", help=f"comma list from {','.join(ORDER)}")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quick", action="store_true", help="small fast configuration")
    parser.add_argument("--results-dir", type=Path, default=None)
    parser.add_argument("--workers", type=int, default=max(1, min(6, (os.cpu_count() or 2) // 2)))
    args = parser.parse_args()

    results = args.results_dir or REPO_ROOT / ("results_quick" if args.quick else "results")
    results.mkdir(parents=True, exist_ok=True)
    # Worker processes inherit this: framework variants load the model trained here.
    os.environ[MODEL_ENV] = str(results / "models" / "ids_operational.joblib")
    configure_logging("INFO", log_file=results / "reports" / "run_experiments.log.jsonl")
    wanted = ORDER if args.suite == "all" else tuple(s.strip() for s in args.suite.split(","))
    unknown = set(wanted) - set(ORDER)
    if unknown:
        parser.error(f"unknown suites: {sorted(unknown)}")
    table = suites(args.workers)
    failures = []
    for name in ORDER:
        if name not in wanted:
            continue
        t0 = time.perf_counter()
        log.info("suite.start", suite=name, seed=args.seed, quick=args.quick)
        try:
            out = table[name](args.seed, args.quick, results)
        except Exception as exc:  # report and continue with the other suites
            log.error("suite.failed", suite=name, error=repr(exc))
            failures.append(name)
            continue
        log.info("suite.done", suite=name, seconds=round(time.perf_counter() - t0, 1),
                 output=str(out))  # fmt: skip
    print(f"\nResults in {results}" + (f"\nFAILED SUITES: {failures}" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
