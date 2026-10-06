"""Phase 17: scalability with swarm size (5 ... 100 drones), measured sequentially.

For each N:

1. **D2DAP latency** over random pairs in an N-drone network, for ``hint`` and ``trial``
   peer resolution (trial decryption is O(N): observation O4).
2. **Full adaptive framework** run (benign swarm + one insider flooding attack), with the
   flight area scaled as sqrt(N) so node density stays constant. Measured: simulation
   throughput (packet receptions processed per wall-second), monitor latency per window,
   IDS inference time, trust-update latency, CPU time, peak RSS, security communication
   overhead per drone, and detection latency of the attack.

All timings are software measurements on the machine in the manifest.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import psutil

from app.benchmarks.stats import summarize
from app.core.rng import RandomStreams
from app.experiments.plotting import SERIES, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, ExperimentRecorder
from app.experiments.scenario import ScenarioConfig, Variant, run_attack_scenario
from app.security.d2dap.config import D2DAPConfig
from app.security.d2dap.service import D2DAPSystem
from app.services.monitor import SecurityMonitor

NAME = "scalability"
SIZES = (5, 10, 25, 50, 100)


def auth_latency(n: int, mode: str, trials: int, seed: int) -> dict[str, float]:
    system = D2DAPSystem(D2DAPConfig(peer_resolution=mode, crp_count=trials + 2),
                         RandomStreams(seed))  # fmt: skip
    for i in range(n):
        system.enroll(f"D{i + 1}")
    rng = np.random.default_rng(seed)
    lat, pm = [], []
    for k in range(trials):
        i, j = rng.choice(n, size=2, replace=False)
        r = system.authenticate(f"D{i + 1}", f"D{j + 1}", (k + 1) * 10_000)
        lat.append(r.latency_ms)
        pm.append(r.ops_responder["point_mul"])
    return {**summarize(lat, "auth_latency_ms_"), "responder_point_mul_mean": float(np.mean(pm))}


def framework_run(n: int, seed: int, duration_ms: int) -> dict[str, Any]:
    cfg = ScenarioConfig(num_drones=n, duration_ms=duration_ms,
                         attack_start_ms=duration_ms // 3, attack_duration_ms=duration_ms // 2,
                         area_m=300.0 * (n / 10) ** 0.5)  # fmt: skip
    cfg = replace(cfg, target=f"D{min(3, n)}")
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    cpu0, w0 = time.process_time(), time.perf_counter()
    res = run_attack_scenario(Variant.ADAPTIVE, "flooding", cfg, seed)
    wall, cpu = time.perf_counter() - w0, time.process_time() - cpu0
    mon = next(e for e in res.extensions if isinstance(e, SecurityMonitor))
    df = res.traffic()
    first_flag = [d.t_ms for d in mon.policy.decisions
                  if d.drone_id == cfg.target and d.t_ms >= cfg.attack_start_ms]  # fmt: skip
    sec = df[df.protocol.isin(["auth_request", "auth_response", "rl_broadcast", "trust_report",
                               "policy_notice"])].drop_duplicates("packet_id")  # fmt: skip
    dur_s = duration_ms / 1000
    updates = max(1, mon.stats.trust_updates)
    return {
        "receptions": len(df),
        "wall_s": wall,
        "cpu_s": cpu,
        "sim_throughput_receptions_per_wall_s": len(df) / wall,
        "rss_mb": proc.memory_info().rss / 2**20,
        "rss_delta_mb": (proc.memory_info().rss - rss0) / 2**20,
        "monitor_ms_per_window_mean": float(np.mean(mon.stats.processing_ms)),
        "monitor_ms_per_window_p95": float(np.percentile(mon.stats.processing_ms, 95)),
        "ids_ms_per_window_mean": float(np.mean(mon.stats.ids_ms)),
        "trust_policy_ms_per_window_mean": float(np.mean(mon.stats.trust_ms)),
        "trust_update_us": float(np.sum(mon.stats.trust_ms)) / updates * 1000,
        "security_bytes_per_s": float(sec.size_bytes.sum()) / dur_s,
        "security_bytes_per_s_per_drone": float(sec.size_bytes.sum()) / dur_s / n,
        "auth_compute_ms_per_s": sum(e.compute_ms for e in res.auth_events) / dur_s,
        "detection_ms": float(min(first_flag) - cfg.attack_start_ms) if first_flag else np.nan,
        "attack_mitigation_rate": 1
        - res.evidence.packets_accepted / max(1, res.evidence.packets_sent),
    }


def run(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    sizes = (5, 10) if quick else SIZES
    trials, duration = (5, 20_000) if quick else (30, 30_000)
    rec = ExperimentRecorder(NAME, seed, {"sizes": sizes, "auth_trials": trials,
                                          "framework_duration_ms": duration,
                                          "execution": "sequential"}, results_dir)  # fmt: skip
    rows: list[dict[str, Any]] = []
    for n in sizes:
        row: dict[str, Any] = {"drones": n}
        for mode in ("hint", "trial"):
            row |= {f"{mode}_{k}": v for k, v in auth_latency(n, mode, trials, seed).items()}
        row |= framework_run(n, seed, duration)
        rows.append(row)
    df = pd.DataFrame(rows)
    raw = rec.save_frame(df, "scalability.csv")
    t7 = df[["drones", "hint_auth_latency_ms_mean", "trial_auth_latency_ms_mean",
             "trial_responder_point_mul_mean", "cpu_s", "rss_mb",
             "sim_throughput_receptions_per_wall_s", "monitor_ms_per_window_mean",
             "trust_update_us", "detection_ms",
             "security_bytes_per_s_per_drone"]].round(3)  # fmt: skip
    rec.save_table(t7, "table7", [raw], "Table 7: scalability (our software measurement)")
    _figure(rec, df, raw, seed)
    return rec.finalize({"sizes": list(sizes)})


def _figure(rec: ExperimentRecorder, df: pd.DataFrame, raw: Path, seed: int) -> None:
    path = rec.figure_path("scalability", [raw], "Scalability with swarm size")
    panels = [
        (["hint_auth_latency_ms_mean", "trial_auth_latency_ms_mean"],
         ["D2DAP, hint", "D2DAP, trial decryption"], "Auth latency (ms)"),
        (["monitor_ms_per_window_mean", "ids_ms_per_window_mean"],
         ["monitor total", "IDS inference"], "Processing per 1 s window (ms)"),
        (["trust_update_us"], ["per trust update"], "Trust update latency (us)"),
        (["security_bytes_per_s_per_drone"], ["per drone"], "Security overhead (B/s)"),
    ]  # fmt: skip
    with figure(path, nrows=2, ncols=2, size=(10, 6.8)) as (fig, axes):
        for ax, (cols, labels, ylabel) in zip(axes, panels, strict=True):
            for i, (c, lab) in enumerate(zip(cols, labels, strict=True)):
                ax.plot(df.drones, df[c], marker="o", color=SERIES[i], label=lab)
            ax.set_xscale("log")
            ax.set_xticks(df.drones, [str(v) for v in df.drones])
            ax.set_xlabel("Drones in swarm")
            ax.set_ylabel(ylabel)
            ax.legend(fontsize=8)
        fig.suptitle("Scalability of D2DAP and the adaptive framework", fontweight="bold")
        note(fig, f"Our software measurement, sequential runs, seed {seed}.")
