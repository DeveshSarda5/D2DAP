"""Phase 6 experiment: characterise normal (benign) traffic of a D2DAP-secured swarm.

Saves the full packet log (structured representation used later for feature
extraction), per-protocol statistics, a rate time series and two figures.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from app.experiments.plotting import SERIES, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, ExperimentRecorder
from app.services.swarm import build_secure_swarm
from app.simulation.config import SimulationConfig
from app.simulation.traffic_log import rate_timeseries, traffic_summary

NAME = "traffic_profile"
PROTOCOL_ORDER = ["telemetry", "heartbeat", "video", "command", "auth_request",
                  "auth_response", "rl_broadcast"]  # fmt: skip


def run(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    drones, seconds = (6, 30) if quick else (10, 120)
    sim = SimulationConfig(num_drones=drones)
    rec = ExperimentRecorder(NAME, seed, {"simulation": sim, "duration_s": seconds}, results_dir)
    sw = build_secure_swarm(sim, seed=seed)
    sw.run(seconds * 1000)
    df = sw.traffic_log.to_frame()
    raw = rec.save_frame(df, "packets.csv")
    summary = traffic_summary(df, seconds)
    summ = rec.save_frame(summary, "protocol_summary.csv", kind="processed")
    rec.save_table(
        summary.round(3),
        "summary",
        [raw],
        f"Normal traffic profile ({drones} drones, {seconds} s, simulation)",
    )
    ts = rate_timeseries(df, 1000)
    ts_path = rec.save_frame(ts.reset_index(), "rate_timeseries.csv", kind="processed")

    path = rec.figure_path("rates", [ts_path], "Packet rate over time by protocol")
    with figure(path, size=(7.5, 4)) as (fig, (ax,)):
        cols = [c for c in PROTOCOL_ORDER if c in ts.columns]
        for i, col in enumerate(cols[:5]):
            ax.plot(ts.index, ts[col], color=SERIES[i], linewidth=1.6, label=col)
        ax.set_xlabel("Simulation time (s)")
        ax.set_ylabel("Packets per second (all receivers)")
        ax.set_title("Benign swarm traffic: periodic, bursty and on-demand auth")
        ax.legend(ncols=3)
        note(fig, f"Our simulation result. {drones} drones, seed {seed}.")
    path = rec.figure_path("sizes", [raw], "Packet size distribution by protocol")
    with figure(path, size=(7, 3.8)) as (fig, (ax,)):
        bins = np.linspace(0, 1300, 53).tolist()
        for i, proto in enumerate(["telemetry", "heartbeat", "video", "auth_request"]):
            sizes = df.loc[df.protocol == proto, "size_bytes"]
            if len(sizes):
                ax.hist(sizes, bins=bins, color=SERIES[i], alpha=0.75, label=proto)
        ax.set_yscale("log")
        ax.set_xlabel("Packet size on the wire (bytes, incl. AEAD tag)")
        ax.set_ylabel("Packets (log scale)")
        ax.set_title("Packet size distribution")
        ax.legend()
        note(fig, f"Our simulation result. Seed {seed}.")
    c = sw.coordinator.counters
    return rec.finalize({
        "packets": len(df),
        "auth_attempts": c.attempts,
        "auth_success": c.successes,
        "auth_failures": dict(c.by_reason),
        "summary_file": str(summ),
    })  # fmt: skip
