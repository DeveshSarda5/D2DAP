"""Experiment: quality and cost of the SOFTWARE PUF models (Phase 3).

Measures, for the XOR-Arbiter model at several noise levels (with and without
majority voting) and for the ideal keyed-hash model:

* uniqueness, uniformity, reliability, bit aliasing (standard PUF metrics);
* software evaluation time per challenge (on this machine; NOT a hardware PUF latency).
"""

from __future__ import annotations

import time
from pathlib import Path

import pandas as pd

from app.core.rng import RandomStreams
from app.experiments.plotting import SERIES, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, ExperimentRecorder
from app.security.puf import PUF, XORArbiterPUF, make_puf, puf_quality

NAME = "puf_quality"


def _population(model: str, n: int, streams: RandomStreams, noise: float, votes: int) -> list[PUF]:
    if model == "ideal":
        return [make_puf("ideal", streams.numpy(f"puf:{i}")) for i in range(n)]
    return [
        XORArbiterPUF(streams.numpy(f"puf:{i}"), noise_sigma=noise, majority_votes=votes)
        for i in range(n)
    ]


def run(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    devices, n_ch, repeats = (6, 10, 3) if quick else (16, 40, 5)
    noise_levels = [0.0, 0.25, 0.5, 1.0, 2.0]
    config = {
        "devices": devices,
        "challenges": n_ch,
        "repeats": repeats,
        "noise_levels": noise_levels,
        "votes": [1, 5],
        "xor_k": 4,
        "stages": 128,
        "response_bits": 128,
    }
    rec = ExperimentRecorder(NAME, seed, config, results_dir)
    streams = RandomStreams(seed)
    ch_rng = streams.numpy("challenges")
    challenges = [ch_rng.bytes(16) for _ in range(n_ch)]

    rows = []
    settings = [("xor_arbiter", s, v) for s in noise_levels for v in (1, 5)] + [("ideal", 0.0, 1)]
    for model, noise, votes in settings:
        pufs = _population(model, devices, streams, noise, votes)
        q = puf_quality(pufs, challenges, repeats=repeats)
        t0 = time.perf_counter_ns()
        for c in challenges:
            pufs[0].evaluate(c)
        eval_us = (time.perf_counter_ns() - t0) / len(challenges) / 1e3
        rows.append(
            {
                "model": model,
                "noise_sigma": noise,
                "majority_votes": votes,
                "uniqueness": q.uniqueness,
                "uniformity": q.uniformity,
                "reliability": q.reliability,
                "bit_aliasing_std": q.bit_aliasing_std,
                "eval_time_us": eval_us,
            }
        )
    df = pd.DataFrame(rows)
    raw = rec.save_frame(df, "puf_quality.csv")
    rec.save_table(
        df.round(4),
        "table",
        [raw],
        "Software PUF quality (simulation; ideal: uniqueness 0.5, uniformity 0.5, reliability 1)",
    )

    arb = df[df.model == "xor_arbiter"]
    fig_path = rec.figure_path("reliability", [raw], "Software PUF reliability vs noise")
    with figure(fig_path, size=(6.0, 3.8)) as (fig, (ax,)):
        for i, votes in enumerate((1, 5)):
            sub = arb[arb.majority_votes == votes]
            ax.plot(
                sub.noise_sigma,
                sub.reliability,
                marker="o",
                color=SERIES[i],
                label=f"{votes} vote{'s' if votes > 1 else ''}",
            )
        ax.set_xlabel("Evaluation noise sigma (relative to stage-weight std)")
        ax.set_ylabel("Reliability (1 - intra-HD)")
        ax.set_title("Software XOR-Arbiter PUF: reliability vs. noise")
        ax.set_ylim(0, 1.02)
        ax.legend(title="Majority voting")
        note(fig, f"Our simulation result (software PUF model, not hardware). Seed {seed}.")
    rec.save_json([c.hex() for c in challenges], "challenges.json")
    return rec.finalize({"rows": len(df)})
