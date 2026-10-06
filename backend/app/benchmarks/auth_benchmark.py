"""Phase 5: authentication benchmarking framework.

Produces (all "Our Experimental Result" on the machine recorded in the manifest, unless
labelled Literature):

1. per-operation micro-benchmarks (T_PM, T_PA, T_H, T_ED, T_PUF, T_SSG, T_SSR, T_R, inv);
2. repeated full MAKA runs per security level and peer-resolution mode, with latency
   mean / median / std / P95 / P99, CPU time per authentication (batch-averaged; Windows
   process timers are too coarse for single runs), Python heap peak (tracemalloc),
   process RSS, throughput, bytes, messages and operation counts;
3. communication cost (measured bytes vs. the paper's theoretical bits);
4. an *estimate* of drone CPU cycles = our instrumented op counts x the paper's per-op
   cycle costs (clearly labelled Estimated);
5. PUF-noise sensitivity of authentication success.
"""

from __future__ import annotations

import time
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import psutil

from app.benchmarks import literature as lit
from app.benchmarks.stats import summarize
from app.core.rng import RandomStreams
from app.experiments.plotting import INK_2, SERIES, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, ExperimentRecorder
from app.security.crypto import IV_BYTES, TIMESTAMP_BYTES, CryptoSuite, SecurityLevel
from app.security.d2dap.config import D2DAPConfig, PUFConfig
from app.security.d2dap.service import AuthResult, D2DAPSystem
from app.security.puf import XORArbiterPUF
from app.security.secret_sharing import ShamirScheme

NAME = "authentication"
INTERRUPTION_FACTOR = 50
LEVELS = [SecurityLevel.L128, SecurityLevel.L192, SecurityLevel.L256]
#: Mapping of our op names to the paper's Table VIII symbols (mod_inv has no paper entry).
OP_TO_PAPER = {
    "point_mul": "point_mul",
    "point_add": "point_add",
    "hash": "hash",
    "sym_enc": "sym",
    "sym_dec": "sym",
    "puf": "puf",
    "ss_gen": "ss_gen",
    "ss_rec": "ss_rec",
    "rand": "rand",
}


@dataclass(frozen=True)
class BenchSettings:
    micro_reps: int
    trials: int
    warmup: int
    memory_trials: int
    n_drones: int
    noise_trials: int

    @classmethod
    def make(cls, quick: bool) -> BenchSettings:
        if quick:
            return cls(micro_reps=30, trials=20, warmup=3, memory_trials=5, n_drones=6,
                       noise_trials=6)  # fmt: skip
        return cls(micro_reps=300, trials=200, warmup=10, memory_trials=30, n_drones=10,
                   noise_trials=40)  # fmt: skip


# ---------------------------------------------------------------- micro benchmarks
def _time_us(fn: Callable[[], object], reps: int) -> list[float]:
    out = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        out.append((time.perf_counter_ns() - t0) / 1e3)
    return out


def micro_benchmark(level: SecurityLevel, streams: RandomStreams, reps: int) -> pd.DataFrame:
    """Time each primitive ``reps`` times (after one warm-up call each)."""
    suite = CryptoSuite(level, streams.crypto(f"micro:{level.value}"))
    sharing = ShamirScheme(suite.n, 2)
    poly = sharing.polynomial([suite.rand_scalar(), suite.rand_scalar()])
    Y = suite.mul_g(suite.rand_scalar())
    k = suite.rand_scalar()
    key = suite.rand_bytes(suite.params.aes_key_bytes)
    body = suite.rand_bytes(suite.hash_bytes + suite.scalar_bytes + TIMESTAMP_BYTES)
    blob = suite.encrypt(key, body)
    puf = XORArbiterPUF(streams.numpy(f"micro-puf:{level.value}"))
    challenge = bytes(16)
    shares = [sharing.share(poly, 11), sharing.share(poly, 23)]
    ops: dict[str, Callable[[], object]] = {
        "point_mul": lambda: suite.mul(Y, k),
        "point_mul_generator": lambda: suite.mul_g(k),
        "point_add": lambda: suite.add(Y, Y),
        "hash": lambda: suite.H(body),
        "sym_enc": lambda: suite.encrypt(key, body),
        "sym_dec": lambda: suite.decrypt(key, blob),
        "puf": lambda: puf.evaluate(challenge),
        "ss_gen": lambda: sharing.share(poly, 37),
        "ss_rec": lambda: sharing.reconstruct(shares),
        "rand": suite.rand_scalar,
        "mod_inv": lambda: suite.inv(k),
    }
    rows = []
    for name, fn in ops.items():
        fn()  # warm-up (e.g. generator precomputation)
        for i, us in enumerate(_time_us(fn, reps)):
            rows.append({"level": level.value, "op": name, "rep": i, "time_us": us})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- MAKA trials
def _system(
    level: SecurityLevel, mode: str, n: int, *, crp: int, seed: int, puf: PUFConfig | None = None
) -> tuple[D2DAPSystem, float]:
    cfg = D2DAPConfig(security_level=level, peer_resolution=mode, crp_count=crp,
                      puf=puf or PUFConfig())  # fmt: skip
    system = D2DAPSystem(cfg, RandomStreams(seed))
    t0 = time.perf_counter_ns()
    for i in range(n):
        system.enroll(f"D{i + 1}")
    reg_ms = (time.perf_counter_ns() - t0) / 1e6 / n
    return system, reg_ms


def _pairs(n: int, count: int, rng: np.random.Generator) -> list[tuple[str, str]]:
    out = []
    for _ in range(count):
        i, j = rng.choice(n, size=2, replace=False)
        out.append((f"D{i + 1}", f"D{j + 1}"))
    return out


def maka_trials(
    level: SecurityLevel, mode: str, s: BenchSettings, seed: int
) -> tuple[list[AuthResult], dict[str, float]]:
    """Run warm-up + ``trials`` timed authentications; return results and batch metrics."""
    total = s.warmup + s.trials + s.memory_trials
    system, reg_ms = _system(level, mode, s.n_drones, crp=total, seed=seed)
    pairs = _pairs(s.n_drones, total, np.random.default_rng(seed))
    t = 0
    for a, b in pairs[: s.warmup]:
        t += 10_000
        system.authenticate(a, b, t)
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    cpu0, wall0 = time.process_time_ns(), time.perf_counter_ns()
    results = []
    for a, b in pairs[s.warmup : s.warmup + s.trials]:
        t += 10_000
        results.append(system.authenticate(a, b, t))
    cpu_ns, wall_ns = time.process_time_ns() - cpu0, time.perf_counter_ns() - wall0
    rss1 = proc.memory_info().rss
    peaks = []
    for a, b in pairs[s.warmup + s.trials :]:
        t += 10_000
        tracemalloc.start()
        system.authenticate(a, b, t)
        peaks.append(tracemalloc.get_traced_memory()[1] / 1024)
        tracemalloc.stop()
    batch = {
        "cpu_ms_per_auth": cpu_ns / 1e6 / s.trials,
        "wall_ms_per_auth_batch": wall_ns / 1e6 / s.trials,
        "throughput_auth_per_s": s.trials / (wall_ns / 1e9),
        "heap_peak_kb_mean": float(np.mean(peaks)),
        "rss_mb_after": rss1 / 2**20,
        "rss_delta_mb": (rss1 - rss0) / 2**20,
        "registration_ms_per_drone": reg_ms,
        "success_rate": float(np.mean([r.success for r in results])),
    }
    return results, batch


# ---------------------------------------------------------------- PUF noise
def puf_noise_study(s: BenchSettings, seed: int) -> pd.DataFrame:
    rows = []
    for sigma in (0.0, 0.02, 0.05, 0.1, 0.25):
        for votes in (1, 5, 15):
            puf = PUFConfig(noise_sigma=sigma, majority_votes=votes)
            system, _ = _system(
                SecurityLevel.L128, "hint", 4, crp=s.noise_trials + 1, seed=seed, puf=puf
            )
            pairs = _pairs(4, s.noise_trials, np.random.default_rng(seed))
            res = [system.authenticate(a, b, (k + 1) * 10_000) for k, (a, b) in enumerate(pairs)]
            reasons = pd.Series([r.failure_reason for r in res if not r.success])
            rows.append({
                "noise_sigma": sigma,
                "majority_votes": votes,
                "trials": len(res),
                "success_rate": float(np.mean([r.success for r in res])),
                "dominant_failure": reasons.mode().iat[0] if len(reasons) else "",
            })  # fmt: skip
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- reporting helpers
def theoretical_bytes(level: SecurityLevel) -> int:
    """Our encoding: iv + |a| + |b| + |T| + |sigma1| + |sigma2| per message, x2."""
    suite = CryptoSuite(level, RandomStreams(0).crypto("t"))
    return 2 * (IV_BYTES + suite.hash_bytes + 3 * suite.scalar_bytes + TIMESTAMP_BYTES)


def _cell(df: pd.DataFrame, config: str, column: str) -> float:
    """Typed scalar accessor: value of ``column`` in the row whose ``config`` matches."""
    values = df.loc[df["config"] == config, column].to_numpy(dtype=float)
    return float(values[0])


def estimated_cycles(ops: dict[str, float], level: int) -> float:
    """ESTIMATE: our op counts x paper Table VIII drone cycles (mod_inv excluded)."""
    table = lit.OP_CYCLES_DRONE[level]
    return sum(ops.get(ours, 0.0) * table[paper] for ours, paper in OP_TO_PAPER.items())


def run(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    s = BenchSettings.make(quick)
    configs = [(lvl, "hint") for lvl in LEVELS] + [(SecurityLevel.L128, "trial")]
    rec = ExperimentRecorder(
        NAME, seed, {"settings": s.__dict__, "configs": [(c[0].value, c[1]) for c in configs],
                     "network_delay_ms": 0, "note": "latency = measured compute time only"},
        results_dir,
    )  # fmt: skip
    streams = RandomStreams(seed)

    # 1. micro benchmarks
    micro = pd.concat([micro_benchmark(lvl, streams, s.micro_reps) for lvl in LEVELS])
    micro_raw = rec.save_frame(micro, "micro_ops_raw.csv")
    micro_sum = (
        micro.groupby(["level", "op"])["time_us"]
        .apply(lambda x: pd.Series(summarize(list(x))))
        .unstack()
        .reset_index()
    )
    # Samples > 50x the median are host interruptions (e.g. OS suspend), not crypto cost.
    # They are KEPT in the raw data and in mean/std; robust statistics (median) are
    # used for derived figures, and the count is reported.
    micro_sum["host_interruptions"] = (
        micro.groupby(["level", "op"])["time_us"]
        .apply(lambda x: int((x > INTERRUPTION_FACTOR * x.median()).sum()))
        .to_numpy()
    )
    micro_proc = rec.save_frame(micro_sum, "micro_ops_summary.csv", kind="processed")

    # 2. MAKA trials
    all_rows, summary_rows = [], []
    for lvl, mode in configs:
        results, batch = maka_trials(lvl, mode, s, seed)
        label = f"D2DAP-{lvl.value}-{mode}"
        for r in results:
            all_rows.append({"config": label, "level": lvl.value, "mode": mode, **r.as_record()})
        lat = summarize([r.latency_ms for r in results], "latency_ms_")
        ops_i = pd.DataFrame([r.ops_initiator for r in results]).mean()
        ops_j = pd.DataFrame([r.ops_responder for r in results]).mean()
        summary_rows.append({
            "config": label, "level": lvl.value, "mode": mode, **lat, **batch,
            "messages": float(np.mean([r.messages for r in results])),
            "bytes": float(np.mean([r.total_bytes for r in results])),
            "rl_broadcast_bytes": float(np.mean([r.rl_broadcast_bytes for r in results])),
            "ops_total_per_auth": float(ops_i.sum() + ops_j.sum()),
            "point_mul_initiator": float(ops_i["point_mul"]),
            "point_mul_responder": float(ops_j["point_mul"]),
            "est_cycles_initiator": estimated_cycles(
                {str(k): float(v) for k, v in ops_i.items()}, lvl.value),
            "est_cycles_responder": estimated_cycles(
                {str(k): float(v) for k, v in ops_j.items()}, lvl.value),
        })  # fmt: skip
    trials_raw = rec.save_frame(pd.DataFrame(all_rows), "maka_trials_raw.csv")
    summary = pd.DataFrame(summary_rows)
    summ_path = rec.save_frame(summary, "maka_summary.csv", kind="processed")

    # Table 1: authentication performance
    t1 = summary[[
        "config", "latency_ms_mean", "latency_ms_median", "latency_ms_std", "latency_ms_p95",
        "latency_ms_p99", "cpu_ms_per_auth", "heap_peak_kb_mean", "messages", "bytes",
        "ops_total_per_auth", "throughput_auth_per_s",
    ]].round(3)  # fmt: skip
    rec.save_table(t1, "table1_performance", [trials_raw, summ_path],
                   "Table 1: D2DAP authentication performance (our measurement, software, "
                   f"{s.trials} trials, compute only)")  # fmt: skip

    # Table 2: communication cost (ours measured vs paper theoretical)
    t2 = pd.DataFrame([
        {
            "protocol": f"D2DAP-{lvl.value}",
            "messages": 2,
            "bytes_measured": int(_cell(summary, f"D2DAP-{lvl.value}-hint", "bytes")),
            "bits_measured": int(_cell(summary, f"D2DAP-{lvl.value}-hint", "bytes")) * 8,
            "bits_theoretical_our_encoding": theoretical_bytes(lvl) * 8,
            "bits_literature_paper_TableVII": lit.COMM_COST_BITS[lvl.value],
            "rl_broadcast_bits": int(
                _cell(summary, f"D2DAP-{lvl.value}-hint", "rl_broadcast_bytes")) * 8,
        }
        for lvl in LEVELS
    ])  # fmt: skip
    t2_path = rec.save_table(
        t2,
        "table2_communication",
        [trials_raw],
        "Table 2: communication cost per MAKA (measured vs Literature)",
    )

    # Estimated cycles vs paper Table IX (clearly an estimate)
    est = pd.DataFrame([
        {
            "level": lvl.value,
            "our_op_counts_x_paper_cycles_ESTIMATED": round(
                _cell(summary, f"D2DAP-{lvl.value}-hint", "est_cycles_initiator")),
            "paper_TableIX_per_drone_LITERATURE": lit.COMP_COST_PER_DRONE_CYCLES[lvl.value],
            "implied_point_mul_in_paper": round(
                lit.COMP_COST_PER_DRONE_CYCLES[lvl.value]
                / lit.OP_CYCLES_DRONE[lvl.value]["point_mul"], 2),
            "our_point_mul_count": _cell(
                summary, f"D2DAP-{lvl.value}-hint", "point_mul_initiator"),
        }
        for lvl in LEVELS
    ])  # fmt: skip
    rec.save_table(
        est,
        "cycles_estimate",
        [summ_path],
        "ESTIMATED drone cycles (our op counts x paper per-op cycles) vs Literature",
    )

    micro_tab = micro_sum[micro_sum.op.isin([*OP_TO_PAPER, "mod_inv", "point_mul_generator"])]
    micro_cols = ["level", "op", "mean", "median", "std", "p95", "p99", "host_interruptions"]
    rec.save_table(
        micro_tab[micro_cols].round(2),
        "micro_ops",
        [micro_raw],
        "Per-operation software cost (microseconds, ours)",
    )

    # 5. PUF noise sensitivity
    noise = puf_noise_study(s, seed)
    noise_path = rec.save_frame(noise, "puf_noise_auth.csv")
    rec.save_table(
        noise,
        "puf_noise",
        [noise_path],
        "Authentication success vs software-PUF noise (D2DAP has no error correction)",
    )

    _figures(
        rec,
        seed,
        _ReportData(pd.DataFrame(all_rows), trials_raw, summary, summ_path, t2, t2_path,
                    micro_sum, micro_proc, noise, noise_path),
    )  # fmt: skip
    return rec.finalize({
        "success_rate_min": float(summary["success_rate"].min()),
        "latency_ms_mean_L128_hint": _cell(summary, "D2DAP-128-hint", "latency_ms_mean"),
    })  # fmt: skip


@dataclass(frozen=True)
class _ReportData:
    """Frames and their saved paths needed to draw the Phase 5 figures."""

    trials: pd.DataFrame
    trials_raw: Path
    summary: pd.DataFrame
    summ_path: Path
    t2: pd.DataFrame
    t2_path: Path
    micro_sum: pd.DataFrame
    micro_proc: Path
    noise: pd.DataFrame
    noise_path: Path


def _figures(rec: ExperimentRecorder, seed: int, d: _ReportData) -> None:
    trials, trials_raw, summary, summ_path = d.trials, d.trials_raw, d.summary, d.summ_path
    t2, t2_path, micro_sum, micro_proc = d.t2, d.t2_path, d.micro_sum, d.micro_proc
    noise, noise_path = d.noise, d.noise_path
    caption = f"Our simulation result (software, this machine). Seed {seed}."
    # Authentication latency distribution
    path = rec.figure_path("latency", [trials_raw], "D2DAP authentication latency")
    with figure(path, size=(7, 4)) as (fig, (ax,)):
        labels = list(summary.config)
        data = [trials.loc[trials.config == c, "latency_ms"].to_numpy() for c in labels]
        bp = ax.boxplot(data, patch_artist=True, widths=0.5, showfliers=True,
                        medianprops={"color": INK_2, "linewidth": 1.5})  # fmt: skip
        for patch in bp["boxes"]:
            patch.set_facecolor(SERIES[0])
            patch.set_alpha(0.55)
        ax.set_xticks(range(1, len(labels) + 1), [lab.replace("D2DAP-", "") for lab in labels])
        ax.set_ylabel("Latency per authentication (ms)")
        ax.set_xlabel("Security level - peer resolution")
        ax.set_title("D2DAP mutual authentication latency (compute only)")
        note(fig, caption)
    # Communication cost: ours vs literature
    path = rec.figure_path("communication", [t2_path], "Communication cost vs paper")
    with figure(path, size=(6.5, 4)) as (fig, (ax,)):
        x = np.arange(len(t2))
        ax.bar(x - 0.2, t2.bits_measured, 0.38, color=SERIES[0], label="Measured (ours)")
        ax.bar(x + 0.2, t2.bits_literature_paper_TableVII, 0.38, color=SERIES[1],
               label="Paper Table VII (Literature)")  # fmt: skip
        for i, (a, b) in enumerate(zip(t2.bits_measured, t2.bits_literature_paper_TableVII,
                                       strict=True)):  # fmt: skip
            ax.text(i - 0.2, a, f"{a}", ha="center", va="bottom", fontsize=8, color=INK_2)
            ax.text(i + 0.2, b, f"{b}", ha="center", va="bottom", fontsize=8, color=INK_2)
        ax.set_xticks(x, [p.replace("D2DAP-", "") + "-bit" for p in t2.protocol])
        ax.set_ylabel("Bits per MAKA (2 messages)")
        ax.set_title("D2DAP communication cost")
        ax.legend()
        note(fig, caption + " Paper bits counted by parameter length; ours are serialized bytes.")
    # Computational cost breakdown: mean op time x op count per side
    path = rec.figure_path(
        "computation_breakdown", [micro_proc, summ_path], "Compute cost breakdown by primitive"
    )
    hint = summary[summary["mode"] == "hint"]
    counts = trials[trials["mode"] == "hint"].groupby("level")[
        [f"ops_initiator_{k}" for k in OP_TO_PAPER]].mean()  # fmt: skip
    with figure(path, size=(7, 4)) as (fig, (ax,)):
        left = np.zeros(len(hint))
        for idx, op in enumerate(["point_mul", "puf", "sym_enc", "sym_dec", "hash", "point_add",
                                  "ss_rec", "rand"]):  # fmt: skip
            vals = []
            for lvl in hint.level:
                mean_us = micro_sum.loc[(micro_sum.level == lvl) & (micro_sum.op == op),
                                        "median"].iat[0]  # fmt: skip
                vals.append(mean_us * counts.loc[lvl, f"ops_initiator_{op}"] / 1000)
            ax.barh([f"{lv}-bit" for lv in hint.level], vals, left=left,
                    color=SERIES[idx % len(SERIES)], label=op, height=0.55)  # fmt: skip
            left += np.array(vals)
        ax.set_xlabel("Initiator compute time (ms) = op count x median op time")
        ax.set_title("Where D2DAP's computation goes (initiator side)")
        ax.legend(ncols=4, loc="upper center", bbox_to_anchor=(0.5, -0.2))
        note(fig, caption)
    # PUF noise
    path = rec.figure_path("puf_noise", [noise_path], "Auth success vs PUF noise")
    with figure(path, size=(6, 3.8)) as (fig, (ax,)):
        for i, votes in enumerate(sorted(noise.majority_votes.unique())):
            sub = noise[noise.majority_votes == votes]
            ax.plot(sub.noise_sigma, sub.success_rate * 100, marker="o", color=SERIES[i],
                    label=f"{votes} vote(s)")  # fmt: skip
        ax.set_xlabel("Software PUF evaluation noise sigma")
        ax.set_ylabel("Authentication success (%)")
        ax.set_ylim(-3, 103)
        ax.set_title("D2DAP success vs PUF noise (no error correction)")
        ax.legend(title="Majority voting")
        note(fig, caption)
