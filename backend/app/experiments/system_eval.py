"""Experiment driver for Phases 14-16: showcase run, baseline comparison, ablation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from matplotlib.patches import Patch

from app.experiments.comparison import (
    ABLATIONS_PHASE16,
    SYSTEM_LABELS,
    SYSTEMS_PHASE15,
    execute,
    per_attack,
    plan,
    summarize,
)
from app.experiments.plotting import INK_2, MUTED, SERIES, STATUS, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, ExperimentRecorder
from app.experiments.scenario import ScenarioConfig, Variant, run_attack_scenario
from app.models.enums import SecurityState
from app.services.monitor import SecurityMonitor

STATE_COLORS = {
    "normal": STATUS["good"], "monitor": "#9ec5f4", "restrict": STATUS["warning"],
    "reauthenticate": STATUS["serious"], "quarantine": STATUS["critical"],
}  # fmt: skip


def _cfg(quick: bool) -> ScenarioConfig:
    if quick:
        return ScenarioConfig(num_drones=8, duration_ms=40_000, attack_start_ms=8_000,
                              attack_duration_ms=24_000)  # fmt: skip
    return ScenarioConfig()


def _workers() -> int:
    return max(1, min(6, (os.cpu_count() or 2) // 2))


# ---------------------------------------------------------------- Phase 14 showcase
@dataclass(frozen=True)
class _Showcase:
    """Recorded showcase run data used by the three figures."""

    rec: ExperimentRecorder
    cfg: ScenarioConfig
    trust: pd.DataFrame
    decisions: pd.DataFrame
    trust_path: Path
    decisions_path: Path
    seed: int

    @property
    def start(self) -> float:
        return self.cfg.attack_start_ms / 1000

    @property
    def end(self) -> float:
        return (self.cfg.attack_start_ms + self.cfg.attack_duration_ms) / 1000

    @property
    def others(self) -> list[str]:
        return [d for d in sorted(self.trust.drone_id.unique()) if d != self.cfg.target][:3]

    @property
    def caption(self) -> str:
        return (f"Our simulation result: insider flooding by {self.cfg.target} "
                f"(t={self.start:.0f}-{self.end:.0f} s), seed {self.seed}.")  # fmt: skip


def showcase(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    """One fully recorded end-to-end run: insider flooding against the full framework."""
    cfg = _cfg(quick)
    rec = ExperimentRecorder("showcase", seed, {"scenario": cfg.__dict__, "attack": "flooding",
                                                "variant": "adaptive"}, results_dir)  # fmt: skip
    res = run_attack_scenario(Variant.ADAPTIVE, "flooding", cfg, seed)
    mon = next(e for e in res.extensions if isinstance(e, SecurityMonitor))
    trust, dec = mon.trust_frame(), mon.decisions_frame()
    sc = _Showcase(rec, cfg, trust, dec, rec.save_frame(trust, "trust_updates.csv"),
                   rec.save_frame(dec, "policy_decisions.csv"), seed)  # fmt: skip
    rec.save_frame(mon.alerts_frame(), "ids_alerts.csv")
    rec.save_frame(res.traffic(), "packets.csv")
    rec.save_json(res.evidence.as_record(), "attack_evidence.json")
    _fig_trust(sc)
    _fig_probability(sc)
    _fig_timeline(sc)
    target_states: list[str] = (
        dec[dec.drone_id == cfg.target].new_state.tolist() if len(dec) else []
    )
    return rec.finalize({"decisions": len(dec), "alerts": len(mon.alerts),
                         "max_state_target": max((SecurityState(s).severity
                                                  for s in target_states), default=0)})  # fmt: skip


def _fig_trust(sc: _Showcase) -> None:
    trust, target = sc.trust, sc.cfg.target
    path = sc.rec.figure_path("trust_over_time", [sc.trust_path, sc.decisions_path],
                              "Trust score over time")  # fmt: skip
    with figure(path, size=(8, 4.2)) as (fig, (ax,)):
        ax.axvspan(sc.start, sc.end, color="#f0efec", label="attack active")
        for y, lab in ((0.8, "NORMAL"), (0.6, "MONITOR"), (0.4, "RESTRICT"), (0.2, "RE-AUTH")):
            ax.axhline(y, color=MUTED, linewidth=0.8, linestyle=":")
            ax.text(sc.cfg.duration_ms / 1000, y, f" {lab}", va="bottom", ha="right",
                    fontsize=7, color=MUTED)  # fmt: skip
        sub = trust[trust.drone_id == target]
        ax.plot(sub.t_ms / 1000, sub.new, color=SERIES[1], label=f"{target} (compromised)")
        for i, d in enumerate(sc.others):
            s = trust[trust.drone_id == d]
            ax.plot(s.t_ms / 1000, s.new, color=SERIES[[0, 2, 6][i]], linewidth=1.4,
                    label=f"{d} (honest)")  # fmt: skip
        ax.set_ylim(0, 1.02)
        ax.set_xlabel("Simulation time (s)")
        ax.set_ylabel("Trust score")
        ax.set_title("Continuous trust: compromised insider vs honest drones")
        ax.legend(loc="lower left", ncols=2)
        note(fig, sc.caption)


def _fig_probability(sc: _Showcase) -> None:
    trust, target = sc.trust, sc.cfg.target
    path = sc.rec.figure_path("attack_probability", [sc.trust_path],
                              "IDS attack probability over time")  # fmt: skip
    with figure(path, size=(8, 3.6)) as (fig, (ax,)):
        ax.axvspan(sc.start, sc.end, color="#f0efec")
        sub = trust[(trust.drone_id == target) & trust.e_attack_prob.notna()]
        ax.plot(sub.t_ms / 1000, sub.e_attack_prob, color=SERIES[1], label=target)
        for i, d in enumerate(sc.others[:2]):
            s = trust[(trust.drone_id == d) & trust.e_attack_prob.notna()]
            ax.plot(s.t_ms / 1000, s.e_attack_prob, color=SERIES[[0, 2][i]], linewidth=1.2,
                    label=d)  # fmt: skip
        ax.axhline(0.5, color=MUTED, linestyle=":", linewidth=0.8)
        ax.set_ylim(-0.02, 1.02)
        ax.set_xlabel("Simulation time (s)")
        ax.set_ylabel("P(attack) per 1 s window")
        ax.set_title("ML IDS attack probability")
        ax.legend(loc="upper left")
        note(fig, sc.caption)


def _fig_timeline(sc: _Showcase) -> None:
    dec, duration = sc.decisions, sc.cfg.duration_ms / 1000
    path = sc.rec.figure_path("response_timeline", [sc.decisions_path],
                              "Adaptive response timeline")  # fmt: skip
    drones = [sc.cfg.target, *sc.others]
    with figure(path, size=(8, 2.8)) as (fig, (ax,)):
        for row_i, d in enumerate(drones):
            changes = dec[dec.drone_id == d].sort_values("t_ms") if len(dec) else dec
            t_prev, st_prev = 0.0, "normal"
            for _, ch in changes.iterrows():
                ax.barh(row_i, ch.t_ms / 1000 - t_prev, left=t_prev, height=0.6,
                        color=STATE_COLORS[st_prev])  # fmt: skip
                t_prev, st_prev = ch.t_ms / 1000, ch.new_state
            ax.barh(row_i, duration - t_prev, left=t_prev, height=0.6, color=STATE_COLORS[st_prev])
        ax.set_yticks(range(len(drones)), drones)
        ax.invert_yaxis()
        ax.axvline(sc.start, color=INK_2, linewidth=1)
        ax.axvline(sc.end, color=INK_2, linewidth=1, linestyle="--")
        handles = [Patch(color=c, label=s.upper()) for s, c in STATE_COLORS.items()]
        ax.legend(handles=handles, ncols=5, loc="upper center", bbox_to_anchor=(0.5, -0.35),
                  fontsize=8)  # fmt: skip
        ax.set_xlabel("Simulation time (s)  (solid line: attack start, dashed: attack end)")
        ax.set_title("Security state per drone (policy decisions)")
        ax.grid(axis="y", visible=False)
        note(fig, sc.caption)


# ---------------------------------------------------------------- Phases 15/16
def _bars(rec: ExperimentRecorder, name: str, summary: pd.DataFrame, src: Path, *,
          title: str, seed: int) -> None:  # fmt: skip
    metrics = [("detection_rate", "Detection rate"), ("mitigation_rate", "Mitigation rate"),
               ("fpr_flag_rate", "False-positive flag rate"),
               ("disruption_rate", "Benign disruption rate")]  # fmt: skip
    path = rec.figure_path(name, [src], title)
    with figure(path, nrows=1, ncols=4, size=(13, 3.8)) as (fig, axes):
        for ax, (col, label) in zip(axes, metrics, strict=True):
            vals = summary[col].to_numpy(dtype=float)
            ax.barh(range(len(summary)), vals, color=SERIES[: len(summary)])
            for i, v in enumerate(vals):
                ax.text(v, i, f" {v:.3f}", va="center", fontsize=8, color=INK_2)
            ax.set_yticks(range(len(summary)), [str(v) for v in summary.variant])
            ax.invert_yaxis()
            top = float(np.nanmax(vals)) if len(vals) else 0.0
            is_rate = col in ("detection_rate", "mitigation_rate")
            ax.set_xlim(0, max(1.0, top * 1.25) if is_rate else max(0.02, top * 1.4))
            ax.set_title(label, fontsize=10)
        fig.suptitle(title, fontweight="bold")
        note(fig, f"Our simulation result, mean over attacks x seeds (base seed {seed}).")


def _run_suite(name: str, variants: tuple[Variant, ...], *, seed: int, quick: bool,
               results_dir: Path, title: str) -> Path:  # fmt: skip
    cfg = _cfg(quick)
    seeds = [seed] if quick else [seed, seed + 1, seed + 2]
    rec = ExperimentRecorder(name, seed, {"scenario": cfg.__dict__, "seeds": seeds,
                                          "variants": [v.value for v in variants]},
                             results_dir)  # fmt: skip
    raw = execute(plan(variants, seeds, cfg), 1 if quick else _workers())
    raw_path = rec.save_frame(raw, "runs.csv")
    _report_suite(rec, raw, raw_path, variants, title=title, seed=seed)
    return rec.finalize({"runs": len(raw)})


SUMMARY_COLUMNS = ["system", "detection_rate", "fpr_flag_rate", "disruption_rate", "framed_rate",
                   "fnr", "detection_ms_median", "response_ms_median", "mitigation_rate",
                   "collateral_rate", "monitor_ms_per_window", "security_bytes_per_s"]  # fmt: skip


def _report_suite(rec: ExperimentRecorder, raw: pd.DataFrame, raw_path: Path,
                  variants: tuple[Variant, ...], *, title: str, seed: int) -> None:  # fmt: skip
    summary = summarize(raw)
    s_path = rec.save_frame(summary, "summary.csv", kind="processed")
    rec.save_table(summary[SUMMARY_COLUMNS].round(4), "table", [raw_path, s_path], title)
    for metric in ("mitigation_rate", "detected", "detection_ms", "max_attacker_state"):
        pa = per_attack(raw, metric)
        pa = pa[[v.value for v in variants if v.value in pa.columns]]
        p = rec.save_frame(pa.reset_index(), f"per_attack_{metric}.csv", kind="processed")
        rec.save_table(pa.round(3).reset_index(), f"per_attack_{metric}", [p],
                       f"{title}: per-attack {metric}")  # fmt: skip
    _bars(rec, "comparison", summary, s_path, title=title, seed=seed)
    _heatmap(rec, raw, raw_path, variants, seed)


def rebuild_tables(results_dir: Path = DEFAULT_RESULTS, seed: int = 42) -> None:
    """Recompute tables/figures of the comparison and ablation suites from their recorded
    raw ``runs.csv`` (no re-simulation; raw data is the source of truth)."""
    import json  # noqa: PLC0415

    for name, variants, title in (
        ("baseline_comparison", SYSTEMS_PHASE15, "Table 6: adaptive framework vs baselines (A-D)"),
        ("ablation", ABLATIONS_PHASE16, "Ablation study of the adaptive framework"),
    ):
        raw_path = results_dir / "raw" / name / "runs.csv"
        manifest = results_dir / "raw" / name / "manifest.json"
        rec = ExperimentRecorder(name, seed, json.loads(manifest.read_text(encoding="utf-8"))
                                 ["config"], results_dir)  # fmt: skip
        _report_suite(rec, pd.read_csv(raw_path), raw_path, variants, title=title, seed=seed)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data.setdefault("notes", []).append("tables/figures rebuilt from runs.csv (framed_rate)")
        manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _heatmap(rec: ExperimentRecorder, raw: pd.DataFrame, raw_path: Path,
             variants: tuple[Variant, ...], seed: int) -> None:  # fmt: skip
    from matplotlib.colors import LinearSegmentedColormap  # noqa: PLC0415

    pa = per_attack(raw, "mitigation_rate")
    pa = pa[[v.value for v in variants if v.value in pa.columns]]
    grid = pa.to_numpy(dtype=float)
    cmap = LinearSegmentedColormap.from_list("seq", ["#fcfcfb", "#9ec5f4", "#3987e5", "#184f95"])
    path = rec.figure_path("mitigation_heatmap", [raw_path], "Mitigation rate per attack/system")
    with figure(path, size=(1.6 * len(pa.columns) + 3, 5)) as (fig, (ax,)):
        im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto")
        ax.set_xticks(range(len(pa.columns)), pa.columns, rotation=30, ha="right")
        ax.set_yticks(range(len(pa.index)), pa.index)
        ax.grid(False)
        for i in range(grid.shape[0]):
            for j in range(grid.shape[1]):
                if not np.isnan(grid[i, j]):
                    ax.text(j, i, f"{grid[i, j]:.2f}", ha="center", va="center", fontsize=8,
                            color="#ffffff" if grid[i, j] > 0.6 else "#0b0b0b")  # fmt: skip
        fig.colorbar(im, ax=ax, fraction=0.04)
        ax.set_title("Mitigation rate (share of attack packets not accepted)")
        note(fig, f"Our simulation result, mean over seeds (base seed {seed}).")


def baseline_comparison(seed: int = 42, quick: bool = False,
                        results_dir: Path = DEFAULT_RESULTS) -> Path:  # fmt: skip
    return _run_suite("baseline_comparison", SYSTEMS_PHASE15, seed=seed, quick=quick,
                      results_dir=results_dir,
                      title="Table 6: adaptive framework vs baselines (A-D)")  # fmt: skip


def ablation(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    return _run_suite("ablation", ABLATIONS_PHASE16, seed=seed, quick=quick,
                      results_dir=results_dir,
                      title="Ablation study of the adaptive framework")  # fmt: skip


#: One-at-a-time sensitivity settings (label, trust overrides, policy overrides).
SENSITIVITY: tuple[tuple[str, dict[str, float], dict[str, float]], ...] = (
    ("default", {}, {}),
    ("bands -0.1", {}, {"normal": 0.70, "monitor": 0.50, "restrict": 0.30, "reauthenticate": 0.10}),
    ("bands +0.1", {}, {"normal": 0.90, "monitor": 0.70, "restrict": 0.50, "reauthenticate": 0.30}),
    ("w_ml_attack 1.5", {"w_ml_attack": 1.5}, {}),
    ("w_ml_attack 4.5", {"w_ml_attack": 4.5}, {}),
    ("decay 0.75", {"decay": 0.75}, {}),
    ("decay 0.95", {"decay": 0.95}, {}),
)
SENSITIVITY_KINDS = ("flooding", "privilege_escalation", "abnormal", "spoofing", "benign")


def sensitivity(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    """Phase 13/16: experimental evaluation of the policy thresholds and trust weights."""
    from app.experiments.comparison import Job  # noqa: PLC0415

    cfg = _cfg(quick)
    seeds = [seed] if quick else [seed, seed + 1]
    meta = {"scenario": cfg.__dict__, "seeds": seeds, "settings": SENSITIVITY,
            "kinds": SENSITIVITY_KINDS}  # fmt: skip
    rec = ExperimentRecorder("sensitivity", seed, meta, results_dir)
    jobs = [Job("adaptive", k, s, cfg, (), tuple(t.items()), tuple(p.items()), label)
            for label, t, p in SENSITIVITY for s in seeds for k in SENSITIVITY_KINDS]  # fmt: skip
    raw = execute(jobs, 1 if quick else _workers())
    raw_path = rec.save_frame(raw, "runs.csv")
    att = raw[raw.kind != "benign"]
    table = pd.DataFrame([
        {"setting": label,
         "detection_rate": att[att.config_label == label].detected.mean(),
         "detection_ms_median": att[att.config_label == label].detection_ms.median(),
         "mitigation_rate": att[att.config_label == label].mitigation_rate.mean(),
         "fpr_flag_rate": raw[raw.config_label == label].flag_rate.mean(),
         "disruption_rate": raw[raw.config_label == label].disruption_rate.mean(),
         "collateral_rate": raw[raw.config_label == label].collateral_rate.mean()}
        for label, _, _ in SENSITIVITY
    ])  # fmt: skip
    t_path = rec.save_frame(table, "summary.csv", kind="processed")
    rec.save_table(
        table.round(4),
        "table",
        [raw_path, t_path],
        "Sensitivity of the adaptive framework to thresholds and trust weights",
    )
    path = rec.figure_path("tradeoff", [t_path], "Detection/mitigation vs disruption per setting")
    with figure(path, size=(7, 4.5)) as (fig, (ax,)):
        xs = table["disruption_rate"].to_numpy(dtype=float)
        ys = table["mitigation_rate"].to_numpy(dtype=float)
        for i, label in enumerate(table["setting"]):
            ax.scatter([xs[i]], [ys[i]], s=70, color=SERIES[i % len(SERIES)], label=str(label),
                       zorder=3)  # fmt: skip
        ax.set_xlabel("Benign disruption rate (honest drone-windows in RESTRICT or worse)")
        ax.set_ylabel("Mitigation rate (insider + spoofing attacks)")
        ax.set_title("Threshold / weight sensitivity: security vs disruption")
        ax.legend(fontsize=8, ncols=2)
        note(fig, f"Our simulation result, {len(seeds)} seed(s), base seed {seed}.")
    return rec.finalize({"settings": len(SENSITIVITY)})


STRESS_RATES = (0.0, 0.01, 0.05)
STRESS_SYSTEMS = ("d2dap_ids", "d2dap_ids_trust", "adaptive")
STRESS_KINDS = ("benign", "flooding", "privilege_escalation", "spoofing")


def stress(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    """Detector-noise stress test (RQ-C1): synthetic IDS false alarms injected at rate r.

    A *synthetic* stress test of the response layer, labelled as such: the same seeded
    false-alarm stream is applied to Systems B, C and D on identical scenarios.
    """
    from app.experiments.comparison import Job  # noqa: PLC0415

    cfg = _cfg(quick)
    seeds = [seed] if quick else [seed, seed + 1]
    meta = {"scenario": cfg.__dict__, "seeds": seeds, "rates": STRESS_RATES,
            "systems": STRESS_SYSTEMS, "kinds": STRESS_KINDS,
            "note": "SYNTHETIC false alarms injected into IDS output"}  # fmt: skip
    rec = ExperimentRecorder("stress", seed, meta, results_dir)
    jobs = [Job(v, k, s, cfg, (), (), (), f"r={r}", (("ids_false_alarm_rate", r),))
            for v in STRESS_SYSTEMS for r in STRESS_RATES for s in seeds
            for k in STRESS_KINDS]  # fmt: skip
    raw = execute(jobs, 1 if quick else _workers())
    raw_path = rec.save_frame(raw, "runs.csv")
    att = raw[raw.kind != "benign"]
    rows = []
    for v in STRESS_SYSTEMS:
        for r in STRESS_RATES:
            sel = raw[(raw.variant == v) & (raw.config_label == f"r={r}")]
            a = att[(att.variant == v) & (att.config_label == f"r={r}")]
            rows.append({"system": SYSTEM_LABELS[v], "variant": v, "false_alarm_rate": r,
                         "disruption_rate": sel.disruption_rate.mean(),
                         "collateral_rate": sel.collateral_rate.mean(),
                         "fpr_flag_rate": sel.flag_rate.mean(),
                         "mitigation_rate": a.mitigation_rate.mean(),
                         "detection_rate": a.detected.mean()})  # fmt: skip
    table = pd.DataFrame(rows)
    t_path = rec.save_frame(table, "summary.csv", kind="processed")
    rec.save_table(table.drop(columns=["variant"]).round(4), "table", [raw_path, t_path],
                   "Detector-noise stress test (SYNTHETIC IDS false alarms)")  # fmt: skip
    path = rec.figure_path("disruption_vs_noise", [t_path],
                           "Benign disruption vs IDS false alarms")  # fmt: skip
    with figure(path, nrows=1, ncols=2, size=(11, 4)) as (fig, axes):
        for i, v in enumerate(STRESS_SYSTEMS):
            sub = table[table.variant == v]
            x = sub.false_alarm_rate.to_numpy(dtype=float) * 100
            axes[0].plot(x, sub.disruption_rate.to_numpy(dtype=float) * 100, marker="o",
                         color=SERIES[i + 1], label=SYSTEM_LABELS[v])  # fmt: skip
            axes[1].plot(x, sub.mitigation_rate.to_numpy(dtype=float) * 100, marker="o",
                         color=SERIES[i + 1], label=SYSTEM_LABELS[v])  # fmt: skip
        axes[0].set_xlabel("Injected IDS false-alarm rate (% of windows)")
        axes[0].set_ylabel("Honest drone-windows disrupted (%)")
        axes[0].set_title("Collateral disruption")
        axes[1].set_xlabel("Injected IDS false-alarm rate (% of windows)")
        axes[1].set_ylabel("Attack mitigation (%)")
        axes[1].set_title("Attack mitigation")
        axes[0].legend(fontsize=8)
        note(fig, "SYNTHETIC stress test of the response layer; our simulation, "
                  f"{len(seeds)} seed(s), base seed {seed}.")  # fmt: skip
    return rec.finalize({"rows": len(raw)})


__all__ = ["SYSTEM_LABELS", "ablation", "baseline_comparison", "sensitivity", "showcase", "stress"]
