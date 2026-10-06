"""Phases 15-16: baseline comparison (Systems A-D) and ablation study.

The *same* scenarios (every traffic attack + a benign run) and the *same* seeds are
executed against every system. Metrics per run (ground truth is used only here, for
evaluation):

* ``detected``          the layer flagged the attack source during the attack
                        (A: D2DAP rejections/failures; B: IDS alert; C/D/ablations:
                        policy state >= MONITOR, or a block);
* ``detection_ms``      attack start -> first flag;
* ``mitigation_rate``   attack packets not accepted (D2DAP or policy drops) /
                        attack packets that reached a receiver;
* ``response_ms``       attack start -> first attack packet dropped by a *policy* action;
* ``flag_rate``         benign drone-windows flagged (false positives);
* ``disruption_rate``   benign drone-windows in RESTRICT or worse (operational impact);
* ``collateral_rate``   benign packets dropped by policy / benign packets received;
* overhead              monitor processing ms per window; bytes/s of reports, notices,
                        authentication (incl. re-authentication) and RL broadcasts.

Runs execute in parallel worker processes (independent, deterministic per seed).
Wall-clock overhead is therefore measured under load; the scalability study (Phase 17)
measures overhead sequentially.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from app.attacks.manager import TRAFFIC_ATTACKS
from app.experiments.scenario import (
    ScenarioConfig,
    Variant,
    run_attack_scenario,
    run_benign_scenario,
)
from app.models.enums import BENIGN_LABEL, SecurityState
from app.policy.engine import PolicyConfig
from app.services.monitor import MonitorConfig, SecurityMonitor
from app.services.swarm import SecureSwarm
from app.trust.config import TrustConfig

DEFENSE_DROPS = frozenset({"auth_failed", "integrity", "replay", "unauthenticated", "no_session"})
NOT_A_DEFENSE = frozenset({"channel_loss", "out_of_range", "no_such_receiver",
                           "receiver_inactive"})  # fmt: skip
SEVERITY = {s.value: s.severity for s in SecurityState}

SYSTEMS_PHASE15 = (Variant.D2DAP, Variant.D2DAP_IDS, Variant.D2DAP_IDS_TRUST, Variant.ADAPTIVE)
ABLATIONS_PHASE16 = (Variant.ADAPTIVE, Variant.NO_TRUST, Variant.NO_ML, Variant.NO_POLICY,
                     Variant.NO_ATTRIBUTION, Variant.D2DAP)  # fmt: skip
SYSTEM_LABELS = {
    "d2dap": "A: Authentication only (D2DAP)",
    "d2dap_ids": "B: D2DAP + ML IDS (alert/block)",
    "d2dap_ids_trust": "C: D2DAP + IDS + Trust (binary)",
    "adaptive": "D: Full adaptive framework",
    "no_trust": "Full - Trust Engine",
    "no_ml": "Full - ML IDS",
    "no_policy": "Full - Policy Engine",
    "no_attribution": "Full - attribution-aware fusion",
}


@dataclass(frozen=True)
class Job:
    variant: str
    kind: str  # attack kind or "benign"
    seed: int
    cfg: ScenarioConfig
    params: tuple[tuple[str, Any], ...] = ()
    #: Sensitivity study: TrustConfig / PolicyConfig field overrides and a label.
    trust_overrides: tuple[tuple[str, Any], ...] = ()
    policy_overrides: tuple[tuple[str, Any], ...] = ()
    label: str = ""
    monitor_overrides: tuple[tuple[str, Any], ...] = ()

    def framework_kwargs(self) -> dict[str, Any] | None:
        if not (self.trust_overrides or self.policy_overrides or self.monitor_overrides):
            return None
        return {
            "trust_config": TrustConfig().model_copy(update=dict(self.trust_overrides)),
            "policy_config": PolicyConfig().model_copy(update=dict(self.policy_overrides)),
            "monitor_config": MonitorConfig().model_copy(update=dict(self.monitor_overrides)),
        }


# ---------------------------------------------------------------- helpers
def _monitor(extensions: list[Any]) -> SecurityMonitor | None:
    return next((e for e in extensions if isinstance(e, SecurityMonitor)), None)


def _state_timeline(mon: SecurityMonitor, drones: list[str], n_windows: int, w_ms: int
                    ) -> dict[str, np.ndarray[Any, Any]]:  # fmt: skip
    """Severity per drone per window, reconstructed from policy transitions."""
    out = {d: np.zeros(n_windows, dtype=int) for d in drones}
    for dec in mon.policy.decisions:
        if dec.drone_id in out:
            out[dec.drone_id][dec.t_ms // w_ms :] = dec.new_state.severity
    return out


def _benign_window_rates(mon: SecurityMonitor | None, variant: str, honest: list[str],
                         n_windows: int, w_ms: int) -> tuple[float, float, int]:  # fmt: skip
    """(flag_rate, disruption_rate, windows) over honest drones' windows."""
    total = len(honest) * n_windows
    if mon is None or total == 0:
        return 0.0, 0.0, total
    if variant == "d2dap_ids":
        flagged = {(a.src, a.window) for a in mon.alerts if a.src in honest}
        blocked = flagged  # B blocks every flagged source for one window
        return len(flagged) / total, len(blocked) / total, total
    tl = _state_timeline(mon, honest, n_windows, w_ms)
    flag = sum(int((v >= 1).sum()) for v in tl.values())
    disrupt = sum(int((v >= SecurityState.RESTRICT.severity).sum()) for v in tl.values())
    if variant == "d2dap_ids_trust":  # binary mode: any non-NORMAL state is a block
        disrupt = flag
    return flag / total, disrupt / total, total


def _overheads(sw: SecureSwarm, mon: SecurityMonitor | None, duration_s: float,
               events: list[Any]) -> dict[str, float]:  # fmt: skip
    df = sw.traffic_log.to_frame()
    sent = df.drop_duplicates("packet_id")
    by = sent.groupby("protocol")["size_bytes"].sum()

    def bps(proto: str) -> float:
        return float(by.get(proto, 0)) / duration_s

    return {
        "auth_bytes_per_s": bps("auth_request") + bps("auth_response"),
        "rl_bytes_per_s": bps("rl_broadcast"),
        "report_bytes_per_s": bps("trust_report"),
        "notice_bytes_per_s": bps("policy_notice"),
        "security_bytes_per_s": sum(
            bps(p)
            for p in (
                "auth_request",
                "auth_response",
                "rl_broadcast",
                "trust_report",
                "policy_notice",
            )
        ),
        "auth_compute_ms_per_s": sum(e.compute_ms for e in events) / duration_s,
        "monitor_ms_per_window": float(np.mean(mon.stats.processing_ms))
        if mon and mon.stats.processing_ms
        else 0.0,
        "monitor_ids_ms_per_window": float(np.mean(mon.stats.ids_ms))
        if mon and mon.stats.ids_ms
        else 0.0,
        "reauth_count": float(
            sum(
                1
                for d in (mon.policy.decisions if mon else [])
                if d.new_state is SecurityState.REAUTHENTICATE
            )
        ),
        "quarantine_count": float(
            sum(
                1
                for d in (mon.policy.decisions if mon else [])
                if d.new_state is SecurityState.QUARANTINE
            )
        ),
    }


# ---------------------------------------------------------------- one run
def run_job(job: Job) -> dict[str, Any]:
    cfg, v = job.cfg, Variant(job.variant)
    w_ms = 1000
    n_windows = cfg.duration_ms // w_ms
    row: dict[str, Any] = {"variant": job.variant, "kind": job.kind, "seed": job.seed,
                           "config_label": job.label}  # fmt: skip
    if job.kind == BENIGN_LABEL:
        res_b = run_benign_scenario(v, cfg, job.seed, framework_kwargs=job.framework_kwargs())
        sw, ext, events = res_b.swarm, res_b.extensions, res_b.auth_events
        attack_srcs: set[str] = set()
    else:
        res = run_attack_scenario(v, job.kind, cfg, job.seed, dict(job.params),
                                  framework_kwargs=job.framework_kwargs())  # fmt: skip
        sw, ext, events = res.swarm, res.extensions, res.auth_events
    mon = _monitor(ext)
    df = sw.traffic_log.to_frame()
    honest = sorted(i for i in sw.d2dap.agents if not sw.engine.network.nodes[i].compromised)
    if job.kind != BENIGN_LABEL:
        att = df[df.attack_id.notna()]
        attack_srcs = set(att.src)
        honest = [h for h in honest if h not in attack_srcs]
        reached = att[~att.dropped_reason.isin(NOT_A_DEFENSE)]
        accepted = reached.dropped_reason.isna().sum()
        start, end = cfg.attack_start_ms, cfg.attack_start_ms + cfg.attack_duration_ms
        # Attempted = created by the attacker, incl. packets never transmitted because the
        # policy revoked its sessions; channel losses are not a defence and are excluded.
        lost = int(att.dropped_reason.isin(NOT_A_DEFENSE).sum())
        attempted = max(res.evidence.packets_attempted, len(att)) - lost
        row["attack_packets_attempted"] = attempted
        row["attack_packets"] = len(reached)
        row["mitigation_rate"] = 1 - accepted / attempted if attempted > 0 else float("nan")
        defended = reached[reached.dropped_reason.notna()]
        crypto = defended[defended.dropped_reason.isin(DEFENSE_DROPS)]
        policy = defended[defended.dropped_reason.str.startswith("policy:", na=False)]
        row["d2dap_drop_share"] = len(crypto) / len(reached) if len(reached) else 0.0
        row["policy_drop_share"] = len(policy) / len(reached) if len(reached) else 0.0
        row["response_ms"] = (float(policy.timestamp_ms.min() - start) if len(policy)
                              else float("nan"))  # fmt: skip
        auth_fail = sum(1 for e in events if not e.success and e.attack_id is not None)
        d2dap_flag = (len(crypto) / len(reached) >= 0.1 if len(reached) else False) or (
            auth_fail > 0)  # fmt: skip
        layer_flag_ms = float("nan")
        if mon is not None:
            if job.variant == "d2dap_ids":
                hits = [a.t_ms for a in mon.alerts if a.src in attack_srcs and start <= a.t_ms
                        <= end + w_ms]  # fmt: skip
            else:
                hits = [
                    d.t_ms
                    for d in mon.policy.decisions
                    if d.drone_id in attack_srcs
                    and d.new_state.severity >= 1
                    and start <= d.t_ms <= end + w_ms
                ]
            if hits:
                layer_flag_ms = float(min(hits) - start)
        row["layer_detected"] = not np.isnan(layer_flag_ms)
        row["d2dap_detected"] = bool(d2dap_flag)
        row["detected"] = bool(d2dap_flag or row["layer_detected"])
        row["detection_ms"] = layer_flag_ms
        row["max_attacker_state"] = max(
            (d.new_state.severity for d in (mon.policy.decisions if mon else [])
             if d.drone_id in attack_srcs), default=0)  # fmt: skip
    flag, disrupt, wins = _benign_window_rates(mon, job.variant, honest, n_windows, w_ms)
    row.update(flag_rate=flag, disruption_rate=disrupt, benign_windows=wins)
    benign_rx = df[(df.label == BENIGN_LABEL) & ~df.dropped_reason.isin(NOT_A_DEFENSE)]
    benign_rx = benign_rx[benign_rx.src.isin(honest)]
    pol = benign_rx.dropped_reason.fillna("").str.startswith("policy:")
    row["collateral_rate"] = float(pol.mean()) if len(benign_rx) else 0.0
    row.update(_overheads(sw, mon, cfg.duration_ms / 1000, events))
    return row


def plan(variants: tuple[Variant, ...], seeds: list[int], cfg: ScenarioConfig) -> list[Job]:
    jobs = []
    for v in variants:
        for s in seeds:
            for kind in (*TRAFFIC_ATTACKS, BENIGN_LABEL):
                params = (("window", "in"),) if kind == "replay" else ()
                jobs.append(Job(v.value, kind, s, cfg, params))
    return jobs


def execute(jobs: list[Job], workers: int) -> pd.DataFrame:
    if workers <= 1:
        return pd.DataFrame([run_job(j) for j in jobs])
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return pd.DataFrame(list(pool.map(run_job, jobs, chunksize=1)))


#: Attacks that abuse an *honest* drone's identity (forged / replayed / tampered packets
#: carry the victim's address): the claimed source is innocent and must not be sanctioned.
IDENTITY_ABUSE = ("spoofing", "replay", "tampering", "dos")


def _framed_rate(ab: pd.DataFrame, variant: str) -> float:
    """Share of identity-abuse runs in which the forged honest identity was sanctioned.

    Sanctioned = policy state RESTRICT or worse; for System B (IDS alert -> one-window
    block of the source) any alert on the abused identity blocks the innocent drone.
    """
    if not len(ab):
        return float("nan")
    if variant == "d2dap_ids":
        return float(ab.layer_detected.astype(bool).mean())
    return float((ab.max_attacker_state >= SecurityState.RESTRICT.severity).mean())


def summarize(raw: pd.DataFrame) -> pd.DataFrame:
    """System-level summary (Table 6 / ablation table)."""
    att = raw[raw.kind != BENIGN_LABEL]
    abuse = raw[raw.kind.isin(IDENTITY_ABUSE)]
    ben = raw[raw.kind == BENIGN_LABEL]
    rows = []
    for v, g in att.groupby("variant", sort=False):
        b = ben[ben.variant == v]
        allr = raw[raw.variant == v]
        ab = abuse[abuse.variant == v]
        rows.append({
            "system": SYSTEM_LABELS.get(str(v), str(v)),
            "variant": v,
            "detection_rate": g.detected.mean(),
            "layer_detection_rate": g.layer_detected.mean(),
            "fpr_flag_rate": allr.flag_rate.mean(),
            "fpr_benign_runs": b.flag_rate.mean() if len(b) else float("nan"),
            "disruption_rate": allr.disruption_rate.mean(),
            "fnr": 1 - g.detected.mean(),
            "detection_ms_median": g.detection_ms.median(),
            "response_ms_median": g.response_ms.median(),
            "mitigation_rate": g.mitigation_rate.mean(),
            "collateral_rate": allr.collateral_rate.mean(),
            # Share of identity-abuse runs in which the forged honest identity was driven
            # to RESTRICT or worse (framing of an innocent drone).
            "framed_rate": _framed_rate(ab, str(v)),
            "monitor_ms_per_window": allr.monitor_ms_per_window.mean(),
            "security_bytes_per_s": allr.security_bytes_per_s.mean(),
            "auth_compute_ms_per_s": allr.auth_compute_ms_per_s.mean(),
            "runs": len(allr),
        })  # fmt: skip
    return pd.DataFrame(rows)


def per_attack(raw: pd.DataFrame, metric: str) -> pd.DataFrame:
    att = raw[raw.kind != BENIGN_LABEL]
    return att.pivot_table(index="kind", columns="variant", values=metric, aggfunc="mean")
