"""Phase 8: STRIDE security evaluation driven by simulated attacks (not theory).

For every threat scenario and system variant (repeated over seeds):

1. launch the simulated attack; 2. observe; 3. record evidence;
4. does D2DAP prevent/detect it?  5. does the IDS detect it?  6. trust impact;
7. policy response;  8. limitations.

Columns whose layer is not part of the run are reported as ``pending`` (they are filled
by re-running this evaluator after the adaptive framework exists, Phase 14/15).
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from app.experiments.plotting import SERIES, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, ExperimentRecorder
from app.experiments.scenario import ScenarioConfig, ScenarioResult, Variant, run_attack_scenario
from app.models.enums import SecurityState
from app.security.crypto import aead_open, aead_seal
from app.security.d2dap.messages import AuthMessage, ShareBody
from app.security.signature import gen_sign, verify_sign
from app.services.monitor import SecurityMonitor
from app.services.swarm import SecureSwarm

NAME = "stride"
NOT_A_DEFENSE = frozenset({"channel_loss", "out_of_range", "no_such_receiver",
                           "receiver_inactive"})  # fmt: skip
DETECTION_SHARE = 0.10
REJECTION_SIGNALS = {"auth_failed", "integrity", "replay", "unauthenticated", "no_session"}


@dataclass(frozen=True)
class StrideScenario:
    threat: str
    description: str
    kind: str
    params: dict[str, Any]
    limitation: str


SCENARIOS: tuple[StrideScenario, ...] = (
    StrideScenario("S", "Forged data/auth claiming a legitimate drone", "spoofing", {},
                   "Link-layer source addresses are spoofable; rejection relies on "
                   "missing sessions."),
    StrideScenario("S", "Replay of captured M1 within Delta-T (+ data replays)", "replay",
                   {"window": "in"},
                   "O1: responder accepts in-window M1 replays (no replay cache in D2DAP); "
                   "each consumes a CRP and leaves a half-open session."),
    StrideScenario("S", "Replay of stale captured messages", "replay", {"window": "stale"},
                   "Depends on loosely synchronised clocks and the Delta-T choice."),
    StrideScenario("S/E", "Node capture + clone using extracted credentials", "impersonation",
                   {}, "Relies on PUF unclonability; here a SOFTWARE PUF model enforces it."),
    StrideScenario("T", "On-path bit flipping of a drone's packets", "tampering", {},
                   "Tampered packets are dropped (availability loss); an on-path attacker is "
                   "not identifiable from packet sources."),
    StrideScenario("R", "Sender denies having sent a message", "repudiation", {},
                   "Data plane uses symmetric AEAD: either session peer can forge, so data "
                   "messages are repudiable; only signed M1/M2 are non-repudiable."),
    StrideScenario("I", "Passive eavesdropping", "eavesdropping", {},
                   "Link-layer addresses and traffic patterns remain observable; a passive "
                   "attacker cannot be detected by traffic analysis."),
    StrideScenario("I", "Insider scanning / exfiltration", "abnormal", {},
                   "An authenticated insider's traffic is validly sealed."),
    StrideScenario("D", "Bogus AUTH_REQUEST flood (computational DoS)", "dos", {},
                   "Verification work is spent before rejection; spoofed sources defeat "
                   "per-source blocking."),
    StrideScenario("D", "Insider volumetric flooding", "flooding", {},
                   "An authenticated insider's traffic is validly sealed."),
    StrideScenario("E", "Unregistered drone tries to join", "unauthorized_access", {},
                   "Each attempt still costs the responder verification work."),
    StrideScenario("E", "Compromised worker issues leader-only commands", "privilege_escalation",
                   {}, "D2DAP has no authorisation (role) layer; insider recovers A (O3)."),
)  # fmt: skip


# ---------------------------------------------------------------- repudiation analysis
def repudiation_analysis(swarm: SecureSwarm) -> dict[str, bool]:
    """Executable non-repudiation checks on a running D2DAP swarm.

    * A judge holding (CM, a, T) disclosed by the receiver and the sender's public key can
      verify an M1 signature, and the receiver cannot forge an M1 under the sender's key.
    * For AEAD data packets, the receiver can create a packet that verifies exactly like
      one from the sender (same symmetric key): data messages are repudiable.
    """
    agents = swarm.d2dap.agents
    a, b = sorted(agents)[:2]
    sender, receiver = agents[a], agents[b]
    now = swarm.engine.clock.now_ms + 1
    m1 = sender.initiate(b, now)
    msg = AuthMessage.from_bytes(m1, sender.suite)
    key = sender.pending[b].key  # the receiver derives the same K = x_j Y_i
    body = ShareBody.from_bytes(receiver.suite.decrypt(key, msg.body), receiver.suite)
    Y_sender = swarm.d2dap.directory.get(a)
    judge_verifies = verify_sign(sender.suite, msg.body, (msg.sigma_a, msg.sigma_b), a=body.a,
                                 t_bytes=body.t_bytes, Y=Y_sender)  # fmt: skip
    if receiver.credentials is None:
        raise ValueError("receiver must be enrolled")
    forged = gen_sign(receiver.suite, msg.body, body.a, body.t_bytes, receiver.credentials.x)
    receiver_can_forge_m1 = verify_sign(sender.suite, msg.body, forged, a=body.a,
                                        t_bytes=body.t_bytes, Y=Y_sender)  # fmt: skip
    sender.abort_pending(b)
    # Data plane: take a live session. Both peers hold the same AEAD key, so a packet the
    # receiver fabricates "from" the sender is bit-identical to one the sender would emit.
    live = [(d, s) for d in swarm.engine.network.nodes.values() for s in d.sessions.values()]
    if not live:
        raise ValueError("repudiation analysis needs at least one live session")
    drone, sess = live[0]
    peer_sess = swarm.engine.network.get(sess.peer_id).session_by_id(
        sess.session_id, drone.drone_id
    )
    peer_key = peer_sess.key if peer_sess is not None else b"\x00" * 16
    nonce, aad = b"\x00" * 12, b"src|dst|command|1|sid"
    by_sender = aead_seal(sess.key, nonce, b"cmd", aad)
    by_receiver = aead_seal(peer_key, nonce, b"cmd", aad)
    data_indistinguishable = by_sender == by_receiver and aead_open(
        sess.key, nonce, by_receiver, aad) is not None  # fmt: skip
    return {
        "m1_signature_judge_verifiable": bool(judge_verifies),
        "receiver_can_forge_m1": bool(receiver_can_forge_m1),
        "data_packet_forgeable_by_receiver": bool(data_indistinguishable),
    }


# ---------------------------------------------------------------- metrics
def success_rate(res: ScenarioResult) -> float:
    """Fraction of the attack's packets that achieved their goal (accepted by a receiver)."""
    ev = res.evidence
    if res.kind == "eavesdropping":
        frac = ev.extra.get("data_plaintext_fraction")
        return float(frac) if frac is not None else float("nan")
    # Same definition as Table 6: accepted / attempted (attempted includes packets the
    # policy prevented from ever being transmitted); channel losses are not a defence.
    lost = sum(v for k, v in ev.dropped.items() if k in NOT_A_DEFENSE)
    attempted = max(ev.packets_attempted, ev.packets_sent) - lost
    return ev.packets_accepted / attempted if attempted > 0 else float("nan")


def _layer_record(res: ScenarioResult) -> dict[str, Any]:
    """IDS / trust / policy observations about the attack's claimed sources."""
    mon = next((e for e in res.extensions if isinstance(e, SecurityMonitor)), None)
    if mon is None:
        return {}
    df = res.traffic()
    srcs = set(df.loc[df.attack_id.notna(), "src"])
    start, end = res.evidence.start_ms, res.evidence.end_ms + 1000
    alerted = any(a.src in srcs and start <= a.t_ms <= end for a in mon.alerts)
    states = [d.new_state.severity for d in mon.policy.decisions
              if d.drone_id in srcs and start <= d.t_ms <= end]  # fmt: skip
    trusts = [u.new for u in mon.trust.log if u.drone_id in srcs and start <= u.t_ms <= end]
    return {
        "ids_alerted": float(alerted),
        "max_attacker_state": float(max(states, default=0)),
        "min_attacker_trust": float(min(trusts, default=float("nan"))),
    }


def run_record(res: ScenarioResult) -> dict[str, Any]:
    ev = res.evidence
    attack_s = (ev.end_ms - ev.start_ms) / 1000
    return _layer_record(res) | {
        "variant": res.variant.value,
        "seed": res.seed,
        "kind": res.kind,
        "success_rate": success_rate(res),
        "d2dap_rejection_signals": sum(v for k, v in ev.dropped.items() if k in REJECTION_SIGNALS),
        "victim_cpu_ms_per_s": ev.victim_compute_ms / attack_s if attack_s else 0.0,
        **{k: v for k, v in ev.as_record().items() if k not in {"attack_id", "kind"}},
    }


_STATE_NAMES = {s.severity: s.value.upper() for s in SecurityState}


def _fmt_pct(x: float) -> str:
    return "n/a" if np.isnan(x) else f"{100 * x:.1f}% success"


def _mitigated(kind: str, rate: float, cpu: float) -> str:
    if kind == "dos":
        return f"Partial (all rejected; victim CPU {cpu:.0f} ms/s)" if rate < 0.01 else "No"
    if np.isnan(rate):
        return "n/a"
    if rate <= 0.01:
        return "Yes"
    return "No" if rate >= 0.9 else "Partial"


def build_table(
    raw: pd.DataFrame, variants: list[Variant], repudiation: dict[str, bool]
) -> pd.DataFrame:
    """STRIDE table; columns for variants not run are 'pending'."""
    mean = raw.groupby(["kind", "variant", "params"], dropna=False).mean(numeric_only=True)
    rows = []
    for sc in SCENARIOS:
        pkey = str(sorted(sc.params.items()))

        def cell(v: Variant, col: str, pkey: str = pkey, kind: str = sc.kind) -> float:
            if v not in variants or (kind, v.value, pkey) not in mean.index:
                return float("nan")
            return float(np.asarray(mean.loc[(kind, v.value, pkey), col], dtype=float))

        if sc.kind == "repudiation":
            rows.append({
                "Threat": sc.threat, "Attack Scenario": sc.description,
                "Baseline": "No signatures: fully repudiable",
                "D2DAP": ("M1/M2 non-repudiable (judge-verifiable: "
                          f"{repudiation.get('m1_signature_judge_verifiable')}; receiver forge: "
                          f"{repudiation.get('receiver_can_forge_m1')}); data repudiable "
                          "(receiver forge: "
                          f"{repudiation.get('data_packet_forgeable_by_receiver')})"),
                "D2DAP + IDS": "pending" if Variant.D2DAP_IDS not in variants else "no change",
                "Adaptive Framework": "pending" if Variant.ADAPTIVE not in variants
                else "audit log of trust evidence (not cryptographic)",
                "Detected?": "n/a", "Trust impact (adaptive)": "n/a",
                "Policy response (adaptive)": "n/a", "Mitigated?": "Partial",
                "Evidence": "repudiation_analysis() executable checks",
                "Limitations": sc.limitation,
            })  # fmt: skip
            continue
        d_rate = cell(Variant.D2DAP, "success_rate")
        a_rate = cell(Variant.ADAPTIVE, "success_rate")
        ids_hit = cell(Variant.D2DAP_IDS, "ids_alerted")
        state = cell(Variant.ADAPTIVE, "max_attacker_state")
        trust_min = cell(Variant.ADAPTIVE, "min_attacker_trust")
        signals = cell(Variant.D2DAP, "d2dap_rejection_signals")
        failures = cell(Variant.D2DAP, "auth_attempts") - cell(Variant.D2DAP, "auth_accepted")
        sent = cell(Variant.D2DAP, "packets_sent")
        share = signals / sent if sent else 0.0
        # Detected = D2DAP explicitly rejects a meaningful share (>= 10 %) of the attack's
        # packets or reports authentication failures (incidental drops do not count).
        d2dap_det = "Yes" if (share >= DETECTION_SHARE or failures > 0) else "No"
        detected = f"D2DAP: {d2dap_det}"
        if not np.isnan(ids_hit):
            detected += f"; IDS: {ids_hit:.0%} of runs"
        cpu = cell(Variant.D2DAP, "victim_cpu_ms_per_s")
        evidence = (f"D2DAP: sent {cell(Variant.D2DAP, 'packets_sent'):.0f}, accepted "
                    f"{cell(Variant.D2DAP, 'packets_accepted'):.0f}, rejections {signals:.0f}, "
                    f"auth fail {failures:.0f}, CRPs consumed "
                    f"{cell(Variant.D2DAP, 'crp_consumed'):.1f}")  # fmt: skip
        rows.append({
            "Threat": sc.threat,
            "Attack Scenario": sc.description,
            "Baseline": _fmt_pct(cell(Variant.BASELINE, "success_rate")),
            "D2DAP": _fmt_pct(d_rate),
            "D2DAP + IDS": "pending" if Variant.D2DAP_IDS not in variants
            else _fmt_pct(cell(Variant.D2DAP_IDS, "success_rate")),
            "Adaptive Framework": "pending" if Variant.ADAPTIVE not in variants
            else _fmt_pct(cell(Variant.ADAPTIVE, "success_rate")),
            "Detected?": detected,
            "Trust impact (adaptive)": "pending" if np.isnan(state) else (
                "n/a" if np.isnan(trust_min) else f"min trust {trust_min:.2f}"),
            "Policy response (adaptive)": "pending" if np.isnan(state) else
            _STATE_NAMES[round(state)],
            "Mitigated?": _mitigated(sc.kind, a_rate if not np.isnan(a_rate) else d_rate, cpu),
            "Evidence": evidence,
            "Limitations": sc.limitation,
        })  # fmt: skip
    return pd.DataFrame(rows)


def _stride_job(job: tuple[str, str, int, ScenarioConfig, tuple[tuple[str, Any], ...]]
                ) -> dict[str, Any]:  # fmt: skip
    """One (scenario, variant, seed) run; executed in a worker process."""
    variant, kind, seed, cfg, params = job
    res = run_attack_scenario(Variant(variant), kind, cfg, seed, dict(params))
    return run_record(res) | {"params": str(sorted(params))}


def run(
    seed: int = 42,
    quick: bool = False,
    results_dir: Path = DEFAULT_RESULTS,
    variants: list[Variant] | None = None,
    workers: int = 1,
) -> Path:
    variants = variants or [Variant.BASELINE, Variant.D2DAP]
    seeds = [seed] if quick else [seed, seed + 1, seed + 2]
    cfg = ScenarioConfig(duration_ms=30_000, attack_start_ms=8_000, attack_duration_ms=15_000,
                         num_drones=8) if quick else ScenarioConfig()  # fmt: skip
    rec = ExperimentRecorder(NAME, seed, {"scenario": cfg.__dict__, "seeds": seeds,
                                          "variants": [v.value for v in variants]},
                             results_dir)  # fmt: skip
    packet_scenarios = [sc for sc in SCENARIOS if sc.kind != "repudiation"]
    jobs = [(v.value, sc.kind, s, cfg, tuple(sorted(sc.params.items())))
            for sc in packet_scenarios for v in variants for s in seeds]  # fmt: skip
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            records = list(pool.map(_stride_job, jobs, chunksize=1))
    else:
        records = [_stride_job(j) for j in jobs]
    # Repudiation is analysed on a live D2DAP swarm (executable checks, not packets).
    probe = run_attack_scenario(Variant.D2DAP, "flooding", cfg, seed)
    repudiation = repudiation_analysis(probe.swarm)
    raw_df = pd.DataFrame(records)
    raw_path = rec.save_frame(raw_df, "stride_runs.csv")
    rec.save_json(repudiation, "repudiation_analysis.json")
    table = build_table(raw_df, variants, repudiation)
    table_path = rec.save_table(
        table, "table", [raw_path], "STRIDE evaluation from simulated attacks (mean over seeds)"
    )
    _figure(rec, raw_df, raw_path, variants, seed)
    return rec.finalize({"runs": len(raw_df), "table": str(table_path), **repudiation})


def _figure(
    rec: ExperimentRecorder, raw: pd.DataFrame, raw_path: Path, variants: list[Variant], seed: int
) -> None:
    labels = [f"{sc.kind}{'(' + sc.params['window'] + ')' if 'window' in sc.params else ''}"
              for sc in SCENARIOS if sc.kind != "repudiation"]  # fmt: skip
    keys = [(sc.kind, str(sorted(sc.params.items()))) for sc in SCENARIOS
            if sc.kind != "repudiation"]  # fmt: skip
    mean = raw.groupby(["kind", "params", "variant"])["success_rate"].mean()
    path = rec.figure_path("success", [raw_path], "Attack success rate per STRIDE scenario")
    with figure(path, size=(8, 5.2)) as (fig, (ax,)):
        y = np.arange(len(keys))
        h = 0.8 / len(variants)
        for i, v in enumerate(variants):
            vals = [100 * mean.get((k, p, v.value), np.nan) for k, p in keys]
            ax.barh(y + i * h - 0.4 + h / 2, vals, h * 0.92, color=SERIES[i], label=v.value)
        ax.set_yticks(y, labels)
        ax.invert_yaxis()
        ax.set_xlabel("Attack success rate (% of attack packets accepted)")
        ax.set_xlim(0, 105)
        ax.set_title("STRIDE scenarios: attack success by system variant")
        ax.legend(loc="lower right")
        note(fig, f"Our simulation result, mean over seeds (base seed {seed}). "
                  "Eavesdropping = plaintext fraction.")  # fmt: skip
