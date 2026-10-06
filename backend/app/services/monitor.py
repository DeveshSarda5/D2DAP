"""SecurityMonitor: the integrated pipeline of the adaptive framework (Phase 14).

Every observation window (default 1 s), hosted on the leader:

    traffic log  ->  window features (observable only)  ->  ML IDS P(attack), class
         + D2DAP AuthEvents (successes, failures, re-authentications)
    ->  attribution-aware Evidence  ->  TrustEngine  ->  PolicyEngine  ->  PolicyEnforcer

Modes (system variants / ablations, Phases 15-16):

* ``ids_block``      B: IDS alerts; flagged sources are blocked for the next window;
* ``trust_binary``   C: trust engine + single block threshold;
* ``adaptive``       D: trust engine + graded adaptive policy (full framework);
* ``raw_policy``     ablation "- Trust": graded policy driven by 1 - P(attack) of the
                     current window (no memory, no fusion);
* ``observe``        ablation "- Policy": trust and decisions computed, never enforced.

Ablations "- ML" and "- attribution" are TrustConfig switches with mode ``adaptive``.
Cooperative monitoring cost is accounted honestly: each drone sends one TRUST_REPORT per
window to the host (real packets, counted as overhead).
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field

from app.ids.features import extract_windows
from app.ids.models import TrainedModel
from app.models.enums import AuthState, PacketProtocol, SecurityState
from app.policy.enforcement import PolicyEnforcer
from app.policy.engine import PolicyConfig, PolicyDecision, PolicyEngine
from app.services.auth_coordinator import AuthEvent
from app.services.swarm import SecureSwarm
from app.trust.config import TrustConfig
from app.trust.engine import INSIDER_CLASSES, Evidence, TrustEngine, TrustUpdate

S = SecurityState
_EVIDENCE_COLUMNS = ("tx_count", "verified_count", "integrity_fail_count", "replay_reject_count",
                     "unauth_data_count", "no_session_count", "auth_fail_count",
                     "verified_cmd_count", "src_is_leader")  # fmt: skip
_VIOLATION_COLUMNS = ("integrity_fail_count", "replay_reject_count", "unauth_data_count",
                      "no_session_count")  # fmt: skip
REPORT_HEADER_BYTES = 16
REPORT_BYTES_PER_SOURCE = 12


class MonitorConfig(BaseModel):
    mode: str = Field("adaptive", pattern="^(ids_block|trust_binary|adaptive|raw_policy|observe)$")
    window_ms: int = Field(1000, ge=100)
    #: Process window w once this much time after its end has passed (late deliveries).
    grace_ms: int = Field(100, ge=0)
    ids_threshold: float = Field(0.5, gt=0, lt=1)
    host: str = "D1"
    send_reports: bool = True
    #: STRESS TEST ONLY (default 0): probability that a window's IDS output is replaced by
    #: a confident false alarm of a random attack class, modelling a less accurate detector.
    ids_false_alarm_rate: float = Field(0.0, ge=0, le=1)


@dataclass(frozen=True)
class IdsOutput:
    """Per-row IDS results for one window."""

    p_attack: np.ndarray[Any, Any]
    p_insider: np.ndarray[Any, Any]
    classes: list[str]


@dataclass(frozen=True)
class Alert:
    t_ms: int
    window: int
    src: str
    p_attack: float
    attack_class: str


@dataclass
class MonitorStats:
    windows: int = 0
    processing_ms: list[float] = field(default_factory=list)
    ids_ms: list[float] = field(default_factory=list)
    trust_ms: list[float] = field(default_factory=list)
    trust_updates: int = 0
    report_bytes: int = 0


class SecurityMonitor:
    """Window-by-window detection, trust and policy over a running swarm."""

    def __init__(
        self,
        swarm: SecureSwarm,
        ids_model: TrainedModel | None,
        config: MonitorConfig | None = None,
        trust_config: TrustConfig | None = None,
        policy_config: PolicyConfig | None = None,
    ) -> None:
        self.swarm = swarm
        self.ids = ids_model
        self.config = config or MonitorConfig()
        mode = self.config.mode
        pcfg = policy_config or PolicyConfig()
        if mode == "trust_binary":
            pcfg = pcfg.model_copy(update={"mode": "binary"})
        self.trust = TrustEngine(trust_config, registered=set(swarm.d2dap.agents))
        self.policy = PolicyEngine(pcfg)
        self.enforcer = PolicyEnforcer(swarm, pcfg, host=self.config.host,
                                       enforce=mode != "observe")  # fmt: skip
        self.alerts: list[Alert] = []
        self.stats = MonitorStats()
        self._pending: list[dict[str, Any]] = []
        self._cursor = 0
        self._next_window = 0
        self._auth: dict[int, list[AuthEvent]] = defaultdict(list)
        #: Drones already rewarded for their current forced re-authentication (one reward
        #: per policy-forced re-authentication; prevents farming rewards per new session).
        self._rewarded: set[str] = set()
        self._insider_idx: list[int] = []
        self._benign_idx: int | None = None
        self._noise_rng = swarm.streams.numpy("ids-false-alarms")
        if ids_model is not None:
            classes = ids_model.classes
            self._insider_idx = [i for i, c in enumerate(classes) if c in INSIDER_CLASSES]
            self._benign_idx = classes.index("benign") if "benign" in classes else None

    def install(self) -> SecurityMonitor:
        self.enforcer.install()
        self.swarm.coordinator.add_listener(self._on_auth)
        self.swarm.engine.add_tick_hook(self._tick)
        return self

    # ------------------------------------------------------------- inputs
    def _on_auth(self, event: AuthEvent) -> None:
        self._auth[event.t_ms // self.config.window_ms].append(event)

    def _roles(self) -> dict[str, str]:
        return {i: d.role.value for i, d in self.swarm.engine.network.nodes.items()}

    def _tick(self, now_ms: int) -> None:
        self.enforcer.tick(now_ms)
        recs = self.swarm.traffic_log.records
        self._pending.extend(recs[self._cursor :])
        self._cursor = len(recs)
        w = self.config.window_ms
        while now_ms >= (self._next_window + 1) * w + self.config.grace_ms:
            self._process(self._next_window, now_ms)
            self._next_window += 1

    # ------------------------------------------------------------- per window
    def _ids(self, feats: pd.DataFrame) -> IdsOutput:
        if self.ids is None or feats.empty:
            n = len(feats)
            return IdsOutput(np.zeros(n), np.zeros(n), ["benign"] * n)
        proba = self.ids.predict_proba(feats)
        p_attack = 1.0 - proba[:, self._benign_idx] if self._benign_idx is not None else (
            np.ones(len(feats)))  # fmt: skip
        p_ins = (
            proba[:, self._insider_idx].sum(axis=1) if self._insider_idx else np.zeros(len(feats))
        )
        classes = [self.ids.classes[i] for i in proba.argmax(axis=1)]
        rate = self.config.ids_false_alarm_rate
        if rate > 0:
            attack_classes = [c for c in self.ids.classes if c != "benign"]
            for i in range(len(feats)):
                if self._noise_rng.random() < rate:
                    cls = attack_classes[int(self._noise_rng.integers(0, len(attack_classes)))]
                    p = float(self._noise_rng.uniform(0.6, 1.0))
                    p_attack[i], classes[i] = p, cls
                    p_ins[i] = p if cls in INSIDER_CLASSES else 0.0
        return IdsOutput(p_attack, p_ins, classes)

    def _process(self, window: int, now_ms: int) -> None:
        t0 = time.perf_counter_ns()
        w = self.config.window_ms
        start, end = window * w, (window + 1) * w
        in_win = [r for r in self._pending if start <= r["timestamp_ms"] < end]
        self._pending = [r for r in self._pending if r["timestamp_ms"] >= end]
        feats = extract_windows(pd.DataFrame(in_win), self._roles(), w, with_labels=False) if (
            in_win) else pd.DataFrame()  # fmt: skip
        t1 = time.perf_counter_ns()
        ids_out = self._ids(feats)
        t2 = time.perf_counter_ns()
        auth = self._auth.pop(window, [])
        evidence = self._evidence(window, end, feats, ids_out, auth)
        for ev in evidence.values():
            if ev.attack_prob is not None and ev.attack_prob >= self.config.ids_threshold:
                self.alerts.append(Alert(end, window, ev.drone_id, ev.attack_prob,
                                         ev.attack_class or ""))  # fmt: skip
                if self.config.mode == "ids_block":
                    self.enforcer.block_until(ev.drone_id, end + w)
        if self.config.mode != "ids_block":
            for ev in evidence.values():
                self._apply_trust(ev)
            self._reauth_failures(auth, end)
        t3 = time.perf_counter_ns()
        self.stats.windows += 1
        self.stats.ids_ms.append((t2 - t1) / 1e6)
        self.stats.trust_ms.append((t3 - t2) / 1e6)
        self.stats.processing_ms.append((t3 - t0) / 1e6)
        if self.config.send_reports:
            self._send_reports(feats, now_ms)

    def _evidence(
        self, window: int, end: int, feats: pd.DataFrame, ids: IdsOutput, auth: list[AuthEvent]
    ) -> dict[str, Evidence]:
        out: dict[str, Evidence] = {}
        succ: dict[str, int] = defaultdict(int)
        fail: dict[str, int] = defaultdict(int)
        reauth: dict[str, int] = defaultdict(int)
        for e in auth:
            if e.success and e.stage == "complete":
                succ[e.initiator] += 1
                forced = e.reauth or self.policy.state(e.initiator) in (
                    S.REAUTHENTICATE,
                    S.QUARANTINE,
                )
                if forced and e.initiator not in self._rewarded:
                    reauth[e.initiator] = 1
                    self._rewarded.add(e.initiator)
            elif not e.success and e.stage != "timeout":
                fail[e.initiator] += 1
        col = {c: feats[c].to_numpy(dtype=float) for c in _EVIDENCE_COLUMNS} if len(feats) else {}
        for i, src_raw in enumerate(feats["src"].tolist() if len(feats) else []):
            src = str(src_raw)
            violations = int(sum(col[c][i] for c in _VIOLATION_COLUMNS))
            has_ml = self.ids is not None
            out[src] = Evidence(
                src, window, end, attack_prob=float(ids.p_attack[i]) if has_ml else None,
                insider_prob=float(ids.p_insider[i]) if has_ml else None,
                attack_class=ids.classes[i] if has_ml else None,
                tx_count=int(col["tx_count"][i]), verified=int(col["verified_count"][i]),
                unverified=violations + int(col["auth_fail_count"][i]),
                auth_success=succ.pop(src, 0), auth_failures=fail.pop(src, 0),
                violations=violations, reauth_success=reauth.pop(src, 0),
                authz_violations=int(col["verified_cmd_count"][i] * (1 - col["src_is_leader"][i])),
            )  # fmt: skip
        for src in set(succ) | set(fail) | set(reauth):
            out[src] = Evidence(src, window, end, auth_success=succ.get(src, 0),
                                auth_failures=fail.get(src, 0),
                                reauth_success=reauth.get(src, 0))  # fmt: skip
        return out

    def _apply_trust(self, ev: Evidence) -> None:
        if self.config.mode == "raw_policy":
            p = ev.attack_prob or 0.0
            update = TrustUpdate(ev.drone_id, ev.window, ev.t_ms, self._raw_prev(ev.drone_id),
                                 1.0 - p, 0.0, 0.0, 0.0, 0.0, {}, 1.0, ev,
                                 f"raw IDS score 1-P(attack)={1 - p:.2f}")  # fmt: skip
        else:
            update = self.trust.update(ev)
        self.stats.trust_updates += 1
        drone = self.swarm.engine.network.nodes.get(ev.drone_id)
        if drone is not None:
            drone.trust_score = update.new
        self._commit(self.policy.evaluate(update))

    def _raw_prev(self, drone_id: str) -> float:
        drone = self.swarm.engine.network.nodes.get(drone_id)
        return drone.trust_score if drone is not None else 1.0

    def _reauth_failures(self, auth: list[AuthEvent], end: int) -> None:
        """Hard rule: the drone's OWN forced re-authentication failed -> quarantine.

        Only initiator-side failures count ("initiate"/"complete": computed on the drone
        itself). Responder-side failures carry a *claimed* identity that anyone can forge,
        so they never trigger the hard rule (prevents framing an honest drone).
        """
        for e in auth:
            if not e.success and e.stage in ("initiate", "complete") and e.reauth:
                self._commit(self.policy.reauthentication_failed(e.initiator, end,
                                                                 self.trust.trust(e.initiator),
                                                                 e.reason or "?"))  # fmt: skip

    def _commit(self, decision: PolicyDecision | None) -> None:
        if decision is None:
            return
        self.enforcer.apply(decision)
        if decision.new_state in (S.REAUTHENTICATE, S.QUARANTINE):
            self._rewarded.discard(decision.drone_id)
        drone = self.swarm.engine.network.nodes.get(decision.drone_id)
        if drone is not None and decision.new_state is S.NORMAL and drone.sessions:
            drone.auth_state = AuthState.AUTHENTICATED

    def _send_reports(self, feats: pd.DataFrame, now_ms: int) -> None:
        host = self.config.host
        net = self.swarm.engine.network
        if host not in net.nodes or not net.nodes[host].active:
            return
        n_src = max(1, len(feats))
        size = REPORT_HEADER_BYTES + REPORT_BYTES_PER_SOURCE * n_src
        for d in net.active_nodes():
            if d.drone_id == host or d.drone_id not in self.swarm.d2dap.agents:
                continue
            pkt = self.swarm.engine.factory.make(now_ms, d.drone_id, host,
                                                 PacketProtocol.TRUST_REPORT, size)  # fmt: skip
            self.stats.report_bytes += size
            self.swarm.engine.transmit(pkt)  # sealed over the drone's session with the host

    # ------------------------------------------------------------- outputs
    def trust_frame(self) -> pd.DataFrame:
        return pd.DataFrame([u.as_record() for u in self.trust.log])

    def decisions_frame(self) -> pd.DataFrame:
        return pd.DataFrame([d.as_record() for d in self.policy.decisions])

    def alerts_frame(self) -> pd.DataFrame:
        return pd.DataFrame([a.__dict__ for a in self.alerts])
