"""Live simulation service for the dashboard (Phase 19).

Runs a *real* simulation of the selected system variant on a background thread, in
(optionally accelerated) real time, and exposes thread-safe snapshots of the actual
engine / D2DAP / IDS / trust / policy state. Nothing shown on the dashboard is
hard-coded: every value is read from the running objects.
"""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from typing import Any

from pydantic import BaseModel, Field

from app.attacks.base import AttackSpec
from app.attacks.manager import ATTACK_TYPES, AttackManager
from app.core.logging import get_logger
from app.experiments.scenario import ScenarioConfig, Variant, build_variant
from app.services.auth_coordinator import AuthEvent
from app.services.framework import ModelUnavailableError
from app.services.monitor import SecurityMonitor
from app.services.swarm import SecureSwarm

log = get_logger(__name__)
HISTORY_WINDOWS = 180
MAX_EVENTS = 300


class LiveConfig(BaseModel):
    num_drones: int = Field(10, ge=3, le=60)
    seed: int = 42
    variant: str = Field("adaptive", pattern="^(adaptive|d2dap_ids_trust|d2dap_ids|no_ml|d2dap)$")
    speed: float = Field(1.0, gt=0, le=50)  # simulated seconds per wall second


class AttackRequest(BaseModel):
    kind: str
    target: str
    duration_s: float = Field(30.0, gt=0, le=600)
    rate_pps: float = Field(20.0, gt=0, le=200)


class LiveSimulation:
    """Owns one running swarm; all public methods are thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._running = False
        self.config: LiveConfig | None = None
        self.swarm: SecureSwarm | None = None
        self.monitor: SecurityMonitor | None = None
        self.attacks: AttackManager | None = None
        self.notice: str = ""
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._seq = 0
        self._decisions_seen = 0
        self._alerts_seen = 0

    # ------------------------------------------------------------- lifecycle
    def start(self, config: LiveConfig, background: bool = True) -> dict[str, Any]:
        self.stop()
        with self._lock:
            variant = Variant(config.variant)
            # Long-running demo: CRPs are refreshed from the CS when low (see crp-budget note).
            cfg = ScenarioConfig(num_drones=config.num_drones, duration_ms=10**9,
                                 area_m=300.0 * (config.num_drones / 10) ** 0.5,
                                 crp_count=64, reprovision_below=8)  # fmt: skip
            self.notice = ""
            try:
                swarm, ext = build_variant(variant, cfg, config.seed)
            except ModelUnavailableError:
                variant = Variant.NO_ML
                config = config.model_copy(update={"variant": variant.value})
                swarm, ext = build_variant(variant, cfg, config.seed)
                self.notice = "IDS model not trained yet: running the no-ML variant."
            self.config, self.swarm = config, swarm
            self.monitor = next((e for e in ext if isinstance(e, SecurityMonitor)), None)
            self.attacks = AttackManager(swarm)
            self._events.clear()
            self._decisions_seen = self._alerts_seen = 0
            swarm.coordinator.add_listener(self._on_auth)
            self._event("system", f"Started {variant.value} with {config.num_drones} drones "
                                  f"(seed {config.seed})")  # fmt: skip
        if background:
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="live-sim", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> None:
        self._running = False
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        self._thread = None

    def _loop(self) -> None:
        while self._running:
            t0 = time.perf_counter()
            self.step(1)
            cfg, swarm = self.config, self.swarm
            if cfg is None or swarm is None:
                return
            budget = swarm.engine.config.tick_ms / 1000 / cfg.speed
            time.sleep(max(0.0, budget - (time.perf_counter() - t0)))

    def step(self, ticks: int = 1) -> None:
        with self._lock:
            if self.swarm is None:
                return
            for _ in range(ticks):
                self.swarm.engine.step()
            self._collect()

    # ------------------------------------------------------------- events
    def _event(self, kind: str, message: str, **fields: Any) -> None:
        self._seq += 1
        t = self.swarm.engine.clock.now_ms if self.swarm else 0
        self._events.append({"id": self._seq, "t_ms": t, "kind": kind, "message": message,
                             **fields})  # fmt: skip

    def _on_auth(self, e: AuthEvent) -> None:
        if e.stage == "respond" and e.success:
            return  # half-open acceptances are reported with the final outcome
        if e.success:
            if e.reauth:  # routine (re-)key sessions are not shown, to keep the feed readable
                self._event("auth", f"D2DAP re-authentication {e.initiator} -> {e.responder}",
                            drone=e.initiator, success=True)  # fmt: skip
        else:
            self._event("auth", f"D2DAP failure claimed by {e.initiator} at {e.responder}: "
                                f"{e.reason}", drone=e.initiator, success=False)  # fmt: skip

    def _collect(self) -> None:
        mon = self.monitor
        if mon is None:
            return
        for d in mon.policy.decisions[self._decisions_seen :]:
            self._event("policy", f"{d.drone_id}: {d.previous_state.value.upper()} -> "
                                  f"{d.new_state.value.upper()} (trust {d.trust_after:.2f})",
                        drone=d.drone_id, state=d.new_state.value,
                        explanation=d.explanation)  # fmt: skip
        self._decisions_seen = len(mon.policy.decisions)
        for a in mon.alerts[self._alerts_seen :]:
            self._event("ids", f"IDS alert on {a.src}: P(attack)={a.p_attack:.2f} "
                               f"({a.attack_class})", drone=a.src, p=a.p_attack)  # fmt: skip
        self._alerts_seen = len(mon.alerts)

    # ------------------------------------------------------------- control
    def launch_attack(self, req: AttackRequest) -> dict[str, Any]:
        with self._lock:
            if self.swarm is None or self.attacks is None:
                raise RuntimeError("simulation not running")
            if req.kind not in ATTACK_TYPES:
                raise ValueError(f"unknown attack {req.kind}")
            now = self.swarm.engine.clock.now_ms
            attack = self.attacks.launch(AttackSpec(
                kind=req.kind, target=req.target, start_ms=now + 1,
                duration_ms=int(req.duration_s * 1000), rate_pps=req.rate_pps))  # fmt: skip
            self._event("attack", f"Injected {req.kind} on {req.target} for {req.duration_s:.0f} s "
                                  "(ground truth, for the demo)", drone=req.target)  # fmt: skip
            return {"attack_id": attack.spec.attack_id}

    # ------------------------------------------------------------- snapshots
    def status(self) -> dict[str, Any]:
        with self._lock:
            sw = self.swarm
            return {
                "running": self._running,
                "config": self.config.model_dump() if self.config else None,
                "sim_time_s": sw.engine.clock.now_s if sw else 0.0,
                "notice": self.notice,
            }

    def state(self) -> dict[str, Any]:
        with self._lock:
            if self.swarm is None:
                return {"drones": [], "edges": [], **self.status()}
            net = self.swarm.engine.network
            agents = self.swarm.d2dap.agents
            drones = []
            for d in net.nodes.values():
                if not d.active and d.drone_id.startswith("X-"):
                    continue
                s = d.summary()
                s["registered"] = d.drone_id in agents
                s["crp_remaining"] = agents[d.drone_id].crp_remaining if s["registered"] else None
                s["external_radio"] = d.drone_id.startswith("X-")
                drones.append(s)
            return {**self.status(), "drones": drones,
                    "edges": [{"a": a, "b": b, "distance_m": dist}
                              for a, b, dist in net.topology()],
                    "active_attacks": self._active_attacks()}  # fmt: skip

    def _active_attacks(self) -> list[dict[str, Any]]:
        active = self.attacks.active() if self.attacks else []
        return [a.evidence.as_record() for a in active]

    def events(self, since: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self._events if e["id"] > since]

    def trust_history(self) -> dict[str, Any]:
        with self._lock:
            mon = self.monitor
            if mon is None:
                return {"series": {}, "bands": {}}
            series: dict[str, list[dict[str, float | None]]] = {}
            horizon = (self.swarm.engine.clock.now_ms if self.swarm else 0) - HISTORY_WINDOWS * 1000
            for u in mon.trust.log:
                if u.t_ms >= horizon:
                    series.setdefault(u.drone_id, []).append(
                        {"t": u.t_ms / 1000, "trust": round(u.new, 4),
                         "p": None if u.evidence.attack_prob is None
                         else round(u.evidence.attack_prob, 4)})  # fmt: skip
            c = mon.policy.config
            return {"series": series, "bands": {"normal": c.normal, "monitor": c.monitor,
                                                "restrict": c.restrict,
                                                "reauthenticate": c.reauthenticate}}  # fmt: skip

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            sw = self.swarm
            if sw is None:
                return {}
            net, coord = sw.engine.network, sw.coordinator.counters
            mon = self.monitor
            drops = Counter(r["dropped_reason"] for r in sw.traffic_log.records[-5000:]
                            if r["dropped_reason"])  # fmt: skip
            states = Counter(d.security_state.value for d in net.nodes.values()
                             if d.drone_id in sw.d2dap.agents)  # fmt: skip
            proc = mon.stats.processing_ms[-30:] if mon else []
            return {
                "sim_time_s": sw.engine.clock.now_s,
                "packets_sent": net.counters.sent,
                "packets_delivered": net.counters.delivered,
                "packets_dropped": net.counters.dropped,
                "recent_drop_reasons": dict(drops),
                "auth_success": coord.successes,
                "auth_failures": coord.failures,
                "auth_failure_reasons": dict(coord.by_reason),
                "ids_alerts": len(mon.alerts) if mon else 0,
                "policy_decisions": len(mon.policy.decisions) if mon else 0,
                "states": dict(states),
                "monitor_ms_per_window": round(sum(proc) / len(proc), 2) if proc else None,
                "windows": mon.stats.windows if mon else 0,
                "rl_entries": len(sw.d2dap.revocation_list),
            }


LIVE = LiveSimulation()
