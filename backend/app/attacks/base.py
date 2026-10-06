"""Attack framework: specification, evidence collection, attacker nodes.

Every attack:

* has a ground-truth ``label`` (written on every packet it creates or alters) and an
  ``attack_id`` (one per launched instance);
* maps to one or more STRIDE categories;
* produces measurable :class:`AttackEvidence` (packets sent/accepted/dropped by reason,
  authentication outcomes, crypto work forced on victims, CRP consumption, extras).

Ground-truth fields are for evaluation only and are never used as IDS features.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np
from pydantic import BaseModel, Field

from app.core.rng import SystemRandomSource
from app.models.enums import DroneRole
from app.models.packet import Packet
from app.security.crypto import CryptoSuite
from app.security.d2dap.messages import AuthMessage
from app.services.auth_coordinator import AuthEvent
from app.services.swarm import SecureSwarm
from app.simulation.drone import Drone
from app.simulation.traffic import TrafficSource


class Stride(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"


class AttackSpec(BaseModel):
    """Declarative description of one attack instance."""

    kind: str
    target: str  # victim drone (impersonated / attacked / compromised, depending on kind)
    start_ms: int = Field(10_000, ge=0)
    duration_ms: int = Field(20_000, gt=0)
    rate_pps: float = Field(20.0, ge=0)
    params: dict[str, Any] = Field(default_factory=dict)
    attack_id: str = ""

    @property
    def end_ms(self) -> int:
        return self.start_ms + self.duration_ms


@dataclass
class AttackEvidence:
    """Measured evidence of one attack instance."""

    attack_id: str
    kind: str
    stride: list[str]
    attacker: str
    target: str
    start_ms: int
    end_ms: int
    packets_attempted: int = 0  # created (or altered) by the attacker, incl. never transmitted
    packets_sent: int = 0
    packets_accepted: int = 0
    dropped: Counter[str] = field(default_factory=Counter)
    auth_attempts: int = 0
    auth_accepted: int = 0
    auth_failures: Counter[str] = field(default_factory=Counter)
    victim_compute_ms: float = 0.0
    crp_consumed: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    def as_record(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "kind": self.kind,
            "stride": "".join(self.stride),
            "attacker": self.attacker,
            "target": self.target,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "packets_attempted": self.packets_attempted,
            "packets_sent": self.packets_sent,
            "packets_accepted": self.packets_accepted,
            "packets_dropped": sum(self.dropped.values()),
            "drop_reasons": dict(self.dropped),
            "auth_attempts": self.auth_attempts,
            "auth_accepted": self.auth_accepted,
            "auth_failures": dict(self.auth_failures),
            "victim_compute_ms": round(self.victim_compute_ms, 3),
            "crp_consumed": self.crp_consumed,
            **{f"extra_{k}": v for k, v in self.extra.items()},
        }


class Attack:
    """Base class. Subclasses implement :meth:`_start` / :meth:`_stop` and set metadata."""

    kind: str = "attack"
    stride: tuple[Stride, ...] = ()
    insider: bool = False

    def __init__(self, spec: AttackSpec, swarm: SecureSwarm) -> None:
        self.spec = spec
        self.swarm = swarm
        self.engine = swarm.engine
        self.network = swarm.engine.network
        self.rng: np.random.Generator = swarm.streams.numpy(f"attack:{spec.attack_id}")
        self.attacker_id = spec.target if self.insider else f"X-{spec.attack_id}"
        self.active = False
        self.finished = False
        self._sources: list[tuple[str, TrafficSource]] = []
        self.evidence = AttackEvidence(
            attack_id=spec.attack_id,
            kind=self.kind,
            stride=[s.value for s in self.stride],
            attacker=self.attacker_id,
            target=spec.target,
            start_ms=spec.start_ms,
            end_ms=spec.end_ms,
        )
        self.network.add_observer(self._observe)
        swarm.coordinator.add_listener(self._on_auth)

    # ------------------------------------------------------------- lifecycle
    def tick(self, now_ms: int) -> None:
        if not self.active and not self.finished and now_ms >= self.spec.start_ms:
            self.active = True
            self._start(now_ms)
        if self.active and now_ms >= self.spec.end_ms:
            self.active = False
            self.finished = True
            self._stop(now_ms)
            for drone_id, src in self._sources:
                self.engine.remove_source(drone_id, src)
            self._sources.clear()
        if self.active:
            self._on_tick(now_ms)

    def _start(self, now_ms: int) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _stop(self, now_ms: int) -> None:
        """Default: nothing to undo besides traffic sources."""

    def _on_tick(self, now_ms: int) -> None:
        """Per-tick behaviour while active (default: none)."""

    def add_source(self, drone_id: str, source: TrafficSource) -> None:
        self.engine.add_source(drone_id, source)
        self._sources.append((drone_id, source))

    # ------------------------------------------------------------- evidence
    def owns(self, packet: Packet) -> bool:
        return packet.attack_id == self.spec.attack_id

    def _observe(self, packet: Packet) -> None:
        if not self.owns(packet):
            return
        ev = self.evidence
        ev.packets_sent += 1
        if packet.dropped_reason is None:
            ev.packets_accepted += 1
        else:
            ev.dropped[packet.dropped_reason] += 1

    def _on_auth(self, event: AuthEvent) -> None:
        if not self.active:
            return
        if self.attributes_auth(event):
            self.evidence.auth_attempts += 1
            if event.success:
                self.evidence.auth_accepted += 1
            else:
                self.evidence.auth_failures[event.reason or "unknown"] += 1
            self.evidence.victim_compute_ms += event.compute_ms
            if event.success and event.stage == "respond":
                # Each responder acceptance of an attacker-sent M1 consumes one victim CRP.
                self.evidence.crp_consumed += 1

    def attributes_auth(self, event: AuthEvent) -> bool:
        """Whether an auth outcome was caused by this attack (ground-truth packet id)."""
        return event.attack_id == self.spec.attack_id

    # ------------------------------------------------------------- helpers
    def make_packet(self, dst: str, protocol: Any, size: int, **kw: Any) -> Packet:
        src = kw.pop("src", self.spec.target)
        return self.engine.factory.make(
            self.engine.clock.now_ms, src, dst, protocol, size, true_src=self.attacker_id,
            label=self.kind, attack_id=self.spec.attack_id, **kw,
        )  # fmt: skip

    def auth_wire_size(self) -> int:
        """M1 size from the *public* parameters (security level), as an attacker knows it."""
        level = self.swarm.d2dap.config.security_level
        return AuthMessage.wire_size(CryptoSuite(level, SystemRandomSource()))

    def target_drone(self) -> Drone:
        return self.network.get(self.spec.target)

    def spawn_attacker_node(self, near: str, offset_m: float = 40.0) -> Drone:
        """Register an external attacker radio near ``near`` (it follows that drone)."""
        anchor = self.network.get(near)
        pos = anchor.position + np.array([offset_m, 0.0, 0.0])
        node = self.engine.add_drone(self.attacker_id, DroneRole.WORKER, pos,
                                     with_normal_traffic=False)  # fmt: skip
        node.compromised = True
        self.engine.join(self.attacker_id)
        self._follow = near
        return node

    def follow(self) -> None:
        """Keep the attacker radio within range of the drone it shadows."""
        anchor = self.network.get(getattr(self, "_follow", self.spec.target))
        me = self.network.get(self.attacker_id)
        me.position = anchor.position + np.array([30.0, 10.0, 0.0])

    def peers_of(self, drone_id: str) -> list[str]:
        return sorted(d.drone_id for d in self.network.neighbors(drone_id)
                      if not d.drone_id.startswith("X-"))  # fmt: skip
