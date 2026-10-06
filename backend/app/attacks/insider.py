"""Attacks by a COMPROMISED but legitimately registered drone (insider threat).

The insider holds valid D2DAP credentials and a working PUF, so it authenticates
successfully and its packets are sealed with valid session keys. D2DAP authenticates
identity, not behaviour; these attacks are therefore invisible to authentication alone
(observation O5) and are the main motivation for the trust/policy layer.
"""

from __future__ import annotations

from typing import Any

from app.attacks.base import Attack, Stride
from app.attacks.external import _RateSource
from app.models.enums import DroneRole, PacketProtocol
from app.models.packet import Packet


class _InsiderAttack(Attack):
    insider = True

    def _start(self, now_ms: int) -> None:
        self.target_drone().compromised = True
        self.add_source(self.spec.target, _RateSource(self, self.spec.rate_pps, self._build))
        self.on_start(now_ms)

    def on_start(self, now_ms: int) -> None:
        """Subclass hook."""

    def _stop(self, now_ms: int) -> None:
        self.target_drone().compromised = bool(self.spec.params.get("remain_compromised", False))

    def _build(self, now_ms: int) -> Packet | None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _random_peer(self, exclude_leader: bool = False) -> str | None:
        peers = [
            d.drone_id
            for d in self.network.neighbors(self.spec.target)
            if not d.drone_id.startswith("X-")
            and not (exclude_leader and d.role is DroneRole.LEADER)
        ]
        peers.sort()
        return peers[int(self.rng.integers(0, len(peers)))] if peers else None


class FloodingAttack(_InsiderAttack):
    """Volumetric flood of large, validly sealed packets towards one victim."""

    kind = "flooding"
    stride = (Stride.DENIAL_OF_SERVICE,)

    def on_start(self, now_ms: int) -> None:
        self._victim = self.spec.params.get("victim") or self._random_peer()

    def _build(self, now_ms: int) -> Packet | None:
        victim = self._victim if self._victim in self.network.nodes else self._random_peer()
        if victim is None:
            return None
        size = int(self.rng.integers(1200, 1450))
        return self.make_packet(victim, PacketProtocol.VIDEO, size)


class PrivilegeEscalationAttack(_InsiderAttack):
    """A WORKER issues privileged COMMAND packets (leader-only) to its peers.

    Also performs observation O3: recovers the network master secret ``A`` from two of
    its own shares using its own PUF, and records whether this succeeded.
    """

    kind = "privilege_escalation"
    stride = (Stride.ELEVATION_OF_PRIVILEGE,)

    def on_start(self, now_ms: int) -> None:
        agent = self.swarm.d2dap.agents.get(self.spec.target)
        recovered: bool | None = None if agent is None else False
        if agent is not None and agent.credentials and len(agent.credentials.challenges) >= 2:
            c = agent.credentials
            pts = [
                (agent.suite.to_scalar(agent.registration_a(c.challenges[k])), c.b[k])
                for k in (0, 1)
            ]
            A = agent.shamir.reconstruct(pts)
            recovered = agent.suite.H(A.to_bytes(agent.suite.scalar_bytes, "big"),
                                      agent.id_bytes) == c.V  # fmt: skip
        self.evidence.extra["master_secret_recovered"] = recovered

    def _build(self, now_ms: int) -> Packet | None:
        dst = self._random_peer(exclude_leader=True)
        if dst is None:
            return None
        return self.make_packet(dst, PacketProtocol.COMMAND, int(self.rng.integers(70, 120)))


class AbnormalTrafficAttack(_InsiderAttack):
    """Reconnaissance-style scanning (many destinations, tiny packets) mixed with
    exfiltration bursts (large packets to a non-leader peer)."""

    kind = "abnormal"
    stride = (Stride.INFORMATION_DISCLOSURE, Stride.DENIAL_OF_SERVICE)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._rr = 0

    def _build(self, now_ms: int) -> Packet | None:
        if self.rng.random() < float(self.spec.params.get("scan_fraction", 0.7)):
            peers = sorted(
                d.drone_id for d in self.network.active_nodes()
                if d.drone_id != self.spec.target and not d.drone_id.startswith("X-")
            )  # fmt: skip
            if not peers:
                return None
            self._rr = (self._rr + 1) % len(peers)
            return self.make_packet(peers[self._rr], PacketProtocol.TELEMETRY,
                                    int(self.rng.integers(40, 64)))  # fmt: skip
        dst = self._random_peer(exclude_leader=True)
        if dst is None:
            return None
        return self.make_packet(dst, PacketProtocol.VIDEO, int(self.rng.integers(1300, 1450)))
