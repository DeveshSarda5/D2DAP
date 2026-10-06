"""Authentication service interface and the D2DAP implementation of it.

:class:`D2DAPSystem` wires the Control Server, the public directory, the revocation
list and per-drone agents together and exposes one call::

    result = system.authenticate("D1", "D2", now_ms)

which runs M1 -> V1 -> M2 -> V2 and returns an :class:`AuthResult` with success/failure,
failure reason and stage, latency, messages and bytes, per-side operation counts and
session information. :class:`NoAuthService` is the "no authentication" baseline.
"""

from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from app.core.rng import RandomStreams
from app.security.crypto import OpCounter
from app.security.d2dap.agent import DroneSecurityAgent
from app.security.d2dap.config import D2DAPConfig
from app.security.d2dap.control_server import ControlServer
from app.security.d2dap.entities import FailureReason, ProtocolAbort, PublicDirectory
from app.security.d2dap.revocation import RevocationList
from app.security.puf import PUF, BoundPUF, make_puf


@dataclass
class AuthResult:
    """Everything measured about one authentication attempt."""

    protocol: str
    initiator: str
    responder: str
    success: bool
    failure_reason: str | None = None
    failure_stage: str | None = None  # "initiate" | "respond" | "complete"
    session_id: str | None = None
    message_bytes: list[int] = field(default_factory=list)
    rl_broadcasts: int = 0
    rl_broadcast_bytes: int = 0
    ops_initiator: dict[str, int] = field(default_factory=dict)
    ops_responder: dict[str, int] = field(default_factory=dict)
    compute_ms_initiator: float = 0.0
    compute_ms_responder: float = 0.0
    network_ms: float = 0.0
    t_start_ms: int = 0
    t_end_ms: int = 0

    @property
    def messages(self) -> int:
        return len(self.message_bytes)

    @property
    def total_bytes(self) -> int:
        return sum(self.message_bytes)

    @property
    def latency_ms(self) -> float:
        """End-to-end latency = measured compute (both sides) + simulated network delay."""
        return self.compute_ms_initiator + self.compute_ms_responder + self.network_ms

    def as_record(self) -> dict[str, Any]:
        rec = asdict(self)
        rec.update(
            messages=self.messages,
            total_bytes=self.total_bytes,
            total_bits=self.total_bytes * 8,
            latency_ms=self.latency_ms,
        )
        for side in ("initiator", "responder"):
            for k, v in rec.pop(f"ops_{side}").items():
                rec[f"ops_{side}_{k}"] = v
        rec["message_bytes"] = "|".join(map(str, self.message_bytes))
        return rec


class AuthenticationService(Protocol):
    """Interface consumed by the integration layer."""

    name: str

    def enroll(self, drone_id: str) -> None:
        """Provision a drone so it can authenticate."""
        ...

    def authenticate(
        self, initiator: str, responder: str, now_ms: int, delays_ms: tuple[int, int] = (0, 0)
    ) -> AuthResult:
        """Run a full mutual authentication between two drones."""
        ...


def _ops_delta(after: OpCounter, before: dict[str, int]) -> dict[str, int]:
    return {k: v - before[k] for k, v in after.as_dict().items()}


class D2DAPSystem:
    """Control server + agents: the D2DAP authentication service."""

    name = "D2DAP"

    def __init__(self, config: D2DAPConfig, streams: RandomStreams) -> None:
        self.config = config
        self.streams = streams
        self.cs = ControlServer(config, streams.crypto("control-server"))
        self.agents: dict[str, DroneSecurityAgent] = {}

    @property
    def directory(self) -> PublicDirectory:
        return self.cs.directory

    @property
    def revocation_list(self) -> RevocationList:
        return self.cs.revocation_list

    def make_puf(self, device_label: str) -> PUF:
        """Manufacture a (software) PUF for a physical device ``device_label``."""
        p = self.config.puf
        return make_puf(
            p.model,
            self.streams.numpy(f"puf-manufacture:{device_label}"),
            noise_sigma=p.noise_sigma,
            majority_votes=p.majority_votes,
            k=p.xor_k,
            stages=p.stages,
        )

    def create_agent(self, drone_id: str, puf: PUF | None = None) -> DroneSecurityAgent:
        """Create the on-drone agent (its PUF is bound to the device)."""
        agent = DroneSecurityAgent(
            drone_id,
            BoundPUF(drone_id, puf if puf is not None else self.make_puf(drone_id)),
            self.config,
            directory=self.cs.directory,
            revocation_list=self.cs.revocation_list,
            rand=self.streams.crypto(f"agent:{drone_id}"),
        )
        self.agents[drone_id] = agent
        return agent

    def enroll(self, drone_id: str) -> None:
        agent = self.agents.get(drone_id) or self.create_agent(drone_id)
        self.cs.register(agent)

    def authenticate(
        self, initiator: str, responder: str, now_ms: int, delays_ms: tuple[int, int] = (0, 0)
    ) -> AuthResult:
        """Run M1 -> V1 -> M2 -> V2 directly between two agents (no packet network)."""
        ai, aj = self.agents[initiator], self.agents[responder]
        res = AuthResult(self.name, initiator, responder, success=False, t_start_ms=now_ms)
        res.network_ms = float(delays_ms[0])
        ops_i0, ops_j0 = ai.ops.as_dict(), aj.ops.as_dict()
        rl_b0, rl_bytes0 = self.revocation_list.broadcasts, self.revocation_list.broadcast_bytes
        t = now_ms
        stage = "initiate"
        try:
            w0 = time.perf_counter_ns()
            m1 = ai.initiate(responder, t)
            c1 = (time.perf_counter_ns() - w0) / 1e6
            res.compute_ms_initiator += c1
            res.message_bytes.append(len(m1))
            t += math.ceil(c1) + delays_ms[0]

            stage = "respond"
            w0 = time.perf_counter_ns()
            try:
                out = aj.respond(m1, t, hint=initiator)
            finally:
                res.compute_ms_responder += (time.perf_counter_ns() - w0) / 1e6
            res.message_bytes.append(len(out.m2))
            res.network_ms += delays_ms[1]
            t += math.ceil(res.compute_ms_responder) + delays_ms[1]

            stage = "complete"
            w0 = time.perf_counter_ns()
            try:
                session = ai.complete(out.m2, t)
            finally:
                c3 = (time.perf_counter_ns() - w0) / 1e6
                res.compute_ms_initiator += c3
                t += math.ceil(c3)
            res.success = True
            res.session_id = session.session_id
        except ProtocolAbort as exc:
            res.failure_reason = exc.reason.value
            res.failure_stage = stage
            ai.abort_pending(responder)
        res.t_end_ms = t
        res.ops_initiator = _ops_delta(ai.ops, ops_i0)
        res.ops_responder = _ops_delta(aj.ops, ops_j0)
        res.rl_broadcasts = self.revocation_list.broadcasts - rl_b0
        res.rl_broadcast_bytes = self.revocation_list.broadcast_bytes - rl_bytes0
        return res

    def session_key(self, drone_id: str, peer_id: str) -> bytes | None:
        rec = self.agents[drone_id].sessions.get(peer_id)
        return rec.session_key if rec else None


class NoAuthService:
    """Baseline without authentication: every claimed identity is accepted."""

    name = "NoAuth"

    def __init__(self) -> None:
        self.enrolled: set[str] = set()

    def enroll(self, drone_id: str) -> None:
        self.enrolled.add(drone_id)

    def authenticate(
        self, initiator: str, responder: str, now_ms: int, delays_ms: tuple[int, int] = (0, 0)
    ) -> AuthResult:
        return AuthResult(
            self.name, initiator, responder, success=True, t_start_ms=now_ms, t_end_ms=now_ms
        )


__all__ = [
    "AuthResult",
    "AuthenticationService",
    "D2DAPSystem",
    "FailureReason",
    "NoAuthService",
]
