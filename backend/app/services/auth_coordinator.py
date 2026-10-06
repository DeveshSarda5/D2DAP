"""Runs D2DAP over the simulated network (packet-level MAKA) and manages sessions.

* On-demand authentication: when a drone first sends unicast data to a peer without a
  session, the data is held and the initiator sends ``AUTH_REQUEST`` (real M1 bytes).
* The responder's handler runs V1; on success it sends ``AUTH_RESPONSE`` (M2) and an
  ``RL_BROADCAST``; the initiator's handler runs V2 and both sides install the session
  (``SessionInfo.key`` = data-plane key). Held packets are then released.
* Every outcome is published as an :class:`AuthEvent` (consumed by IDS features and the
  trust engine) and annotated on the packet (``auth_ok`` / ``auth_failure``).
* :meth:`reauthenticate` revokes a drone's sessions so that fresh MAKA runs are required
  (used by the adaptive policy).

Attackers inject their own ``AUTH_REQUEST`` packets (forged / replayed / cloned); they
are processed by exactly the same responder handler.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.models.enums import BROADCAST, AuthState, PacketProtocol
from app.models.packet import Packet
from app.security.d2dap.entities import FailureReason, ProtocolAbort
from app.security.d2dap.service import D2DAPSystem
from app.services.secure_transport import (
    DATA_PROTOCOLS,
    SEALED_PROTOCOLS,
    SecureTransport,
    data_key,
)
from app.simulation.drone import Drone, SessionInfo
from app.simulation.engine import SimulationEngine

log = get_logger(__name__)

MAX_HELD_PER_PAIR = 64
SIMULATED_COMPUTE_DELAY_MS = 15
AUTH_TIMEOUT_MS = 3000


@dataclass(frozen=True)
class AuthEvent:
    """One MAKA outcome observed in the network."""

    t_ms: int
    initiator: str  # claimed initiator (link-layer source of M1)
    responder: str
    success: bool
    reason: str | None
    #: "initiate" | "respond" | "complete" | "timeout". A *successful* "respond" event means
    #: the responder accepted M1 and installed a (half-open) session; the MAKA's final
    #: outcome is the initiator's "complete" event. In-window replays (O1) show up as
    #: successful "respond" events that are never followed by a "complete".
    stage: str
    compute_ms: float
    reauth: bool = False
    #: GROUND TRUTH of the triggering packet (evaluation only; detectors never read it).
    attack_id: str | None = None


AuthListener = Callable[[AuthEvent], None]


@dataclass
class _Attempt:
    started_ms: int
    reauth: bool
    compute_ms: float = 0.0


@dataclass
class CoordinatorCounters:
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    auth_bytes: int = 0
    rl_broadcast_bytes: int = 0
    held_dropped: int = 0
    responder_accepts: int = 0
    refused_unregistered: int = 0
    rekeys: int = 0
    reprovisions: int = 0
    by_reason: dict[str, int] = field(default_factory=lambda: defaultdict(int))


class AuthCoordinator:
    """Glue between :class:`D2DAPSystem`, the network and the secure transport."""

    def __init__(
        self,
        engine: SimulationEngine,
        d2dap: D2DAPSystem,
        transport: SecureTransport,
        rekey_interval_ms: int | None = None,
        *,
        reprovision_below: int | None = None,
    ) -> None:
        self.engine = engine
        self.network = engine.network
        self.d2dap = d2dap
        self.transport = transport
        self.counters = CoordinatorCounters()
        self._listeners: list[AuthListener] = []
        self._attempts: dict[tuple[str, str], _Attempt] = {}
        self._held: dict[tuple[str, str], list[Packet]] = defaultdict(list)
        self._blocked_initiators: set[str] = set()
        self._reauth_flag: set[str] = set()
        #: Optional session lifetime (our addition; D2DAP does not specify re-keying).
        self.rekey_interval_ms = rekey_interval_ms
        #: CS re-provisioning when a drone runs low on one-time CRPs (our addition; models a
        #: periodic return-to-base refresh over the secure registration channel).
        self.reprovision_below = reprovision_below
        #: Simulated processing delay of one MAKA step. Measured wall-clock compute time is
        #: reported (AuthEvent.compute_ms) but never fed back into simulated time, so a run
        #: is a pure function of (config, seed) on any machine. 15 ms ~ measured P-256
        #: per-side cost in Phase 5.
        self.compute_delay_ms = SIMULATED_COMPUTE_DELAY_MS

    # ------------------------------------------------------------- wiring
    def install(self) -> None:
        self.network.set_handler(PacketProtocol.AUTH_REQUEST, self._on_request)
        self.network.set_handler(PacketProtocol.AUTH_RESPONSE, self._on_response)
        self.network.set_handler(PacketProtocol.RL_BROADCAST, lambda p, r: None)
        self.engine.set_send_hook(self._send_hook)
        self.engine.add_tick_hook(self._expire_attempts)
        if self.rekey_interval_ms:
            self.engine.add_tick_hook(self._rekey)

    def add_listener(self, listener: AuthListener) -> None:
        self._listeners.append(listener)

    def _emit(self, event: AuthEvent) -> None:
        if event.success and event.stage == "respond":
            self.counters.responder_accepts += 1
        elif event.success:
            self.counters.attempts += 1
            self.counters.successes += 1
        else:
            self.counters.attempts += 1
            self.counters.failures += 1
            self.counters.by_reason[event.reason or "unknown"] += 1
        for listener in self._listeners:
            listener(event)

    def enroll(self, drone: Drone) -> None:
        """Register a drone with the Control Server (Registration phase)."""
        self.d2dap.enroll(drone.drone_id)
        drone.auth_state = AuthState.REGISTERED

    def block_initiator(self, drone_id: str, blocked: bool = True) -> None:
        """Quarantined drones are not allowed to start new sessions."""
        (self._blocked_initiators.add if blocked else self._blocked_initiators.discard)(drone_id)

    # ------------------------------------------------------------- data path
    def _send_hook(self, packet: Packet) -> Packet | None:
        if self._refuse_unregistered(packet):
            self.counters.refused_unregistered += 1
            return None
        sealed = self.transport.seal(packet)
        if sealed.session_id is not None or not self._needs_session(sealed):
            return sealed
        key = (packet.true_src, packet.dst)
        held = self._held[key]
        if len(held) < MAX_HELD_PER_PAIR:
            held.append(packet)
        else:
            self.counters.held_dropped += 1
        if key not in self._attempts:
            self.start(packet.true_src, packet.dst, packet.timestamp_ms)
        return None

    def _refuse_unregistered(self, packet: Packet) -> bool:
        """A registered drone never sends data to a destination without a published key."""
        return (
            self.transport.require_auth
            and packet.attack_id is None
            and packet.protocol in DATA_PROTOCOLS
            and packet.dst != BROADCAST
            and packet.true_src in self.d2dap.agents
            and self.d2dap.directory.get(packet.dst) is None
        )

    def _rekey(self, now_ms: int) -> None:
        interval = self.rekey_interval_ms or 0
        for drone in self.network.active_nodes():
            for peer, sess in list(drone.sessions.items()):
                if now_ms - sess.established_ms >= interval:
                    drone.drop_peer(peer)
                    other = self.network.nodes.get(peer)
                    if other is not None:
                        other.drop_peer(drone.drone_id)
                    self.counters.rekeys += 1

    def _needs_session(self, packet: Packet) -> bool:
        sender = self.network.nodes.get(packet.true_src)
        return (
            self.transport.require_auth
            and packet.protocol in SEALED_PROTOCOLS
            and packet.dst != BROADCAST
            and packet.payload is None
            and sender is not None
            and packet.true_src in self.d2dap.agents
            and packet.dst in self.d2dap.agents
        )

    # ------------------------------------------------------------- MAKA over packets
    def start(self, initiator: str, responder: str, now_ms: int, reauth: bool = False) -> bool:
        """Send M1 from ``initiator`` to ``responder``. Returns False if it could not start."""
        if initiator in self._blocked_initiators:
            return False
        agent = self.d2dap.agents.get(initiator)
        if agent is None:
            return False
        reauth = reauth or initiator in self._reauth_flag
        w0 = time.perf_counter_ns()
        try:
            m1 = agent.initiate(responder, now_ms)
        except ProtocolAbort as exc:
            self._emit(AuthEvent(now_ms, initiator, responder, False, exc.reason.value,
                                 "initiate", 0.0, reauth))  # fmt: skip
            self._drop_held((initiator, responder))
            return False
        compute = (time.perf_counter_ns() - w0) / 1e6
        self._attempts[(initiator, responder)] = _Attempt(now_ms, reauth, compute)
        pkt = self.engine.factory.make(
            now_ms + self.compute_delay_ms, initiator, responder, PacketProtocol.AUTH_REQUEST,
            len(m1), payload=m1,
        )  # fmt: skip
        self.counters.auth_bytes += len(m1)
        self.network.send(pkt)
        return True

    def _on_request(self, packet: Packet, receiver: Drone) -> None:
        agent = self.d2dap.agents.get(receiver.drone_id)
        now = packet.delivered_ms or packet.timestamp_ms
        if agent is None or packet.payload is None:
            packet.auth_ok, packet.auth_failure = False, FailureReason.NOT_REGISTERED.value
            packet.dropped_reason = "auth_failed"
            return
        w0 = time.perf_counter_ns()
        try:
            out = agent.respond(packet.payload, now, hint=packet.src)
        except ProtocolAbort as exc:
            compute = (time.perf_counter_ns() - w0) / 1e6
            packet.auth_ok, packet.auth_failure = False, exc.reason.value
            packet.dropped_reason = "auth_failed"
            self._emit(AuthEvent(now, packet.src, receiver.drone_id, False, exc.reason.value,
                                 "respond", compute, packet.src in self._reauth_flag,
                                 packet.attack_id))  # fmt: skip
            return
        compute = (time.perf_counter_ns() - w0) / 1e6
        packet.auth_ok = True
        t_send = now + self.compute_delay_ms
        # The responder installs its half of the session now (paper: after sending M2).
        self._install(receiver.drone_id, out.peer_id, out.session.session_id,
                      out.session.session_key, now)  # fmt: skip
        resp = self.engine.factory.make(t_send, receiver.drone_id, packet.src,
                                        PacketProtocol.AUTH_RESPONSE, len(out.m2),
                                        payload=out.m2)  # fmt: skip
        self.counters.auth_bytes += len(out.m2)
        rl_size = agent.suite.hash_bytes
        rl = self.engine.factory.make(t_send, receiver.drone_id, BROADCAST,
                                      PacketProtocol.RL_BROADCAST, rl_size)  # fmt: skip
        self.counters.rl_broadcast_bytes += rl_size
        attempt = self._attempts.get((out.peer_id, receiver.drone_id))
        if attempt is not None:
            attempt.compute_ms += compute
        reauth = packet.src in self._reauth_flag
        self._emit(AuthEvent(now, packet.src, receiver.drone_id, True, None, "respond",
                             compute, reauth, packet.attack_id))  # fmt: skip
        self.network.send(resp)
        self.network.send(rl)

    def _on_response(self, packet: Packet, receiver: Drone) -> None:
        agent = self.d2dap.agents.get(receiver.drone_id)
        now = packet.delivered_ms or packet.timestamp_ms
        key = (receiver.drone_id, packet.src)
        attempt = self._attempts.pop(key, None)
        if agent is None or packet.payload is None:
            packet.dropped_reason = "auth_failed"
            return
        w0 = time.perf_counter_ns()
        try:
            session = agent.complete(packet.payload, now)
        except ProtocolAbort as exc:
            compute = (time.perf_counter_ns() - w0) / 1e6
            packet.auth_ok, packet.auth_failure = False, exc.reason.value
            packet.dropped_reason = "auth_failed"
            self._emit(
                AuthEvent(
                    now,
                    receiver.drone_id,
                    packet.src,
                    False,
                    exc.reason.value,
                    "complete",
                    compute,
                    attempt.reauth if attempt else False,
                    packet.attack_id,
                )
            )
            self._drop_held(key)
            return
        compute = (time.perf_counter_ns() - w0) / 1e6
        packet.auth_ok = True
        self._install(receiver.drone_id, session.peer_id, session.session_id,
                      session.session_key, now)  # fmt: skip
        total = compute + (attempt.compute_ms if attempt else 0.0)
        reauth = attempt.reauth if attempt else False
        self._reauth_flag.discard(receiver.drone_id)
        self._emit(AuthEvent(now, receiver.drone_id, session.peer_id, True, None, "complete",
                             total, reauth))  # fmt: skip
        self._release_held(key, now)

    def _maybe_reprovision(self, drone_id: str) -> None:
        agent = self.d2dap.agents.get(drone_id)
        limit = self.reprovision_below
        if agent is not None and limit is not None and agent.crp_remaining < limit:
            self.d2dap.cs.reprovision(agent)
            self.counters.reprovisions += 1

    def _install(self, me: str, peer: str, session_id: str, sk: bytes, now: int) -> None:
        self._maybe_reprovision(me)
        drone = self.network.nodes[me]
        drone.add_session(SessionInfo(peer, session_id, now, key=data_key(sk)))
        self.transport.reset_peer(me, peer)

    def _release_held(self, key: tuple[str, str], now: int) -> None:
        for pkt in self._held.pop(key, []):
            pkt.timestamp_ms = max(pkt.timestamp_ms, now)
            sealed = self.transport.seal(pkt)
            if self.network.nodes[pkt.true_src].active:
                self.network.send(sealed)

    def _drop_held(self, key: tuple[str, str]) -> None:
        self.counters.held_dropped += len(self._held.pop(key, []))

    def _expire_attempts(self, now_ms: int) -> None:
        for key, att in list(self._attempts.items()):
            if now_ms - att.started_ms > AUTH_TIMEOUT_MS:
                del self._attempts[key]
                agent = self.d2dap.agents.get(key[0])
                if agent is not None:
                    agent.abort_pending(key[1])
                self._drop_held(key)
                self._emit(AuthEvent(now_ms, key[0], key[1], False, "timeout", "timeout",
                                     att.compute_ms, att.reauth))  # fmt: skip

    # ------------------------------------------------------------- policy actions
    def revoke_sessions(self, drone_id: str) -> int:
        """Revoke every session of ``drone_id`` on both ends."""
        drone = self.network.nodes[drone_id]
        peers = list(drone.sessions)
        drone.revoke_sessions()
        agent = self.d2dap.agents.get(drone_id)
        if agent is not None:
            agent.sessions.clear()
        for peer in peers:
            other = self.network.nodes.get(peer)
            if other is not None:
                other.drop_peer(drone_id)
            pa = self.d2dap.agents.get(peer)
            if pa is not None:
                pa.sessions.pop(drone_id, None)
        return len(peers)

    def reauthenticate(self, drone_id: str, now_ms: int) -> int:
        """Force fresh MAKA runs: revoke sessions; new sessions are set up on demand."""
        n = self.revoke_sessions(drone_id)
        self._reauth_flag.add(drone_id)
        self.network.nodes[drone_id].auth_state = AuthState.REAUTH_PENDING
        log.info("policy.reauthenticate", drone=drone_id, revoked=n, t_ms=now_ms)
        return n
