"""Authenticated data plane on top of D2DAP sessions (our addition, mapping item 22).

D2DAP ends with a session key ``SK``. To make post-authentication traffic verifiable,
unicast data packets between drones that share a session are sealed with AES-GCM:

* key   = first 16 bytes of SHA3-256("data-plane" || SK);
* nonce = 8-byte sender sequence number || 4 zero bytes (unique per sender);
* AAD   = header (claimed src, dst, protocol, seq, session id).

At the receiver: unknown session -> drop ``no_session``; AEAD failure -> drop
``integrity``; repeated / too-old sequence number -> drop ``replay``. Packets without a
session are dropped as ``unauthenticated`` when ``require_auth`` is on (D2DAP systems)
and accepted when it is off (no-authentication baseline).

Broadcast heartbeats are left unauthenticated (no pairwise session applies); this is a
documented limitation.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field

from app.models.enums import BROADCAST, CONTROL_PLANE, PacketProtocol
from app.models.packet import Packet
from app.security.crypto import aead_open, aead_seal
from app.simulation.drone import Drone, SessionInfo
from app.simulation.network import DroneNetwork

GCM_TAG_BYTES = 16
REPLAY_WINDOW = 256
DATA_PROTOCOLS = frozenset({PacketProtocol.TELEMETRY, PacketProtocol.VIDEO, PacketProtocol.COMMAND})
#: Everything sealed with the session key: data plus the monitor's trust reports
#: (an unauthenticated report channel would itself be tamperable).
SEALED_PROTOCOLS = DATA_PROTOCOLS | {PacketProtocol.TRUST_REPORT}


def data_key(session_key: bytes) -> bytes:
    """Derive the AES-GCM data-plane key from a D2DAP session key."""
    return hashlib.sha3_256(b"data-plane" + session_key).digest()[:16]


def _nonce(seq: int) -> bytes:
    return (seq % 2**64).to_bytes(8, "big") + b"\x00" * 4


def _aad(p: Packet) -> bytes:
    return f"{p.src}|{p.dst}|{p.protocol.value}|{p.seq}|{p.session_id}".encode()


@dataclass
class _ReplayWindow:
    highest: int = -1
    seen: deque[int] = field(default_factory=lambda: deque(maxlen=REPLAY_WINDOW))

    def check_and_add(self, seq: int) -> bool:
        if seq in self.seen or seq <= self.highest - REPLAY_WINDOW:
            return False
        self.seen.append(seq)
        self.highest = max(self.highest, seq)
        return True


@dataclass
class TransportCounters:
    sealed: int = 0
    opened: int = 0
    integrity_failures: int = 0
    replays_blocked: int = 0
    unauthenticated_dropped: int = 0
    no_session_dropped: int = 0


class SecureTransport:
    """Send hook + receive handler implementing the authenticated data plane."""

    def __init__(self, network: DroneNetwork, require_auth: bool = True) -> None:
        self.network = network
        self.require_auth = require_auth
        self.counters = TransportCounters()
        self._windows: dict[tuple[str, str], _ReplayWindow] = {}

    def install(self) -> None:
        for proto in SEALED_PROTOCOLS:
            self.network.set_handler(proto, self.on_receive)

    # ------------------------------------------------------------- sender side
    def seal(self, packet: Packet) -> Packet:
        """Engine send hook: seal unicast data packets if a session exists."""
        if packet.protocol not in SEALED_PROTOCOLS or packet.dst == BROADCAST:
            return packet
        if packet.payload is not None:  # already carries bytes (e.g. crafted by an attacker)
            return packet
        sender = self.network.nodes.get(packet.true_src)
        session = sender.sessions.get(packet.dst) if sender else None
        if session is None or not session.key:
            return packet
        packet.session_id = session.session_id
        plaintext = bytes(max(1, packet.size_bytes - GCM_TAG_BYTES))
        packet.payload = aead_seal(session.key, _nonce(packet.seq), plaintext, _aad(packet))
        packet.size_bytes = len(packet.payload)
        session.packets_sent += 1
        self.counters.sealed += 1
        return packet

    # ------------------------------------------------------------- receiver side
    @staticmethod
    def _session_for(packet: Packet, receiver: Drone) -> SessionInfo | None:
        return receiver.session_by_id(packet.session_id, packet.src)

    def on_receive(self, packet: Packet, receiver: Drone) -> None:
        if packet.session_id is None:
            packet.integrity_ok = None
            if self.require_auth:
                packet.dropped_reason = "unauthenticated"
                self.counters.unauthenticated_dropped += 1
            return
        session = self._session_for(packet, receiver)
        if session is None or packet.payload is None:
            packet.integrity_ok = False
            packet.dropped_reason = "no_session"
            self.counters.no_session_dropped += 1
            return
        if aead_open(session.key, _nonce(packet.seq), packet.payload, _aad(packet)) is None:
            packet.integrity_ok = False
            packet.dropped_reason = "integrity"
            self.counters.integrity_failures += 1
            return
        window = self._windows.setdefault((receiver.drone_id, packet.src), _ReplayWindow())
        if not window.check_and_add(packet.seq):
            packet.integrity_ok = True
            packet.dropped_reason = "replay"
            self.counters.replays_blocked += 1
            return
        packet.integrity_ok = True
        session.packets_received += 1
        self.counters.opened += 1

    def inspect(self, packet: Packet, receiver: Drone) -> bool | None:
        """Verify a packet's AEAD *without* delivering it (no replay/counter side effects).

        Used by the policy enforcer ("verify-then-drop") so that packets dropped by policy
        are still attributed: a validly sealed packet is bound to its claimed identity.
        """
        if packet.protocol not in SEALED_PROTOCOLS or packet.session_id is None:
            return None
        session = self._session_for(packet, receiver)
        if session is None or packet.payload is None:
            return False
        return aead_open(session.key, _nonce(packet.seq), packet.payload, _aad(packet)) is not None

    def reset_peer(self, a: str, b: str) -> None:
        """Forget replay state after a re-key (new session)."""
        self._windows.pop((a, b), None)
        self._windows.pop((b, a), None)


def is_security_overhead(packet: Packet) -> bool:
    return packet.protocol in CONTROL_PLANE
