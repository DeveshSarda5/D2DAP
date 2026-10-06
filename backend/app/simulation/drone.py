"""Simulated drone entity.

A :class:`Drone` holds kinematic state, mission role, a battery *model*, and the
security-relevant state that the adaptive framework reads and writes
(authentication state, trust score, security state, sessions).
Cryptographic credentials live in the D2DAP layer, keyed by ``drone_id``, so that the
simulator stays independent of the authentication protocol.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import numpy as np
import numpy.typing as npt

from app.models.enums import AuthState, DroneRole, SecurityState

Vec3 = npt.NDArray[np.float64]


@dataclass
class SessionInfo:
    """A D2D session established with a peer."""

    peer_id: str
    session_id: str
    established_ms: int
    key: bytes = b""  # data-protection key derived from SK (empty before Phase 4)
    packets_sent: int = 0
    packets_received: int = 0
    tx_seq: int = 0
    rx_highest_seq: int = -1


@dataclass(frozen=True)
class CommRecord:
    """One entry in a drone's communication history."""

    t_ms: int
    direction: str  # "tx" | "rx"
    peer: str
    protocol: str
    size_bytes: int
    ok: bool


@dataclass
class Drone:
    """A simulated drone."""

    drone_id: str
    role: DroneRole
    position: Vec3
    velocity: Vec3 = field(default_factory=lambda: np.zeros(3))
    battery_level: float = 100.0
    auth_state: AuthState = AuthState.UNREGISTERED
    trust_score: float = 1.0
    security_state: SecurityState = SecurityState.NORMAL
    active: bool = False
    #: Ground truth: is this drone controlled by an adversary? Never read by detectors.
    compromised: bool = False
    sessions: dict[str, SessionInfo] = field(default_factory=dict)  # peer -> tx session
    #: Every live session by id (receive side). Handles simultaneous-open races where the
    #: two peers end up transmitting under different (both valid) sessions.
    session_index: dict[str, SessionInfo] = field(default_factory=dict)
    history: deque[CommRecord] = field(default_factory=lambda: deque(maxlen=200))
    waypoint: Vec3 | None = None
    pause_until_ms: int = 0
    tx_packets: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0

    def distance_to(self, other: Drone) -> float:
        return float(np.linalg.norm(self.position - other.position))

    def record(self, rec: CommRecord) -> None:
        self.history.append(rec)
        if rec.direction == "tx":
            self.tx_packets += 1
            self.tx_bytes += rec.size_bytes
        else:
            self.rx_packets += 1
            self.rx_bytes += rec.size_bytes

    def add_session(self, session: SessionInfo) -> None:
        self.sessions[session.peer_id] = session
        self.session_index[session.session_id] = session
        self.auth_state = AuthState.AUTHENTICATED

    def session_by_id(self, session_id: str | None, peer_id: str) -> SessionInfo | None:
        """Live session ``session_id`` shared with ``peer_id`` (receive-side lookup)."""
        s = self.session_index.get(session_id) if session_id else None
        return s if s is not None and s.peer_id == peer_id else None

    def drop_peer(self, peer_id: str) -> None:
        """Forget every session with ``peer_id``."""
        self.sessions.pop(peer_id, None)
        for sid in [k for k, s in self.session_index.items() if s.peer_id == peer_id]:
            del self.session_index[sid]

    def revoke_sessions(self) -> int:
        """Drop all sessions (used by re-authentication / quarantine). Returns peer count."""
        count = len(self.sessions)
        self.sessions.clear()
        self.session_index.clear()
        return count

    def summary(self) -> dict[str, object]:
        """JSON-friendly snapshot (used by API / dashboard)."""
        return {
            "drone_id": self.drone_id,
            "role": self.role.value,
            "position": [round(float(v), 2) for v in self.position],
            "velocity": [round(float(v), 2) for v in self.velocity],
            "battery_level": round(self.battery_level, 2),
            "auth_state": self.auth_state.value,
            "trust_score": round(self.trust_score, 4),
            "security_state": self.security_state.value,
            "active": self.active,
            "sessions": sorted(self.sessions),
            "tx_packets": self.tx_packets,
            "rx_packets": self.rx_packets,
        }
