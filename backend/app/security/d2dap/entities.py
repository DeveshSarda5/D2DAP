"""D2DAP entities: credentials, public directory, failure reasons, session records."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from app.security.crypto import Point


class FailureReason(str, Enum):
    """Abort conditions of the MAKA phase (Fig. 3) plus implementation-level failures."""

    FRESHNESS = "freshness"  # |T_j - T_i| > Delta T (or no candidate key decrypts fresh)
    SIGNATURE = "signature"  # VerifySign failed
    REVOKED_PAIR = "revoked_pair"  # responder: H(a_ik||a_jk) already in RL
    NOT_IN_RL = "not_in_rl"  # initiator: H(a_ik||a_jk) missing from RL
    SECRET_MISMATCH = "secret_mismatch"  # noqa: S105 - enum label, not a credential
    CRP_EXHAUSTED = "crp_exhausted"  # no unused challenge-response pair left (added)
    UNKNOWN_PEER = "unknown_peer"  # no published public key for the peer
    NOT_REGISTERED = "not_registered"  # local drone holds no credentials
    MALFORMED = "malformed"  # cannot parse message / degenerate shares
    REPLAY_DETECTED = "replay_detected"  # optional replay cache (our hardening)
    NO_PENDING_SESSION = "no_pending_session"  # initiator received an unsolicited M2


class ProtocolAbort(Exception):  # noqa: N818 - "abort" is the paper's term
    """Raised when a MAKA check fails."""

    def __init__(self, reason: FailureReason, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail


@dataclass
class DroneCredentials:
    """Exactly what D2DAP stores on a drone: ``{ID_i, x_i, b_i, C_i, RL, V_i}``.

    ``a_i`` and ``R_i`` are *not* stored; they are regenerated from the PUF. ``RL`` is a
    shared reference (see :class:`~app.security.d2dap.revocation.RevocationList`).
    """

    drone_id: str
    x: int
    challenges: list[bytes]
    b: list[int]
    V: bytes

    def remove_pair(self, challenge: bytes) -> None:
        idx = self.challenges.index(challenge)
        del self.challenges[idx]
        del self.b[idx]

    def share_for(self, challenge: bytes) -> int:
        return self.b[self.challenges.index(challenge)]

    def clone(self) -> DroneCredentials:
        """Copy of stored data (models the adversary's ``Extract`` query)."""
        return DroneCredentials(self.drone_id, self.x, list(self.challenges), list(self.b), self.V)


@dataclass
class PublicDirectory:
    """Published public keys ``Y_i`` (announced by the CS at registration)."""

    keys: dict[str, Point] = field(default_factory=dict)

    def publish(self, drone_id: str, Y: Point) -> None:
        self.keys[drone_id] = Y

    def withdraw(self, drone_id: str) -> None:
        self.keys.pop(drone_id, None)

    def get(self, drone_id: str) -> Point | None:
        return self.keys.get(drone_id)

    def ids(self) -> list[str]:
        return sorted(self.keys)


@dataclass
class PendingSession:
    """Initiator state between sending M1 and receiving M2."""

    peer_id: str
    challenge: bytes
    a: bytes
    b: int
    t_ms: int
    key: bytes


@dataclass(frozen=True)
class SessionRecord:
    """An established D2DAP session."""

    peer_id: str
    session_id: str
    session_key: bytes
    established_ms: int
    role: str  # "initiator" | "responder"
