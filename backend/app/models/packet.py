"""Structured packet representation shared by simulator, attacks, IDS and dashboard.

Fields are split into what a *receiver/IDS can observe* and *ground truth* that exists
only for evaluation (``true_src``, ``label``, ``attack_id``). Feature extraction must
never read ground-truth fields; this is enforced by
:data:`OBSERVABLE_FIELDS` and tested in the IDS leakage tests.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.models.enums import BENIGN_LABEL, PacketProtocol


@dataclass(slots=True)
class Packet:
    """One simulated link-layer frame."""

    # ---- observable header -------------------------------------------------
    packet_id: int
    timestamp_ms: int  # transmission time (simulation clock)
    src: str  # claimed source address (spoofable)
    dst: str  # destination drone id or BROADCAST
    protocol: PacketProtocol
    size_bytes: int
    seq: int = 0
    session_id: str | None = None
    ttl: int = 8
    payload: bytes | None = None  # real bytes when meaningful (auth / encrypted data)
    # ---- receiver-side observations (filled on delivery) --------------------
    delivered_ms: int | None = None
    integrity_ok: bool | None = None  # AEAD / signature verification result at receiver
    auth_ok: bool | None = None  # D2DAP outcome for AUTH_* packets
    auth_failure: str | None = None  # D2DAP abort reason if any
    dropped_reason: str | None = None
    # ---- ground truth (evaluation only, never a feature) -------------------
    true_src: str = ""
    label: str = BENIGN_LABEL
    attack_id: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.true_src:
            self.true_src = self.src
        if self.size_bytes <= 0:
            raise ValueError("packet size must be positive")

    @property
    def is_attack(self) -> bool:
        return self.label != BENIGN_LABEL

    def to_record(self) -> dict[str, Any]:
        """Flat dict for DataFrames / CSV (payload omitted, protocol as string)."""
        rec = asdict(self)
        rec.pop("payload")
        rec.pop("meta")
        rec["protocol"] = self.protocol.value
        return rec


#: Columns an IDS is allowed to use. Ground-truth columns are deliberately excluded.
OBSERVABLE_FIELDS: frozenset[str] = frozenset(
    {
        "packet_id",
        "timestamp_ms",
        "src",
        "dst",
        "protocol",
        "size_bytes",
        "seq",
        "session_id",
        "ttl",
        "delivered_ms",
        "integrity_ok",
        "auth_ok",
        "auth_failure",
    }
)
#: ``dropped_reason`` is simulator bookkeeping (a receiver cannot observe lost frames).
GROUND_TRUTH_FIELDS: frozenset[str] = frozenset(
    {"true_src", "label", "attack_id", "dropped_reason"}
)
