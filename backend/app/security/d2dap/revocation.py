"""Append-only revocation list ``RL`` (D2DAP Setup / MAKA).

Drones may insert entries ``H(a_ik || a_jk)`` but never delete them. Dissemination is
modelled as immediate and reliable (as assumed by the paper); every insertion is counted
as one broadcast so that its communication overhead can be reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RevocationList:
    """Insert-only set of used share-pair digests."""

    _entries: set[bytes] = field(default_factory=set)
    broadcasts: int = 0
    broadcast_bytes: int = 0

    def __contains__(self, entry: object) -> bool:
        return entry in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def insert(self, entry: bytes) -> bool:
        """Insert and broadcast ``entry``; returns False if it was already present."""
        if entry in self._entries:
            return False
        self._entries.add(entry)
        self.broadcasts += 1
        self.broadcast_bytes += len(entry)
        return True

    @property
    def storage_bytes(self) -> int:
        return sum(len(e) for e in self._entries)
