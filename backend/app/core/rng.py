"""Deterministic, named random streams.

Every stochastic component (mobility, traffic, attacks, PUF manufacturing variation,
key generation in simulation mode, ...) draws from its *own* named stream derived from a
single master seed. Adding a new consumer therefore never shifts the random numbers seen
by existing consumers, which keeps experiments reproducible as the code grows.

Security note: in ``deterministic`` mode the "cryptographic" randomness (private keys,
signature nonces, challenges) is reproducible from the seed. This is intended for
simulation only; :class:`SystemRandomSource` uses the OS CSPRNG instead.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Protocol

import numpy as np


def stable_hash(name: str) -> int:
    """Return a platform-independent 64-bit hash of ``name`` (Python's ``hash`` is salted)."""
    return int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:8], "big")


class RandomSource(Protocol):
    """Source of random bytes / integers used by cryptographic code."""

    def randbytes(self, n: int) -> bytes:
        """Return ``n`` random bytes."""
        ...

    def randbelow(self, upper: int) -> int:
        """Return a uniform integer in ``[0, upper)``."""
        ...


class SystemRandomSource:
    """OS CSPRNG (``secrets``). Non-reproducible; use for non-simulation deployments."""

    def randbytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)

    def randbelow(self, upper: int) -> int:
        return secrets.randbelow(upper)


class DeterministicRandomSource:
    """Seeded byte stream built from SHA3-256 in counter mode (reproducible).

    Rejection sampling makes ``randbelow`` exactly uniform.
    """

    def __init__(self, seed: int, label: str) -> None:
        self._key = hashlib.sha3_256(f"{seed}:{label}".encode()).digest()
        self._counter = 0

    def randbytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            block = hashlib.sha3_256(self._key + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
            out.extend(block)
        return bytes(out[:n])

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError("upper must be positive")
        nbytes = (upper.bit_length() + 7) // 8 + 1
        limit = (256**nbytes // upper) * upper
        while True:
            value = int.from_bytes(self.randbytes(nbytes), "big")
            if value < limit:
                return value % upper


class RandomStreams:
    """Factory for named, independent random streams derived from one master seed."""

    def __init__(self, master_seed: int, deterministic_crypto: bool = True) -> None:
        self.master_seed = int(master_seed)
        self.deterministic_crypto = deterministic_crypto
        self._generators: dict[str, np.random.Generator] = {}

    def numpy(self, name: str) -> np.random.Generator:
        """Return (and cache) the numpy Generator for stream ``name``."""
        if name not in self._generators:
            seq = np.random.SeedSequence([self.master_seed, stable_hash(name)])
            self._generators[name] = np.random.default_rng(seq)
        return self._generators[name]

    def crypto(self, name: str) -> RandomSource:
        """Return a random source for cryptographic material for stream ``name``."""
        if self.deterministic_crypto:
            return DeterministicRandomSource(self.master_seed, name)
        return SystemRandomSource()

    def child_seed(self, name: str) -> int:
        """Derive an integer seed for a sub-component (e.g. an sklearn ``random_state``)."""
        return int(stable_hash(f"{self.master_seed}:{name}") % (2**31 - 1))
