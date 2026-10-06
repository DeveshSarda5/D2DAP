"""SOFTWARE PUF SIMULATION.

This module does **not** implement a physical PUF. No PUF hardware is available.
It provides software *models* of PUF behaviour behind a hardware-agnostic interface
(:class:`PUF`) so that a real PUF driver could replace it later.

Two models are provided:

* :class:`XORArbiterPUF`: the standard *additive delay model* of a k-XOR Arbiter PUF
  (the same model family the D2DAP authors used through ``pypuf``). Each simulated
  device gets its own randomly drawn stage-delay weights ("manufacturing variation").
  Optional Gaussian evaluation noise models response instability; majority voting
  over repeated evaluations models a simple stabilisation step.
* :class:`IdealPUF`: a keyed hash (HMAC-SHA3-256). It models the *idealised*
  assumptions used in D2DAP's analysis (unique, unpredictable, perfectly robust).

Limitations (also in ``docs/research-notes/software-puf.md``):

* A software PUF's secret is a seed / weight matrix held in memory. Anyone who reads
  that memory can clone it. A real PUF's "unclonability" is physical and cannot be
  reproduced in software. In the simulation, unclonability is *enforced by the model
  boundary*: an attacker's device gets different weights and the original device's PUF
  can only be evaluated by its owner (:class:`BoundPUF`).
* Arbiter-type PUFs are known to be vulnerable to ML modelling attacks. We do not
  evaluate modelling attacks.
* Timing of a software PUF says nothing about the latency of a hardware PUF.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

import numpy as np
import numpy.typing as npt

from app.core.errors import PUFAccessError

CHALLENGE_BYTES = 16  # 128-bit challenges, as in D2DAP registration


class PUF(Protocol):
    """Hardware-agnostic PUF interface: challenge bytes -> response bytes."""

    @property
    def response_bits(self) -> int: ...

    def evaluate(self, challenge: bytes) -> bytes:
        """Return the response to ``challenge``."""
        ...


def _check_challenge(challenge: bytes) -> None:
    if len(challenge) != CHALLENGE_BYTES:
        raise ValueError(f"challenge must be {CHALLENGE_BYTES} bytes, got {len(challenge)}")


class XORArbiterPUF:
    """k-XOR Arbiter PUF additive delay model producing multi-bit responses.

    A single arbiter chain outputs one bit per ``stages``-bit sub-challenge:
    ``bit = sign(w . Phi(c))`` with the parity feature map
    ``Phi_j = prod_{l>=j} (1 - 2 c_l)`` and a bias term. A k-XOR PUF multiplies the
    signs of ``k`` independent chains. A ``response_bits`` response is obtained from
    ``response_bits`` sub-challenges derived from the 128-bit challenge with SHAKE-256
    (a deterministic challenge expansion, like an on-chip LFSR).
    """

    def __init__(
        self,
        rng: np.random.Generator,
        *,
        stages: int = 128,
        k: int = 4,
        response_bits: int = 128,
        noise_sigma: float = 0.0,
        majority_votes: int = 1,
    ) -> None:
        if majority_votes < 1 or majority_votes % 2 == 0:
            raise ValueError("majority_votes must be a positive odd integer")
        if response_bits % 8:
            raise ValueError("response_bits must be a multiple of 8")
        self.stages, self.k = stages, k
        self._response_bits = response_bits
        self.noise_sigma, self.majority_votes = noise_sigma, majority_votes
        # "Manufacturing variation": per-device stage-delay differences ~ N(0, 1).
        self._weights: npt.NDArray[np.float64] = rng.normal(0.0, 1.0, size=(k, stages + 1))
        self._noise_rng = np.random.default_rng(rng.integers(0, 2**63 - 1))

    @property
    def response_bits(self) -> int:
        return self._response_bits

    def _features(self, challenge: bytes) -> npt.NDArray[np.float64]:
        nbytes = self._response_bits * self.stages // 8
        stream = hashlib.shake_256(b"XAPUF-expand" + challenge).digest(nbytes)
        bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))
        sub = bits.reshape(self._response_bits, self.stages).astype(np.float64)
        signs = 1.0 - 2.0 * sub
        phi = np.cumprod(signs[:, ::-1], axis=1)[:, ::-1]  # Phi_j = prod_{l>=j}
        return np.hstack([phi, np.ones((self._response_bits, 1))])

    def _single_eval(self, phi: npt.NDArray[np.float64]) -> npt.NDArray[np.int8]:
        delays = self._weights @ phi.T  # (k, response_bits)
        if self.noise_sigma > 0:
            delays = delays + self._noise_rng.normal(0.0, self.noise_sigma, size=delays.shape)
        signs: npt.NDArray[np.int8] = np.prod(np.sign(delays), axis=0).astype(np.int8)
        return signs  # values in {-1, +1}

    def evaluate(self, challenge: bytes) -> bytes:
        _check_challenge(challenge)
        phi = self._features(challenge)
        votes = sum(self._single_eval(phi).astype(np.int32) for _ in range(self.majority_votes))
        bits = (np.asarray(votes) < 0).astype(np.uint8)  # -1 -> bit 1
        return np.packbits(bits).tobytes()


class IdealPUF:
    """Idealised PUF: HMAC-SHA3-256 under a per-device secret (perfectly robust)."""

    def __init__(self, device_secret: bytes, response_bits: int = 128) -> None:
        if len(device_secret) < 16:
            raise ValueError("device secret must be at least 128 bits")
        if response_bits % 8 or response_bits > 256:
            raise ValueError("response_bits must be a multiple of 8 and <= 256")
        self._secret = device_secret
        self._response_bits = response_bits

    @property
    def response_bits(self) -> int:
        return self._response_bits

    def evaluate(self, challenge: bytes) -> bytes:
        _check_challenge(challenge)
        mac = hmac.new(self._secret, b"IdealPUF" + challenge, hashlib.sha3_256).digest()
        return mac[: self._response_bits // 8]


@dataclass
class BoundPUF:
    """A PUF physically embedded in one device.

    Only code running *on* the owning device (``caller_id == owner_id``) can query it.
    This models the physical access restriction that the D2DAP threat model relies on
    (the ``Puf(c, D_i)`` query requires the device). Evaluation counts are kept for
    benchmarking.
    """

    owner_id: str
    puf: PUF
    evaluations: int = 0

    def evaluate(self, challenge: bytes, caller_id: str) -> bytes:
        if caller_id != self.owner_id:
            raise PUFAccessError(f"{caller_id} cannot evaluate the PUF of {self.owner_id}")
        self.evaluations += 1
        return self.puf.evaluate(challenge)


def make_puf(
    model: str,
    rng: np.random.Generator,
    *,
    noise_sigma: float = 0.0,
    majority_votes: int = 1,
    k: int = 4,
    stages: int = 128,
) -> PUF:
    """Factory: ``model`` is ``"xor_arbiter"`` or ``"ideal"``."""
    if model == "xor_arbiter":
        return XORArbiterPUF(
            rng, stages=stages, k=k, noise_sigma=noise_sigma, majority_votes=majority_votes
        )
    if model == "ideal":
        return IdealPUF(rng.bytes(32))
    raise ValueError(f"unknown PUF model {model!r}")


# ---------------------------------------------------------------- quality metrics
def hamming_fraction(a: bytes, b: bytes) -> float:
    """Fraction of differing bits between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("length mismatch")
    x = np.unpackbits(np.frombuffer(bytes(i ^ j for i, j in zip(a, b, strict=True)), np.uint8))
    return float(x.mean())


@dataclass(frozen=True)
class PUFQuality:
    """Standard PUF quality metrics (ideal values in brackets)."""

    uniqueness: float  # mean inter-device Hamming distance [0.5]
    uniformity: float  # mean fraction of 1-bits [0.5]
    reliability: float  # 1 - mean intra-device Hamming distance over re-evaluations [1.0]
    bit_aliasing_std: float  # std over bit positions of the across-device 1-rate [0]


def puf_quality(pufs: list[PUF], challenges: list[bytes], repeats: int = 5) -> PUFQuality:
    """Compute uniqueness, uniformity, reliability and bit aliasing for a PUF population."""
    if len(pufs) < 2:
        raise ValueError("need at least two devices")
    resp = [[p.evaluate(c) for c in challenges] for p in pufs]
    inter = [
        hamming_fraction(resp[i][c], resp[j][c])
        for i in range(len(pufs))
        for j in range(i + 1, len(pufs))
        for c in range(len(challenges))
    ]
    bit_matrix = np.array(
        [np.unpackbits(np.frombuffer(b"".join(r), np.uint8)) for r in resp], dtype=np.float64
    )
    intra = [
        hamming_fraction(resp[i][c], pufs[i].evaluate(challenges[c]))
        for i in range(len(pufs))
        for c in range(len(challenges))
        for _ in range(repeats)
    ]
    return PUFQuality(
        uniqueness=float(np.mean(inter)),
        uniformity=float(bit_matrix.mean()),
        reliability=1.0 - float(np.mean(intra)),
        bit_aliasing_std=float(bit_matrix.mean(axis=0).std()),
    )
