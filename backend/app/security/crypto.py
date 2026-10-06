"""Instrumented cryptographic suite for D2DAP.

Real cryptography (not mocked):

* Elliptic curves: NIST P-256 / P-384 / P-521 via the ``ecdsa`` package (pure Python
  point arithmetic, like the ``tinyec`` library used by the D2DAP authors);
* Hash: SHA3-256 / SHA3-384 / SHA3-512 (``hashlib``);
* Symmetric: AES-CTR with 128/192/256-bit keys (``cryptography``);
* Data plane (our addition): AES-GCM.

Every primitive call increments an :class:`OpCounter` using the operation symbols of
the D2DAP paper (T_PM, T_PA, T_H, T_ED, T_PUF, T_SSG, T_SSR, T_R) plus modular
inversions, so measured operation counts can be compared with the paper's cost model.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, fields
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdsa import NIST256p, NIST384p, NIST521p
from ecdsa.ellipticcurve import PointJacobi

from app.core.rng import RandomSource

Point = Any  # ecdsa PointJacobi (untyped third-party class)

IV_BYTES = 16
TIMESTAMP_BYTES = 8


class SecurityLevel(int, Enum):
    """Security levels of D2DAP Table VI (bits)."""

    L128 = 128
    L192 = 192
    L256 = 256


@dataclass(frozen=True)
class LevelParams:
    curve_name: str
    hash_name: str
    aes_key_bytes: int


LEVELS: dict[SecurityLevel, LevelParams] = {
    SecurityLevel.L128: LevelParams("P-256", "sha3_256", 16),
    SecurityLevel.L192: LevelParams("P-384", "sha3_384", 24),
    SecurityLevel.L256: LevelParams("P-521", "sha3_512", 32),
}
_CURVES = {"P-256": NIST256p, "P-384": NIST384p, "P-521": NIST521p}


@dataclass
class OpCounter:
    """Counts of cryptographic operations (symbols follow D2DAP Sec. VI-B)."""

    point_mul: int = 0  # T_PM
    point_add: int = 0  # T_PA
    hash: int = 0  # T_H
    sym_enc: int = 0  # T_ED (encryption)
    sym_dec: int = 0  # T_ED (decryption)
    puf: int = 0  # T_PUF
    ss_gen: int = 0  # T_SSG
    ss_rec: int = 0  # T_SSR
    rand: int = 0  # T_R
    mod_inv: int = 0  # modular inversion (not separately listed in the paper)

    def as_dict(self) -> dict[str, int]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def total(self) -> int:
        return sum(self.as_dict().values())

    def __add__(self, other: OpCounter) -> OpCounter:
        return OpCounter(**{k: v + getattr(other, k) for k, v in self.as_dict().items()})

    def reset(self) -> None:
        for f in fields(self):
            setattr(self, f.name, 0)


class CryptoSuite:
    """Curve, hash and cipher for one security level, with operation counting."""

    def __init__(self, level: SecurityLevel, rand: RandomSource) -> None:
        self.level = level
        self.params = LEVELS[level]
        curve = _CURVES[self.params.curve_name]
        self.curve = curve
        self.G: Point = curve.generator
        self.n: int = int(curve.order)
        self.scalar_bytes = (self.n.bit_length() + 7) // 8
        self.hash_bytes = hashlib.new(self.params.hash_name).digest_size
        self._rand = rand
        self.ops = OpCounter()

    # ------------------------------------------------------------- hashing
    def H(self, *parts: bytes) -> bytes:
        """``H(p1 || p2 || ...)`` with 4-byte length prefixes (unambiguous concatenation)."""
        self.ops.hash += 1
        h = hashlib.new(self.params.hash_name)
        for p in parts:
            h.update(len(p).to_bytes(4, "big"))
            h.update(p)
        return h.digest()

    def to_scalar(self, digest: bytes) -> int:
        """Interpret a digest as an element of Z_n (mapping item 6 in the D2DAP mapping)."""
        return int.from_bytes(digest, "big") % self.n

    def scalar_bytes_of(self, k: int) -> bytes:
        return (k % self.n).to_bytes(self.scalar_bytes, "big")

    # ------------------------------------------------------------- randomness
    def rand_scalar(self) -> int:
        """Uniform scalar in [1, n-1] (T_R)."""
        self.ops.rand += 1
        return 1 + self._rand.randbelow(self.n - 1)

    def rand_bytes(self, n: int) -> bytes:
        return self._rand.randbytes(n)

    # ------------------------------------------------------------- EC arithmetic
    def mul_g(self, k: int) -> Point:
        self.ops.point_mul += 1
        return self.G * (k % self.n)

    def mul(self, point: Point, k: int) -> Point:
        self.ops.point_mul += 1
        return point * (k % self.n)

    def add(self, p: Point, q: Point) -> Point:
        self.ops.point_add += 1
        return p + q

    def inv(self, k: int) -> int:
        self.ops.mod_inv += 1
        return pow(k, -1, self.n)

    @staticmethod
    def x_of(point: Point) -> int:
        return int(point.x())

    def encode_point(self, point: Point) -> bytes:
        """Uncompressed SEC1 encoding (published public keys)."""
        size = (self.curve.curve.p().bit_length() + 7) // 8
        return b"\x04" + int(point.x()).to_bytes(size, "big") + int(point.y()).to_bytes(size, "big")

    def decode_point(self, data: bytes) -> Point:
        return PointJacobi.from_bytes(self.curve.curve, data, generator=False)

    # ------------------------------------------------------------- symmetric
    def kdf(self, shared_point: Point, label: bytes = b"D2DAP-K") -> bytes:
        """Derive an AES key from an EC point (mapping item 8)."""
        size = (self.curve.curve.p().bit_length() + 7) // 8
        x = int(shared_point.x()).to_bytes(size, "big")
        return self.H(label, x)[: self.params.aes_key_bytes]

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """AES-CTR; returns ``iv || ciphertext`` (T_ED)."""
        self.ops.sym_enc += 1
        iv = self._rand.randbytes(IV_BYTES)
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return iv + enc.update(plaintext) + enc.finalize()

    def decrypt(self, key: bytes, blob: bytes) -> bytes:
        self.ops.sym_dec += 1
        iv, ct = blob[:IV_BYTES], blob[IV_BYTES:]
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return dec.update(ct) + dec.finalize()


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-GCM seal for post-authentication data packets (our addition, mapping item 22)."""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes | None:
    """AES-GCM open; ``None`` if the integrity check fails."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        return None
