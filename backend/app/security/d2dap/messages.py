"""Wire format of D2DAP MAKA messages and their plaintext bodies.

``M1 = {CM, sigma1, sigma2}`` and ``M2 = {DM, sigma3, sigma4}`` share one layout::

    | iv (16) | ciphertext (|a| + |b| + 8) | sigma_a (s) | sigma_b (s) |

``s`` is the scalar length of the curve and ``|a|`` the hash length. No identity is
transmitted (as in the paper). Sizes are *measured* from these bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.security.crypto import IV_BYTES, TIMESTAMP_BYTES, CryptoSuite


class MalformedMessageError(ValueError):
    """Message cannot be parsed."""


@dataclass(frozen=True)
class AuthMessage:
    """Encrypted body plus signature (M1 or M2)."""

    body: bytes  # iv || AES-CTR ciphertext
    sigma_a: int
    sigma_b: int

    def to_bytes(self, scalar_bytes: int) -> bytes:
        return (
            self.body
            + self.sigma_a.to_bytes(scalar_bytes, "big")
            + self.sigma_b.to_bytes(scalar_bytes, "big")
        )

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> AuthMessage:
        s = suite.scalar_bytes
        body_len = IV_BYTES + suite.hash_bytes + s + TIMESTAMP_BYTES
        if len(data) != body_len + 2 * s:
            raise MalformedMessageError(f"expected {body_len + 2 * s} bytes, got {len(data)}")
        body = data[:body_len]
        sa = int.from_bytes(data[body_len : body_len + s], "big")
        sb = int.from_bytes(data[body_len + s :], "big")
        return cls(body, sa, sb)

    @staticmethod
    def wire_size(suite: CryptoSuite) -> int:
        return IV_BYTES + suite.hash_bytes + 3 * suite.scalar_bytes + TIMESTAMP_BYTES


@dataclass(frozen=True)
class ShareBody:
    """Decrypted plaintext ``a || b || T``."""

    a: bytes  # hash output H(R || ID)
    b: int  # share F(a) mod n
    t_ms: int

    def to_bytes(self, suite: CryptoSuite) -> bytes:
        return self.a + suite.scalar_bytes_of(self.b) + self.t_ms.to_bytes(TIMESTAMP_BYTES, "big")

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> ShareBody:
        h, s = suite.hash_bytes, suite.scalar_bytes
        if len(data) != h + s + TIMESTAMP_BYTES:
            raise MalformedMessageError("bad plaintext length")
        return cls(
            a=data[:h],
            b=int.from_bytes(data[h : h + s], "big"),
            t_ms=int.from_bytes(data[h + s :], "big"),
        )

    @property
    def t_bytes(self) -> bytes:
        return self.t_ms.to_bytes(TIMESTAMP_BYTES, "big")
