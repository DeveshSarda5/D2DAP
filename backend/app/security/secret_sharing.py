"""Shamir (t, n) threshold secret sharing over a prime field (Shamir 1979; D2DAP Sec. III-C).

D2DAP uses t = 2: ``F(x) = A + B x mod q`` (Eq. 1) and reconstructs ``A`` from two shares
with Lagrange interpolation at x = 0 (Eq. 2). This module implements general t.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.security.crypto import OpCounter


class SecretSharingError(ValueError):
    """Invalid share set (duplicate abscissae, too few shares, x = 0)."""


@dataclass(frozen=True)
class Polynomial:
    """``F(x) = sum_i coeffs[i] x^i mod prime``; ``coeffs[0]`` is the secret."""

    coeffs: tuple[int, ...]
    prime: int

    @property
    def secret(self) -> int:
        return self.coeffs[0]

    @property
    def threshold(self) -> int:
        return len(self.coeffs)

    def __call__(self, x: int) -> int:
        acc = 0
        for c in reversed(self.coeffs):  # Horner's rule
            acc = (acc * x + c) % self.prime
        return acc


class ShamirScheme:
    """Share generation and Lagrange reconstruction with operation counting."""

    def __init__(self, prime: int, threshold: int, ops: OpCounter | None = None) -> None:
        if threshold < 2:
            raise SecretSharingError("threshold must be >= 2")
        self.prime = prime
        self.threshold = threshold
        self.ops = ops if ops is not None else OpCounter()

    def polynomial(self, coeffs: Sequence[int]) -> Polynomial:
        if len(coeffs) != self.threshold:
            raise SecretSharingError(f"need exactly {self.threshold} coefficients")
        return Polynomial(tuple(c % self.prime for c in coeffs), self.prime)

    def share(self, poly: Polynomial, x: int) -> tuple[int, int]:
        """Generate the share ``(x, F(x))`` (T_SSG)."""
        if x % self.prime == 0:
            raise SecretSharingError("x = 0 would reveal the secret")
        self.ops.ss_gen += 1
        return x % self.prime, poly(x)

    def reconstruct(self, shares: Sequence[tuple[int, int]]) -> int:
        """Lagrange interpolation at 0 (Eq. 2 of D2DAP) (T_SSR)."""
        if len(shares) < self.threshold:
            raise SecretSharingError(f"need at least {self.threshold} shares")
        xs = [x % self.prime for x, _ in shares]
        if len(set(xs)) != len(xs):
            raise SecretSharingError("duplicate share abscissae")
        if any(x == 0 for x in xs):
            raise SecretSharingError("share abscissa must be non-zero")
        self.ops.ss_rec += 1
        p = self.prime
        secret = 0
        for i, (xi, yi) in enumerate(shares):
            num, den = 1, 1
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    num = num * xj % p
                    den = den * (xj - xi) % p
            secret = (secret + yi * num * pow(den, -1, p)) % p
        return secret
