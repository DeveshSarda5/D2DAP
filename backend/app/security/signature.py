"""D2DAP signature scheme: GenSign (Algorithm 1) and VerifySign (Algorithm 2).

An ECDSA variant whose nonce point is additionally multiplied by ``h = H(a || T)``::

    GenSign:    r <-R Z*_n,  M = H(CM),  alpha = (r*h) P,  s1 = alpha_x,
                s2 = (M + x*s1) * r^-1  mod n
    VerifySign: beta = M * s2^-1,  gamma = s1 * s2^-1,
                alpha = h * (beta P + gamma Y);   accept iff alpha_x = s1

Correctness: ``beta P + gamma Y = s2^-1 (M + s1 x) P = r P``, so ``h (rP) = alpha``.
All scalars are reduced modulo the group order ``n`` (mapping item 2).
"""

from __future__ import annotations

from app.security.crypto import CryptoSuite, Point


def _h_scalar(suite: CryptoSuite, a: bytes, t_bytes: bytes) -> int:
    h = suite.to_scalar(suite.H(a, t_bytes))
    if h == 0:  # probability ~ 2^-256; reject rather than produce a degenerate point
        raise ValueError("degenerate H(a||T)")
    return h


def gen_sign(
    suite: CryptoSuite, message: bytes, a: bytes, t_bytes: bytes, x: int
) -> tuple[int, int]:
    """Algorithm 1: return ``(sigma1, sigma2)``."""
    m = suite.to_scalar(suite.H(message))
    h = _h_scalar(suite, a, t_bytes)
    while True:
        r = suite.rand_scalar()
        alpha = suite.mul_g(r * h)
        s1 = suite.x_of(alpha) % suite.n
        if s1 == 0:
            continue
        s2 = (m + x * s1) * suite.inv(r) % suite.n
        if s2 != 0:
            return s1, s2


def verify_sign(
    suite: CryptoSuite,
    message: bytes,
    signature: tuple[int, int],
    *,
    a: bytes,
    t_bytes: bytes,
    Y: Point,
) -> bool:
    """Algorithm 2: True iff ``signature = (sigma1, sigma2)`` verifies under ``Y``."""
    s1, s2 = signature
    if not (0 < s1 < suite.n and 0 < s2 < suite.n):
        return False
    m = suite.to_scalar(suite.H(message))
    h = _h_scalar(suite, a, t_bytes)
    w = suite.inv(s2)
    beta, gamma = m * w % suite.n, s1 * w % suite.n
    combined = suite.add(suite.mul_g(beta), suite.mul(Y, gamma))
    alpha = suite.mul(combined, h)
    return suite.x_of(alpha) % suite.n == s1
