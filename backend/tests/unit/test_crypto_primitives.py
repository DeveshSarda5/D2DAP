"""Tests for the crypto suite, Shamir secret sharing and the D2DAP signature scheme."""

from __future__ import annotations

import pytest

from app.core.rng import DeterministicRandomSource
from app.security.crypto import (
    IV_BYTES,
    CryptoSuite,
    OpCounter,
    SecurityLevel,
    aead_open,
    aead_seal,
)
from app.security.secret_sharing import SecretSharingError, ShamirScheme
from app.security.signature import gen_sign, verify_sign


@pytest.fixture
def suite() -> CryptoSuite:
    return CryptoSuite(SecurityLevel.L128, DeterministicRandomSource(1, "test"))


class TestCryptoSuite:
    @pytest.mark.parametrize(
        ("level", "hash_len", "scalar_len"),
        [(SecurityLevel.L128, 32, 32), (SecurityLevel.L192, 48, 48), (SecurityLevel.L256, 64, 66)],
    )
    def test_levels(self, level: SecurityLevel, hash_len: int, scalar_len: int) -> None:
        s = CryptoSuite(level, DeterministicRandomSource(0, "x"))
        assert s.hash_bytes == hash_len
        assert s.scalar_bytes == scalar_len
        assert len(s.H(b"a")) == hash_len

    def test_hash_concatenation_unambiguous(self, suite: CryptoSuite) -> None:
        assert suite.H(b"ab", b"c") != suite.H(b"a", b"bc")
        assert suite.ops.hash == 2

    def test_encrypt_roundtrip_and_counts(self, suite: CryptoSuite) -> None:
        key = suite.rand_bytes(16)
        blob = suite.encrypt(key, b"hello drone")
        assert len(blob) == IV_BYTES + 11
        assert suite.decrypt(key, blob) == b"hello drone"
        assert suite.decrypt(suite.rand_bytes(16), blob) != b"hello drone"
        assert (suite.ops.sym_enc, suite.ops.sym_dec) == (1, 2)

    def test_point_ops_and_encoding(self, suite: CryptoSuite) -> None:
        x = suite.rand_scalar()
        Y = suite.mul_g(x)
        assert suite.decode_point(suite.encode_point(Y)) == Y
        assert suite.add(suite.mul_g(2), suite.mul_g(3)) == suite.mul_g(5)
        assert suite.inv(x) * x % suite.n == 1

    def test_ecdh_agreement(self, suite: CryptoSuite) -> None:
        xi, xj = suite.rand_scalar(), suite.rand_scalar()
        Yi, Yj = suite.mul_g(xi), suite.mul_g(xj)
        assert suite.kdf(suite.mul(Yj, xi)) == suite.kdf(suite.mul(Yi, xj))

    def test_aead_detects_tampering(self) -> None:
        key, nonce = b"k" * 16, b"n" * 12
        ct = aead_seal(key, nonce, b"payload", b"hdr")
        assert aead_open(key, nonce, ct, b"hdr") == b"payload"
        assert aead_open(key, nonce, ct, b"HDR") is None
        bad = bytes([ct[0] ^ 1]) + ct[1:]
        assert aead_open(key, nonce, bad, b"hdr") is None

    def test_op_counter_arithmetic(self) -> None:
        a = OpCounter(point_mul=2, hash=1)
        b = OpCounter(point_mul=1, puf=1)
        assert (a + b).as_dict()["point_mul"] == 3
        assert (a + b).total() == 5
        a.reset()
        assert a.total() == 0


class TestShamir:
    P = 2**127 - 1  # Mersenne prime

    def test_two_of_n_reconstruction(self) -> None:
        sch = ShamirScheme(self.P, 2)
        poly = sch.polynomial([123456789, 987654321])
        shares = [sch.share(poly, x) for x in (5, 17, 99)]
        assert sch.reconstruct(shares[:2]) == 123456789
        assert sch.reconstruct([shares[0], shares[2]]) == 123456789
        assert sch.ops.ss_gen == 3
        assert sch.ops.ss_rec == 2

    def test_three_of_n(self) -> None:
        sch = ShamirScheme(self.P, 3)
        poly = sch.polynomial([42, 7, 11])
        shares = [sch.share(poly, x) for x in (1, 2, 3, 4)]
        assert sch.reconstruct(shares[1:]) == 42
        with pytest.raises(SecretSharingError, match="at least 3"):
            sch.reconstruct(shares[:2])

    def test_one_share_reveals_nothing_deterministic(self) -> None:
        """With t = 2, any secret is consistent with a single share (information-theoretic)."""
        sch = ShamirScheme(self.P, 2)
        x, y = 10, 555
        for candidate_secret in (0, 1, 999):
            slope = (y - candidate_secret) * pow(x, -1, self.P) % self.P
            assert sch.polynomial([candidate_secret, slope])(x) == y

    def test_invalid_inputs(self) -> None:
        sch = ShamirScheme(self.P, 2)
        poly = sch.polynomial([1, 2])
        with pytest.raises(SecretSharingError, match="duplicate"):
            sch.reconstruct([(3, poly(3)), (3, poly(3))])
        with pytest.raises(SecretSharingError, match="x = 0"):
            sch.share(poly, 0)
        with pytest.raises(SecretSharingError, match="non-zero"):
            sch.reconstruct([(0, 1), (2, poly(2))])
        with pytest.raises(SecretSharingError, match=">= 2"):
            ShamirScheme(self.P, 1)
        with pytest.raises(SecretSharingError, match="exactly"):
            sch.polynomial([1])


class TestSignature:
    def _keys(self, suite: CryptoSuite) -> tuple[int, object]:
        x = suite.rand_scalar()
        return x, suite.mul_g(x)

    def test_valid_signature_verifies(self, suite: CryptoSuite) -> None:
        x, Y = self._keys(suite)
        s1, s2 = gen_sign(suite, b"CM", b"a" * 32, b"T" * 8, x)
        assert verify_sign(suite, b"CM", (s1, s2), a=b"a" * 32, t_bytes=b"T" * 8, Y=Y)

    def test_op_counts_match_algorithms(self, suite: CryptoSuite) -> None:
        x, Y = self._keys(suite)
        suite.ops.reset()
        s1, s2 = gen_sign(suite, b"CM", b"a", b"T", x)
        assert (suite.ops.point_mul, suite.ops.hash, suite.ops.rand, suite.ops.mod_inv) == (
            1,
            2,
            1,
            1,
        )
        suite.ops.reset()
        verify_sign(suite, b"CM", (s1, s2), a=b"a", t_bytes=b"T", Y=Y)
        assert (suite.ops.point_mul, suite.ops.point_add, suite.ops.hash) == (3, 1, 2)

    @pytest.mark.parametrize("field", ["message", "a", "t", "key", "s1", "s2"])
    def test_any_change_breaks_verification(self, suite: CryptoSuite, field: str) -> None:
        x, Y = self._keys(suite)
        s1, s2 = gen_sign(suite, b"CM", b"a", b"T", x)
        args = {"message": b"CM", "a": b"a", "t": b"T", "Y": Y, "s1": s1, "s2": s2}
        if field == "message":
            args["message"] = b"CX"
        elif field == "a":
            args["a"] = b"b"
        elif field == "t":
            args["t"] = b"U"
        elif field == "key":
            args["Y"] = suite.mul_g(suite.rand_scalar())
        elif field == "s1":
            args["s1"] = (s1 + 1) % suite.n
        else:
            args["s2"] = (s2 + 1) % suite.n
        assert not verify_sign(
            suite,
            args["message"],
            (args["s1"], args["s2"]),
            a=args["a"],
            t_bytes=args["t"],
            Y=args["Y"],
        )

    def test_out_of_range_rejected(self, suite: CryptoSuite) -> None:
        _, Y = self._keys(suite)
        assert not verify_sign(suite, b"m", (0, 5), a=b"a", t_bytes=b"T", Y=Y)
        assert not verify_sign(suite, b"m", (5, suite.n), a=b"a", t_bytes=b"T", Y=Y)
