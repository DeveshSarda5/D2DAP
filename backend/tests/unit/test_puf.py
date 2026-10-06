"""Tests for the SOFTWARE PUF simulation (Phase 3).

The four PUF cases of D2DAP Sec. III-B are tested explicitly:

* Case 1: C_i != C_j, D_i != D_j -> R_i != R_j
* Case 2: C_i != C_j, D_i == D_j -> R_i != R_j
* Case 3: C_i == C_j, D_i != D_j -> R_i != R_j
* Case 4: C_i == C_j, D_i == D_j -> R_i == R_j
"""

from __future__ import annotations

import numpy as np
import pytest

from app.core.errors import PUFAccessError
from app.security.puf import (
    PUF,
    BoundPUF,
    IdealPUF,
    XORArbiterPUF,
    hamming_fraction,
    make_puf,
    puf_quality,
)

C1 = bytes(range(16))
C2 = bytes(range(1, 17))


def device(
    seed: int, noise_sigma: float = 0.0, majority_votes: int = 1, response_bits: int = 128
) -> XORArbiterPUF:
    return XORArbiterPUF(
        np.random.default_rng(seed),
        noise_sigma=noise_sigma,
        majority_votes=majority_votes,
        response_bits=response_bits,
    )


@pytest.fixture(params=["xor_arbiter", "ideal"])
def pair(request: pytest.FixtureRequest) -> tuple[PUF, PUF]:
    model = request.param
    return (
        make_puf(model, np.random.default_rng(100)),
        make_puf(model, np.random.default_rng(200)),
    )


class TestPaperCases:
    def test_case4_same_device_same_challenge(self, pair: tuple[PUF, PUF]) -> None:
        a, _ = pair
        assert a.evaluate(C1) == a.evaluate(C1)

    def test_case3_different_device_same_challenge(self, pair: tuple[PUF, PUF]) -> None:
        a, b = pair
        assert a.evaluate(C1) != b.evaluate(C1)

    def test_case2_same_device_different_challenge(self, pair: tuple[PUF, PUF]) -> None:
        a, _ = pair
        assert a.evaluate(C1) != a.evaluate(C2)

    def test_case1_different_device_different_challenge(self, pair: tuple[PUF, PUF]) -> None:
        a, b = pair
        assert a.evaluate(C1) != b.evaluate(C2)

    def test_response_length(self, pair: tuple[PUF, PUF]) -> None:
        a, _ = pair
        assert len(a.evaluate(C1)) == 16


class TestAccessControl:
    def test_owner_can_evaluate(self) -> None:
        bound = BoundPUF("D1", device(1))
        assert bound.evaluate(C1, caller_id="D1") == device(1).evaluate(C1)
        assert bound.evaluations == 1

    def test_unauthorized_access_fails(self) -> None:
        bound = BoundPUF("D1", device(1))
        with pytest.raises(PUFAccessError, match="cannot evaluate"):
            bound.evaluate(C1, caller_id="ATTACKER")
        assert bound.evaluations == 0

    def test_clone_device_differs(self) -> None:
        """A replica built on a different device gets different 'manufacturing' weights."""
        original, clone = device(1), device(999)
        assert hamming_fraction(original.evaluate(C1), clone.evaluate(C1)) > 0.25


class TestValidation:
    def test_challenge_length_enforced(self) -> None:
        with pytest.raises(ValueError, match="16 bytes"):
            device(1).evaluate(b"short")
        with pytest.raises(ValueError, match="16 bytes"):
            IdealPUF(b"k" * 32).evaluate(b"x" * 17)

    def test_bad_parameters(self) -> None:
        with pytest.raises(ValueError, match="odd"):
            device(1, majority_votes=2)
        with pytest.raises(ValueError, match="multiple of 8"):
            device(1, response_bits=12)
        with pytest.raises(ValueError, match="128 bits"):
            IdealPUF(b"short")
        with pytest.raises(ValueError, match="unknown"):
            make_puf("optical", np.random.default_rng(0))

    def test_hamming_length_mismatch(self) -> None:
        with pytest.raises(ValueError, match="length"):
            hamming_fraction(b"a", b"ab")


class TestQuality:
    def _challenges(self, n: int = 20) -> list[bytes]:
        rng = np.random.default_rng(42)
        return [rng.bytes(16) for _ in range(n)]

    def test_noise_free_population_quality(self) -> None:
        q = puf_quality([device(s) for s in range(8)], self._challenges(), repeats=2)
        assert 0.45 < q.uniqueness < 0.55
        assert 0.4 < q.uniformity < 0.6
        assert q.reliability == 1.0

    def test_ideal_puf_quality(self) -> None:
        pufs = [make_puf("ideal", np.random.default_rng(s)) for s in range(8)]
        q = puf_quality(pufs, self._challenges(), repeats=2)
        assert 0.45 < q.uniqueness < 0.55
        assert q.reliability == 1.0

    def test_noise_reduces_reliability_and_majority_vote_helps(self) -> None:
        ch = self._challenges(10)
        noisy = [device(s, noise_sigma=1.0) for s in range(4)]
        voted = [device(s, noise_sigma=1.0, majority_votes=9) for s in range(4)]
        q_noisy = puf_quality(noisy, ch, repeats=3)
        q_voted = puf_quality(voted, ch, repeats=3)
        assert q_noisy.reliability < 0.99
        assert q_voted.reliability > q_noisy.reliability

    def test_quality_needs_two_devices(self) -> None:
        with pytest.raises(ValueError, match="two devices"):
            puf_quality([device(1)], [C1])
