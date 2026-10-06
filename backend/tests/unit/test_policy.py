"""Adaptive policy engine tests (Phase 13)."""

from __future__ import annotations

import pytest

from app.models.enums import SecurityState as S
from app.policy.engine import PolicyConfig, PolicyEngine
from app.trust.engine import Evidence, TrustUpdate


def upd(trust: float, t_s: float = 0, drone: str = "D4", prev: float = 0.9, **ev: object
        ) -> TrustUpdate:  # fmt: skip
    evidence = Evidence(drone, int(t_s), int(t_s * 1000), **ev)  # type: ignore[arg-type]
    return TrustUpdate(drone, int(t_s), int(t_s * 1000), prev, trust, 1, 1, 0, 0, {}, 1.0,
                       evidence, "test")  # fmt: skip


class TestBands:
    @pytest.mark.parametrize(
        ("trust", "state"),
        [(0.95, S.NORMAL), (0.7, S.MONITOR), (0.5, S.RESTRICT), (0.3, S.REAUTHENTICATE),
         (0.1, S.QUARANTINE)],
    )  # fmt: skip
    def test_default_bands(self, trust: float, state: S) -> None:
        eng = PolicyEngine()
        eng.evaluate(upd(trust))
        assert eng.state("D4") is state

    def test_no_decision_without_change(self) -> None:
        eng = PolicyEngine()
        assert eng.evaluate(upd(0.95)) is None

    def test_thresholds_must_be_ordered(self) -> None:
        with pytest.raises(ValueError, match="thresholds"):
            PolicyConfig(normal=0.5, monitor=0.6)

    def test_configurable_thresholds(self) -> None:
        eng = PolicyEngine(PolicyConfig(normal=0.9, monitor=0.7, restrict=0.5, reauthenticate=0.3))
        eng.evaluate(upd(0.85))
        assert eng.state("D4") is S.MONITOR


class TestHysteresis:
    def test_relaxing_requires_margin(self) -> None:
        eng = PolicyEngine()
        eng.evaluate(upd(0.55, 1))  # RESTRICT
        assert eng.evaluate(upd(0.62, 2)) is None  # 0.62 < 0.60 + 0.05: stay RESTRICT
        d = eng.evaluate(upd(0.66, 3))
        assert d is not None
        assert d.new_state is S.MONITOR

    def test_escalation_is_immediate(self) -> None:
        eng = PolicyEngine()
        d = eng.evaluate(upd(0.35, 1))
        assert d is not None
        assert d.previous_state is S.NORMAL
        assert d.new_state is S.REAUTHENTICATE
        assert "force_reauthentication" in d.actions


class TestHardRules:
    def test_repeat_reauthentication_quarantines(self) -> None:
        eng = PolicyEngine(PolicyConfig(reauth_repeat_limit=2, reauth_window_s=60))
        t = 0.0
        for _ in range(2):  # enter RE-AUTH, recover to NORMAL, twice
            eng.evaluate(upd(0.3, t))
            eng.evaluate(upd(0.95, t + 5))
            t += 10
        d = eng.evaluate(upd(0.3, t))
        assert d is not None
        assert d.new_state is S.QUARANTINE
        assert "repeat offender" in d.rule

    def test_failed_reauthentication_quarantines(self) -> None:
        eng = PolicyEngine()
        eng.evaluate(upd(0.3, 1))
        d = eng.reauthentication_failed("D4", 2000, 0.3, "secret_mismatch")
        assert d is not None
        assert d.new_state is S.QUARANTINE
        assert "secret_mismatch" in d.rule

    def test_failed_reauth_ignored_outside_reauth_state(self) -> None:
        assert PolicyEngine().reauthentication_failed("D4", 0, 0.9, "x") is None

    def test_quarantine_exit_needs_time_reauth_and_trust(self) -> None:
        eng = PolicyEngine(PolicyConfig(quarantine_min_s=20))
        eng.evaluate(upd(0.1, 0))
        assert eng.state("D4") is S.QUARANTINE
        assert eng.evaluate(upd(0.9, 5)) is None  # too early
        assert eng.evaluate(upd(0.9, 25)) is None  # no successful re-authentication yet
        d = eng.evaluate(upd(0.9, 26, reauth_success=1))
        assert d is not None
        assert d.new_state is S.RESTRICT  # probation, not straight to NORMAL
        assert "quarantine exit" in d.rule


class TestBinaryMode:
    def test_single_threshold(self) -> None:
        eng = PolicyEngine(PolicyConfig(mode="binary", binary_threshold=0.5))
        eng.evaluate(upd(0.45, 1))
        assert eng.state("D4") is S.QUARANTINE
        eng.evaluate(upd(0.52, 2))
        assert eng.state("D4") is S.QUARANTINE  # hysteresis
        eng.evaluate(upd(0.6, 3))
        assert eng.state("D4") is S.NORMAL


class TestExplanation:
    def test_explanation_contains_evidence(self) -> None:
        eng = PolicyEngine()
        d = eng.evaluate(upd(0.31, 4, prev=0.72, attack_prob=0.91, attack_class="dos",
                             auth_failures=2, verified=5, unverified=5))  # fmt: skip
        assert d is not None
        text = d.explanation
        for fragment in ("Drone D4", "Trust before = 0.72", "Attack probability = 0.91 (dos)",
                         "Authentication failures = 2", "Trust after = 0.31",
                         "Decision = REAUTHENTICATE"):  # fmt: skip
            assert fragment in text
        assert d.as_record()["new_state"] == "reauthenticate"
