"""TrustEngine tests: design requirements R1-R5 (docs/architecture/trust-model.md).

Thresholds used here are the default policy bands: NORMAL >= 0.80, MONITOR >= 0.60,
RESTRICT >= 0.40, RE-AUTHENTICATE >= 0.20, QUARANTINE < 0.20.
"""

from __future__ import annotations

import pytest

from app.trust.config import TrustConfig
from app.trust.engine import Evidence, TrustEngine

DRONES = {"D1", "D2", "D3"}


def benign(i: int, drone: str = "D2", tx: int = 10) -> Evidence:
    return Evidence(drone, i, i * 1000, attack_prob=0.02, insider_prob=0.0, tx_count=tx,
                    verified=tx)  # fmt: skip


def insider_attack(i: int, drone: str = "D2") -> Evidence:
    return Evidence(drone, i, i * 1000, attack_prob=0.98, insider_prob=0.97,
                    attack_class="flooding", tx_count=60, verified=60)  # fmt: skip


def warm(engine: TrustEngine, n: int = 30, drone: str = "D2") -> int:
    for i in range(n):
        engine.update(benign(i, drone))
    return n


def first_below(values: list[float], threshold: float) -> int | None:
    return next((i + 1 for i, v in enumerate(values) if v < threshold), None)


class TestRequirements:
    def test_r1_steady_state_and_single_false_positive(self) -> None:
        eng = TrustEngine(registered=DRONES)
        k = warm(eng)
        assert eng.trust("D2") >= 0.90
        fp = Evidence(
            "D2", k, k * 1000, attack_prob=0.9, insider_prob=0.9, tx_count=10, verified=10
        )  # worst case: confident insider-class false positive
        assert eng.update(fp).new >= 0.60  # never RESTRICT on one window
        for i in range(k + 1, k + 11):
            eng.update(benign(i))
        assert eng.trust("D2") >= 0.80  # back to NORMAL quickly

    def test_r2_sustained_insider_attack_escalates(self) -> None:
        eng = TrustEngine(registered=DRONES)
        k = warm(eng)
        values = [eng.update(insider_attack(k + i)).new for i in range(20)]
        assert (first_below(values, 0.60) or 99) <= 3
        assert (first_below(values, 0.40) or 99) <= 6
        assert (first_below(values, 0.20) or 99) <= 15

    def test_r3_recovery_after_attack_burst(self) -> None:
        eng = TrustEngine(registered=DRONES)
        k = warm(eng)
        for i in range(4):
            eng.update(insider_attack(k + i))
        assert eng.trust("D2") < 0.60
        recovered = [eng.update(benign(k + 4 + i)).new for i in range(40)]
        idx = next(i for i, v in enumerate(recovered) if v >= 0.80)
        assert idx < 25

    def test_r4_spoofed_identity_is_not_framed(self) -> None:
        """Attacker spoofs D2: unverified packets, external-class IDS output."""
        eng = TrustEngine(registered=DRONES)
        k = warm(eng)
        values = []
        for i in range(40):
            ev = Evidence("D2", k + i, (k + i) * 1000, attack_prob=0.98, insider_prob=0.02,
                          attack_class="spoofing", tx_count=25, verified=5, unverified=20,
                          violations=20, auth_failures=2)  # fmt: skip
            values.append(eng.update(ev).new)
        assert min(values) >= 0.60  # MONITOR at worst, never restricted

    def test_r4_without_attribution_the_victim_is_framed(self) -> None:
        """Ablation: attribution-unaware fusion quarantines the innocent victim."""
        eng = TrustEngine(TrustConfig(attribution_aware=False), registered=DRONES)
        k = warm(eng)
        for i in range(40):
            eng.update(
                Evidence(
                    "D2",
                    k + i,
                    0,
                    attack_prob=0.98,
                    insider_prob=0.02,
                    tx_count=25,
                    verified=5,
                    unverified=20,
                    violations=20,
                )
            )
        assert eng.trust("D2") < 0.20

    def test_r6_benign_burst_recognised_by_ids_not_restricted(self) -> None:
        """A legitimate video burst: rate jumps 6x but the IDS says benign."""
        eng = TrustEngine(registered=DRONES)
        k = warm(eng, 30)
        values = []
        for i in range(15):  # 15 s burst
            ev = Evidence("D2", k + i, 0, attack_prob=0.01, insider_prob=0.005, tx_count=60,
                          verified=60)  # fmt: skip
            values.append(eng.update(ev).new)
        assert min(values) >= 0.60

    def test_r6_without_ml_the_heuristic_can_restrict(self) -> None:
        """Documented limitation of the no-ML ablation."""
        eng = TrustEngine(TrustConfig(use_ml=False), registered=DRONES)
        for i in range(30):
            eng.update(Evidence("D2", i, 0, tx_count=10, verified=10))
        values = [eng.update(Evidence("D2", 30 + i, 0, tx_count=60, verified=60)).new
                  for i in range(15)]  # fmt: skip
        assert min(values) < 0.60

    def test_r4_forged_dos_during_legit_burst_not_framed(self) -> None:
        """Regression (final run): outsider floods AUTH_REQUESTs forging D2 while D2 has a
        legitimate video burst. External-class IDS mass must not corroborate the burst."""
        eng = TrustEngine(registered=DRONES)
        k = warm(eng, 30)
        values = []
        for i in range(15):
            ev = Evidence("D2", k + i, 0, attack_prob=0.999, insider_prob=0.001,
                          attack_class="dos", tx_count=34, verified=32, unverified=2,
                          auth_failures=2)  # fmt: skip
            values.append(eng.update(ev).new)
        assert min(values) >= 0.60

    def test_r5_unregistered_rogue_is_quarantined(self) -> None:
        eng = TrustEngine(registered=DRONES)
        values = [eng.update(Evidence("ROGUE", i, i * 1000, attack_prob=0.97, insider_prob=0.0,
                                      tx_count=20, unverified=20, auth_failures=3)).new
                  for i in range(15)]  # fmt: skip
        assert values[0] < 0.5
        assert (first_below(values, 0.20) or 99) <= 10


class TestMechanics:
    def test_audit_record_complete(self) -> None:
        eng = TrustEngine(registered=DRONES)
        u = eng.update(insider_attack(3))
        assert u.previous > u.new
        assert u.t_ms == 3000
        assert u.evidence.attack_class == "flooding"
        assert "IDS P(attack)=0.98" in u.reason
        assert u.components["ml_attack"] < 0
        rec = u.as_record()
        assert {"previous", "new", "reason", "t_ms", "c_ml_attack", "e_attack_prob"} <= set(rec)
        assert eng.history("D2") == [u]

    def test_decay_returns_to_prior(self) -> None:
        cfg = TrustConfig()
        eng = TrustEngine(cfg, registered=DRONES)
        eng.update(insider_attack(0))
        eng.update(Evidence("D2", 200, 200_000))  # 200 idle windows of decay
        prior = cfg.prior_alpha / (cfg.prior_alpha + cfg.prior_beta)
        assert eng.trust("D2") == pytest.approx(prior, abs=1e-3)

    def test_reauthentication_reward(self) -> None:
        eng = TrustEngine(registered=DRONES)
        k = warm(eng)
        for i in range(5):
            eng.update(insider_attack(k + i))
        before = eng.trust("D2")
        assert eng.reward_reauthentication("D2", k + 5, 0).new > before

    def test_escalation_multiplier_grows(self) -> None:
        eng = TrustEngine(registered=DRONES)
        mults = [eng.update(insider_attack(i)).multiplier for i in range(6)]
        assert mults[0] == 1.0
        assert mults == sorted(mults)
        assert mults[-1] > 1.5

    def test_anomaly_detector_flags_rate_spike(self) -> None:
        eng = TrustEngine(TrustConfig(use_ml=False), registered=DRONES)
        for i in range(20):
            eng.update(Evidence("D2", i, 0, tx_count=10, verified=10))
        u = eng.update(Evidence("D2", 20, 0, tx_count=200, verified=200))
        assert u.components.get("anomaly", 0) < 0
        assert "anomaly" in u.reason

    def test_ml_ablation_uses_normal_behaviour_evidence(self) -> None:
        eng = TrustEngine(TrustConfig(use_ml=False), registered=DRONES)
        u = eng.update(Evidence("D2", 0, 0, attack_prob=0.99, tx_count=5, verified=5))
        assert "ml_attack" not in u.components
        assert u.components["normal_behaviour"] > 0

    def test_saturation_bounds_burst_effect(self) -> None:
        eng = TrustEngine(TrustConfig(attribution_aware=False), registered=DRONES)
        a = eng.update(Evidence("D1", 0, 0, violations=10)).negative
        b = eng.update(Evidence("D3", 0, 0, violations=10_000)).negative
        assert b < 2.0 * 1.01  # never more than w_violation per window
        assert a > 0.9 * b
