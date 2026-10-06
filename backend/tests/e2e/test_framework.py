"""End-to-end tests of the integrated adaptive framework (Phase 14).

These use the ``no_ml`` variant (trust from D2DAP outcomes, verdicts, role violations
and rate anomalies) so they do not depend on the trained IDS artefact; the IDS-driven
variants are exercised when the operational model exists.
"""

from __future__ import annotations

import pytest

from app.experiments.scenario import (
    ScenarioConfig,
    Variant,
    run_attack_scenario,
    run_benign_scenario,
)
from app.models.enums import SecurityState
from app.services.framework import model_path
from app.services.monitor import SecurityMonitor

pytestmark = [pytest.mark.e2e, pytest.mark.slow]
CFG = ScenarioConfig(num_drones=8, duration_ms=45_000, attack_start_ms=8_000,
                     attack_duration_ms=30_000)  # fmt: skip
SEVERE = {"reauthenticate", "quarantine"}


def monitor_of(result: object) -> SecurityMonitor:
    ext = result.extensions  # type: ignore[attr-defined]
    assert isinstance(ext[0], SecurityMonitor)
    return ext[0]


def test_insider_flood_is_escalated_and_mitigated() -> None:
    res = run_attack_scenario(Variant.NO_ML, "flooding", CFG, seed=11)
    mon = monitor_of(res)
    states = set(mon.decisions_frame().query("drone_id == 'D3'").new_state)
    assert states & SEVERE
    policy_drops = sum(v for k, v in res.evidence.dropped.items() if k.startswith("policy:"))
    assert policy_drops > 0
    assert res.evidence.packets_accepted < res.evidence.packets_sent


def test_privilege_escalation_commands_blocked() -> None:
    res = run_attack_scenario(Variant.NO_ML, "privilege_escalation", CFG, seed=11)
    assert res.evidence.dropped["policy:privileged_blocked"] > 0
    reasons = " ".join(monitor_of(res).trust_frame().reason)
    assert "privileged command(s) from a non-leader" in reasons


def test_spoofed_victim_not_restricted() -> None:
    res = run_attack_scenario(Variant.NO_ML, "spoofing", CFG, seed=11)
    d = monitor_of(res).decisions_frame()
    victim = d[d.drone_id == "D3"]
    assert not set(victim.new_state) & {"restrict", "reauthenticate", "quarantine"}
    assert res.evidence.packets_accepted == 0  # D2DAP still blocks the spoofed packets


def test_benign_swarm_never_severely_sanctioned() -> None:
    """Without ML, the rate-anomaly heuristic can briefly RESTRICT a drone during a
    legitimate video burst (a measured false positive of this ablation); it must never
    force re-authentication or quarantine an honest drone, and must recover."""
    res = run_benign_scenario(Variant.NO_ML, CFG, seed=12)
    d = monitor_of(res).decisions_frame()
    if len(d):
        assert not set(d.new_state) & SEVERE
    for drone in res.swarm.engine.network.nodes.values():
        assert drone.security_state.severity <= SecurityState.MONITOR.severity


def test_every_decision_is_explained_and_audited() -> None:
    res = run_attack_scenario(Variant.NO_ML, "flooding", CFG, seed=13)
    mon = monitor_of(res)
    trust = mon.trust_frame()
    assert {"previous", "new", "reason", "t_ms"} <= set(trust.columns)
    for text in mon.decisions_frame().explanation:
        assert text.startswith("Drone ")
        assert "Trust before" in text
        assert "Decision =" in text
    assert mon.stats.windows >= 40
    assert mon.stats.report_bytes > 0


@pytest.mark.skipif(not model_path().exists(), reason="operational IDS model not trained yet")
@pytest.mark.parametrize("variant", [Variant.D2DAP_IDS, Variant.D2DAP_IDS_TRUST, Variant.ADAPTIVE])
def test_ids_variants_run(variant: Variant) -> None:
    res = run_attack_scenario(variant, "flooding", CFG, seed=11)
    mon = monitor_of(res)
    assert mon.stats.windows >= 40
    assert len(mon.alerts_frame()) > 0  # the IDS flags the flood


def test_full_pipeline_is_reproducible() -> None:
    """Same (config, seed) -> identical traffic, trust and decisions (machine-independent)."""
    a = run_attack_scenario(Variant.NO_ML, "flooding", CFG, seed=21)
    b = run_attack_scenario(Variant.NO_ML, "flooding", CFG, seed=21)
    cols = ["packet_id", "timestamp_ms", "src", "dst", "protocol", "size_bytes", "dropped_reason"]
    assert a.traffic()[cols].equals(b.traffic()[cols])
    da, db = monitor_of(a).decisions_frame(), monitor_of(b).decisions_frame()
    assert da.drop(columns=["explanation"]).equals(db.drop(columns=["explanation"]))
    assert [u.new for u in monitor_of(a).trust.log] == [u.new for u in monitor_of(b).trust.log]
