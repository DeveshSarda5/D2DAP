"""Tests of the baseline-comparison / ablation metric machinery (Phases 15-16)."""

from __future__ import annotations

import pandas as pd
import pytest

from app.experiments.comparison import Job, run_job, summarize
from app.experiments.scenario import ScenarioConfig
from app.services.framework import model_path

pytestmark = [pytest.mark.integration, pytest.mark.slow]
CFG = ScenarioConfig(num_drones=6, duration_ms=30_000, attack_start_ms=6_000,
                     attack_duration_ms=18_000, area_m=250)  # fmt: skip


@pytest.fixture(scope="module")
def rows() -> list[dict[str, object]]:
    jobs = [Job(v, k, 3, CFG) for v in ("d2dap", "no_ml") for k in ("flooding", "benign")]
    return [run_job(j) for j in jobs]


def test_authentication_only_does_not_mitigate_insider_flood(rows: list[dict[str, object]]
                                                             ) -> None:  # fmt: skip
    a = next(r for r in rows if r["variant"] == "d2dap" and r["kind"] == "flooding")
    assert a["mitigation_rate"] < 0.2  # type: ignore[operator]
    assert a["policy_drop_share"] == 0.0
    assert a["layer_detected"] is False


def test_trust_layer_detects_and_mitigates(rows: list[dict[str, object]]) -> None:
    f = next(r for r in rows if r["variant"] == "no_ml" and r["kind"] == "flooding")
    assert f["layer_detected"] is True
    assert f["policy_drop_share"] > 0.1  # type: ignore[operator]
    assert f["detection_ms"] >= 0  # type: ignore[operator]
    assert f["monitor_ms_per_window"] > 0  # type: ignore[operator]
    assert f["report_bytes_per_s"] > 0  # type: ignore[operator]


def test_benign_rows_have_rates(rows: list[dict[str, object]]) -> None:
    for r in rows:
        if r["kind"] == "benign":
            assert 0.0 <= r["flag_rate"] <= 1.0  # type: ignore[operator]
            assert r["benign_windows"] > 0  # type: ignore[operator]


def test_summary_table(rows: list[dict[str, object]]) -> None:
    s = summarize(pd.DataFrame(rows))
    assert set(s.variant) == {"d2dap", "no_ml"}
    assert {"detection_rate", "fpr_flag_rate", "mitigation_rate", "fnr"} <= set(s.columns)
    no_ml = s[s.variant == "no_ml"].iloc[0]
    d2 = s[s.variant == "d2dap"].iloc[0]
    assert no_ml.mitigation_rate > d2.mitigation_rate


def test_tampering_fully_mitigated_with_monitor_and_reports_sealed() -> None:
    """Regression: the monitor's TRUST_REPORT channel is sealed (was tamperable)."""
    row = run_job(Job("no_ml", "tampering", 3, CFG))
    assert row["mitigation_rate"] == pytest.approx(1.0)
    assert row["attack_packets_attempted"] > 0


def test_mitigation_counts_attempts_never_transmitted() -> None:
    """A quarantined insider's packets are held (sessions revoked): still mitigated."""
    row = run_job(Job("no_ml", "flooding", 3, CFG))
    assert row["attack_packets_attempted"] >= row["attack_packets"]


@pytest.mark.skipif(not model_path().exists(), reason="operational IDS model not trained yet")
def test_false_alarm_injection_raises_flags() -> None:
    """Stress-test hook: injected false alarms produce IDS flags on a benign swarm."""
    clean = run_job(Job("d2dap_ids", "benign", 3, CFG))
    noisy = run_job(Job("d2dap_ids", "benign", 3, CFG, (), (), (), "r=0.2",
                        (("ids_false_alarm_rate", 0.2),)))  # fmt: skip
    assert noisy["flag_rate"] > clean["flag_rate"]


def test_framed_rate_definition() -> None:
    from app.experiments.comparison import _framed_rate  # noqa: PLC0415

    ab = pd.DataFrame({"max_attacker_state": [0, 2, 4, 1], "layer_detected": [1, 0, 0, 1]})
    assert _framed_rate(ab, "adaptive") == 0.5  # states >= RESTRICT
    assert _framed_rate(ab, "d2dap_ids") == 0.5  # B: any alert blocks the identity
    assert pd.isna(_framed_rate(ab.iloc[0:0], "adaptive"))
