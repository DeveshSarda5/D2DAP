"""Tests of the STRIDE evaluation machinery (Phase 8)."""

from __future__ import annotations

import pandas as pd
import pytest

from app.experiments.scenario import ScenarioConfig, Variant, run_attack_scenario
from app.experiments.stride_eval import (
    SCENARIOS,
    build_table,
    repudiation_analysis,
    run_record,
    success_rate,
)

pytestmark = pytest.mark.integration
CFG = ScenarioConfig(num_drones=6, duration_ms=12_000, attack_start_ms=4000,
                     attack_duration_ms=6000, area_m=250)  # fmt: skip


def test_d2dap_reduces_spoofing_success_vs_baseline() -> None:
    base = run_attack_scenario(Variant.BASELINE, "spoofing", CFG, seed=2)
    d2 = run_attack_scenario(Variant.D2DAP, "spoofing", CFG, seed=2)
    assert success_rate(base) > 0.8
    assert success_rate(d2) == 0.0
    assert run_record(d2)["d2dap_rejection_signals"] > 0


def test_tampering_silently_succeeds_without_integrity() -> None:
    base = run_attack_scenario(Variant.BASELINE, "tampering", CFG, seed=2)
    d2 = run_attack_scenario(Variant.D2DAP, "tampering", CFG, seed=2)
    assert success_rate(base) > 0.9
    assert success_rate(d2) == 0.0


def test_repudiation_analysis_properties() -> None:
    res = run_attack_scenario(Variant.D2DAP, "flooding", CFG, seed=3)
    out = repudiation_analysis(res.swarm)
    assert out == {
        "m1_signature_judge_verifiable": True,
        "receiver_can_forge_m1": False,
        "data_packet_forgeable_by_receiver": True,
    }


def test_table_marks_missing_layers_pending() -> None:
    rows = []
    for sc in SCENARIOS:
        if sc.kind == "repudiation":
            continue
        for v in (Variant.BASELINE, Variant.D2DAP):
            rows.append({"kind": sc.kind, "variant": v.value,
                         "params": str(sorted(sc.params.items())), "success_rate": 0.5,
                         "d2dap_rejection_signals": 0, "auth_attempts": 0, "auth_accepted": 0,
                         "victim_cpu_ms_per_s": 0.0, "packets_sent": 10, "packets_accepted": 5,
                         "crp_consumed": 0})  # fmt: skip
    table = build_table(pd.DataFrame(rows), [Variant.BASELINE, Variant.D2DAP], {})
    assert len(table) == len(SCENARIOS)
    assert set(table["D2DAP + IDS"]) == {"pending"}
    assert set(table["Adaptive Framework"]) == {"pending"}
    assert set(table["Detected?"]) <= {"D2DAP: No", "n/a"}
    assert set(table["Policy response (adaptive)"]) <= {"pending", "n/a"}
    assert set(table["Trust impact (adaptive)"]) <= {"pending", "n/a"}
