"""The simulated IDS dataset is deterministic, including under parallel generation."""

from __future__ import annotations

import pandas as pd
import pytest

from app.ids.dataset import DatasetConfig, generate

pytestmark = [pytest.mark.integration, pytest.mark.slow]
TINY = DatasetConfig(seeds=(7,), kinds=("flooding", "spoofing"), rates_pps=(10.0,),
                     benign_runs_per_seed=1, duration_ms=15_000, drone_counts=(6,))  # fmt: skip


def test_parallel_generation_equals_sequential() -> None:
    a = generate(TINY, base_seed=3, workers=1)
    b = generate(TINY, base_seed=3, workers=2)
    pd.testing.assert_frame_equal(a, b)
    assert set(a.scenario_kind) == {"flooding", "spoofing", "benign"}
    assert (a.label != "benign").any()
