"""Unit tests for the ML IDS pipeline: features, validation/leakage, models, evaluation."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.ids import public
from app.ids.evaluate import detection_latency, evaluate
from app.ids.features import FEATURES, extract_windows
from app.ids.models import MODEL_NAMES, train_model
from app.ids.validation import (
    DataValidationError,
    check_feature_columns,
    clean,
    group_split,
    separability_scan,
    validate,
)
from app.simulation.traffic_log import COLUMNS


def pkt(pid: int, t: int, src: str, dst: str, proto: str, **kw: object) -> dict[str, object]:
    rec: dict[str, object] = dict.fromkeys(COLUMNS)
    rec.update(
        packet_id=pid,
        timestamp_ms=t,
        delivered_ms=t + 2,
        src=src,
        dst=dst,
        protocol=proto,
        size_bytes=100,
        seq=pid,
        ttl=8,
        true_src=src,
        label="benign",
    )
    rec.update(kw)
    return rec


class TestFeatures:
    def test_counts_and_verdicts(self) -> None:
        rows = [
            pkt(1, 100, "A", "B", "telemetry", size_bytes=100),
            pkt(2, 300, "A", "C", "telemetry", size_bytes=300),
            pkt(3, 500, "A", "B", "auth_request", size_bytes=152, auth_ok=False,
                dropped_reason="auth_failed", label="spoofing"),
            pkt(4, 600, "A", "B", "telemetry", size_bytes=100, integrity_ok=False,
                dropped_reason="integrity", label="spoofing"),
            # channel loss: the receiver never sees this packet
            pkt(5, 700, "A", "B", "telemetry", size_bytes=100, dropped_reason="channel_loss"),
            pkt(6, 1500, "B", "A", "command", size_bytes=80),
        ]  # fmt: skip
        win = extract_windows(pd.DataFrame(rows), {"B": "leader"}).set_index(["src", "window"])
        a0 = win.loc[("A", 0)]
        assert a0.tx_count == 4  # packet 5 was lost on the channel: not observable
        assert a0.unique_dst == 2
        assert a0.auth_req_count == 1
        assert a0.auth_fail_count == 1
        assert a0.integrity_fail_count == 1
        assert a0.bytes_total == 652
        assert a0.label == "spoofing"
        assert win.loc[("B", 1)].src_is_leader == 1
        assert win.loc[("B", 1)].cmd_count == 1
        assert win.loc[("B", 1)].label == "benign"

    def test_broadcast_copies_counted_once_for_tx(self) -> None:
        rows = [pkt(1, 10, "A", "B", "heartbeat"), pkt(1, 10, "A", "C", "heartbeat")]
        w = extract_windows(pd.DataFrame(rows)).iloc[0]
        assert (w.tx_count, w.rx_count) == (1, 2)

    def test_replay_duplicate_seq(self) -> None:
        rows = [pkt(1, 10, "A", "B", "telemetry", seq=5), pkt(2, 20, "A", "B", "telemetry", seq=5,
                dropped_reason="replay")]  # fmt: skip
        w = extract_windows(pd.DataFrame(rows)).iloc[0]
        assert w.seq_dup_count == 1
        assert w.replay_reject_count == 1

    def test_ground_truth_does_not_change_features(self) -> None:
        rows = [pkt(1, 10, "A", "B", "telemetry"), pkt(2, 20, "A", "B", "video", size_bytes=1100)]
        a = extract_windows(pd.DataFrame(rows))[list(FEATURES)]
        for r in rows:
            r.update(true_src="X", label="flooding", attack_id="f-1")
        b = extract_windows(pd.DataFrame(rows))[list(FEATURES)]
        pd.testing.assert_frame_equal(a, b)

    def test_policy_drops_not_used_as_verdicts(self) -> None:
        rows = [pkt(1, 10, "A", "B", "telemetry", dropped_reason="policy:quarantine")]
        w = extract_windows(pd.DataFrame(rows)).iloc[0]
        assert w.integrity_fail_count == 0
        assert w.tx_count == 1  # still observed

    def test_empty_input(self) -> None:
        assert extract_windows(pd.DataFrame(columns=list(COLUMNS))).empty


def synth(n_runs: int = 12, seed: int = 0) -> pd.DataFrame:
    """Small learnable dataset: attack windows have high tx_count and auth failures."""
    rng = np.random.default_rng(seed)
    rows = []
    for run in range(n_runs):
        kind = "benign" if run % 3 == 0 else ("flooding" if run % 3 == 1 else "spoofing")
        for w in range(40):
            attack = kind != "benign" and 10 <= w < 30
            label = kind if attack else "benign"
            f = dict.fromkeys(FEATURES, 0.0)
            f["tx_count"] = rng.poisson(60 if label == "flooding" else 8)
            f["auth_fail_count"] = rng.poisson(5 if label == "spoofing" else 0.05)
            f["bytes_total"] = f["tx_count"] * rng.uniform(80, 1200)
            rows.append({**f, "label": label, "run_id": run, "scenario_kind": kind,
                         "src": "D2", "window": w, "t_start_ms": w * 1000, "rate_pps": 10.0,
                         "attack_start_ms": 10_000 if kind != "benign" else -1})  # fmt: skip
    return pd.DataFrame(rows)


class TestValidation:
    def test_group_split_has_no_overlap(self) -> None:
        tr, te = group_split(synth(), 0.3, seed=1)
        assert not set(tr.run_id) & set(te.run_id)
        assert set(te.scenario_kind) == {"benign", "flooding", "spoofing"}

    def test_leakage_detected(self) -> None:
        df = synth()
        with pytest.raises(DataValidationError, match="leakage"):
            validate(df[df.run_id < 8], df[df.run_id >= 6], list(FEATURES))

    def test_forbidden_feature(self) -> None:
        with pytest.raises(DataValidationError, match="ground-truth"):
            check_feature_columns(["tx_count", "label"])

    def test_nan_must_be_cleaned(self) -> None:
        df = synth()
        df.loc[0, "tx_count"] = np.nan
        tr, te = group_split(df, 0.3, seed=1)
        with pytest.raises(DataValidationError, match="NaN"):
            validate(tr, te, list(FEATURES))
        tr2, te2 = group_split(clean(df, list(FEATURES)), 0.3, seed=1)
        assert validate(tr2, te2, list(FEATURES)).nan_cells == 0

    def test_report_duplicates_and_separability(self) -> None:
        tr, te = group_split(synth(), 0.3, seed=2)
        rep = validate(tr, te, list(FEATURES))
        assert rep.group_overlap == 0
        assert rep.class_counts["benign"] > 0
        assert "auth_fail_count" in separability_scan(tr, list(FEATURES), threshold=0.5)


@pytest.fixture(scope="module")
def split() -> tuple[pd.DataFrame, pd.DataFrame]:
    return group_split(synth(18), 0.3, seed=3)


class TestModels:
    @pytest.mark.parametrize("name", MODEL_NAMES)
    def test_each_model_learns(self, name: str, split: tuple[pd.DataFrame, pd.DataFrame]) -> None:
        tr, te = split
        m = train_model(name, tr, list(FEATURES), seed=0, groups=tr.run_id)
        res = evaluate(m, te, n_single=5)
        assert res.metrics["f1_macro"] > 0.8
        assert 0 <= res.metrics["fpr"] <= 1
        assert {"precision", "recall", "f1", "support"} <= set(res.per_class.columns)
        assert res.confusion.to_numpy().sum() == len(te)
        assert res.metrics["inference_ms_single_mean"] > 0

    def test_scaler_fitted_on_training_data_only(
        self, split: tuple[pd.DataFrame, pd.DataFrame]
    ) -> None:
        tr, _ = split
        m = train_model("logistic_regression", tr, list(FEATURES), seed=0, groups=tr.run_id)
        scaler = m.pipeline.named_steps["prep"].named_transformers_["num"].named_steps["scale"]
        expected = np.log1p(tr[list(FEATURES)].to_numpy(dtype=float)).mean(axis=0)
        np.testing.assert_allclose(scaler.mean_, expected, rtol=1e-9)

    def test_detection_latency(self) -> None:
        te = synth(3)
        p = np.where(te.label != "benign", 0.9, 0.1)
        lat = detection_latency(te, p)
        assert lat.detected.all()
        assert (lat.latency_ms == 1000).all()  # first attack window ends 1 s after start


class TestPublicLoader:
    def test_nsl_format_fixture(self, tmp_path: Path) -> None:
        rows = []
        for attack in ("normal", "neptune", "satan", "guess_passwd", "rootkit"):
            vals = [0, "tcp", "http", "SF"] + [1] * 37 + [attack, 21]
            rows.append(",".join(map(str, vals)))
        for name in ("KDDTrain+.txt", "KDDTest+.txt"):
            (tmp_path / name).write_text("\n".join(rows) + "\n", encoding="utf-8")
        assert public.available(tmp_path)
        train, _ = public.load(tmp_path)
        assert list(train.label) == ["benign", "dos", "probe", "r2l", "u2r"]
        assert len(public.NSL_FEATURES) == 41

    def test_missing_dataset(self, tmp_path: Path) -> None:
        with pytest.raises(public.DatasetUnavailableError):
            public.load(tmp_path)

    def test_unknown_attack_name(self, tmp_path: Path) -> None:
        vals = [0, "tcp", "http", "SF"] + [1] * 37 + ["teleport", 1]
        (tmp_path / "x.txt").write_text(",".join(map(str, vals)) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="unmapped"):
            public.load_file(tmp_path / "x.txt")
