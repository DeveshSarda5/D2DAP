"""Dataset validation, cleaning and leakage checks (Phase 9).

Checks performed before any metric is reported:

* schema / NaN / infinite / negative-count validation;
* **train/test leakage**: run (group) overlap between splits;
* **duplicate samples**: exact feature-vector duplicates within and across splits;
* **target leakage**: forbidden ground-truth columns among features, and a
  single-feature separability scan (features that alone separate attack from benign
  almost perfectly are flagged for manual review);
* **preprocessing leakage** is prevented structurally (scalers/encoders live inside
  sklearn Pipelines fitted on the training split only), and verified by a test;
* class distribution / imbalance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from app.ids.features import FEATURES
from app.models.enums import BENIGN_LABEL
from app.models.packet import GROUND_TRUTH_FIELDS

FORBIDDEN_FEATURES = frozenset(GROUND_TRUTH_FIELDS | {"label", "scenario_kind", "target",
                                                      "attack_start_ms", "attack_end_ms",
                                                      "run_id", "seed"})  # fmt: skip
COUNT_FEATURES = tuple(f for f in FEATURES if f.endswith("_count") or f in {"tx_count",
                                                                           "rx_count"})  # fmt: skip


class DataValidationError(ValueError):
    """The dataset is unusable (schema error or leakage that must be fixed first)."""


@dataclass
class ValidationReport:
    rows: int
    features: list[str]
    nan_cells: int
    inf_cells: int
    negative_counts: int
    class_counts: dict[str, int]
    imbalance_ratio: float
    within_split_duplicates: dict[str, int] = field(default_factory=dict)
    cross_split_duplicates: int = 0
    cross_split_duplicate_test_fraction: float = 0.0
    cross_split_duplicate_label_conflicts: int = 0
    group_overlap: int = 0
    near_perfect_features: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def check_feature_columns(feature_cols: list[str]) -> None:
    bad = sorted(set(feature_cols) & FORBIDDEN_FEATURES)
    if bad:
        raise DataValidationError(f"target leakage: ground-truth columns used as features: {bad}")


def clean(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    """Replace infinities, fill NaN with 0 (all features are counts/rates/fractions)."""
    out = df.copy()
    out[feature_cols] = out[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return out


def separability_scan(df: pd.DataFrame, feature_cols: list[str], threshold: float = 0.99
                      ) -> dict[str, float]:  # fmt: skip
    """Single-feature ROC-AUC (attack vs benign); returns features above ``threshold``."""
    y = (df["label"] != BENIGN_LABEL).astype(int)
    if y.nunique() < 2:
        return {}
    out = {}
    for c in feature_cols:
        x = df[c].to_numpy(dtype=float)
        if np.nanstd(x) == 0:
            continue
        auc = roc_auc_score(y, x)
        auc = max(auc, 1 - auc)
        if auc >= threshold:
            out[c] = round(float(auc), 4)
    return out


def validate(
    train: pd.DataFrame, test: pd.DataFrame, feature_cols: list[str], group_col: str = "run_id"
) -> ValidationReport:
    """Run all checks; raise :class:`DataValidationError` on hard leakage."""
    check_feature_columns(feature_cols)
    full = pd.concat([train, test])
    numeric = [c for c in feature_cols if pd.api.types.is_numeric_dtype(full[c])]
    x = full[numeric].to_numpy(dtype=float)
    counts = full["label"].value_counts()
    report = ValidationReport(
        rows=len(full),
        features=list(feature_cols),
        nan_cells=int(np.isnan(x).sum()),
        inf_cells=int(np.isinf(x).sum()),
        negative_counts=int(
            (full[[c for c in COUNT_FEATURES if c in feature_cols]] < 0).sum().sum()
        ),
        class_counts={str(k): int(v) for k, v in counts.items()},
        imbalance_ratio=float(counts.max() / counts.min()) if len(counts) > 1 else 1.0,
    )
    if report.nan_cells or report.inf_cells:
        raise DataValidationError("NaN/inf values present: call clean() first")
    if report.negative_counts:
        raise DataValidationError("negative values in count features")
    if group_col in train.columns and group_col in test.columns:
        report.group_overlap = len(set(train[group_col]) & set(test[group_col]))
        if report.group_overlap:
            raise DataValidationError(
                f"train/test leakage: {report.group_overlap} runs appear in both splits"
            )
    for name, part in (("train", train), ("test", test)):
        report.within_split_duplicates[name] = int(part.duplicated(feature_cols).sum())
    train_keys = train[feature_cols].round(9).apply(tuple, axis=1)
    test_keys = test[feature_cols].round(9).apply(tuple, axis=1)
    train_label = dict(zip(train_keys, train["label"], strict=True))
    in_train = test_keys.isin(set(train_keys))
    report.cross_split_duplicates = int(in_train.sum())
    report.cross_split_duplicate_test_fraction = float(in_train.mean()) if len(test) else 0.0
    test_labels = test.loc[in_train, "label"]
    report.cross_split_duplicate_label_conflicts = int(
        sum(train_label[k] != lbl for k, lbl in zip(test_keys[in_train], test_labels, strict=True))
    )
    report.near_perfect_features = separability_scan(train, numeric)
    return report


def group_split(
    df: pd.DataFrame,
    test_fraction: float,
    seed: int,
    group_col: str = "run_id",
    stratify_col: str = "scenario_kind",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split by run (group), stratified by scenario kind, so no run is in both splits."""
    rng = np.random.default_rng(seed)
    runs = df[[group_col, stratify_col]].drop_duplicates()
    test_runs: list[Any] = []
    for _, grp in runs.groupby(stratify_col):
        ids = grp[group_col].to_numpy()
        rng.shuffle(ids)
        n_test = max(1, round(len(ids) * test_fraction)) if len(ids) > 1 else 0
        test_runs.extend(ids[:n_test].tolist())
    is_test = df[group_col].isin(test_runs)
    return df.loc[~is_test].reset_index(drop=True), df.loc[is_test].reset_index(drop=True)
