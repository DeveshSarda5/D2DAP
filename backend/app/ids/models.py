"""Baseline ML models for the IDS (Phase 10) with one identical methodology.

All models share:

* the same preprocessing (``log1p`` on non-negative features, then standardisation),
  fitted inside the Pipeline on training data only (no preprocessing leakage);
* the same class-imbalance handling ("balanced" class/sample weights);
* the same tuning procedure: a small grid searched with GroupKFold cross-validation
  **on the training split only**, scored by macro-F1;
* the same seed.

Model selection for the integrated system uses the *cross-validation* score, never the
test set (no cherry-picking on test results).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, GroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

MODEL_NAMES = ("logistic_regression", "decision_tree", "random_forest", "xgboost")


def _log1p_nonneg(x: Any) -> Any:
    return np.log1p(np.clip(x, 0, None))


def preprocessor(numeric: list[str], categorical: list[str] | None = None) -> ColumnTransformer:
    """Identical preprocessing for every model."""
    num = Pipeline([("log1p", FunctionTransformer(_log1p_nonneg, feature_names_out="one-to-one")),
                    ("scale", StandardScaler())])  # fmt: skip
    parts: list[tuple[str, Any, list[str]]] = [("num", num, numeric)]
    if categorical:
        parts.append(("cat", OneHotEncoder(handle_unknown="ignore"), categorical))
    return ColumnTransformer(parts)


class RobustXGBClassifier(ClassifierMixin, BaseEstimator):  # type: ignore[misc]
    """XGBoost with per-fit label re-encoding.

    XGBoost requires labels ``0..k-1``. Inside grouped CV a fold may miss a class; the
    sklearn models accept that, XGBoost does not. This wrapper re-encodes labels on every
    fit (and switches to a binary objective when a fold has two classes), so all four
    models run under the *identical* CV procedure. It does not change the model.
    """

    def __init__(self, n_estimators: int = 250, learning_rate: float = 0.1, max_depth: int = 6,
                 subsample: float = 1.0, random_state: int = 0) -> None:  # fmt: skip
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.subsample = subsample
        self.random_state = random_state

    def fit(self, X: Any, y: Any, sample_weight: Any = None) -> RobustXGBClassifier:
        self.le_ = LabelEncoder().fit(y)
        self.classes_ = self.le_.classes_
        binary = len(self.classes_) == 2
        self.model_ = XGBClassifier(
            n_estimators=self.n_estimators, learning_rate=self.learning_rate,
            max_depth=self.max_depth, subsample=self.subsample, tree_method="hist",
            objective="binary:logistic" if binary else "multi:softprob",
            eval_metric="logloss" if binary else "mlogloss",
            random_state=self.random_state, n_jobs=-1, verbosity=0,
        )  # fmt: skip
        self.model_.fit(X, self.le_.transform(y), sample_weight=sample_weight)
        return self

    def predict_proba(self, X: Any) -> Any:
        return self.model_.predict_proba(X)

    def predict(self, X: Any) -> Any:
        return self.le_.inverse_transform(np.asarray(self.model_.predict(X)).astype(int))


def estimator(name: str, seed: int, n_classes: int) -> tuple[Any, dict[str, list[Any]]]:
    """Return (unfitted estimator, small hyper-parameter grid)."""
    if name == "logistic_regression":
        return (LogisticRegression(max_iter=3000, class_weight="balanced", random_state=seed),
                {"clf__C": [0.1, 1.0, 10.0]})  # fmt: skip
    if name == "decision_tree":
        return (DecisionTreeClassifier(class_weight="balanced", random_state=seed),
                {"clf__max_depth": [6, 12, None], "clf__min_samples_leaf": [1, 5]})  # fmt: skip
    if name == "random_forest":
        return (RandomForestClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1,
                                       random_state=seed),
                {"clf__max_depth": [12, None], "clf__min_samples_leaf": [1, 3]})  # fmt: skip
    if name == "xgboost":
        return (RobustXGBClassifier(random_state=seed),
                {"clf__max_depth": [4, 8], "clf__subsample": [0.8, 1.0]})  # fmt: skip
    raise ValueError(f"unknown model {name!r}")


@dataclass
class TrainedModel:
    name: str
    pipeline: Pipeline
    encoder: LabelEncoder
    cv_macro_f1: float
    best_params: dict[str, Any]
    train_seconds: float
    feature_cols: list[str]

    @property
    def classes(self) -> list[str]:
        return [str(c) for c in self.encoder.classes_]

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray[Any, Any]:
        return np.asarray(self.pipeline.predict_proba(X[self.feature_cols]))

    def single_threaded(self) -> TrainedModel:
        """Use one inference thread (deployment-realistic; identical for all models).

        Training may use all cores; per-window inference on a drone/leader is
        single-threaded, and thread-pool start-up would otherwise dominate the latency of
        one-row predictions.
        """
        clf = self.pipeline.named_steps["clf"]
        if hasattr(clf, "n_jobs"):
            clf.n_jobs = 1
        inner = getattr(clf, "model_", None)
        if inner is not None and hasattr(inner, "set_params"):
            inner.set_params(n_jobs=1)
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray[Any, Any]:
        return np.asarray(
            self.encoder.inverse_transform(self.pipeline.predict(X[self.feature_cols]))
        )


def train_model(
    name: str,
    train: pd.DataFrame,
    feature_cols: list[str],
    *,
    seed: int,
    groups: pd.Series | None = None,
    categorical: list[str] | None = None,
    cv_folds: int = 3,
) -> TrainedModel:
    """Tune with grouped CV on the training data only, then refit on all training data."""
    enc = LabelEncoder().fit(train["label"])
    y = enc.transform(train["label"])
    numeric = [c for c in feature_cols if c not in (categorical or [])]
    est, grid = estimator(name, seed, len(enc.classes_))
    pipe = Pipeline([("prep", preprocessor(numeric, categorical)), ("clf", est)])
    weights = compute_sample_weight("balanced", y)
    cv = GroupKFold(n_splits=cv_folds) if groups is not None else cv_folds
    search = GridSearchCV(pipe, grid, scoring="f1_macro", cv=cv, n_jobs=1, refit=True)
    t0 = time.perf_counter()
    fit_kw: dict[str, Any] = {"clf__sample_weight": weights} if name == "xgboost" else {}
    search.fit(train[feature_cols], y, groups=groups, **fit_kw)
    return TrainedModel(
        name=name,
        pipeline=search.best_estimator_,
        encoder=enc,
        cv_macro_f1=float(search.best_score_),
        best_params=dict(search.best_params_),
        train_seconds=time.perf_counter() - t0,
        feature_cols=list(feature_cols),
    )
