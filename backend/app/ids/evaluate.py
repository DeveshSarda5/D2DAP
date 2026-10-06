"""IDS evaluation (Phase 11): detection metrics, efficiency, detection latency.

Binary view: ``P(attack) = 1 - P(benign)`` from the multiclass model; threshold 0.5.
All numbers are computed on the held-out test split (runs never seen in training).
"""

from __future__ import annotations

import pickle
import time
import tracemalloc
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from app.ids.features import WINDOW_MS
from app.ids.models import TrainedModel
from app.models.enums import BENIGN_LABEL


@dataclass
class EvaluationResult:
    model: str
    metrics: dict[str, float]
    per_class: pd.DataFrame
    confusion: pd.DataFrame
    roc: dict[str, list[float]] = field(default_factory=dict)
    pr: dict[str, list[float]] = field(default_factory=dict)
    detection_latency: pd.DataFrame = field(default_factory=pd.DataFrame)
    p_attack: np.ndarray[Any, Any] = field(default_factory=lambda: np.zeros(0))


def attack_probability(model: TrainedModel, X: pd.DataFrame) -> np.ndarray[Any, Any]:
    proba = model.predict_proba(X)
    if BENIGN_LABEL not in model.classes:
        return np.ones(len(X))
    return 1.0 - proba[:, model.classes.index(BENIGN_LABEL)]


def _timing(model: TrainedModel, test: pd.DataFrame, n_single: int, seed: int) -> dict[str, float]:
    model.single_threaded()  # identical, deployment-realistic inference for every model
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(test), size=min(n_single, len(test)))
    singles = []
    for i in idx:
        row = test.iloc[[int(i)]]
        t0 = time.perf_counter_ns()
        model.predict_proba(row)
        singles.append((time.perf_counter_ns() - t0) / 1e6)
    cpu0, w0 = time.process_time_ns(), time.perf_counter_ns()
    reps = 5
    for _ in range(reps):
        model.predict_proba(test)
    wall = (time.perf_counter_ns() - w0) / 1e9 / reps
    cpu = (time.process_time_ns() - cpu0) / 1e9 / reps
    tracemalloc.start()
    model.predict_proba(test)
    peak_kb = tracemalloc.get_traced_memory()[1] / 1024
    tracemalloc.stop()
    return {
        "inference_ms_single_mean": float(np.mean(singles)),
        "inference_ms_single_p95": float(np.percentile(singles, 95)),
        "inference_ms_single_p99": float(np.percentile(singles, 99)),
        "batch_throughput_rows_per_s": len(test) / wall,
        "batch_cpu_us_per_row": cpu / len(test) * 1e6,
        "batch_inference_peak_kb": peak_kb,
        "model_size_kb": len(pickle.dumps(model.pipeline)) / 1024,
        "train_seconds": model.train_seconds,
    }


def detection_latency(test: pd.DataFrame, p_attack: np.ndarray[Any, Any], threshold: float = 0.5,
                      window_ms: int = WINDOW_MS) -> pd.DataFrame:  # fmt: skip
    """Per attack run: time from attack start to the end of the first detected window."""
    df = test.assign(p_attack=p_attack)
    rows = []
    for run_id, grp in df[df["scenario_kind"] != BENIGN_LABEL].groupby("run_id"):
        attack_rows = grp[grp["label"] != BENIGN_LABEL].sort_values("t_start_ms")
        if attack_rows.empty:
            continue
        start = int(grp["attack_start_ms"].iloc[0])
        hit = attack_rows[attack_rows["p_attack"] >= threshold]
        latency = float(hit["t_start_ms"].iloc[0] + window_ms - start) if len(hit) else np.nan
        rows.append({"run_id": run_id, "kind": grp["scenario_kind"].iloc[0],
                     "rate_pps": grp["rate_pps"].iloc[0], "detected": bool(len(hit)),
                     "latency_ms": latency,
                     "window_recall": float(len(hit) / len(attack_rows))})  # fmt: skip
    return pd.DataFrame(rows)


def evaluate(model: TrainedModel, test: pd.DataFrame, seed: int = 0, n_single: int = 300
             ) -> EvaluationResult:  # fmt: skip
    y_true = test["label"].astype(str).to_numpy()
    y_pred = model.predict(test).astype(str)
    labels = sorted(set(y_true) | set(model.classes))
    p_attack = attack_probability(model, test)
    y_bin = (y_true != BENIGN_LABEL).astype(int)
    pred_bin = (p_attack >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_bin, pred_bin, labels=[0, 1]).ravel()
    metrics: dict[str, float] = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision_macro": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "recall_macro": recall_score(y_true, y_pred, average="macro", zero_division=0),
        "f1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "precision_weighted": precision_score(y_true, y_pred, average="weighted", zero_division=0),
        "recall_weighted": recall_score(y_true, y_pred, average="weighted", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "binary_precision": precision_score(y_bin, pred_bin, zero_division=0),
        "binary_recall": recall_score(y_bin, pred_bin, zero_division=0),
        "binary_f1": f1_score(y_bin, pred_bin, zero_division=0),
        "fpr": fp / (fp + tn) if fp + tn else float("nan"),
        "fnr": fn / (fn + tp) if fn + tp else float("nan"),
        "cv_macro_f1": model.cv_macro_f1,
        "test_rows": float(len(test)),
    }
    roc: dict[str, list[float]] = {}
    pr: dict[str, list[float]] = {}
    if y_bin.min() != y_bin.max():  # ROC/PR only valid with both classes present
        metrics["roc_auc_binary"] = roc_auc_score(y_bin, p_attack)
        metrics["pr_auc_binary"] = average_precision_score(y_bin, p_attack)
        fpr_c, tpr_c, _ = roc_curve(y_bin, p_attack)
        prec_c, rec_c, _ = precision_recall_curve(y_bin, p_attack)
        roc = {"fpr": fpr_c.tolist(), "tpr": tpr_c.tolist()}
        pr = {"precision": prec_c.tolist(), "recall": rec_c.tolist()}
    present = sorted(set(y_true))
    if set(present) <= set(model.classes) and len(present) > 2:
        proba = model.predict_proba(test)
        cols = [model.classes.index(c) for c in present]
        sub = proba[:, cols]
        sub = sub / np.clip(sub.sum(axis=1, keepdims=True), 1e-12, None)
        metrics["roc_auc_ovr_macro"] = roc_auc_score(y_true, sub, multi_class="ovr",
                                                     average="macro", labels=present)  # fmt: skip
    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    per_class = pd.DataFrame(
        [{"class": c, "precision": report[c]["precision"], "recall": report[c]["recall"],
          "f1": report[c]["f1-score"], "support": int(report[c]["support"])} for c in labels]
    )  # fmt: skip
    cm = pd.DataFrame(confusion_matrix(y_true, y_pred, labels=labels), index=labels, columns=labels)
    metrics |= _timing(model, test, n_single, seed)
    lat = detection_latency(test, p_attack) if "attack_start_ms" in test.columns else pd.DataFrame()
    if not lat.empty:
        metrics["runs_detected_fraction"] = float(lat["detected"].mean())
        metrics["detection_latency_ms_median"] = float(lat["latency_ms"].median())
        metrics["detection_latency_ms_mean"] = float(lat["latency_ms"].mean())
    return EvaluationResult(model.name, {k: float(v) for k, v in metrics.items()}, per_class, cm,
                            roc, pr, lat, p_attack)  # fmt: skip
