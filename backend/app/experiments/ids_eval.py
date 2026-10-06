"""Phases 9-11: ML IDS pipeline, baseline models and full evaluation.

Pipeline: simulate dataset -> validate -> clean -> group split (by run) -> leakage
checks -> train 4 models (identical methodology) -> evaluate on held-out runs ->
robustness evaluations -> tables/figures -> save the operational model.

The operational model for the integrated framework is chosen by **cross-validation**
macro-F1 on the training split (not by test score).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap

from app.experiments.plotting import SEQ_BLUE, SERIES, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, REPO_ROOT, ExperimentRecorder
from app.ids import public
from app.ids.dataset import DatasetConfig, generate
from app.ids.evaluate import EvaluationResult, evaluate
from app.ids.features import FEATURES
from app.ids.models import MODEL_NAMES, TrainedModel, train_model
from app.ids.validation import clean, group_split, validate
from app.models.enums import BENIGN_LABEL

NAME = "ids"
DATA_DIR = REPO_ROOT / "data" / "generated"
TEST_FRACTION = 0.3
#: Bump whenever simulator/protocol behaviour changes, so cached datasets are regenerated
#: (v3: 256 CRPs, session index, verify-then-drop, sealed reports, sim-time decoupled
#: from wall-clock compute).
SIMULATOR_VERSION = 3


def dataset_path(cfg: DatasetConfig, seed: int) -> Path:
    # The feature list is part of the key: changing features never reuses stale data.
    key = [cfg.__dict__, seed, list(FEATURES), SIMULATOR_VERSION]
    digest = hashlib.sha256(json.dumps(key, default=str).encode()).hexdigest()
    return DATA_DIR / f"d2dsim_{digest[:10]}.csv.gz"


def _display(path: Path) -> str:
    """Repo-relative path when possible (portable manifests), else absolute."""
    try:
        return str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def load_or_generate(cfg: DatasetConfig, seed: int, log: Any = print) -> tuple[pd.DataFrame, Path]:
    path = dataset_path(cfg, seed)
    if path.exists():
        return pd.read_csv(path), path
    workers = max(1, min(6, (os.cpu_count() or 2) // 2))
    df = generate(cfg, base_seed=seed, progress=log, workers=workers)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return df, path


def _train_all(train: pd.DataFrame, seed: int, groups: pd.Series | None,
               feature_cols: list[str], categorical: list[str] | None = None
               ) -> list[TrainedModel]:  # fmt: skip
    return [train_model(m, train, feature_cols, seed=seed, groups=groups, categorical=categorical)
            for m in MODEL_NAMES]  # fmt: skip


def _metrics_row(r: EvaluationResult, split: str) -> dict[str, Any]:
    return {"model": r.model, "split": split, **r.metrics}


def run(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS,
        log: Any = print) -> Path:  # fmt: skip
    cfg = DatasetConfig.quick() if quick else DatasetConfig()
    rec = ExperimentRecorder(NAME, seed, {"dataset": cfg.__dict__, "test_fraction": TEST_FRACTION,
                                          "models": MODEL_NAMES, "features": FEATURES},
                             results_dir)  # fmt: skip
    df, data_path = load_or_generate(cfg, seed, log)
    feats = list(FEATURES)
    df = clean(df, feats)
    rec.save_json({"dataset_file": _display(data_path), "rows": len(df),
                   "runs": int(df.run_id.nunique())}, "dataset_info.json")  # fmt: skip
    dist = df["label"].value_counts().rename_axis("class").reset_index(name="windows")
    dist_path = rec.save_frame(dist, "class_distribution.csv")
    rec.save_table(dist, "class_distribution", [dist_path], "D2D-SIM class distribution (windows)")

    # ---- split + leakage checks (fail hard before any metric if leakage exists)
    train, test = group_split(df, TEST_FRACTION, seed)
    report = validate(train, test, feats)
    rec.save_json(report.as_dict(), "validation_report.json")

    # ---- train + evaluate
    models = _train_all(train, seed, train["run_id"], feats)
    results = [evaluate(m, test, seed) for m in models]
    rows = [_metrics_row(r, "test") for r in results]
    # Robustness 1: drop test windows whose exact feature vector occurs in training.
    keys_train = set(train[feats].round(9).apply(tuple, axis=1))
    test_unique = test[~test[feats].round(9).apply(tuple, axis=1).isin(keys_train)]
    rows += [_metrics_row(evaluate(m, test_unique, seed, n_single=50), "test_dedup")
             for m in models]  # fmt: skip
    # Robustness 2: generalisation to unseen low intensity (train high rate, test lowest).
    low = min(cfg.rates_pps)
    if len(cfg.rates_pps) > 1:
        gen_train = df[(df.rate_pps != low) | (df.scenario_kind == BENIGN_LABEL)]
        gen_train = gen_train[~gen_train.run_id.isin(test.run_id)]
        gen_test = test[(test.rate_pps == low) | (test.scenario_kind == BENIGN_LABEL)]
        gen_models = _train_all(gen_train, seed, gen_train["run_id"], feats)
        rows += [_metrics_row(evaluate(m, gen_test, seed, n_single=50), f"unseen_rate_{low:g}")
                 for m in gen_models]  # fmt: skip
    metrics = pd.DataFrame(rows)
    metrics_path = rec.save_frame(metrics, "metrics_all.csv", kind="processed")
    per_class = pd.concat([r.per_class.assign(model=r.model) for r in results])
    pc_path = rec.save_frame(per_class, "per_class.csv", kind="processed")
    lat = pd.concat([r.detection_latency.assign(model=r.model) for r in results])
    lat_path = rec.save_frame(lat, "detection_latency.csv", kind="processed")
    preds = test[["run_id", "src", "window", "label"]].copy()
    for r in results:
        preds[f"p_attack_{r.model}"] = r.p_attack
    preds_path = rec.save_frame(preds, "test_predictions.csv")
    for r in results:
        rec.save_frame(r.confusion.reset_index(names="true"), f"confusion_{r.model}.csv",
                       kind="processed")  # fmt: skip

    best = max(models, key=lambda m: m.cv_macro_f1)  # selection by CV, not by test
    model_dir = results_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(best, model_dir / "ids_operational.joblib")
    rec.save_json({"selected_model": best.name, "selection": "max CV macro-F1 on training split",
                   "cv_macro_f1": best.cv_macro_f1, "best_params": best.best_params,
                   "classes": best.classes, "features": best.feature_cols},
                  "operational_model.json")  # fmt: skip

    rep = _Report(rec, seed, results, best.name, metrics, metrics_path, per_class, pc_path,
                  lat, lat_path, preds_path)  # fmt: skip
    _tables(rep)
    for draw in (_fig_confusion, _fig_comparison, _fig_prf, _fig_roc, _fig_latency):
        draw(rep)
    public_status = _public_benchmark(rec, seed, log)
    return rec.finalize({"selected_model": best.name, "public_benchmark": public_status,
                         "leakage_group_overlap": report.group_overlap,
                         "cross_split_duplicates": report.cross_split_duplicates})  # fmt: skip


@dataclass(frozen=True)
class _Report:
    """Everything the IDS tables and figures are drawn from (with source paths)."""

    rec: ExperimentRecorder
    seed: int
    results: list[EvaluationResult]
    best: str
    metrics: pd.DataFrame
    metrics_path: Path
    per_class: pd.DataFrame
    pc_path: Path
    lat: pd.DataFrame
    lat_path: Path
    preds_path: Path

    @property
    def caption(self) -> str:
        return f"Our result on simulated data (D2D-SIM), held-out runs. Seed {self.seed}."

    @property
    def names(self) -> list[str]:
        return [r.model for r in self.results]

    @property
    def test_metrics(self) -> pd.DataFrame:
        return self.metrics[self.metrics.split == "test"].set_index("model").loc[self.names]


def _tables(r: _Report) -> None:
    test = r.metrics[r.metrics.split == "test"]
    t4 = test[["model", "accuracy", "precision_macro", "recall_macro", "f1_macro", "f1_weighted",
               "binary_f1", "fpr", "fnr", "roc_auc_binary", "pr_auc_binary", "roc_auc_ovr_macro",
               "inference_ms_single_mean", "batch_throughput_rows_per_s",
               "cv_macro_f1"]].round(4)  # fmt: skip
    r.rec.save_table(
        t4,
        "table4_models",
        [r.metrics_path],
        "Table 4: ML IDS comparison on held-out simulated runs (D2D-SIM)",
    )
    robust = r.metrics.pivot_table(index="model", columns="split", values="f1_macro").round(4)
    r.rec.save_table(
        robust.reset_index(),
        "robustness",
        [r.metrics_path],
        "Macro-F1 under robustness splits (dedup test; unseen low intensity)",
    )
    t5 = r.per_class[r.per_class.model == r.best][["class", "precision", "recall", "f1",
                                                    "support"]]  # fmt: skip
    r.rec.save_table(
        t5.round(4),
        "table5_per_attack",
        [r.pc_path],
        f"Table 5: per-attack performance of the operational model ({r.best})",
    )
    r.rec.save_table(
        r.per_class.round(4),
        "per_class_all_models",
        [r.pc_path],
        "Per-class precision/recall/F1/support for every model",
    )


def _fig_confusion(r: _Report) -> None:
    res = next(x for x in r.results if x.model == r.best)
    cm = res.confusion
    norm = cm.div(cm.sum(axis=1).replace(0, 1), axis=0)
    path = r.rec.figure_path("confusion_matrix", [r.preds_path], f"Confusion matrix ({r.best})")
    cmap = LinearSegmentedColormap.from_list("seq_blue", ["#fcfcfb", *SEQ_BLUE])
    with figure(path, size=(7.5, 6.2)) as (fig, (ax,)):
        grid = norm.to_numpy(dtype=float)
        im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=1)
        ax.set_xticks(range(len(cm)), cm.columns, rotation=45, ha="right")
        ax.set_yticks(range(len(cm)), cm.index)
        ax.grid(False)
        for i in range(len(cm)):
            for j in range(len(cm)):
                v = float(grid[i, j])
                if v >= 0.005:
                    ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=7,
                            color="#ffffff" if v > 0.6 else "#0b0b0b")  # fmt: skip
        ax.set_xlabel("Predicted class")
        ax.set_ylabel("True class")
        ax.set_title(f"Confusion matrix (row-normalised): {r.best}")
        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        note(fig, r.caption)


def _fig_comparison(r: _Report) -> None:
    test = r.test_metrics
    path = r.rec.figure_path("model_comparison", [r.metrics_path], "Model comparison")
    keys = ["accuracy", "f1_macro", "binary_f1", "roc_auc_binary"]
    with figure(path, size=(8, 4.2)) as (fig, (ax,)):
        x = np.arange(len(keys))
        w = 0.8 / len(r.names)
        for i, n in enumerate(r.names):
            vals = test[keys].to_numpy(dtype=float)[i]
            ax.bar(x + i * w - 0.4 + w / 2, vals, w * 0.92, color=SERIES[i], label=n)
        ax.set_xticks(x, ["Accuracy", "Macro F1", "Binary F1", "ROC-AUC (binary)"])
        ax.set_ylim(min(0.5, float(test[keys].min().min()) - 0.05), 1.0)
        ax.set_ylabel("Score")
        ax.set_title("IDS model comparison (identical pipeline)")
        ax.legend(ncols=2, loc="lower right")
        note(fig, r.caption)


def _fig_prf(r: _Report) -> None:
    test = r.test_metrics
    path = r.rec.figure_path("precision_recall_f1", [r.metrics_path], "Macro P/R/F1 per model")
    with figure(path, size=(7.5, 4)) as (fig, (ax,)):
        keys = ["precision_macro", "recall_macro", "f1_macro"]
        x = np.arange(len(r.names))
        for i, k in enumerate(keys):
            ax.bar(x + i * 0.27 - 0.27, test[k].to_numpy(dtype=float), 0.25, color=SERIES[i],
                   label=k.replace("_macro", "").capitalize())  # fmt: skip
        ax.set_xticks(x, r.names)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Macro-averaged score")
        ax.set_title("Precision, recall and F1 (macro over classes)")
        ax.legend(ncols=3, loc="lower center")
        note(fig, r.caption)


def _fig_roc(r: _Report) -> None:
    path = r.rec.figure_path("roc", [r.preds_path], "Binary ROC curves")
    with figure(path, size=(5.8, 5)) as (fig, (ax,)):
        for i, res in enumerate(r.results):
            if res.roc:
                auc = res.metrics.get("roc_auc_binary", float("nan"))
                ax.plot(res.roc["fpr"], res.roc["tpr"], color=SERIES[i],
                        label=f"{res.model} (AUC {auc:.3f})")  # fmt: skip
        ax.plot([0, 1], [0, 1], color="#c3c2b7", linewidth=1, linestyle="--")
        ax.set_xlabel("False positive rate")
        ax.set_ylabel("True positive rate")
        ax.set_title("ROC: attack vs benign windows")
        ax.legend(loc="lower right")
        note(fig, r.caption)


def _fig_latency(r: _Report) -> None:
    path = r.rec.figure_path("detection_latency", [r.lat_path], "Detection latency per attack")
    sub = r.lat[(r.lat.model == r.best) & r.lat.detected]
    kinds = sorted(sub.kind.unique())
    with figure(path, size=(8, 4.2)) as (fig, (ax,)):
        if kinds:
            data = [sub.loc[sub.kind == k, "latency_ms"].to_numpy() / 1000 for k in kinds]
            bp = ax.boxplot(data, patch_artist=True, widths=0.5,
                            medianprops={"color": "#52514e"})  # fmt: skip
            for p in bp["boxes"]:
                p.set_facecolor(SERIES[0])
                p.set_alpha(0.55)
            ax.set_xticks(range(1, len(kinds) + 1), kinds, rotation=30, ha="right")
        ax.set_ylabel("Attack start -> first detected window end (s)")
        ax.set_title(f"IDS detection latency per attack type ({r.best}, 1 s windows)")
        note(fig, r.caption + " Undetected runs excluded (see table).")


def _public_benchmark(rec: ExperimentRecorder, seed: int, log: Any) -> str:
    if not public.available():
        rec.save_json({"status": "not run", "reason": "NSL-KDD files not present in "
                       "data/raw/nsl-kdd (official download requires registration)"},
                      "public_benchmark.json")  # fmt: skip
        return "not run (dataset unavailable)"
    train, test = public.load()
    feats = list(public.NSL_FEATURES)
    report = validate(train, test, feats, group_col="__none__")
    rec.save_json(report.as_dict(), "public_validation_report.json")
    models = [train_model(m, train, feats, seed=seed, categorical=public.NSL_CATEGORICAL)
              for m in MODEL_NAMES]  # fmt: skip
    rows = []
    for m in models:
        r = evaluate(m, test, seed, n_single=100)
        rows.append({"model": m.name, **r.metrics})
        rec.save_frame(r.per_class.assign(model=m.name), f"public_per_class_{m.name}.csv",
                       kind="processed")  # fmt: skip
    df = pd.DataFrame(rows)
    path = rec.save_frame(df, "public_metrics.csv", kind="processed")
    rec.save_table(df[["model", "accuracy", "f1_macro", "f1_weighted", "binary_f1", "fpr",
                       "roc_auc_binary"]].round(4), "public_nslkdd", [path],
                   "Public benchmark: NSL-KDD official split (KDDTrain+ -> KDDTest+)")  # fmt: skip
    log("public benchmark done")
    return "run"
