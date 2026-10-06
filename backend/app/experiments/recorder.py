"""Experiment recording: every run saves seed, config, environment, raw data and metrics.

Layout produced for an experiment ``name``::

    results/raw/<name>/manifest.json   # seed, config, environment, git commit, file list
    results/raw/<name>/*.csv|*.json    # raw measurements
    results/raw/<name>/run.log.jsonl   # structured log of the run
    results/processed/<name>/...       # aggregated metrics
    results/tables/<name>_*.csv|md     # report tables
    results/figures/<name>_*.png       # figures, each with a .source.json sidecar

The sidecar of every figure/table names the raw/processed files it was computed from,
so each result in the report is traceable to data.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RESULTS = REPO_ROOT / "results"

_TRACKED_PACKAGES = (
    "numpy",
    "pandas",
    "scikit-learn",
    "xgboost",
    "ecdsa",
    "cryptography",
    "pydantic",
    "matplotlib",
)


def git_commit() -> str:
    """Current git commit hash (or ``"unknown"``)."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - git resolved from PATH on purpose
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def environment_info() -> dict[str, Any]:
    """Software/hardware context of the run (no hardware *results* are implied)."""
    versions: dict[str, str | None] = {}
    for pkg in _TRACKED_PACKAGES:
        try:
            versions[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            versions[pkg] = None
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "packages": versions,
        "git_commit": git_commit(),
    }


def _jsonable(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, Mapping):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj


@dataclass
class ExperimentRecorder:
    """Collects and writes all artefacts of one experiment."""

    name: str
    seed: int
    config: Mapping[str, Any] | Any
    results_dir: Path = DEFAULT_RESULTS
    started: float = field(default_factory=time.time)
    files: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.raw_dir = self.results_dir / "raw" / self.name
        self.processed_dir = self.results_dir / "processed" / self.name
        self.tables_dir = self.results_dir / "tables"
        self.figures_dir = self.results_dir / "figures"
        for d in (self.raw_dir, self.processed_dir, self.tables_dir, self.figures_dir):
            d.mkdir(parents=True, exist_ok=True)

    @property
    def log_file(self) -> Path:
        return self.raw_dir / "run.log.jsonl"

    def _track(self, path: Path) -> Path:
        self.files.append(str(path.relative_to(self.results_dir)).replace("\\", "/"))
        return path

    def save_frame(self, df: pd.DataFrame, filename: str, kind: str = "raw") -> Path:
        """Save a DataFrame as CSV under ``raw`` or ``processed``."""
        base = self.raw_dir if kind == "raw" else self.processed_dir
        path = base / filename
        df.to_csv(path, index=False)
        return self._track(path)

    def save_json(self, data: Any, filename: str, kind: str = "raw") -> Path:
        base = self.raw_dir if kind == "raw" else self.processed_dir
        path = base / filename
        path.write_text(json.dumps(_jsonable(data), indent=2, default=str), encoding="utf-8")
        return self._track(path)

    def save_table(
        self, df: pd.DataFrame, filename: str, sources: Sequence[Path], caption: str = ""
    ) -> Path:
        """Save a report table as CSV + Markdown with a provenance sidecar."""
        stem = f"{self.name}_{filename}"
        csv_path = self.tables_dir / f"{stem}.csv"
        df.to_csv(csv_path, index=False)
        md = (f"**{caption}**\n\n" if caption else "") + df.to_markdown(index=False)
        (self.tables_dir / f"{stem}.md").write_text(md + "\n", encoding="utf-8")
        self._write_sidecar(self.tables_dir / f"{stem}.source.json", sources, caption)
        return self._track(csv_path)

    def figure_path(self, filename: str, sources: Sequence[Path], caption: str = "") -> Path:
        """Return the path for a figure and write its provenance sidecar."""
        stem = f"{self.name}_{filename}"
        self._write_sidecar(self.figures_dir / f"{stem}.source.json", sources, caption)
        return self._track(self.figures_dir / f"{stem}.png")

    def _write_sidecar(self, path: Path, sources: Sequence[Path], caption: str) -> None:
        rel = [str(Path(s).resolve().relative_to(self.results_dir.resolve())) for s in sources]
        payload = {
            "experiment": self.name,
            "seed": self.seed,
            "caption": caption,
            "sources": [r.replace("\\", "/") for r in rel],
            "git_commit": git_commit(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def finalize(self, metrics: Mapping[str, Any] | None = None) -> Path:
        """Write ``manifest.json`` (seed, config, environment, metrics, files)."""
        manifest = {
            "experiment": self.name,
            "seed": self.seed,
            "config": _jsonable(self.config),
            "environment": environment_info(),
            "started_unix": self.started,
            "duration_s": round(time.time() - self.started, 3),
            "metrics": _jsonable(metrics or {}),
            "files": sorted(set(self.files)),
            "result_type": "Our Experimental Result (software simulation on the machine above)",
        }
        path = self.raw_dir / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        return path
