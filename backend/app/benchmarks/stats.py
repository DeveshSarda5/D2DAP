"""Descriptive statistics for benchmark samples."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np


def summarize(samples: Sequence[float], prefix: str = "") -> dict[str, float]:
    """Mean, median, std, min, max, P95, P99 and a 95 % CI half-width of the mean."""
    arr = np.asarray(samples, dtype=np.float64)
    if arr.size == 0:
        raise ValueError("no samples")
    std = float(arr.std(ddof=1)) if arr.size > 1 else 0.0
    out = {
        "n": float(arr.size),
        "mean": float(arr.mean()),
        "median": float(np.median(arr)),
        "std": std,
        "min": float(arr.min()),
        "max": float(arr.max()),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "ci95": 1.96 * std / float(np.sqrt(arr.size)),
    }
    return {f"{prefix}{k}": v for k, v in out.items()}
