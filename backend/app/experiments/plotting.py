"""Consistent, publication-style static figures (matplotlib, light surface).

Colour roles follow a validated categorical palette (fixed slot order, never cycled),
a reserved status palette for policy states, recessive grid/axes, thin marks,
and text in ink colours (never series colours). One y-axis per chart.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import matplotlib as mpl
from cycler import cycler

mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure

#: Categorical slots in fixed order (validated CVD-safe on adjacent pairs).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
#: Status colours: reserved for policy/health states, always paired with a text label.
STATUS = {
    "good": "#0ca30c",
    "warning": "#fab219",
    "serious": "#ec835a",
    "critical": "#d03b3b",
}
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
SEQ_BLUE = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]

_RC = {
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK_2,
    "axes.titlecolor": INK,
    "axes.titlesize": 12,
    "axes.titleweight": "bold",
    "axes.labelsize": 10,
    "axes.grid": True,
    "axes.axisbelow": True,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.prop_cycle": cycler(color=SERIES),
    "grid.color": GRID,
    "grid.linewidth": 0.6,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "xtick.labelcolor": INK_2,
    "ytick.labelcolor": INK_2,
    "legend.frameon": False,
    "legend.fontsize": 9,
    "lines.linewidth": 2.0,
    "lines.markersize": 6,
    "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"],
    "font.size": 10,
    "savefig.dpi": 200,
    "savefig.bbox": "tight",
}


@contextmanager
def figure(
    path: Path, *, nrows: int = 1, ncols: int = 1, size: tuple[float, float] = (7.0, 4.2)
) -> Iterator[tuple[Figure, list[Axes]]]:
    """Create a styled figure, yield ``(fig, axes_list)``, then save to ``path`` and close."""
    with mpl.rc_context(_RC):
        fig, axes = plt.subplots(nrows, ncols, figsize=size, squeeze=False)
        try:
            yield fig, [ax for row in axes for ax in row]
            fig.tight_layout()
            path.parent.mkdir(parents=True, exist_ok=True)
            fig.savefig(path)
        finally:
            plt.close(fig)


def bar_labels(ax: Axes, fmt: str = "{:.3g}") -> None:
    """Direct-label bar tops in secondary ink."""
    for container in ax.containers:
        ax.bar_label(container, fmt=fmt.format, fontsize=8, color=INK_2, padding=2)  # type: ignore[arg-type]


def note(fig: Figure, text: str) -> None:
    """Small provenance note under the plot (e.g. 'Simulation result, seed 42')."""
    fig.text(0.01, -0.02, text, fontsize=7.5, color=MUTED, ha="left", va="top")
