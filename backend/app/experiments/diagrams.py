"""Phase 22 diagrams: system architecture, D2DAP sequence, topology, STRIDE threat model.

Architecture, sequence and STRIDE figures are *conceptual diagrams* of the implemented
system (labelled as such). The topology figure is drawn from a real simulation snapshot.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from matplotlib.axes import Axes
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Patch

from app.core.rng import RandomStreams
from app.experiments.plotting import INK, INK_2, MUTED, SERIES, figure, note
from app.experiments.recorder import DEFAULT_RESULTS, ExperimentRecorder
from app.models.enums import DroneRole
from app.simulation.config import SimulationConfig
from app.simulation.engine import SimulationEngine

NAME = "diagrams"
EXISTING = "#e1e0d9"  # existing research (paper components)
IMPLEMENTED = "#cde2fb"  # our implementation
CONTRIBUTION = "#f8c9a8"  # our proposed contribution
Rect = tuple[float, float, float, float]


def _box(ax: Axes, rect: Rect, text: str, color: str, *, fontsize: float = 8.5) -> None:
    x, y, w, h = rect
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                facecolor=color, edgecolor=INK_2, linewidth=0.8))  # fmt: skip
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fontsize, color=INK)


def _arrow(ax: Axes, a: tuple[float, float], b: tuple[float, float], *, style: str = "-|>",
           color: str = INK_2, text: str = "", text_offset: float = 0.08) -> None:  # fmt: skip
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle=style, mutation_scale=10, color=color,
                                 linewidth=1.0))  # fmt: skip
    if text:
        ax.text((a[0] + b[0]) / 2, (a[1] + b[1]) / 2 + text_offset, text, ha="center",
                fontsize=7, color=color)  # fmt: skip


def architecture(rec: ExperimentRecorder) -> None:
    path = rec.figure_path("architecture", [], "System architecture (conceptual)")
    with figure(path, size=(11, 6.2)) as (fig, (ax,)):
        ax.set_xlim(0, 11)
        ax.set_ylim(0, 6.2)
        ax.axis("off")
        top = [
            ("Drone swarm simulator\n(mobility, channel,\ntraffic sources)", IMPLEMENTED),
            ("D2DAP authentication\n(software PUF, ECC,\nShamir, MAKA)", EXISTING),
            ("Authenticated data plane\n(AES-GCM sessions,\nreplay window)", IMPLEMENTED),
            ("Window features\n(observable only)", IMPLEMENTED),
            ("ML IDS\nP(attack), class", EXISTING),
        ]
        for i, (text, color) in enumerate(top):
            _box(ax, (0.3 + 2.1 * i, 4.6, 1.9, 1.1), text, color)
            if i:
                _arrow(ax, (0.3 + 2.1 * i - 0.2, 5.15), (0.3 + 2.1 * i, 5.15))
        attack_text = "Attack simulator\n(10 STRIDE-mapped\nattacks on real packets)"
        _box(ax, (0.3, 2.5, 2.1, 1.2), attack_text, IMPLEMENTED)
        _arrow(ax, (2.4, 3.6), (5.0, 4.6), text="attack traffic", text_offset=-0.25)
        _box(ax, (7.6, 2.5, 3.0, 1.2), "Trust engine (ours)\nattribution-aware decayed Beta\n"
             "auth + ML + verdicts + anomaly", CONTRIBUTION)  # fmt: skip
        _arrow(ax, (9.6, 4.6), (9.4, 3.7), text="P(attack)")
        _arrow(ax, (4.1, 4.6), (7.6, 3.4), color=SERIES[1], text="AuthEvents")
        _box(ax, (7.6, 0.5, 3.0, 1.3), "Adaptive policy engine (ours)\nhysteresis + hard rules\n"
             "+ explanations", CONTRIBUTION)  # fmt: skip
        _arrow(ax, (9.1, 2.5), (9.1, 1.8), text="trust")
        actions = ["CONTINUE", "MONITOR", "RESTRICT", "RE-AUTHENTICATE", "QUARANTINE"]
        for i, a in enumerate(actions):
            _box(ax, (0.3 + i * 1.4, 0.75, 1.3, 0.6), a, CONTRIBUTION, fontsize=7.2)
        _arrow(ax, (7.6, 1.05), (7.22, 1.05))
        _arrow(ax, (5.0, 1.35), (2.9, 4.6), color=SERIES[1], text="forced MAKA",
               text_offset=-0.4)  # fmt: skip
        ax.legend(handles=[Patch(color=EXISTING, label="Existing research (D2DAP paper, ML-IDS)"),
                           Patch(color=IMPLEMENTED, label="Our implementation"),
                           Patch(color=CONTRIBUTION, label="Our proposed contribution")],
                  loc="upper center", bbox_to_anchor=(0.5, 0.02), ncols=3, fontsize=8)  # fmt: skip
        ax.set_title("Adaptive trust-aware drone security framework", fontsize=12)
        note(fig, "Conceptual diagram of the implemented software system.")


SEQUENCE_STEPS = (
    ("CS", "CS", "Setup: q, E, P, F(x)=A+Bx, RL={}, H, Enc"),
    ("CS", "Di", "Registration: ID_i, C_i (secure channel)"),
    ("Di", "CS", "a_ik = H(PUF(C_ik)||ID_i), Y_i"),
    ("CS", "Di", "b_ik = F(a_ik), V_i = H(A||ID_i)"),
    ("Di", "Dj", "M1 = {CM=Enc_K(a_ik||b_ik||T_i), s1, s2}"),
    ("Dj", "Dj", "freshness, VerifySign, RL, reconstruct A, V_j"),
    ("Dj", "CS", "RL broadcast H(a_ik||a_jk)"),
    ("Dj", "Di", "M2 = {DM=Enc_K(a_jk||b_jk||T_j), s3, s4}"),
    ("Di", "Di", "freshness, RL, A, V_i, VerifySign; SK=H(a_ik||a_jk||T_i||T_j)"),
)


def sequence(rec: ExperimentRecorder) -> None:
    path = rec.figure_path("d2dap_sequence", [], "D2DAP sequence (conceptual)")
    lanes = {"Di": (1.5, "Drone D_i"), "CS": (5.0, "Control Server CS"), "Dj": (8.5, "Drone D_j")}
    with figure(path, size=(10, 6)) as (fig, (ax,)):
        ax.set_xlim(0, 10)
        ax.set_ylim(0, len(SEQUENCE_STEPS) + 1.5)
        ax.axis("off")
        top = len(SEQUENCE_STEPS) + 0.8
        for x, name in lanes.values():
            _box(ax, (x - 1.0, top, 2.0, 0.55), name, EXISTING)
            ax.plot([x, x], [0.2, top], color=MUTED, linewidth=0.8, linestyle="--")
        for i, (a, b, text) in enumerate(SEQUENCE_STEPS):
            y = top - 0.6 - i * 0.95
            xa, xb = lanes[a][0], lanes[b][0]
            if a == b:
                ax.text(xa + (0.1 if xa < 8 else -0.1), y, f"[{text}]", fontsize=7.5,
                        color=INK_2, va="center", ha="left" if xa < 8 else "right")  # fmt: skip
            else:
                _arrow(ax, (xa, y), (xb, y), color=SERIES[0] if text.startswith("M") else INK_2)
                ax.text((xa + xb) / 2, y + 0.12, text, ha="center", fontsize=7.5, color=INK)
        ax.set_title("D2DAP: Setup, Registration and MAKA (Parai et al., 2026)", fontsize=12)
        note(fig, "Conceptual diagram of the protocol as implemented "
                  "(see docs/d2dap-implementation-mapping.md).")  # fmt: skip


def topology(rec: ExperimentRecorder, seed: int) -> None:
    eng = SimulationEngine(SimulationConfig(num_drones=12), RandomStreams(seed))
    eng.create_swarm()
    eng.run(20_000)
    edges = eng.network.topology()
    nodes = pd.DataFrame([{"id": d.drone_id, "role": d.role.value, "x": d.position[0],
                           "y": d.position[1]} for d in eng.network.active_nodes()])  # fmt: skip
    src = rec.save_frame(nodes, "topology_nodes.csv")
    rec.save_frame(pd.DataFrame(edges, columns=["a", "b", "distance_m"]), "topology_edges.csv")
    path = rec.figure_path("topology", [src], "Drone network topology snapshot")
    xs, ys = nodes["x"].to_numpy(dtype=float), nodes["y"].to_numpy(dtype=float)
    pos = {str(i): (float(x), float(y)) for i, x, y in zip(nodes["id"], xs, ys, strict=True)}
    with figure(path, size=(6.5, 6)) as (fig, (ax,)):
        for a, b, _ in edges:
            ax.plot([pos[a][0], pos[b][0]], [pos[a][1], pos[b][1]], color="#c3c2b7",
                    linewidth=0.8, zorder=1)  # fmt: skip
        colors = {DroneRole.LEADER.value: SERIES[1], DroneRole.RELAY.value: SERIES[2],
                  DroneRole.WORKER.value: SERIES[0]}  # fmt: skip
        for role, color in colors.items():
            sub = nodes[nodes.role == role]
            ax.scatter(sub.x, sub.y, s=120, color=color, edgecolor="#fcfcfb", linewidth=1.5,
                       label=role, zorder=2)  # fmt: skip
        for node_id, xy in pos.items():
            ax.annotate(node_id, xy, xytext=(6, 6), textcoords="offset points", fontsize=8,
                        color=INK_2)  # fmt: skip
        ax.set_xlabel("x (m)")
        ax.set_ylabel("y (m)")
        ax.set_aspect("equal")
        ax.set_title(f"Swarm topology at t=20 s ({len(edges)} links, range 250 m)")
        ax.legend(title="Role")
        note(fig, f"Our simulation snapshot, 12 drones, seed {seed}.")


STRIDE_THREATS = (
    ("S", "Spoofing / replay\n/ clone", "spoofing, replay,\nimpersonation"),
    ("T", "Tampering\nin transit", "tampering"),
    ("R", "Repudiation", "analysis: signatures\nvs AEAD"),
    ("I", "Information\ndisclosure", "eavesdropping,\nabnormal (exfil)"),
    ("D", "Denial of\nservice", "dos (auth flood),\nflooding"),
    ("E", "Elevation of\nprivilege", "unauthorized_access,\nprivilege_escalation"),
)


def stride_model(rec: ExperimentRecorder) -> None:
    path = rec.figure_path("stride_threat_model", [], "STRIDE threat model (conceptual)")
    with figure(path, size=(10, 5.4)) as (fig, (ax,)):
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 6)
        ax.axis("off")
        zone = FancyBboxPatch((0.2, 3.2), 9.6, 2.5, boxstyle="round,pad=0.02",
                              facecolor="#f9f9f7", edgecolor=MUTED, linestyle="--")  # fmt: skip
        ax.add_patch(zone)
        ax.text(5, 5.5, "untrusted zone (public D2D wireless channel)", ha="center", fontsize=8,
                color=MUTED)  # fmt: skip
        _box(ax, (0.6, 3.7, 2.0, 1.2), "Drone D_i\n(trusted boundary)", IMPLEMENTED)
        _box(ax, (7.4, 3.7, 2.0, 1.2), "Drone D_j\n(trusted boundary)", IMPLEMENTED)
        _arrow(ax, (2.6, 4.3), (7.4, 4.3), style="<|-|>", text="D2DAP MAKA + AEAD sessions")
        for i, (letter, name, attacks) in enumerate(STRIDE_THREATS):
            x = 0.25 + i * 1.6
            _box(ax, (x, 0.5, 1.5, 2.2), f"{letter}\n{name}\n\nsimulated:\n{attacks}", EXISTING,
                 fontsize=6.8)  # fmt: skip
            _arrow(ax, (x + 0.75, 2.7), (5.0, 3.95), color=MUTED)
        ax.set_title("STRIDE threat model of D2D communication (after D2DAP Table II)",
                     fontsize=12)  # fmt: skip
        note(fig, "Conceptual diagram; each threat is evaluated by simulated attacks (Phase 8).")


def run(seed: int = 42, quick: bool = False, results_dir: Path = DEFAULT_RESULTS) -> Path:
    rec = ExperimentRecorder(NAME, seed, {"kind": "diagrams"}, results_dir)
    architecture(rec)
    sequence(rec)
    topology(rec, seed)
    stride_model(rec)
    return rec.finalize()
