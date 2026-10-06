"""Window-based flow features per claimed source (Phase 9).

Each sample is one ``(src, window)`` pair: the behaviour of a *claimed* source address
during a ``window_ms`` interval, as observed by all receivers (cooperative monitoring).

Only observable information is used:

* packet header fields (``OBSERVABLE_FIELDS`` of :mod:`app.models.packet`);
* the receiver's own verdicts (integrity / replay / unauthenticated / no-session /
  auth-failed), which a receiver knows because it computed them;
* the source's published role (system configuration, known to every member).

Never used: ground truth (``true_src``, ``label``, ``attack_id``), losses the receiver
cannot see (``channel_loss``, ``out_of_range``, ...), and policy drops (``policy:*``),
which would feed the framework's own decisions back into its detector.
"""

from __future__ import annotations

from collections.abc import Mapping

import numpy as np
import pandas as pd

from app.models.enums import BENIGN_LABEL

WINDOW_MS = 1000
UNOBSERVABLE_DROPS = frozenset({"channel_loss", "out_of_range", "no_such_receiver",
                                "receiver_inactive"})  # fmt: skip
RECEIVER_VERDICTS = frozenset({"integrity", "replay", "unauthenticated", "no_session",
                               "auth_failed"})  # fmt: skip
DATA = ("telemetry", "video", "command")

FEATURES: tuple[str, ...] = (
    "tx_count", "rx_count", "bytes_total", "size_mean", "size_std", "size_max",
    "unique_dst", "iat_mean_ms", "iat_std_ms",
    "frac_telemetry", "frac_video", "frac_command", "frac_heartbeat", "frac_auth",
    "auth_req_count", "auth_unique_dst", "auth_fail_count", "auth_accept_count",
    "unauth_data_count", "integrity_fail_count", "replay_reject_count", "no_session_count",
    "seq_dup_count", "seq_backjump_count", "cmd_count", "src_is_leader", "verified_count",
    "verified_cmd_count",
)  # fmt: skip
#: Packets of the security monitor itself (reports/notices) are not behaviour evidence.
MONITOR_PROTOCOLS = frozenset({"trust_report", "policy_notice"})
KEYS: tuple[str, ...] = ("src", "window", "t_start_ms")


def observable_receptions(packets: pd.DataFrame) -> pd.DataFrame:
    """Rows a receiver actually saw (drop reasons it cannot observe are removed)."""
    reason = packets["dropped_reason"].fillna("")
    keep = ~reason.isin(UNOBSERVABLE_DROPS)
    return packets.loc[keep].copy()


def _verdict(rx: pd.DataFrame, name: str) -> pd.Series:
    return rx["dropped_reason"].fillna("").eq(name).astype(int)


def extract_windows(
    packets: pd.DataFrame,
    roles: Mapping[str, str] | None = None,
    window_ms: int = WINDOW_MS,
    with_labels: bool = True,
) -> pd.DataFrame:
    """Return one feature row per ``(src, window)``; adds ``label`` if ``with_labels``."""
    cols = [*KEYS, *FEATURES] + (["label"] if with_labels else [])
    if packets.empty:
        return pd.DataFrame(columns=cols)
    rx = observable_receptions(packets)
    rx = rx[~rx["protocol"].isin(MONITOR_PROTOCOLS)]
    if rx.empty:
        return pd.DataFrame(columns=cols)
    rx["window"] = rx["timestamp_ms"] // window_ms
    rx["is_auth_req"] = rx["protocol"].eq("auth_request").astype(int)
    rx["auth_fail"] = rx["auth_ok"].eq(False).astype(int)
    rx["auth_accept"] = (rx["is_auth_req"].astype(bool) & rx["auth_ok"].eq(True)).astype(int)
    rx["integrity_fail"] = rx["integrity_ok"].eq(False).astype(int)
    # Cryptographically verified receptions: AEAD-verified data or a D2DAP-accepted M1/M2.
    rx["verified"] = (rx["integrity_ok"].eq(True) | rx["auth_ok"].eq(True)).astype(int)
    rx["verified_cmd"] = (rx["verified"].astype(bool) & rx["protocol"].eq("command")).astype(int)
    for name in ("replay", "unauthenticated", "no_session"):
        rx[f"v_{name}"] = _verdict(rx, name)
    rx_g = rx.groupby(["src", "window"], sort=True)
    agg = pd.DataFrame({
        "rx_count": rx_g.size(),
        "auth_fail_count": rx_g["auth_fail"].sum(),
        "auth_accept_count": rx_g["auth_accept"].sum(),
        "integrity_fail_count": rx_g["integrity_fail"].sum(),
        "replay_reject_count": rx_g["v_replay"].sum(),
        "unauth_data_count": rx_g["v_unauthenticated"].sum(),
        "no_session_count": rx_g["v_no_session"].sum(),
        "verified_count": rx_g["verified"].sum(),
        "verified_cmd_count": rx_g["verified_cmd"].sum(),
    })  # fmt: skip

    # Transmission-level statistics: one row per packet (broadcast copies share an id).
    tx = rx.sort_values(["timestamp_ms", "packet_id"]).drop_duplicates("packet_id")
    tx = tx.sort_values(["src", "timestamp_ms", "packet_id"])
    tx["iat"] = tx.groupby("src")["timestamp_ms"].diff()
    tx["seq_dup"] = tx.duplicated(["src", "seq"]).astype(int)
    tx["seq_backjump"] = (tx.groupby("src")["seq"].diff() < 0).astype(int)
    for proto in ("telemetry", "video", "command", "heartbeat"):
        tx[f"is_{proto}"] = tx["protocol"].eq(proto).astype(int)
    tx["is_auth"] = tx["protocol"].str.startswith("auth").astype(int)
    tx_g = tx.groupby(["src", "window"], sort=True)
    tx_count = tx_g.size()
    agg = agg.join(pd.DataFrame({
        "tx_count": tx_count,
        "bytes_total": tx_g["size_bytes"].sum(),
        "size_mean": tx_g["size_bytes"].mean(),
        "size_std": tx_g["size_bytes"].std().fillna(0.0),
        "size_max": tx_g["size_bytes"].max(),
        "unique_dst": tx_g["dst"].nunique(),
        "iat_mean_ms": tx_g["iat"].mean(),
        "iat_std_ms": tx_g["iat"].std(),
        "frac_telemetry": tx_g["is_telemetry"].sum() / tx_count,
        "frac_video": tx_g["is_video"].sum() / tx_count,
        "frac_command": tx_g["is_command"].sum() / tx_count,
        "frac_heartbeat": tx_g["is_heartbeat"].sum() / tx_count,
        "frac_auth": tx_g["is_auth"].sum() / tx_count,
        "auth_req_count": tx_g["is_auth_req"].sum(),
        "seq_dup_count": tx_g["seq_dup"].sum(),
        "seq_backjump_count": tx_g["seq_backjump"].sum(),
        "cmd_count": tx_g["is_command"].sum(),
    }), how="left")  # fmt: skip
    auth_tx = tx[tx["is_auth_req"] == 1]
    agg["auth_unique_dst"] = auth_tx.groupby(["src", "window"])["dst"].nunique()
    # A source with a single packet has no inter-arrival time: use the window length.
    agg["iat_mean_ms"] = agg["iat_mean_ms"].fillna(float(window_ms))
    agg["iat_std_ms"] = agg["iat_std_ms"].fillna(0.0)
    agg = agg.fillna(0.0).reset_index()
    role_map = dict(roles or {})
    agg["src_is_leader"] = agg["src"].map(lambda s: int(role_map.get(s) == "leader"))
    agg["t_start_ms"] = agg["window"] * window_ms
    if with_labels:
        attack = rx[rx["label"] != BENIGN_LABEL]
        if attack.empty:
            agg["label"] = BENIGN_LABEL
        else:
            mode = attack.groupby(["src", "window"])["label"].agg(
                lambda s: s.value_counts().idxmax()
            )
            agg = agg.merge(mode.rename("label").reset_index(), on=["src", "window"], how="left")
            agg["label"] = agg["label"].fillna(BENIGN_LABEL)
    for c in FEATURES:
        agg[c] = agg[c].astype(np.float64)
    return agg[cols]
