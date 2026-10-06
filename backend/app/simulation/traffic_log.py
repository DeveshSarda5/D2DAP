"""Structured traffic representation (Phase 6).

:class:`TrafficLog` observes every packet whose fate is final (delivered or dropped)
and stores one flat record per packet reception attempt. It exports a pandas DataFrame
whose columns are documented in :data:`COLUMNS` and split into *observable* fields
(usable as IDS features) and *ground-truth* fields (evaluation only).
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from app.models.packet import GROUND_TRUTH_FIELDS, OBSERVABLE_FIELDS, Packet

COLUMNS: tuple[str, ...] = (
    "packet_id", "timestamp_ms", "delivered_ms", "src", "dst", "protocol", "size_bytes",
    "seq", "session_id", "ttl", "integrity_ok", "auth_ok", "auth_failure", "dropped_reason",
    "true_src", "label", "attack_id",
)  # fmt: skip


class TrafficLog:
    """Packet observer that accumulates records."""

    def __init__(self, keep_records: bool = True) -> None:
        self.keep_records = keep_records
        self.records: list[dict[str, Any]] = []
        self.count = 0
        self.bytes = 0

    def __call__(self, packet: Packet) -> None:
        self.count += 1
        self.bytes += packet.size_bytes
        if self.keep_records:
            rec = packet.to_record()
            self.records.append({c: rec.get(c) for c in COLUMNS})

    def to_frame(self) -> pd.DataFrame:
        return pd.DataFrame(self.records, columns=list(COLUMNS))

    def clear(self) -> None:
        self.records.clear()

    @staticmethod
    def observable(df: pd.DataFrame) -> pd.DataFrame:
        """Only the columns an IDS may use (ground truth removed)."""
        return df[[c for c in df.columns if c in OBSERVABLE_FIELDS]]

    @staticmethod
    def ground_truth(df: pd.DataFrame) -> pd.DataFrame:
        return df[["packet_id", *sorted(c for c in df.columns if c in GROUND_TRUTH_FIELDS)]]


def traffic_summary(df: pd.DataFrame, duration_s: float) -> pd.DataFrame:
    """Per-protocol packet count, rate, size statistics and delivery ratio."""
    if df.empty:
        return pd.DataFrame()
    g = df.groupby("protocol")
    out = pd.DataFrame(
        {
            "packets": g.size(),
            "rate_pps": g.size() / duration_s,
            "mean_size_b": g["size_bytes"].mean(),
            "std_size_b": g["size_bytes"].std(),
            "throughput_kbps": g["size_bytes"].sum() * 8 / 1000 / duration_s,
            "delivery_ratio": g["dropped_reason"].apply(lambda s: s.isna().mean()),
        }
    )
    return out.reset_index()


def rate_timeseries(df: pd.DataFrame, bin_ms: int = 1000) -> pd.DataFrame:
    """Packets per second per protocol in fixed bins (for traffic-profile figures)."""
    if df.empty:
        return pd.DataFrame()
    tmp = df.assign(t_bin=(df["timestamp_ms"] // bin_ms) * bin_ms / 1000.0)
    pivot = tmp.pivot_table(index="t_bin", columns="protocol", values="packet_id",
                            aggfunc="count", fill_value=0)  # fmt: skip
    return pivot * (1000 / bin_ms)
