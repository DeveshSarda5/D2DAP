"""Abstract wireless channel: range, latency, loss.

Model (software abstraction, not a radio simulation):

* reachable iff Euclidean distance <= ``comm_range_m``;
* latency = base + transmission time (size / bandwidth) + |N(0, jitter)|;
* loss probability = base_loss + edge_loss * (d / range)^4 (grows near range edge).
"""

from __future__ import annotations

import numpy as np

from app.simulation.config import ChannelConfig


class WirelessChannel:
    """Stateless channel model with its own random stream."""

    def __init__(self, cfg: ChannelConfig, rng: np.random.Generator) -> None:
        self.cfg = cfg
        self._rng = rng

    def in_range(self, distance_m: float) -> bool:
        return distance_m <= self.cfg.comm_range_m

    def loss_probability(self, distance_m: float) -> float:
        ratio = min(distance_m / self.cfg.comm_range_m, 1.0)
        return min(1.0, self.cfg.base_loss + self.cfg.edge_loss * ratio**4)

    def is_lost(self, distance_m: float) -> bool:
        return bool(self._rng.random() < self.loss_probability(distance_m))

    def latency_ms(self, size_bytes: int) -> int:
        tx_ms = size_bytes * 8 / (self.cfg.bandwidth_mbps * 1e6) * 1000
        jitter = (
            abs(float(self._rng.normal(0.0, self.cfg.jitter_ms))) if self.cfg.jitter_ms else 0.0
        )
        return max(1, round(self.cfg.base_latency_ms + tx_ms + jitter))
