"""Traffic generation: periodic, Poisson and on/off burst sources plus behaviour profiles.

Normal swarm behaviour (defaults, all configurable):

* **Telemetry**: periodic (5 Hz) small packets from every drone to the leader
  (MAVLink-like position/attitude reports);
* **Heartbeat**: 1 Hz neighbour broadcast;
* **Video**: on/off bursts from camera-equipped drones (exponential ON/OFF periods);
* **Command**: Poisson control commands from the leader to workers (privileged).

Multi-hop routing is out of scope: a packet whose destination is out of range is
dropped by the channel (``out_of_range``); telemetry falls back to the nearest
neighbour as a relay abstraction.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol

import numpy as np
from pydantic import BaseModel, Field

from app.models.enums import BENIGN_LABEL, BROADCAST, DroneRole, PacketProtocol
from app.models.packet import Packet
from app.simulation.network import DroneNetwork


class TrafficConfig(BaseModel):
    """Normal-traffic profile parameters."""

    telemetry_interval_ms: int = Field(200, ge=10)
    telemetry_size: int = Field(120, ge=16)
    heartbeat_interval_ms: int = Field(1000, ge=50)
    heartbeat_size: int = Field(40, ge=16)
    video_fraction: float = Field(0.4, ge=0, le=1)
    video_on_mean_s: float = Field(4.0, gt=0)
    video_off_mean_s: float = Field(10.0, gt=0)
    video_rate_pps: float = Field(25.0, gt=0)
    video_size: int = Field(1100, ge=64)
    command_rate_per_s: float = Field(0.5, ge=0)
    command_size: int = Field(80, ge=16)
    size_jitter_frac: float = Field(0.1, ge=0, le=0.5)
    #: Extra seed-dependent heterogeneity: per-drone multiplicative rate factor ~ U[1-h, 1+h].
    rate_heterogeneity: float = Field(0.2, ge=0, le=0.9)


class TrafficSource(Protocol):
    """Anything that emits packets each tick."""

    def generate(self, now_ms: int, dt_ms: int) -> list[Packet]:
        """Return packets transmitted in ``(now_ms - dt_ms, now_ms]``."""
        ...


DestinationFn = Callable[[], str | None]


class PacketFactory:
    """Creates packets with unique ids and per-source sequence numbers."""

    def __init__(self, network: DroneNetwork) -> None:
        self._network = network
        self._seq: dict[str, int] = defaultdict(int)

    def make(
        self,
        t_ms: int,
        src: str,
        dst: str,
        protocol: PacketProtocol,
        size: int,
        *,
        true_src: str | None = None,
        label: str = BENIGN_LABEL,
        attack_id: str | None = None,
        payload: bytes | None = None,
    ) -> Packet:
        sender = true_src or src
        self._seq[sender] += 1
        return Packet(
            packet_id=self._network.next_packet_id(),
            timestamp_ms=t_ms,
            src=src,
            dst=dst,
            protocol=protocol,
            size_bytes=max(1, int(size)),
            seq=self._seq[sender],
            true_src=sender,
            label=label,
            attack_id=attack_id,
            payload=payload,
        )


def _jittered_size(rng: np.random.Generator, mean: int, frac: float) -> int:
    return max(16, int(rng.normal(mean, mean * frac))) if frac > 0 else mean


@dataclass(frozen=True)
class StreamSpec:
    """Identity of a packet stream: who sends what, to whom, and how large."""

    src: str
    dst_fn: DestinationFn
    protocol: PacketProtocol
    size: int
    size_jitter: float = 0.1


class _SpecSource:
    """Shared packet-emission logic for spec-based sources."""

    def __init__(self, factory: PacketFactory, spec: StreamSpec, rng: np.random.Generator) -> None:
        self._factory, self.spec, self._rng = factory, spec, rng

    @property
    def src(self) -> str:
        return self.spec.src

    def _emit(self, t_ms: int, out: list[Packet]) -> None:
        dst = self.spec.dst_fn()
        if dst is not None:
            size = _jittered_size(self._rng, self.spec.size, self.spec.size_jitter)
            out.append(self._factory.make(t_ms, self.spec.src, dst, self.spec.protocol, size))


class PeriodicSource(_SpecSource):
    """Emits one packet every ``interval_ms`` (with +-5 % phase jitter)."""

    def __init__(
        self, factory: PacketFactory, spec: StreamSpec, interval_ms: int, rng: np.random.Generator
    ) -> None:
        super().__init__(factory, spec, rng)
        self.interval_ms = interval_ms
        self._next_ms = int(rng.integers(0, interval_ms))

    def generate(self, now_ms: int, dt_ms: int) -> list[Packet]:
        out: list[Packet] = []
        window_start = now_ms - dt_ms
        if self._next_ms <= window_start:  # source was paused (drone inactive): no backlog
            missed = (window_start - self._next_ms) // self.interval_ms + 1
            self._next_ms += missed * self.interval_ms
        while self._next_ms <= now_ms:
            self._emit(self._next_ms, out)
            jitter = int(self._rng.integers(-self.interval_ms // 20, self.interval_ms // 20 + 1))
            self._next_ms += max(1, self.interval_ms + jitter)
        return out


class PoissonSource(_SpecSource):
    """Emits packets as a Poisson process with rate ``rate_per_s``."""

    def __init__(
        self, factory: PacketFactory, spec: StreamSpec, rate_per_s: float, rng: np.random.Generator
    ) -> None:
        super().__init__(factory, spec, rng)
        self.rate = rate_per_s

    def generate(self, now_ms: int, dt_ms: int) -> list[Packet]:
        out: list[Packet] = []
        if self.rate <= 0:
            return out
        n = int(self._rng.poisson(self.rate * dt_ms / 1000.0))
        for t in sorted(self._rng.integers(now_ms - dt_ms + 1, now_ms + 1, size=n).tolist()):
            self._emit(int(t), out)
        return out


class BurstSource:
    """On/off source: exponential ON and OFF periods; Poisson packets while ON."""

    def __init__(
        self,
        factory: PacketFactory,
        spec: StreamSpec,
        rng: np.random.Generator,
        *,
        rate_pps: float,
        on_mean_s: float,
        off_mean_s: float,
    ) -> None:
        self._inner = PoissonSource(factory, spec, rate_pps, rng)
        self._on_mean_ms, self._off_mean_ms = on_mean_s * 1000, off_mean_s * 1000
        self._rng = rng
        self.is_on = False
        self._switch_ms = int(rng.exponential(self._off_mean_ms))

    def generate(self, now_ms: int, dt_ms: int) -> list[Packet]:
        while now_ms >= self._switch_ms:
            self.is_on = not self.is_on
            mean = self._on_mean_ms if self.is_on else self._off_mean_ms
            self._switch_ms += max(1, int(self._rng.exponential(mean)))
        return self._inner.generate(now_ms, dt_ms) if self.is_on else []


# ---------------------------------------------------------------- destinations
def leader_or_nearest(network: DroneNetwork, src: str) -> DestinationFn:
    """Destination policy: the (nearest active) leader if in range, else nearest neighbour."""

    def choose() -> str | None:
        me = network.nodes[src]
        if not me.active:
            return None
        leaders = [
            d for d in network.active_nodes() if d.role is DroneRole.LEADER and d.drone_id != src
        ]
        in_range = [d for d in leaders if network.channel.in_range(me.distance_to(d))]
        if in_range:
            return min(in_range, key=me.distance_to).drone_id
        neigh = network.neighbors(src)
        return min(neigh, key=me.distance_to).drone_id if neigh else None

    return choose


def random_worker(network: DroneNetwork, src: str, rng: np.random.Generator) -> DestinationFn:
    """Destination policy: uniformly random in-range non-leader neighbour."""

    def choose() -> str | None:
        cands = sorted(d.drone_id for d in network.neighbors(src) if d.role is not DroneRole.LEADER)
        return cands[int(rng.integers(0, len(cands)))] if cands else None

    return choose


def broadcast() -> DestinationFn:
    return lambda: BROADCAST


def build_normal_profile(
    network: DroneNetwork,
    factory: PacketFactory,
    drone_id: str,
    cfg: TrafficConfig,
    rng: np.random.Generator,
) -> list[TrafficSource]:
    """Create the normal-behaviour traffic sources of one drone."""
    drone = network.get(drone_id)
    h = cfg.rate_heterogeneity
    factor = float(rng.uniform(1 - h, 1 + h))
    j = cfg.size_jitter_frac
    hb = StreamSpec(drone_id, broadcast(), PacketProtocol.HEARTBEAT, cfg.heartbeat_size, j)
    sources: list[TrafficSource] = [PeriodicSource(factory, hb, cfg.heartbeat_interval_ms, rng)]
    if drone.role is DroneRole.LEADER:
        workers = random_worker(network, drone_id, rng)
        cmd = StreamSpec(drone_id, workers, PacketProtocol.COMMAND, cfg.command_size, j)
        sources.append(PoissonSource(factory, cmd, cfg.command_rate_per_s * factor, rng))
        return sources
    to_leader = leader_or_nearest(network, drone_id)
    tel = StreamSpec(drone_id, to_leader, PacketProtocol.TELEMETRY, cfg.telemetry_size, j)
    interval = max(10, int(cfg.telemetry_interval_ms / factor))
    sources.append(PeriodicSource(factory, tel, interval, rng))
    if rng.random() < cfg.video_fraction:
        vid = StreamSpec(drone_id, to_leader, PacketProtocol.VIDEO, cfg.video_size, j)
        sources.append(
            BurstSource(
                factory,
                vid,
                rng,
                rate_pps=cfg.video_rate_pps * factor,
                on_mean_s=cfg.video_on_mean_s,
                off_mean_s=cfg.video_off_mean_s,
            )
        )
    return sources


class ErraticSource:
    """Abnormal (but not necessarily malicious) behaviour: high-rate packets to random peers.

    Used to exercise the simulator's abnormal-behaviour path; labelled attacks are built
    by :mod:`app.attacks`, which sets ground-truth labels.
    """

    def __init__(
        self,
        factory: PacketFactory,
        network: DroneNetwork,
        src: str,
        rate_pps: float,
        rng: np.random.Generator,
        *,
        label: str = BENIGN_LABEL,
    ) -> None:
        self._factory, self._network, self.src = factory, network, src
        self.rate, self._rng, self.label = rate_pps, rng, label

    def generate(self, now_ms: int, dt_ms: int) -> list[Packet]:
        peers = sorted(d.drone_id for d in self._network.neighbors(self.src))
        if not peers:
            return []
        n = int(self._rng.poisson(self.rate * dt_ms / 1000.0))
        out = []
        for _ in range(n):
            dst = peers[int(self._rng.integers(0, len(peers)))]
            size = int(self._rng.integers(40, 1400))
            proto = PacketProtocol.TELEMETRY
            out.append(self._factory.make(now_ms, self.src, dst, proto, size, label=self.label))
        return out


def flatten(sources: Iterable[TrafficSource], now_ms: int, dt_ms: int) -> list[Packet]:
    """Collect packets from many sources, ordered by transmission time."""
    packets = [p for s in sources for p in s.generate(now_ms, dt_ms)]
    packets.sort(key=lambda p: (p.timestamp_ms, p.packet_id))
    return packets
