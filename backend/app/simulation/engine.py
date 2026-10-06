"""Discrete-time simulation engine.

One :meth:`SimulationEngine.step` = one tick (``tick_ms`` of virtual time):

1. advance the clock;
2. move every active node (mobility) and update its battery model;
3. collect packets from all traffic sources of active nodes and transmit them;
4. deliver every packet whose arrival time has been reached;
5. invoke tick hooks (IDS windows, trust updates, policy, dashboard snapshots).

Everything random draws from named streams of :class:`RandomStreams`, so a run is a
pure function of (configuration, seed).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import numpy as np

from app.core.clock import SimulationClock
from app.core.errors import SimulationError
from app.core.logging import get_logger
from app.core.rng import RandomStreams
from app.models.enums import DroneRole
from app.models.packet import Packet
from app.simulation.channel import WirelessChannel
from app.simulation.config import SimulationConfig
from app.simulation.drone import Drone, Vec3
from app.simulation.mobility import make_mobility, random_position
from app.simulation.network import DroneNetwork
from app.simulation.traffic import (
    PacketFactory,
    TrafficConfig,
    TrafficSource,
    build_normal_profile,
)

log = get_logger(__name__)

TickHook = Callable[[int], None]
#: Optional hook that can transform/seal a packet before transmission (secure transport).
SendHook = Callable[[Packet], Packet | None]


@dataclass
class TickStats:
    t_ms: int
    sent: int
    delivered: int
    active_nodes: int


class SimulationEngine:
    """Owns the clock, network, mobility, traffic sources and the tick loop."""

    def __init__(
        self,
        config: SimulationConfig,
        streams: RandomStreams,
        traffic: TrafficConfig | None = None,
        clock: SimulationClock | None = None,
    ) -> None:
        self.config = config
        self.streams = streams
        self.traffic_config = traffic or TrafficConfig()
        self.clock = clock or SimulationClock()
        channel = WirelessChannel(config.channel, streams.numpy("channel"))
        self.network = DroneNetwork(channel, config.history_size)
        self.factory = PacketFactory(self.network)
        self.mobility = make_mobility(config.area, config.mobility, streams.numpy("mobility"))
        self._sources: dict[str, list[TrafficSource]] = {}
        self._tick_hooks: list[TickHook] = []
        self._send_hook: SendHook | None = None
        self.tick_count = 0

    # ------------------------------------------------------------- nodes
    def add_drone(
        self,
        drone_id: str,
        role: DroneRole = DroneRole.WORKER,
        position: Vec3 | None = None,
        with_normal_traffic: bool = True,
    ) -> Drone:
        """Create and register a drone (inactive until :meth:`join`)."""
        rng = self.streams.numpy(f"placement:{drone_id}")
        pos = position if position is not None else random_position(self.config.area, rng)
        drone = self.network.register(Drone(drone_id=drone_id, role=role, position=pos.copy()))
        if with_normal_traffic:
            self._sources[drone_id] = build_normal_profile(
                self.network,
                self.factory,
                drone_id,
                self.traffic_config,
                self.streams.numpy(f"traffic:{drone_id}"),
            )
        else:
            self._sources[drone_id] = []
        return drone

    def create_swarm(self, prefix: str = "D") -> list[Drone]:
        """Create ``num_drones`` drones (leaders first, then relays, then workers) and join them."""
        n = self.config.num_drones
        n_relay = round((n - self.config.leader_count) * self.config.relay_fraction)
        drones = []
        for i in range(n):
            if i < self.config.leader_count:
                role = DroneRole.LEADER
            elif i < self.config.leader_count + n_relay:
                role = DroneRole.RELAY
            else:
                role = DroneRole.WORKER
            drones.append(self.add_drone(f"{prefix}{i + 1}", role))
        for d in drones:
            self.join(d.drone_id)
        log.info("swarm.created", drones=n, relays=n_relay, leaders=self.config.leader_count)
        return drones

    def join(self, drone_id: str) -> None:
        self.network.join(drone_id)
        log.debug("drone.join", drone=drone_id, t_ms=self.clock.now_ms)

    def leave(self, drone_id: str) -> None:
        self.network.leave(drone_id)
        log.debug("drone.leave", drone=drone_id, t_ms=self.clock.now_ms)

    def add_source(self, drone_id: str, source: TrafficSource) -> None:
        """Attach an extra traffic source (e.g. an attack) to a node."""
        if drone_id not in self.network.nodes:
            raise SimulationError(f"unknown node {drone_id}")
        self._sources.setdefault(drone_id, []).append(source)

    def remove_source(self, drone_id: str, source: TrafficSource) -> None:
        self._sources[drone_id].remove(source)

    # ------------------------------------------------------------- hooks
    def add_tick_hook(self, hook: TickHook) -> None:
        self._tick_hooks.append(hook)

    def set_send_hook(self, hook: SendHook | None) -> None:
        self._send_hook = hook

    # ------------------------------------------------------------- loop
    def _update_battery(self, drone: Drone, moved_m: float, dt_s: float, tx_bytes: int) -> None:
        b = self.config.battery
        drain = (
            b.hover_pct_per_s * dt_s
            + b.move_pct_per_m * moved_m
            + b.tx_pct_per_kb * (tx_bytes / 1024)
        )
        drone.battery_level = max(0.0, drone.battery_level - drain)
        if drone.battery_level == 0.0 and drone.active:
            log.info("drone.battery_depleted", drone=drone.drone_id)
            self.leave(drone.drone_id)

    def transmit(self, packet: Packet) -> int:
        """Send a packet through the optional secure-transport hook."""
        if self._send_hook is not None:
            sealed = self._send_hook(packet)
            if sealed is None:
                return 0
            packet = sealed
        return self.network.send(packet)

    def step(self) -> TickStats:
        dt_ms = self.config.tick_ms
        now = self.clock.advance(dt_ms)
        dt_s = dt_ms / 1000.0
        sent_before = self.network.counters.sent
        tx_before = {d.drone_id: d.tx_bytes for d in self.network.active_nodes()}
        moved: dict[str, float] = {}
        for drone in self.network.active_nodes():
            moved[drone.drone_id] = self.mobility.step(drone, now, dt_s)
        packets: list[Packet] = []
        for drone in self.network.active_nodes():
            for src in self._sources.get(drone.drone_id, []):
                packets.extend(src.generate(now, dt_ms))
        packets.sort(key=lambda p: (p.timestamp_ms, p.packet_id))
        for packet in packets:
            if self.network.nodes[packet.true_src].active:
                self.transmit(packet)
        delivered = self.network.deliver_due(now)
        for drone in list(self.network.active_nodes()):
            tx = drone.tx_bytes - tx_before.get(drone.drone_id, drone.tx_bytes)
            self._update_battery(drone, moved.get(drone.drone_id, 0.0), dt_s, tx)
        for hook in self._tick_hooks:
            hook(now)
        self.tick_count += 1
        return TickStats(
            t_ms=now,
            sent=self.network.counters.sent - sent_before,
            delivered=len(delivered),
            active_nodes=len(self.network.active_nodes()),
        )

    def run(self, duration_ms: int) -> list[TickStats]:
        """Run ticks until ``duration_ms`` of virtual time has elapsed."""
        end = self.clock.now_ms + duration_ms
        stats = []
        while self.clock.now_ms < end:
            stats.append(self.step())
        return stats

    def positions(self) -> dict[str, list[float]]:
        return {d.drone_id: [float(v) for v in d.position] for d in self.network.active_nodes()}

    def rng(self, name: str) -> np.random.Generator:
        return self.streams.numpy(name)
