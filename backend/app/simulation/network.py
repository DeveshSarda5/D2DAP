"""Drone network: node registry, join/leave, neighbour graph and packet delivery.

Delivery pipeline for every transmitted packet::

    send() -> range / loss check (physical transmitter = ``true_src``)
           -> scheduled in a time-ordered event queue (channel latency)
    deliver_due(now) -> ingress filters (policy enforcement at the receiver)
                     -> protocol handler (e.g. D2DAP, AEAD data plane)
                     -> observers (traffic log, IDS feature extraction, dashboard)

Ingress filters run at the *receiver* because a malicious sender does not cooperate
with restrictions; this is how RESTRICT / QUARANTINE decisions are enforced.
"""

from __future__ import annotations

import heapq
import itertools
from collections.abc import Callable
from dataclasses import dataclass, replace

from app.core.errors import SimulationError
from app.models.enums import BROADCAST, PacketProtocol
from app.models.packet import Packet
from app.simulation.channel import WirelessChannel
from app.simulation.drone import CommRecord, Drone

#: Returns a drop reason, or ``None`` to accept the packet.
IngressFilter = Callable[[Packet, Drone], str | None]
#: Processes a packet at the receiver; may set ``integrity_ok`` / ``auth_ok`` / drop reason.
PacketHandler = Callable[[Packet, Drone], None]
#: Sees every packet once its fate is final (delivered or dropped).
PacketObserver = Callable[[Packet], None]


@dataclass
class NetworkCounters:
    sent: int = 0
    delivered: int = 0
    dropped: int = 0
    bytes_sent: int = 0


class DroneNetwork:
    """Registry of nodes plus a discrete-event packet delivery queue."""

    def __init__(self, channel: WirelessChannel, history_size: int = 200) -> None:
        self.channel = channel
        self.nodes: dict[str, Drone] = {}
        self._history_size = history_size
        self._queue: list[tuple[int, int, Packet]] = []
        self._order = itertools.count()
        self._packet_ids = itertools.count(1)
        self._filters: list[tuple[str, IngressFilter]] = []
        self._handlers: dict[PacketProtocol, PacketHandler] = {}
        self._observers: list[PacketObserver] = []
        self.counters = NetworkCounters()

    # ------------------------------------------------------------- registry
    def register(self, drone: Drone) -> Drone:
        """Add a node (drone or external attacker radio). It is inactive until it joins."""
        if drone.drone_id in self.nodes:
            raise SimulationError(f"duplicate node id {drone.drone_id}")
        drone.history = type(drone.history)(drone.history, maxlen=self._history_size)
        self.nodes[drone.drone_id] = drone
        return drone

    def get(self, drone_id: str) -> Drone:
        try:
            return self.nodes[drone_id]
        except KeyError as exc:
            raise SimulationError(f"unknown node {drone_id}") from exc

    def join(self, drone_id: str) -> None:
        self.get(drone_id).active = True

    def leave(self, drone_id: str) -> None:
        drone = self.get(drone_id)
        drone.active = False
        drone.revoke_sessions()
        for other in self.nodes.values():
            other.drop_peer(drone_id)

    def active_nodes(self) -> list[Drone]:
        return [d for d in self.nodes.values() if d.active]

    def neighbors(self, drone_id: str) -> list[Drone]:
        """Active nodes within communication range of ``drone_id``."""
        me = self.get(drone_id)
        return [
            d
            for d in self.active_nodes()
            if d.drone_id != drone_id and self.channel.in_range(me.distance_to(d))
        ]

    def topology(self) -> list[tuple[str, str, float]]:
        """Undirected edges ``(a, b, distance)`` between active, in-range nodes."""
        active = sorted(self.active_nodes(), key=lambda d: d.drone_id)
        edges = []
        for i, a in enumerate(active):
            for b in active[i + 1 :]:
                dist = a.distance_to(b)
                if self.channel.in_range(dist):
                    edges.append((a.drone_id, b.drone_id, round(dist, 2)))
        return edges

    # ------------------------------------------------------------- hooks
    def add_filter(self, name: str, flt: IngressFilter) -> None:
        self._filters.append((name, flt))

    def set_handler(self, protocol: PacketProtocol, handler: PacketHandler) -> None:
        self._handlers[protocol] = handler

    def add_observer(self, observer: PacketObserver) -> None:
        self._observers.append(observer)

    def next_packet_id(self) -> int:
        return next(self._packet_ids)

    # ------------------------------------------------------------- delivery
    def _finalize(self, packet: Packet) -> None:
        if packet.dropped_reason is None:
            self.counters.delivered += 1
        else:
            self.counters.dropped += 1
        for obs in self._observers:
            obs(packet)

    def send(self, packet: Packet) -> int:
        """Transmit ``packet``; returns the number of receivers it was scheduled for."""
        sender = self.get(packet.true_src)
        if not sender.active:
            raise SimulationError(f"inactive node {sender.drone_id} cannot transmit")
        self.counters.sent += 1
        self.counters.bytes_sent += packet.size_bytes
        sender.record(
            CommRecord(
                packet.timestamp_ms,
                "tx",
                packet.dst,
                packet.protocol.value,
                packet.size_bytes,
                True,
            )
        )
        if packet.dst == BROADCAST:
            receivers = self.neighbors(sender.drone_id)
            copies = [replace(packet, dst=r.drone_id, meta=dict(packet.meta)) for r in receivers]
        else:
            receiver = self.nodes.get(packet.dst)
            if receiver is None or not receiver.active:
                packet.dropped_reason = "no_such_receiver"
                self._finalize(packet)
                return 0
            copies = [packet]
        scheduled = 0
        for copy in copies:
            receiver = self.nodes[copy.dst]
            dist = sender.distance_to(receiver)
            if not self.channel.in_range(dist):
                copy.dropped_reason = "out_of_range"
                self._finalize(copy)
                continue
            if self.channel.is_lost(dist):
                copy.dropped_reason = "channel_loss"
                self._finalize(copy)
                continue
            deliver_at = packet.timestamp_ms + self.channel.latency_ms(copy.size_bytes)
            heapq.heappush(self._queue, (deliver_at, next(self._order), copy))
            scheduled += 1
        return scheduled

    def deliver_due(self, now_ms: int) -> list[Packet]:
        """Deliver every queued packet with delivery time <= ``now_ms``."""
        delivered: list[Packet] = []
        while self._queue and self._queue[0][0] <= now_ms:
            deliver_at, _, packet = heapq.heappop(self._queue)
            receiver = self.nodes[packet.dst]
            packet.delivered_ms = deliver_at
            if not receiver.active:
                packet.dropped_reason = "receiver_inactive"
            else:
                for name, flt in self._filters:
                    reason = flt(packet, receiver)
                    if reason is not None:
                        packet.dropped_reason = f"{name}:{reason}"
                        break
            if packet.dropped_reason is None:
                handler = self._handlers.get(packet.protocol)
                if handler is not None:
                    handler(packet, receiver)
            ok = packet.dropped_reason is None
            receiver.record(
                CommRecord(
                    deliver_at, "rx", packet.src, packet.protocol.value, packet.size_bytes, ok
                )
            )
            self._finalize(packet)
            if ok:
                delivered.append(packet)
        return delivered

    @property
    def pending(self) -> int:
        return len(self._queue)
