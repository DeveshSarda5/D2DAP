"""Tests for the drone simulator (Phase 2)."""

from __future__ import annotations

import numpy as np
import pytest

from app.core.errors import SimulationError
from app.core.rng import RandomStreams
from app.models.enums import BROADCAST, DroneRole, PacketProtocol
from app.models.packet import Packet
from app.simulation.config import AreaConfig, ChannelConfig, MobilityConfig, SimulationConfig
from app.simulation.drone import Drone, SessionInfo
from app.simulation.engine import SimulationEngine
from app.simulation.traffic import (
    BurstSource,
    ErraticSource,
    PeriodicSource,
    PoissonSource,
    StreamSpec,
    TrafficConfig,
)


def lossless(**kw: object) -> SimulationConfig:
    """Config with a lossless, jitter-free channel (deterministic delivery checks)."""
    return SimulationConfig(
        channel=ChannelConfig(base_loss=0.0, edge_loss=0.0, jitter_ms=0.0),
        **kw,  # type: ignore[arg-type]
    )


def make_engine(seed: int = 1, **kw: object) -> SimulationEngine:
    return SimulationEngine(lossless(**kw), RandomStreams(seed))


def pos(x: float, y: float = 0.0, z: float = 50.0) -> np.ndarray:
    return np.array([x, y, z])


class TestDeterminism:
    def test_same_seed_identical_runs(self) -> None:
        def run(seed: int) -> tuple[dict[str, list[float]], int, int]:
            eng = SimulationEngine(SimulationConfig(num_drones=8), RandomStreams(seed))
            eng.create_swarm()
            eng.run(5000)
            c = eng.network.counters
            return eng.positions(), c.sent, c.delivered

        assert run(11) == run(11)
        assert run(11) != run(12)


class TestRegistryAndMembership:
    def test_create_swarm_roles_and_join(self) -> None:
        eng = make_engine(num_drones=10, leader_count=1, relay_fraction=0.2)
        drones = eng.create_swarm()
        roles = [d.role for d in drones]
        assert roles.count(DroneRole.LEADER) == 1
        assert roles.count(DroneRole.RELAY) == 2
        assert all(d.active for d in drones)

    def test_duplicate_id_rejected(self) -> None:
        eng = make_engine()
        eng.add_drone("X")
        with pytest.raises(SimulationError, match="duplicate"):
            eng.add_drone("X")

    def test_unknown_node(self) -> None:
        with pytest.raises(SimulationError, match="unknown"):
            make_engine().network.get("nope")

    def test_leave_clears_sessions_everywhere(self) -> None:
        eng = make_engine()
        a = eng.add_drone("A", position=pos(0))
        b = eng.add_drone("B", position=pos(10))
        eng.join("A")
        eng.join("B")
        a.add_session(SessionInfo("B", "s1", 0))
        b.add_session(SessionInfo("A", "s1", 0))
        eng.leave("A")
        assert not a.active
        assert a.sessions == {}
        assert "A" not in b.sessions

    def test_neighbors_respect_range(self) -> None:
        eng = make_engine()
        for name, x in [("A", 0.0), ("B", 100.0), ("C", 400.0)]:
            eng.add_drone(name, position=pos(x), with_normal_traffic=False)
            eng.join(name)
        assert [d.drone_id for d in eng.network.neighbors("A")] == ["B"]
        assert ("A", "B", 100.0) in eng.network.topology()
        assert all("C" not in e[:2] for e in eng.network.topology())


class TestDelivery:
    def _pair(self, dist: float = 50.0) -> SimulationEngine:
        eng = make_engine(mobility=MobilityConfig(model="static"))
        eng.add_drone("A", position=pos(0), with_normal_traffic=False)
        eng.add_drone("B", position=pos(dist), with_normal_traffic=False)
        eng.join("A")
        eng.join("B")
        return eng

    def _packet(self, eng: SimulationEngine, dst: str = "B") -> Packet:
        return eng.factory.make(eng.clock.now_ms, "A", dst, PacketProtocol.TELEMETRY, 100)

    def test_unicast_delivery_and_history(self) -> None:
        eng = self._pair()
        seen: list[Packet] = []
        eng.network.add_observer(seen.append)
        eng.transmit(self._packet(eng))
        eng.run(100)
        assert len(seen) == 1
        assert seen[0].dropped_reason is None
        assert seen[0].delivered_ms is not None
        b = eng.network.get("B")
        assert b.rx_packets == 1
        assert b.history[-1].peer == "A"

    def test_out_of_range_dropped(self) -> None:
        eng = self._pair(dist=1000.0)
        seen: list[Packet] = []
        eng.network.add_observer(seen.append)
        eng.transmit(self._packet(eng))
        assert seen[0].dropped_reason == "out_of_range"

    def test_ingress_filter_drops(self) -> None:
        eng = self._pair()
        eng.network.add_filter("policy", lambda p, r: "blocked" if p.src == "A" else None)
        seen: list[Packet] = []
        eng.network.add_observer(seen.append)
        eng.transmit(self._packet(eng))
        eng.run(100)
        assert seen[0].dropped_reason == "policy:blocked"

    def test_handler_called(self) -> None:
        eng = self._pair()
        calls: list[str] = []

        def handler(p: Packet, r: Drone) -> None:
            calls.append(r.drone_id)
            p.integrity_ok = True

        eng.network.set_handler(PacketProtocol.TELEMETRY, handler)
        eng.transmit(self._packet(eng))
        eng.run(100)
        assert calls == ["B"]

    def test_broadcast_reaches_all_neighbours(self) -> None:
        eng = self._pair()
        eng.add_drone("C", position=pos(0, 60), with_normal_traffic=False)
        eng.join("C")
        seen: list[Packet] = []
        eng.network.add_observer(seen.append)
        eng.transmit(self._packet(eng, dst=BROADCAST))
        eng.run(100)
        assert sorted(p.dst for p in seen) == ["B", "C"]

    def test_inactive_sender_cannot_transmit(self) -> None:
        eng = self._pair()
        eng.leave("A")
        with pytest.raises(SimulationError, match="inactive"):
            eng.network.send(self._packet(eng))

    def test_channel_loss_statistics(self) -> None:
        cfg = SimulationConfig(channel=ChannelConfig(base_loss=0.3, edge_loss=0.0))
        eng = SimulationEngine(cfg, RandomStreams(3))
        eng.add_drone("A", position=pos(0), with_normal_traffic=False)
        eng.add_drone("B", position=pos(10), with_normal_traffic=False)
        eng.join("A")
        eng.join("B")
        seen: list[Packet] = []
        eng.network.add_observer(seen.append)
        for _ in range(2000):
            eng.transmit(eng.factory.make(0, "A", "B", PacketProtocol.TELEMETRY, 50))
        eng.run(200)
        lost = sum(p.dropped_reason == "channel_loss" for p in seen) / len(seen)
        assert 0.26 < lost < 0.34


class TestMobilityAndBattery:
    def test_drones_stay_in_area_and_move(self) -> None:
        area = AreaConfig(x_m=200, y_m=200, z_min_m=20, z_max_m=60)
        eng = SimulationEngine(SimulationConfig(num_drones=6, area=area), RandomStreams(5))
        eng.create_swarm()
        start = eng.positions()
        eng.run(20_000)
        end = eng.positions()
        assert start != end
        for p in end.values():
            assert 0 <= p[0] <= 200
            assert 0 <= p[1] <= 200
            assert 20 <= p[2] <= 60

    def test_battery_drains_and_depleted_drone_leaves(self) -> None:
        eng = make_engine(num_drones=3)
        eng.create_swarm()
        eng.run(2000)
        assert all(d.battery_level < 100 for d in eng.network.active_nodes())
        d1 = eng.network.get("D1")
        d1.battery_level = 1e-9
        eng.step()
        assert not d1.active


class TestTrafficSources:
    def _eng(self) -> SimulationEngine:
        eng = make_engine(mobility=MobilityConfig(model="static"))
        for name, x in [("A", 0.0), ("B", 30.0), ("C", 60.0)]:
            eng.add_drone(name, position=pos(x), with_normal_traffic=False)
            eng.join(name)
        return eng

    def test_periodic_rate(self) -> None:
        eng = self._eng()
        src = PeriodicSource(
            eng.factory,
            StreamSpec("A", lambda: "B", PacketProtocol.TELEMETRY, 100),
            200,
            np.random.default_rng(0),
        )
        packets = [p for t in range(100, 10_001, 100) for p in src.generate(t, 100)]
        assert 48 <= len(packets) <= 52  # 5 Hz over 10 s
        assert all(p.protocol is PacketProtocol.TELEMETRY for p in packets)

    def test_periodic_no_backlog_after_pause(self) -> None:
        eng = self._eng()
        src = PeriodicSource(
            eng.factory,
            StreamSpec("A", lambda: "B", PacketProtocol.TELEMETRY, 50),
            100,
            np.random.default_rng(0),
        )
        assert len(src.generate(60_000, 100)) <= 2

    def test_poisson_mean(self) -> None:
        eng = self._eng()
        src = PoissonSource(
            eng.factory,
            StreamSpec("A", lambda: "B", PacketProtocol.COMMAND, 80),
            10.0,
            np.random.default_rng(1),
        )
        n = sum(len(src.generate(t, 100)) for t in range(100, 100_001, 100))
        assert 900 < n < 1100  # 10/s over 100 s

    def test_burst_alternates(self) -> None:
        eng = self._eng()
        src = BurstSource(
            eng.factory,
            StreamSpec("A", lambda: "B", PacketProtocol.VIDEO, 1000),
            np.random.default_rng(2),
            rate_pps=50.0,
            on_mean_s=1.0,
            off_mean_s=1.0,
        )
        states = []
        counts = []
        for t in range(100, 60_001, 100):
            counts.append(len(src.generate(t, 100)))
            states.append(src.is_on)
        assert any(states)
        assert not all(states)
        off_counts = [c for c, s in zip(counts, states, strict=True) if not s]
        assert sum(off_counts) == 0

    def test_erratic_source_labels(self) -> None:
        eng = self._eng()
        src = ErraticSource(
            eng.factory, eng.network, "A", 100.0, np.random.default_rng(3), label="x"
        )
        pkts = src.generate(1000, 100)
        assert pkts
        assert {p.dst for p in pkts} <= {"B", "C"}
        assert all(p.label == "x" for p in pkts)

    def test_normal_profile_generates_expected_protocols(self) -> None:
        eng = SimulationEngine(
            lossless(num_drones=6),
            RandomStreams(4),
            TrafficConfig(video_fraction=1.0),
        )
        eng.create_swarm()
        seen: list[Packet] = []
        eng.network.add_observer(seen.append)
        eng.run(30_000)
        protos = {p.protocol for p in seen}
        assert {PacketProtocol.TELEMETRY, PacketProtocol.HEARTBEAT, PacketProtocol.VIDEO} <= protos
        assert all(p.label == "benign" for p in seen)
