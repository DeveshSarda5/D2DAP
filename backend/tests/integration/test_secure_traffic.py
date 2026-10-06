"""Integration tests: D2DAP over packets, authenticated data plane, traffic log (Phase 6)."""

from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from app.models.enums import AuthState, DroneRole, PacketProtocol
from app.models.packet import GROUND_TRUTH_FIELDS, Packet
from app.services.auth_coordinator import AuthEvent
from app.services.swarm import SecureSwarm, build_secure_swarm
from app.simulation.config import ChannelConfig, MobilityConfig, SimulationConfig
from app.simulation.drone import Drone
from app.simulation.traffic_log import TrafficLog, rate_timeseries, traffic_summary

pytestmark = pytest.mark.integration
AREA = {"x_m": 150, "y_m": 150, "z_min_m": 30, "z_max_m": 60}


def small_swarm(require_auth: bool = True, n: int = 4, seed: int = 3) -> SecureSwarm:
    cfg = SimulationConfig(
        num_drones=n,
        area={"x_m": 150, "y_m": 150, "z_min_m": 30, "z_max_m": 60},  # type: ignore[arg-type]
        channel=ChannelConfig(base_loss=0.0, edge_loss=0.0),
        mobility=MobilityConfig(model="static"),
    )
    return build_secure_swarm(cfg, seed=seed, require_auth=require_auth)


class TestOnDemandAuthentication:
    def test_sessions_established_and_data_protected(self) -> None:
        sw = small_swarm()
        events: list[AuthEvent] = []
        sw.coordinator.add_listener(events.append)
        sw.run(5000)
        assert events
        assert all(e.success for e in events)
        assert all(e.compute_ms > 0 for e in events)
        leader = sw.engine.network.get("D1")
        assert leader.role is DroneRole.LEADER
        assert leader.sessions  # workers authenticated with the leader
        assert all(d.auth_state is AuthState.AUTHENTICATED for d in sw.engine.network.nodes.values()
                   if d.sessions)  # fmt: skip
        df = sw.traffic_log.to_frame()
        data = df[df.protocol.isin(["telemetry", "video", "command"])]
        delivered = data[data.dropped_reason.isna()]
        assert len(delivered) > 50
        assert delivered.integrity_ok.all()
        assert delivered.session_id.notna().all()
        final = [e for e in events if e.stage == "complete"]
        assert final
        assert (df.protocol == "auth_request").sum() >= len(final)
        # every completed MAKA was preceded by the responder accepting M1
        assert sum(e.stage == "respond" for e in events) >= len(final)
        assert (df.protocol == "rl_broadcast").any()
        assert sw.transport.counters.integrity_failures == 0

    def test_session_keys_match_between_peers(self) -> None:
        sw = small_swarm()
        sw.run(3000)
        for drone in sw.engine.network.nodes.values():
            for sid, sess in drone.session_index.items():
                other = sw.engine.network.get(sess.peer_id).session_by_id(sid, drone.drone_id)
                assert other is not None
                assert other.key == sess.key

    def test_simultaneous_open_race_regression(self) -> None:
        """A->B and B->A MAKA crossing must not strand data (found in Phase 6)."""
        sw = small_swarm(n=3)
        now = sw.engine.clock.now_ms
        assert sw.coordinator.start("D2", "D3", now)
        assert sw.coordinator.start("D3", "D2", now)
        sw.run(500)
        d2, d3 = sw.engine.network.get("D2"), sw.engine.network.get("D3")
        with_d3 = [s for s in d2.session_index.values() if s.peer_id == "D3"]
        assert len(with_d3) == 2  # two valid sessions with the same peer
        for src, dst in (("D2", "D3"), ("D3", "D2")):
            pkt = sw.engine.factory.make(sw.engine.clock.now_ms, src, dst,
                                         PacketProtocol.TELEMETRY, 100)  # fmt: skip
            sw.engine.transmit(pkt)
            sw.run(200)
            assert pkt.dropped_reason is None
            assert pkt.integrity_ok
        assert d3.drone_id in d2.sessions


class TestDataPlaneAttacksBlocked:
    def test_tampered_payload_dropped(self) -> None:
        sw = small_swarm()
        sw.run(3000)

        def tamper(p: Packet, r: Drone) -> str | None:
            """On-path attacker flips one ciphertext bit; never drops (returns None)."""
            if p.payload and p.protocol is PacketProtocol.TELEMETRY:
                p.payload = bytes([p.payload[0] ^ 1]) + p.payload[1:]
            return None

        sw.engine.network.add_filter("mitm", tamper)
        sw.run(2000)
        assert sw.transport.counters.integrity_failures > 0
        df = sw.traffic_log.to_frame()
        assert (df.dropped_reason == "integrity").sum() == sw.transport.counters.integrity_failures

    def test_replayed_data_packet_dropped(self) -> None:
        sw = small_swarm()
        captured: list[Packet] = []
        sw.engine.network.add_observer(
            lambda p: captured.append(p) if p.integrity_ok and p.session_id else None
        )
        sw.run(3000)
        original = captured[0]
        replay = replace(original, packet_id=sw.engine.network.next_packet_id(),
                         timestamp_ms=sw.engine.clock.now_ms, delivered_ms=None,
                         dropped_reason=None, integrity_ok=None, label="replay")  # fmt: skip
        sw.engine.network.send(replay)
        sw.run(200)
        assert replay.dropped_reason == "replay"

    def test_unauthenticated_spoofed_data_dropped(self) -> None:
        sw = small_swarm()
        sw.engine.add_drone("X", position=np.array([60.0, 60.0, 40.0]), with_normal_traffic=False)
        sw.engine.join("X")
        sw.run(1000)
        spoof = sw.engine.factory.make(sw.engine.clock.now_ms, "D2", "D1", PacketProtocol.COMMAND,
                                       80, true_src="X", label="spoofing")  # fmt: skip
        sw.engine.network.send(spoof)
        sw.run(200)
        assert spoof.dropped_reason == "unauthenticated"

    def test_noauth_baseline_accepts_spoofed_data(self) -> None:
        sw = small_swarm(require_auth=False)
        sw.engine.add_drone("X", position=np.array([60.0, 60.0, 40.0]), with_normal_traffic=False)
        sw.engine.join("X")
        spoof = sw.engine.factory.make(0, "D2", "D1", PacketProtocol.COMMAND, 80, true_src="X")
        sw.engine.network.send(spoof)
        sw.run(200)
        assert spoof.dropped_reason is None


class TestReauthentication:
    def test_reauth_revokes_and_reestablishes(self) -> None:
        sw = small_swarm()
        events: list[AuthEvent] = []
        sw.coordinator.add_listener(events.append)
        sw.run(3000)
        target = next(d for d in sw.engine.network.nodes.values()
                      if d.role is not DroneRole.LEADER and d.sessions)  # fmt: skip
        old = {p: s.session_id for p, s in target.sessions.items()}
        revoked = sw.coordinator.reauthenticate(target.drone_id, sw.engine.clock.now_ms)
        assert revoked == len(old)
        assert target.auth_state is AuthState.REAUTH_PENDING
        sw.run(3000)
        assert target.sessions
        assert all(target.sessions[p].session_id != sid for p, sid in old.items()
                   if p in target.sessions)  # fmt: skip
        assert any(e.reauth and e.success for e in events)


class TestTrafficLog:
    def test_columns_and_ground_truth_split(self) -> None:
        sw = small_swarm()
        sw.run(4000)
        df = sw.traffic_log.to_frame()
        obs = TrafficLog.observable(df)
        assert not set(obs.columns) & GROUND_TRUTH_FIELDS
        assert {"src", "dst", "protocol", "size_bytes", "timestamp_ms"} <= set(obs.columns)
        gt = TrafficLog.ground_truth(df)
        assert "label" in gt.columns

    def test_summary_and_timeseries(self) -> None:
        sw = small_swarm()
        sw.run(5000)
        df = sw.traffic_log.to_frame()
        summ = traffic_summary(df, 5.0)
        assert set(summ.protocol) >= {"telemetry", "heartbeat"}
        assert (summ.delivery_ratio <= 1).all()
        ts = rate_timeseries(df, 1000)
        assert ts.shape[0] >= 4
        assert traffic_summary(df.iloc[0:0], 1.0).empty


class TestCRPBudget:
    """D2DAP CRPs are one-time: a hub re-keying with many peers exhausts them."""

    def _hub(self, crp: int, reprovision: int | None) -> SecureSwarm:
        from app.security.d2dap.config import D2DAPConfig  # noqa: PLC0415

        cfg = SimulationConfig(
            num_drones=6,
            area=AREA,  # type: ignore[arg-type]
            channel=ChannelConfig(base_loss=0.0, edge_loss=0.0),
            mobility=MobilityConfig(model="static"),
        )
        d2dap = D2DAPConfig(crp_count=crp)
        return build_secure_swarm(cfg, d2dap, seed=4, rekey_interval_ms=2000,
                                  reprovision_below=reprovision)  # fmt: skip

    def test_hub_exhausts_crps_without_reprovisioning(self) -> None:
        sw = self._hub(crp=12, reprovision=None)
        sw.run(30_000)
        assert sw.d2dap.agents["D1"].crp_remaining == 0
        assert sw.coordinator.counters.by_reason["crp_exhausted"] > 0

    def test_reprovisioning_prevents_exhaustion(self) -> None:
        sw = self._hub(crp=12, reprovision=4)
        sw.run(30_000)
        assert sw.coordinator.counters.reprovisions > 0
        assert sw.coordinator.counters.by_reason.get("crp_exhausted", 0) == 0
