"""Builder for a secured swarm: simulator + D2DAP + authenticated data plane + traffic log."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.rng import RandomStreams
from app.security.d2dap.config import D2DAPConfig
from app.security.d2dap.service import D2DAPSystem
from app.services.auth_coordinator import AuthCoordinator
from app.services.secure_transport import SecureTransport
from app.simulation.config import SimulationConfig
from app.simulation.engine import SimulationEngine
from app.simulation.traffic import TrafficConfig
from app.simulation.traffic_log import TrafficLog


@dataclass
class SecureSwarm:
    """All wired components of one simulated, D2DAP-secured swarm."""

    engine: SimulationEngine
    d2dap: D2DAPSystem
    transport: SecureTransport
    coordinator: AuthCoordinator
    traffic_log: TrafficLog
    streams: RandomStreams

    def run(self, duration_ms: int) -> None:
        self.engine.run(duration_ms)


def build_secure_swarm(
    sim: SimulationConfig,
    d2dap: D2DAPConfig | None = None,
    traffic: TrafficConfig | None = None,
    seed: int = 0,
    *,
    require_auth: bool = True,
    keep_records: bool = True,
    rekey_interval_ms: int | None = None,
    reprovision_below: int | None = None,
) -> SecureSwarm:
    """Create the swarm, register every drone with the CS and install the security layers.

    ``require_auth=False`` gives the no-authentication baseline (plaintext data accepted).
    """
    streams = RandomStreams(seed)
    engine = SimulationEngine(sim, streams, traffic)
    d2dap_cfg = d2dap or D2DAPConfig(crp_count=64)
    system = D2DAPSystem(d2dap_cfg, streams)
    transport = SecureTransport(engine.network, require_auth=require_auth)
    coordinator = AuthCoordinator(engine, system, transport, rekey_interval_ms,
                                  reprovision_below=reprovision_below)  # fmt: skip
    log = TrafficLog(keep_records=keep_records)
    engine.network.add_observer(log)
    drones = engine.create_swarm()
    if require_auth:
        for d in drones:
            coordinator.enroll(d)
        transport.install()
        coordinator.install()
    return SecureSwarm(engine, system, transport, coordinator, log, streams)
