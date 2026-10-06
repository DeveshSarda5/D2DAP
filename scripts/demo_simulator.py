"""Phase 2 demo: run the drone swarm simulator and print what happened.

python scripts/demo_simulator.py --drones 10 --seconds 30 --seed 7
"""

from __future__ import annotations

import argparse
from collections import Counter

from app.core.rng import RandomStreams
from app.models.packet import Packet
from app.simulation.config import SimulationConfig
from app.simulation.engine import SimulationEngine


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drones", type=int, default=10)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    engine = SimulationEngine(SimulationConfig(num_drones=args.drones), RandomStreams(args.seed))
    log: list[Packet] = []
    engine.network.add_observer(log.append)
    engine.create_swarm()

    # Membership dynamics: one drone leaves mid-run and rejoins later.
    leaver = f"D{args.drones}"
    engine.run(args.seconds * 1000 // 3)
    engine.leave(leaver)
    engine.run(args.seconds * 1000 // 3)
    engine.join(leaver)
    engine.run(args.seconds * 1000 - engine.clock.now_ms)

    print(f"Simulated {engine.clock.now_s:.1f} s, {args.drones} drones, seed={args.seed}\n")
    print(f"{'drone':<6}{'role':<8}{'battery%':>9}{'tx':>7}{'rx':>7}{'neigh':>7}  position (m)")
    for d in engine.network.nodes.values():
        neigh = len(engine.network.neighbors(d.drone_id)) if d.active else 0
        p = ", ".join(f"{v:6.1f}" for v in d.position)
        print(
            f"{d.drone_id:<6}{d.role.value:<8}{d.battery_level:9.2f}"
            f"{d.tx_packets:7d}{d.rx_packets:7d}{neigh:7d}  ({p})"
        )
    by_proto = Counter(p.protocol.value for p in log)
    drops = Counter(p.dropped_reason for p in log if p.dropped_reason)
    delivered = sum(p.dropped_reason is None for p in log)
    print(f"\nPacket receptions logged: {len(log)}  delivered: {delivered}")
    print("By protocol:", dict(by_proto))
    print("Drop reasons:", dict(drops))
    print(f"Topology edges now: {len(engine.network.topology())}")


if __name__ == "__main__":
    main()
