# Drone Simulator (Phase 2)

Package: `backend/app/simulation/`

| Module | Responsibility |
|---|---|
| `config.py` | Pydantic configs: area, mobility, channel, battery model, swarm size |
| `drone.py` | `Drone` entity: id, role, position, velocity, battery *model*, auth state, trust score, security state, sessions, communication history |
| `mobility.py` | Random-waypoint (with pauses) and static mobility |
| `channel.py` | Abstract wireless channel: range, latency (base + tx time + jitter), distance-dependent loss |
| `network.py` | Node registry, join/leave, neighbour graph, event-queue delivery, ingress filters (policy enforcement), protocol handlers, observers |
| `traffic.py` | Periodic / Poisson / on-off burst sources, normal behaviour profiles, erratic (abnormal) source |
| `engine.py` | Tick loop: clock → mobility → traffic → transmit → deliver → battery → hooks |

## Design decisions

- **Deterministic:** every random draw comes from a named stream (`RandomStreams`). The same seed and config give an identical run, which is tested.
- **Observable vs. ground truth:** `Packet.src` is the *claimed* source, which can be spoofed. `Packet.true_src`, `label` and `attack_id` are evaluation-only ground truth.
- **Receiver-side enforcement:** restrictions and quarantine are enforced by ingress filters at the receivers, because a malicious sender does not cooperate.
- **No multi-hop routing:** out-of-range packets are dropped. Telemetry uses the nearest neighbour when the leader is out of range, as a relay abstraction.
- **Battery is a linear model** (hover + distance + transmitted bytes). It is not a measurement and is never reported as energy consumption.

Demo: `python scripts/demo_simulator.py --drones 10 --seconds 30 --seed 7`
