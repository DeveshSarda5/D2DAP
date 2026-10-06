"""Professor demo (Phase 20): the whole framework, step by step, in plain language.

    python scripts/run_demo.py                       # insider flooding on D3
    python scripts/run_demo.py --attack spoofing     # an outsider spoofs D3 instead
    python scripts/run_demo.py --attack privilege_escalation --drones 8

Steps: 1 create network, 2 register drones, 3 authenticate, 4 normal traffic,
5 launch attack, 6 detect, 7 update trust, 8 adaptive policy, 9 final state, 10 save.
Everything printed is read from the running simulation.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime

from app.attacks.base import AttackSpec
from app.attacks.manager import ATTACK_TYPES, TRAFFIC_ATTACKS, AttackManager
from app.experiments.recorder import REPO_ROOT
from app.experiments.scenario import ScenarioConfig, Variant, build_variant
from app.services.auth_coordinator import AuthEvent
from app.services.framework import ModelUnavailableError
from app.services.monitor import SecurityMonitor

WIDTH = 78


def banner(step: int, title: str, what: str) -> None:
    print("\n" + "=" * WIDTH)
    print(f" STEP {step}: {title}")
    print("-" * WIDTH)
    print(f" {what}")
    print("=" * WIDTH)


def drone_table(monitor: SecurityMonitor | None, swarm: object) -> None:
    net = swarm.engine.network  # type: ignore[attr-defined]
    agents = swarm.d2dap.agents  # type: ignore[attr-defined]
    print(
        f" {'drone':<6}{'role':<8}{'auth state':<16}{'trust':>7}  {'security state':<16}{'CRPs':>5}"
    )
    for d in sorted(net.nodes.values(), key=lambda x: (len(x.drone_id), x.drone_id)):
        if d.drone_id.startswith("X-"):
            continue
        crp = agents[d.drone_id].crp_remaining if d.drone_id in agents else "-"
        print(
            f" {d.drone_id:<6}{d.role.value:<8}{d.auth_state.value:<16}{d.trust_score:>7.3f}  "
            f"{d.security_state.value.upper():<16}{crp!s:>5}"
        )


def main() -> int:  # noqa: PLR0915 - a linear, narrated script
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--drones", type=int, default=10)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--attack", default="flooding", choices=TRAFFIC_ATTACKS)
    p.add_argument("--target", default="D3")
    p.add_argument("--normal-s", type=int, default=15)
    p.add_argument("--attack-s", type=int, default=30)
    p.add_argument("--after-s", type=int, default=35)
    args = p.parse_args()
    out_dir = REPO_ROOT / "results" / "demo" / datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)

    banner(
        1,
        "Create the drone network",
        f"{args.drones} simulated drones (1 leader, relays, workers) with mobility "
        "and Wi-Fi-like links.",
    )
    cfg = ScenarioConfig(num_drones=args.drones, duration_ms=10**9, crp_count=256)
    variant = Variant.ADAPTIVE
    try:
        swarm, ext = build_variant(variant, cfg, args.seed)
    except ModelUnavailableError:
        print(
            " (IDS model not trained yet -> running without ML; train it with "
            "`python scripts/run_experiments.py --suite ids`)"
        )
        variant = Variant.NO_ML
        swarm, ext = build_variant(variant, cfg, args.seed)
    monitor = next(e for e in ext if isinstance(e, SecurityMonitor))
    net = swarm.engine.network
    print(f" Created {len(net.nodes)} drones; {len(net.topology())} radio links in range.")

    banner(
        2,
        "Register drones with the Control Server (D2DAP Setup + Registration)",
        "Each drone gets an ID, 128-bit PUF challenges and Shamir shares b=F(a); A stays secret.",
    )
    agent = swarm.d2dap.agents["D2"]
    print(
        f" Curve {swarm.d2dap.cs.public_parameters['curve']}, hash "
        f"{swarm.d2dap.cs.public_parameters['hash']}, cipher "
        f"{swarm.d2dap.cs.public_parameters['cipher']}"
    )
    print(f" Every drone holds {agent.crp_remaining} one-time CRPs (SOFTWARE PUF simulation).")

    events: list[AuthEvent] = []
    swarm.coordinator.add_listener(events.append)
    banner(
        3,
        "Authenticate drones with D2DAP (drone-to-drone, no server involved)",
        "Sessions are created on demand when a drone first sends data to a peer.",
    )
    swarm.run(3000)
    done = [e for e in events if e.stage == "complete" and e.success]
    print(
        f" {len(done)} mutual authentications completed; mean compute "
        f"{sum(e.compute_ms for e in done) / max(1, len(done)):.1f} ms per MAKA (both sides)."
    )
    for e in done[:4]:
        print(f"   {e.initiator} <-> {e.responder}: session established")

    banner(
        4,
        "Normal operation",
        f"{args.normal_s} s of telemetry, video and heartbeats; the IDS and trust engine "
        "watch every 1 s window.",
    )
    swarm.run(args.normal_s * 1000)
    drone_table(monitor, swarm)

    insider = ATTACK_TYPES[args.attack].insider
    stride = "".join(s.value for s in ATTACK_TYPES[args.attack].stride)
    banner(
        5,
        f"Launch attack: {args.attack} ({'compromised insider' if insider else 'outsider'})",
        f"Target {args.target}; STRIDE {stride}; {args.attack_s} s.",
    )
    t_attack = swarm.engine.clock.now_ms
    manager = AttackManager(swarm)
    attack = manager.launch(
        AttackSpec(
            kind=args.attack,
            target=args.target,
            start_ms=t_attack + 1,
            duration_ms=args.attack_s * 1000,
            rate_pps=25,
        )
    )
    n_dec, n_alert = len(monitor.policy.decisions), len(monitor.alerts)
    swarm.run(args.attack_s * 1000)

    banner(6, "Detect the attack", "ML IDS alerts and D2DAP rejections during the attack window.")
    alerts = monitor.alerts[n_alert:]
    first = next((a for a in alerts if a.src == args.target), None)
    print(
        f" IDS alerts during the attack: {len(alerts)}"
        + (
            f"; first on {args.target} after {(first.t_ms - t_attack) / 1000:.1f} s "
            f"(P(attack)={first.p_attack:.2f}, class {first.attack_class})"
            if first
            else ""
        )
    )
    ev = attack.evidence
    print(
        f" Attack packets: {ev.packets_sent} sent, {ev.packets_accepted} accepted; "
        f"dropped by reason: {dict(ev.dropped)}"
    )

    banner(7, "Update trust", "Trust of the targeted identity (attribution-aware evidence fusion).")
    hist = [u for u in monitor.trust.log if u.drone_id == args.target and u.t_ms >= t_attack - 2000]
    for u in hist[:: max(1, len(hist) // 8)][:10]:
        print(f"   t={u.t_ms / 1000:6.1f}s  trust {u.previous:.2f} -> {u.new:.2f}  ({u.reason})")

    banner(8, "Adaptive policy response", "Every decision with its explanation.")
    decisions = monitor.policy.decisions[n_dec:]
    if not decisions:
        print(" No policy change was needed (D2DAP alone rejected the attack packets).")
    for d in decisions[:6]:
        print("\n" + "\n".join("   " + line for line in d.explanation.splitlines()))

    banner(
        9,
        "Recovery and final security state",
        f"{args.after_s} s after the attack ends: honest drones stay NORMAL; "
        "a reformed drone can recover.",
    )
    swarm.run(args.after_s * 1000)
    drone_table(monitor, swarm)

    banner(10, "Save results", str(out_dir.relative_to(REPO_ROOT)))
    monitor.trust_frame().to_csv(out_dir / "trust_updates.csv", index=False)
    monitor.decisions_frame().to_csv(out_dir / "policy_decisions.csv", index=False)
    monitor.alerts_frame().to_csv(out_dir / "ids_alerts.csv", index=False)
    swarm.traffic_log.to_frame().to_csv(out_dir / "packets.csv", index=False)
    summary = {
        "seed": args.seed,
        "variant": variant.value,
        "attack": args.attack,
        "target": args.target,
        "evidence": attack.evidence.as_record(),
        "decisions": [d.as_record() for d in monitor.policy.decisions],
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    print(
        " Saved trust_updates.csv, policy_decisions.csv, ids_alerts.csv, packets.csv, summary.json"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
