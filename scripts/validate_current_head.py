"""Generate small executable trust/policy checks for a current-head audit."""

from __future__ import annotations

import csv
from pathlib import Path

from app.models.enums import SecurityState
from app.policy.engine import PolicyEngine
from app.trust.engine import Evidence, TrustEngine


OUT = Path("results/current_head")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    trust_rows: list[dict[str, object]] = []
    engine = TrustEngine(registered={"D2"})
    for window in range(10):
        evidence = Evidence(
            "D2", window, window * 1000, attack_prob=0.98, insider_prob=0.97,
            attack_class="flooding", tx_count=60, verified=60,
        )
        update = engine.update(evidence)
        trust_rows.append({
            "case": "verified_insider_flooding",
            "window": window,
            "trust": update.new,
            "previous": update.previous,
            "positive": update.positive,
            "negative": update.negative,
            "multiplier": update.multiplier,
            "reason": update.reason,
        })

    spoof_engine = TrustEngine(registered={"D2"})
    for window in range(10):
        evidence = Evidence(
            "D2", window, window * 1000, attack_prob=0.98, insider_prob=0.02,
            attack_class="spoofing", tx_count=25, verified=5, unverified=20,
            violations=20, auth_failures=2,
        )
        update = spoof_engine.update(evidence)
        trust_rows.append({
            "case": "unverified_spoofing",
            "window": window,
            "trust": update.new,
            "previous": update.previous,
            "positive": update.positive,
            "negative": update.negative,
            "multiplier": update.multiplier,
            "reason": update.reason,
        })

    with (OUT / "trust_validation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(trust_rows[0]))
        writer.writeheader()
        writer.writerows(trust_rows)

    policy = PolicyEngine()
    policy_rows: list[dict[str, object]] = []
    for i, trust in enumerate((0.95, 0.70, 0.50, 0.30, 0.10), start=1):
        evidence = Evidence("D4", i, i * 1000)
        from app.trust.engine import TrustUpdate

        update = TrustUpdate("D4", i, i * 1000, 0.9, trust, 1, 1, 0, 0, {}, 1.0, evidence, "audit")
        decision = policy.evaluate(update)
        policy_rows.append({
            "trust": trust,
            "decision": decision.new_state.value if decision else "none",
            "expected_band": (
                SecurityState.NORMAL.value if trust >= 0.8 else
                SecurityState.MONITOR.value if trust >= 0.6 else
                SecurityState.RESTRICT.value if trust >= 0.4 else
                SecurityState.REAUTHENTICATE.value if trust >= 0.2 else
                SecurityState.QUARANTINE.value
            ),
        })

    with (OUT / "policy_validation.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(policy_rows[0]))
        writer.writeheader()
        writer.writerows(policy_rows)


if __name__ == "__main__":
    main()
