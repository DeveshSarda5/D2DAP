"""Attack registry and scheduler.

manager = AttackManager(swarm)
manager.launch(AttackSpec(kind="replay", target="D3", start_ms=20_000))
swarm.run(60_000)
df = manager.evidence_frame()
"""

from __future__ import annotations

import pandas as pd

from app.attacks.base import Attack, AttackEvidence, AttackSpec, Stride
from app.attacks.external import (
    DosAuthFloodAttack,
    EavesdroppingAttack,
    ImpersonationAttack,
    ReplayAttack,
    SpoofingAttack,
    TamperingAttack,
    UnauthorizedAccessAttack,
)
from app.attacks.insider import AbnormalTrafficAttack, FloodingAttack, PrivilegeEscalationAttack
from app.core.errors import SimulationError
from app.services.swarm import SecureSwarm

ATTACK_TYPES: dict[str, type[Attack]] = {
    cls.kind: cls
    for cls in (
        SpoofingAttack,
        ReplayAttack,
        TamperingAttack,
        DosAuthFloodAttack,
        ImpersonationAttack,
        UnauthorizedAccessAttack,
        EavesdroppingAttack,
        FloodingAttack,
        PrivilegeEscalationAttack,
        AbnormalTrafficAttack,
    )
}

#: Attacks that emit or alter packets (and can therefore be labelled for the IDS).
TRAFFIC_ATTACKS: tuple[str, ...] = tuple(k for k in ATTACK_TYPES if k != "eavesdropping")


def stride_of(kind: str) -> tuple[Stride, ...]:
    return ATTACK_TYPES[kind].stride


class AttackManager:
    """Launches attacks and drives their lifecycle from the engine tick."""

    def __init__(self, swarm: SecureSwarm) -> None:
        self.swarm = swarm
        self.attacks: list[Attack] = []
        swarm.engine.add_tick_hook(self._tick)

    def launch(self, spec: AttackSpec) -> Attack:
        if spec.kind not in ATTACK_TYPES:
            raise SimulationError(f"unknown attack kind {spec.kind!r}")
        if spec.target not in self.swarm.engine.network.nodes:
            raise SimulationError(f"unknown attack target {spec.target}")
        if not spec.attack_id:
            spec = spec.model_copy(update={"attack_id": f"{spec.kind}-{len(self.attacks) + 1}"})
        attack = ATTACK_TYPES[spec.kind](spec, self.swarm)
        self.attacks.append(attack)
        return attack

    def _tick(self, now_ms: int) -> None:
        for attack in self.attacks:
            attack.tick(now_ms)

    def active(self) -> list[Attack]:
        return [a for a in self.attacks if a.active]

    def evidence(self) -> list[AttackEvidence]:
        return [a.evidence for a in self.attacks]

    def evidence_frame(self) -> pd.DataFrame:
        return pd.DataFrame([e.as_record() for e in self.evidence()])
