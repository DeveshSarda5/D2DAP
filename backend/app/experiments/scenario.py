"""Reusable attack-scenario runner over system variants.

A *variant* selects which security layers are active:

* ``baseline``   no authentication (plaintext, any identity accepted);
* ``d2dap``      D2DAP authentication + authenticated data plane (System A);
* ``d2dap_ids`` (B), ``d2dap_ids_trust`` (C), ``adaptive`` (D) and the ablations
  install the security monitor (:mod:`app.services.framework`), so every phase evaluates
  *the same scenarios* with the same seeds.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import pandas as pd

from app.attacks.base import Attack, AttackEvidence, AttackSpec
from app.attacks.manager import AttackManager
from app.security.d2dap.config import D2DAPConfig
from app.services.auth_coordinator import AuthEvent
from app.services.swarm import SecureSwarm, build_secure_swarm
from app.simulation.config import AreaConfig, SimulationConfig
from app.simulation.traffic import TrafficConfig


class Variant(str, Enum):
    BASELINE = "baseline"
    D2DAP = "d2dap"
    D2DAP_IDS = "d2dap_ids"
    D2DAP_IDS_TRUST = "d2dap_ids_trust"
    ADAPTIVE = "adaptive"
    # ablations of the full framework (Phase 16)
    NO_TRUST = "no_trust"
    NO_ML = "no_ml"
    NO_POLICY = "no_policy"
    NO_ATTRIBUTION = "no_attribution"


@dataclass(frozen=True)
class ScenarioConfig:
    """Shared scenario parameters (identical across variants)."""

    num_drones: int = 10
    duration_ms: int = 60_000
    attack_start_ms: int = 15_000
    attack_duration_ms: int = 30_000
    rate_pps: float = 20.0
    target: str = "D3"
    #: Session lifetime; re-keying creates fresh M1s (needed for in-window replay).
    rekey_interval_ms: int | None = 10_000
    area_m: float = 300.0
    traffic: TrafficConfig | None = None
    #: One-time CRPs per drone (D2DAP leaves m unspecified). A hub with k peers re-keying
    #: every R s consumes k CRPs per R s, so m must cover the run (see crp-budget note).
    crp_count: int = 256
    #: Re-provision CRPs from the CS when fewer remain (models return-to-base); None = off.
    reprovision_below: int | None = None


#: Optional extra hooks (variant, swarm, seed) -> state, e.g. for instrumentation.
StackExtension = Callable[[Variant, SecureSwarm, int], Any]
STACK_EXTENSIONS: list[StackExtension] = []


@dataclass
class ScenarioResult:
    variant: Variant
    seed: int
    kind: str
    evidence: AttackEvidence
    attack: Attack
    swarm: SecureSwarm
    auth_events: list[AuthEvent] = field(default_factory=list)
    extensions: list[Any] = field(default_factory=list)

    def traffic(self) -> pd.DataFrame:
        return self.swarm.traffic_log.to_frame()


@dataclass
class BenignResult:
    """A scenario run without any attack."""

    variant: Variant
    seed: int
    swarm: SecureSwarm
    auth_events: list[AuthEvent] = field(default_factory=list)
    extensions: list[Any] = field(default_factory=list)


def build_variant(
    variant: Variant,
    cfg: ScenarioConfig,
    seed: int,
    framework_kwargs: dict[str, Any] | None = None,
) -> tuple[SecureSwarm, list[Any]]:
    sim = SimulationConfig(
        num_drones=cfg.num_drones,
        area=AreaConfig(x_m=cfg.area_m, y_m=cfg.area_m, z_min_m=30, z_max_m=90),
    )
    swarm = build_secure_swarm(
        sim,
        D2DAPConfig(crp_count=cfg.crp_count),
        traffic=cfg.traffic,
        seed=seed,
        require_auth=variant is not Variant.BASELINE,
        rekey_interval_ms=cfg.rekey_interval_ms if variant is not Variant.BASELINE else None,
        reprovision_below=cfg.reprovision_below,
    )
    extensions: list[Any] = []
    if variant not in (Variant.BASELINE, Variant.D2DAP):
        from app.services.framework import install_framework  # noqa: PLC0415 - avoid cycle

        extensions.append(install_framework(swarm, variant.value, **(framework_kwargs or {})))
    extensions += [ext(variant, swarm, seed) for ext in STACK_EXTENSIONS]
    return swarm, extensions


def run_benign_scenario(
    variant: Variant,
    cfg: ScenarioConfig,
    seed: int,
    *,
    framework_kwargs: dict[str, Any] | None = None,
) -> BenignResult:
    """Run the same scenario without any attack (benign data, false positives)."""
    swarm, extensions = build_variant(variant, cfg, seed, framework_kwargs)
    events: list[AuthEvent] = []
    swarm.coordinator.add_listener(events.append)
    swarm.run(cfg.duration_ms)
    return BenignResult(variant, seed, swarm, events, extensions)


def run_attack_scenario(
    variant: Variant,
    kind: str,
    cfg: ScenarioConfig,
    seed: int,
    params: dict[str, Any] | None = None,
    *,
    framework_kwargs: dict[str, Any] | None = None,
) -> ScenarioResult:
    """Run one attack against one variant and return the evidence."""
    swarm, extensions = build_variant(variant, cfg, seed, framework_kwargs)
    events: list[AuthEvent] = []
    swarm.coordinator.add_listener(events.append)
    manager = AttackManager(swarm)
    attack = manager.launch(
        AttackSpec(
            kind=kind,
            target=cfg.target,
            start_ms=cfg.attack_start_ms,
            duration_ms=cfg.attack_duration_ms,
            rate_pps=cfg.rate_pps,
            params=params or {},
        )
    )
    swarm.run(cfg.duration_ms)
    return ScenarioResult(variant, seed, kind, attack.evidence, attack, swarm, events, extensions)
