"""Assembles the adaptive framework for each system variant / ablation (Phases 14-16).

| Variant           | Layers                                                           |
|-------------------|------------------------------------------------------------------|
| d2dap (A)         | D2DAP + authenticated data plane                                 |
| d2dap_ids (B)     | A + ML IDS; flagged sources blocked for one window (naive IPS)   |
| d2dap_ids_trust(C)| A + IDS + TrustEngine; single block threshold                    |
| adaptive (D)      | A + IDS + TrustEngine + graded adaptive policy (full framework)  |
| no_trust          | D without TrustEngine (policy on raw per-window IDS score)       |
| no_ml             | D without ML IDS (trust from D2DAP/verdict/anomaly evidence)     |
| no_policy         | D without enforcement (trust + decisions only)                   |
| no_attribution    | D with attribution-unaware evidence fusion                       |
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import joblib

from app.experiments.recorder import DEFAULT_RESULTS
from app.ids.models import TrainedModel
from app.policy.engine import PolicyConfig
from app.services.monitor import MonitorConfig, SecurityMonitor
from app.services.swarm import SecureSwarm
from app.trust.config import TrustConfig

MODEL_PATH = DEFAULT_RESULTS / "models" / "ids_operational.joblib"
#: Environment override (inherited by worker processes; used by run_experiments --quick).
MODEL_ENV = "ADS_IDS_MODEL"


def model_path() -> Path:
    return Path(os.environ.get(MODEL_ENV, str(MODEL_PATH)))


#: variant -> (monitor mode, uses IDS model, TrustConfig overrides)
VARIANT_SPECS: dict[str, tuple[str, bool, dict[str, bool]]] = {
    "d2dap_ids": ("ids_block", True, {}),
    "d2dap_ids_trust": ("trust_binary", True, {}),
    "adaptive": ("adaptive", True, {}),
    "no_trust": ("raw_policy", True, {}),
    "no_ml": ("adaptive", False, {"use_ml": False}),
    "no_policy": ("observe", True, {}),
    "no_attribution": ("adaptive", True, {"attribution_aware": False}),
}


class ModelUnavailableError(FileNotFoundError):
    """The operational IDS model has not been trained yet (run the IDS experiment)."""


@lru_cache(maxsize=4)
def _load(path: Path) -> TrainedModel:
    if not path.exists():
        raise ModelUnavailableError(
            f"{path} not found: run `python scripts/run_experiments.py --suite ids` first"
        )
    model = joblib.load(path)
    if not isinstance(model, TrainedModel):
        raise TypeError(f"{path} does not contain a TrainedModel")
    return model.single_threaded()


def load_ids_model(path: Path | None = None) -> TrainedModel:
    """Load (and cache) the operational IDS model chosen in the IDS experiment."""
    return _load(path or model_path())


def install_framework(
    swarm: SecureSwarm,
    variant: str,
    model: TrainedModel | None = None,
    *,
    trust_config: TrustConfig | None = None,
    policy_config: PolicyConfig | None = None,
    monitor_config: MonitorConfig | None = None,
) -> SecurityMonitor:
    """Install the security monitor configured for ``variant`` on a D2DAP swarm."""
    if variant not in VARIANT_SPECS:
        raise ValueError(f"variant {variant!r} has no monitor (choose from {list(VARIANT_SPECS)})")
    mode, uses_ids, overrides = VARIANT_SPECS[variant]
    ids_model = (model or load_ids_model()) if uses_ids else None
    tcfg = (trust_config or TrustConfig()).model_copy(update=overrides)
    mcfg = (monitor_config or MonitorConfig()).model_copy(update={"mode": mode})
    return SecurityMonitor(swarm, ids_model, mcfg, tcfg, policy_config).install()
