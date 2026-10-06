"""Trust model parameters (see ``docs/architecture/trust-model.md`` for the rationale).

Every default is derived from an explicit design requirement (R1-R4) and is verified by
``tests/unit/test_trust.py``; Phase 16 measures sensitivity to these values. They are
NOT claimed to be optimal.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class TrustConfig(BaseModel):
    """Decayed Beta-reputation trust with attribution-aware evidence fusion."""

    # ---- prior (registered drones start trusted but not maximally so)
    prior_alpha: float = Field(4.0, gt=0)
    prior_beta: float = Field(0.5, gt=0)
    #: Prior for a claimed source that is not a registered drone (rogue address).
    unknown_prior_alpha: float = Field(1.0, gt=0)
    unknown_prior_beta: float = Field(1.0, gt=0)
    # ---- forgetting: evidence mass decays by this factor per window (half-life ~4.3 windows)
    decay: float = Field(0.85, gt=0, lt=1)
    # ---- evidence weights (unit = one window of fully trusted ML evidence)
    w_normal: float = Field(1.0, ge=0)  # positive mass for a benign-looking window
    w_ml_attack: float = Field(3.0, ge=0)  # negative mass x P(attack): "easy to lose"
    w_auth_success: float = Field(0.5, ge=0)  # completed MAKA as initiator
    w_auth_failure: float = Field(2.0, ge=0)  # saturating per-window crypto failures
    w_violation: float = Field(2.0, ge=0)  # integrity / replay / unauthenticated verdicts
    w_anomaly: float = Field(1.0, ge=0)  # statistical rate anomaly (heuristic)
    w_reauth_success: float = Field(4.0, ge=0)  # passed a policy-forced re-authentication
    # ---- attribution: evidence not cryptographically bound to the claimed identity
    #: Weight of evidence that does not bind to the identity holder (spoofing-type classes,
    #: unverified packets). Chosen so that sustained spoofing of an honest drone leaves it in
    #: MONITOR at worst (requirement R4); no escalation is applied to such evidence.
    unattributed_factor: float = Field(0.05, ge=0, le=1)
    # ---- saturation of count evidence: weight x (1 - exp(-n / k))
    saturation_k: float = Field(3.0, gt=0)
    # ---- repeat-offender escalation
    escalation_gamma: float = Field(0.15, ge=0)
    escalation_cap: float = Field(3.0, ge=1)
    history_windows: int = Field(30, ge=1)
    bad_window_mass: float = Field(1.0, gt=0)  # negative mass that makes a window "bad"
    # ---- statistical anomaly detector (per-drone EWMA of transmissions per window)
    anomaly_z0: float = Field(3.0, gt=0)
    anomaly_z_scale: float = Field(3.0, gt=0)
    ewma_alpha: float = Field(0.1, gt=0, lt=1)
    anomaly_warmup_windows: int = Field(5, ge=1)
    #: With ML present, the heuristic only *corroborates*: it is scaled by max(P(attack),
    #: floor) and never escalates on its own (requirement R6: legitimate bursts the IDS
    #: recognises as benign must not restrict a drone).
    anomaly_ml_floor: float = Field(0.2, ge=0, le=1)
    # ---- ablation switches (Phase 16)
    use_ml: bool = True
    use_auth: bool = True
    use_violations: bool = True
    use_anomaly: bool = True
    attribution_aware: bool = True
