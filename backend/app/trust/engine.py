"""TrustEngine: continuous, explainable trust per drone (OUR PROPOSED CONTRIBUTION).

Model: a *decayed Beta reputation* (Josang & Ismail 2002 provide the Beta basis; the
evidence fusion, attribution weighting and escalation are ours)::

    alpha_k = lambda * alpha_{k-1} + positive_evidence_k
    beta_k  = lambda * beta_{k-1}  + negative_evidence_k
    T_k     = (alpha_k + a0) / (alpha_k + beta_k + a0 + b0)

Evidence of one observation window for drone ``d``:

* ML IDS:  +w_normal * (1-p);
           -w_ml_attack * [ p_ins * (c * m + (1-c) * u) + p_ext * u ]
  where p_ins / p_ext is the probability mass on insider / external attack classes,
  ``c`` the verified (attributable) fraction and ``u`` the unattributed factor
* D2DAP:   +w_auth_success per completed MAKA; -w_auth_failure * sat(n_fail) * u
* verdicts (integrity / replay / unauthenticated / no-session): -w_violation * sat(n) * u
* verified privileged commands from a non-leader (role violation): -w_violation * sat(n) * m
* statistical anomaly (EWMA z-score of the *verified* packet rate):
  -w_anomaly * clip((z - z0) / z_scale, 0, 1) * c * max(p_ins, floor) with ML present
  (corroborating only, no escalation), or * m without ML
* passed policy-forced re-authentication: +w_reauth_success

``sat(n) = 1 - exp(-n / k)`` bounds the effect of bursts; ``m`` is the repeat-offender
multiplier ``min(cap, 1 + gamma * bad_windows_in_history)``.

**Attribution-aware fusion.** A packet that is cryptographically verified (AEAD under a
D2DAP session, or an accepted M1/M2) is *bound* to the claimed identity. Unverified
packets (spoofed, replayed, failed authentication) only prove that *someone* used the
address, and D2DAP already drops them. Likewise, the IDS's *external* attack classes
(spoofing, replay, tampering, impersonation, DoS, unauthorised access) say the identity is
being used by someone else, while *insider* classes (flooding, privilege escalation,
abnormal) describe the key holder's own behaviour. Only insider evidence bound to the
identity is escalated; everything else is scaled by ``u = unattributed_factor``. This
prevents an outsider from framing an honest drone into quarantine with spoofed traffic.
Claimed sources that are not registered drones have no honest owner to protect, so the
attribution discount does not apply to them.

Every update is logged as a :class:`TrustUpdate` (previous, new, evidence, reason, time).
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any

from app.trust.config import TrustConfig

#: IDS classes describing behaviour of the *holder* of the identity's session keys.
INSIDER_CLASSES = frozenset({"flooding", "privilege_escalation", "abnormal"})


@dataclass(frozen=True)
class Evidence:
    """Everything observed about one claimed source in one window."""

    drone_id: str
    window: int
    t_ms: int
    attack_prob: float | None = None  # ML IDS P(attack) (None = no ML evidence)
    insider_prob: float | None = None  # ML IDS probability mass on INSIDER_CLASSES
    attack_class: str | None = None  # ML IDS predicted class
    tx_count: int = 0
    verified: int = 0  # cryptographically verified receptions
    unverified: int = 0  # receptions that failed or lacked verification
    auth_success: int = 0  # completed MAKA as initiator
    auth_failures: int = 0  # failed MAKA attributed to this claimed initiator
    violations: int = 0  # integrity + replay + unauthenticated + no-session verdicts
    #: Verified (identity-bound) privileged commands from a non-leader: role violation.
    authz_violations: int = 0
    reauth_success: int = 0  # passed a policy-forced re-authentication

    @property
    def attribution(self) -> float:
        """Fraction of the window's (non-broadcast) traffic bound to the identity."""
        total = self.verified + self.unverified
        return 1.0 if total == 0 else self.verified / total


@dataclass(frozen=True)
class TrustUpdate:
    """Audit record of one trust update."""

    drone_id: str
    window: int
    t_ms: int
    previous: float
    new: float
    alpha: float
    beta: float
    positive: float
    negative: float
    components: dict[str, float]
    multiplier: float
    evidence: Evidence
    reason: str

    def as_record(self) -> dict[str, Any]:
        rec = {k: v for k, v in asdict(self).items() if k not in {"components", "evidence"}}
        rec.update({f"c_{k}": v for k, v in self.components.items()})
        rec.update({f"e_{k}": v for k, v in asdict(self.evidence).items() if k != "drone_id"})
        return rec


@dataclass
class _DroneState:
    alpha: float = 0.0
    beta: float = 0.0
    prior_alpha: float = 1.0
    prior_beta: float = 1.0
    bad_windows: deque[int] = field(default_factory=deque)
    ewma_mean: float = 0.0
    ewma_var: float = 0.0
    windows_seen: int = 0
    last_window: int | None = None

    def trust(self) -> float:
        a = self.alpha + self.prior_alpha
        return a / (a + self.beta + self.prior_beta)


def _sat(n: float, k: float) -> float:
    return 1.0 - math.exp(-max(n, 0.0) / k)


class TrustEngine:
    """Maintains trust for every claimed source; pure (no simulator dependency)."""

    def __init__(self, config: TrustConfig | None = None, registered: set[str] | None = None
                 ) -> None:  # fmt: skip
        self.config = config or TrustConfig()
        self.registered = set(registered or ())
        self._states: dict[str, _DroneState] = {}
        self.log: list[TrustUpdate] = []

    # ------------------------------------------------------------- state access
    def _state(self, drone_id: str) -> _DroneState:
        st = self._states.get(drone_id)
        if st is None:
            c = self.config
            known = drone_id in self.registered or not self.registered
            st = _DroneState(
                prior_alpha=c.prior_alpha if known else c.unknown_prior_alpha,
                prior_beta=c.prior_beta if known else c.unknown_prior_beta,
            )
            self._states[drone_id] = st
        return st

    def trust(self, drone_id: str) -> float:
        return self._state(drone_id).trust()

    def known(self) -> list[str]:
        return sorted(self._states)

    def history(self, drone_id: str) -> list[TrustUpdate]:
        return [u for u in self.log if u.drone_id == drone_id]

    # ------------------------------------------------------------- evidence terms
    def _anomaly(self, st: _DroneState, tx: float) -> float:
        """Rate-anomaly score in [0, 1]; the baseline only learns from normal windows."""
        c = self.config
        st.windows_seen += 1
        if st.windows_seen <= c.anomaly_warmup_windows:
            st.ewma_mean += (tx - st.ewma_mean) / st.windows_seen
            st.ewma_var += ((tx - st.ewma_mean) ** 2 - st.ewma_var) / st.windows_seen
            return 0.0
        z = (tx - st.ewma_mean) / math.sqrt(st.ewma_var + 1.0)
        score = min(1.0, max(0.0, (z - c.anomaly_z0) / c.anomaly_z_scale))
        if z < c.anomaly_z0:
            st.ewma_mean += c.ewma_alpha * (tx - st.ewma_mean)
            st.ewma_var += c.ewma_alpha * ((tx - st.ewma_mean) ** 2 - st.ewma_var)
        return score

    def _multiplier(self, st: _DroneState, window: int) -> float:
        c = self.config
        while st.bad_windows and st.bad_windows[0] <= window - c.history_windows:
            st.bad_windows.popleft()
        return min(c.escalation_cap, 1.0 + c.escalation_gamma * len(st.bad_windows))

    # ------------------------------------------------------------- update
    def update(self, ev: Evidence) -> TrustUpdate:
        """Apply one window of evidence and return the audit record."""
        c = self.config
        st = self._state(ev.drone_id)
        previous = st.trust()
        steps = 1 if st.last_window is None else max(1, ev.window - st.last_window)
        st.alpha *= c.decay**steps
        st.beta *= c.decay**steps
        st.last_window = ev.window
        m = self._multiplier(st, ev.window)
        discount = c.attribution_aware and (ev.drone_id in self.registered or not self.registered)
        attr = ev.attribution if discount else 1.0
        unattr = c.unattributed_factor if discount else 1.0
        comp: dict[str, float] = {}
        if c.use_ml and ev.attack_prob is not None:
            p = min(1.0, max(0.0, ev.attack_prob))
            p_ins = min(p, max(0.0, ev.insider_prob if ev.insider_prob is not None else p))
            p_ext = p - p_ins
            if not discount:  # unregistered source: every attack class counts fully
                p_ins, p_ext = p, 0.0
            comp["ml_normal"] = c.w_normal * (1.0 - p)
            comp["ml_attack"] = -c.w_ml_attack * (
                p_ins * (attr * m + (1.0 - attr) * unattr) + p_ext * unattr
            )
        if c.use_auth:
            if ev.auth_success:
                comp["auth_success"] = c.w_auth_success * min(ev.auth_success, 3)
            if ev.auth_failures:
                comp["auth_failure"] = (
                    -c.w_auth_failure * _sat(ev.auth_failures, c.saturation_k) * unattr
                )
        if c.use_violations and ev.violations:
            comp["violation"] = -c.w_violation * _sat(ev.violations, c.saturation_k) * unattr
        if c.use_violations and ev.authz_violations:
            # Cryptographically bound to the identity -> full weight with escalation.
            comp["authz_violation"] = -c.w_violation * _sat(ev.authz_violations, c.saturation_k) * m
        if c.use_anomaly:
            # Attribution-aware: the rate of *verified* packets is what the identity holder
            # sent; spoofed packets cannot inflate it (see requirement R4).
            rate = float(ev.verified if discount else ev.tx_count)
            score = self._anomaly(st, rate)
            if score > 0:
                if c.use_ml and ev.attack_prob is not None:
                    # The anomaly is about the holder's own verified traffic, so only
                    # *insider*-class probability may corroborate it (an outsider forging
                    # this identity must not turn a legitimate burst into evidence).
                    insider = ev.insider_prob if ev.insider_prob is not None else ev.attack_prob
                    corroboration = max(insider if discount else ev.attack_prob, c.anomaly_ml_floor)
                    comp["anomaly"] = -c.w_anomaly * score * attr * corroboration
                else:  # no learned detector: the heuristic is primary evidence
                    comp["anomaly"] = -c.w_anomaly * score * m * attr
        if ev.reauth_success:
            comp["reauth_success"] = c.w_reauth_success
        has_negative = any(v < 0 for v in comp.values())
        if not c.use_ml and not has_negative and ev.tx_count > 0:
            comp["normal_behaviour"] = c.w_normal  # ML ablation: benign window evidence
        positive = sum(v for v in comp.values() if v > 0)
        negative = -sum(v for v in comp.values() if v < 0)
        st.alpha += positive
        st.beta += negative
        if negative >= c.bad_window_mass:
            st.bad_windows.append(ev.window)
        new = st.trust()
        reason = self._reason(ev, comp, m, attr)
        update = TrustUpdate(ev.drone_id, ev.window, ev.t_ms, previous, new, st.alpha, st.beta,
                             positive, negative, comp, m, ev, reason)  # fmt: skip
        self.log.append(update)
        return update

    def reward_reauthentication(self, drone_id: str, window: int, t_ms: int) -> TrustUpdate:
        """Positive evidence for passing a policy-forced re-authentication."""
        return self.update(Evidence(drone_id, window, t_ms, reauth_success=1))

    @staticmethod
    def _reason(ev: Evidence, comp: dict[str, float], m: float, attr: float) -> str:
        parts = []
        if "ml_attack" in comp:
            cls = f" ({ev.attack_class})" if ev.attack_class else ""
            parts.append(f"IDS P(attack)={ev.attack_prob:.2f}{cls}, attribution={attr:.2f}")
        if ev.auth_failures:
            parts.append(f"{ev.auth_failures} D2DAP auth failure(s)")
        if ev.auth_success:
            parts.append(f"{ev.auth_success} successful MAKA")
        if ev.violations:
            parts.append(f"{ev.violations} integrity/replay/unauthenticated verdict(s)")
        if ev.authz_violations:
            parts.append(f"{ev.authz_violations} privileged command(s) from a non-leader")
        if "anomaly" in comp:
            parts.append("transmission-rate anomaly")
        if ev.reauth_success:
            parts.append("passed forced re-authentication")
        if m > 1.0 and any(v < 0 for v in comp.values()):
            parts.append(f"repeat-offender x{m:.2f}")
        return "; ".join(parts) if parts else "no evidence (decay toward prior)"
