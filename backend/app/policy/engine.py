"""Adaptive policy engine (OUR PROPOSED CONTRIBUTION, Phase 13).

Maps trust to graded security states with hysteresis and hard rules, and explains every
decision in plain language.

Default bands (configurable; evaluated experimentally in Phase 16, not assumed optimal):

    trust >= 0.80 NORMAL | >= 0.60 MONITOR | >= 0.40 RESTRICT | >= 0.20 RE-AUTHENTICATE
    trust <  0.20 QUARANTINE

Hard rules:

* moving to a *less severe* state requires trust >= band threshold + hysteresis;
* a failed policy-forced re-authentication -> QUARANTINE;
* entering RE-AUTHENTICATE ``reauth_repeat_limit`` times within ``reauth_window_s`` ->
  QUARANTINE (repeat offender that passes authentication but keeps misbehaving);
* QUARANTINE is left only after ``quarantine_min_s``, a *successful* re-authentication,
  and trust above the RESTRICT band (+ hysteresis); the drone then enters RESTRICT
  (probation).

``mode="binary"`` (System C) replaces the graded ladder by a single block threshold.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from pydantic import BaseModel, Field, model_validator

from app.models.enums import SecurityState
from app.trust.engine import TrustUpdate

S = SecurityState


class PolicyConfig(BaseModel):
    mode: str = Field("graded", pattern="^(graded|binary)$")
    normal: float = Field(0.80, gt=0, lt=1)
    monitor: float = Field(0.60, gt=0, lt=1)
    restrict: float = Field(0.40, gt=0, lt=1)
    reauthenticate: float = Field(0.20, gt=0, lt=1)
    hysteresis: float = Field(0.05, ge=0, lt=0.5)
    binary_threshold: float = Field(0.50, gt=0, lt=1)
    reauth_repeat_limit: int = Field(2, ge=1)
    reauth_window_s: float = Field(60.0, gt=0)
    quarantine_min_s: float = Field(20.0, ge=0)
    restrict_rate_pps: float = Field(5.0, gt=0)
    restrict_burst: float = Field(10.0, gt=0)

    @model_validator(mode="after")
    def _ordered(self) -> PolicyConfig:
        if not self.normal > self.monitor > self.restrict > self.reauthenticate:
            raise ValueError("thresholds must satisfy normal > monitor > restrict > reauthenticate")
        return self

    def threshold(self, state: SecurityState) -> float:
        """Lower trust bound of a state's band."""
        return {S.NORMAL: self.normal, S.MONITOR: self.monitor, S.RESTRICT: self.restrict,
                S.REAUTHENTICATE: self.reauthenticate, S.QUARANTINE: 0.0}[state]  # fmt: skip


#: Actions executed when a state is *entered*.
ENTRY_ACTIONS: dict[SecurityState, tuple[str, ...]] = {
    S.NORMAL: ("lift_restrictions",),
    S.MONITOR: ("increase_monitoring",),
    S.RESTRICT: ("rate_limit", "block_privileged_commands"),
    S.REAUTHENTICATE: ("rate_limit", "block_privileged_commands", "revoke_sessions",
                       "force_reauthentication"),
    S.QUARANTINE: ("revoke_sessions", "drop_all_traffic", "block_new_sessions",
                   "broadcast_quarantine_notice"),
}  # fmt: skip


@dataclass(frozen=True)
class PolicyDecision:
    drone_id: str
    t_ms: int
    previous_state: SecurityState
    new_state: SecurityState
    trust_before: float
    trust_after: float
    actions: tuple[str, ...]
    rule: str
    explanation: str

    def as_record(self) -> dict[str, object]:
        return {"drone_id": self.drone_id, "t_ms": self.t_ms,
                "previous_state": self.previous_state.value, "new_state": self.new_state.value,
                "trust_before": round(self.trust_before, 4),
                "trust_after": round(self.trust_after, 4), "actions": "|".join(self.actions),
                "rule": self.rule, "explanation": self.explanation}  # fmt: skip


@dataclass
class _PolicyState:
    state: SecurityState = S.NORMAL
    since_ms: int = 0
    reauth_entries: deque[int] = field(default_factory=deque)
    reauth_success_since_quarantine: bool = False


class PolicyEngine:
    """Stateful mapping from trust updates to security states."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()
        self._states: dict[str, _PolicyState] = {}
        self.decisions: list[PolicyDecision] = []

    def state(self, drone_id: str) -> SecurityState:
        return self._ps(drone_id).state

    def _ps(self, drone_id: str) -> _PolicyState:
        return self._states.setdefault(drone_id, _PolicyState())

    # ------------------------------------------------------------- band logic
    def _band(self, trust: float) -> SecurityState:
        c = self.config
        if c.mode == "binary":
            return S.NORMAL if trust >= c.binary_threshold else S.QUARANTINE
        for st in (S.NORMAL, S.MONITOR, S.RESTRICT, S.REAUTHENTICATE):
            if trust >= c.threshold(st):
                return st
        return S.QUARANTINE

    def _with_hysteresis(self, current: SecurityState, trust: float) -> SecurityState:
        target = self._band(trust)
        if self.config.mode == "binary":
            if (
                current is S.QUARANTINE
                and trust < self.config.binary_threshold + self.config.hysteresis
            ):
                return S.QUARANTINE
            return target
        if target.severity >= current.severity:
            return target
        # Relaxing: step down only while trust clears the destination band + hysteresis.
        while target.severity < current.severity and trust < (
            self.config.threshold(target) + self.config.hysteresis
        ):
            target = _LADDER[target.severity + 1]
        return target

    # ------------------------------------------------------------- decisions
    def evaluate(self, update: TrustUpdate) -> PolicyDecision | None:
        """Re-evaluate after a trust update; returns a decision if the state changes."""
        ps = self._ps(update.drone_id)
        c = self.config
        now = update.t_ms
        target = self._with_hysteresis(ps.state, update.new)
        rule = "trust band"
        if update.evidence.reauth_success and ps.state is S.QUARANTINE:
            ps.reauth_success_since_quarantine = True
        if ps.state is S.QUARANTINE and c.mode == "graded":
            elapsed = (now - ps.since_ms) / 1000
            if (elapsed >= c.quarantine_min_s and ps.reauth_success_since_quarantine
                    and update.new >= c.restrict + c.hysteresis):  # fmt: skip
                target, rule = S.RESTRICT, "quarantine exit: min duration + re-authentication"
            else:
                target = S.QUARANTINE
        if target is S.REAUTHENTICATE and ps.state is not S.REAUTHENTICATE and c.mode == "graded":
            while ps.reauth_entries and ps.reauth_entries[0] < now - c.reauth_window_s * 1000:
                ps.reauth_entries.popleft()
            if len(ps.reauth_entries) >= c.reauth_repeat_limit:
                target, rule = (
                    S.QUARANTINE,
                    (
                        f"repeat offender: re-authentication required {c.reauth_repeat_limit + 1} "
                        f"times within {c.reauth_window_s:.0f} s"
                    ),
                )
        return self._transition(update.drone_id, target, update, rule)

    def reauthentication_failed(self, drone_id: str, t_ms: int, trust: float, reason: str
                                ) -> PolicyDecision | None:  # fmt: skip
        """Hard rule: a failed forced re-authentication quarantines the drone."""
        if self._ps(drone_id).state is not S.REAUTHENTICATE:
            return None
        rule = f"failed re-authentication ({reason})"
        return self._transition(drone_id, S.QUARANTINE, None, rule, t_ms=t_ms, trust=trust)

    def _transition(
        self,
        drone_id: str,
        target: SecurityState,
        update: TrustUpdate | None,
        rule: str,
        *,
        t_ms: int = 0,
        trust: float = 0.0,
    ) -> PolicyDecision | None:
        ps = self._ps(drone_id)
        if target is ps.state:
            return None
        now = update.t_ms if update else t_ms
        before = update.previous if update else trust
        after = update.new if update else trust
        if target is S.REAUTHENTICATE:
            ps.reauth_entries.append(now)
        if target is S.QUARANTINE:
            ps.reauth_success_since_quarantine = False
        decision = PolicyDecision(drone_id, now, ps.state, target, before, after,
                                  ENTRY_ACTIONS[target], rule,
                                  self._explain(drone_id, prev=ps.state, new=target, before=before,
                                                after=after, update=update, rule=rule))  # fmt: skip
        ps.state, ps.since_ms = target, now
        self.decisions.append(decision)
        return decision

    def _explain(
        self,
        drone_id: str,
        *,
        prev: SecurityState,
        new: SecurityState,
        before: float,
        after: float,
        update: TrustUpdate | None,
        rule: str,
    ) -> str:
        lines = [f"Drone {drone_id}", f"Trust before = {before:.2f}"]
        if update is not None:
            ev = update.evidence
            if ev.attack_prob is not None:
                cls = f" ({ev.attack_class})" if ev.attack_class else ""
                lines.append(f"Attack probability = {ev.attack_prob:.2f}{cls}")
            lines.append(f"Authentication failures = {ev.auth_failures}")
            if ev.violations:
                lines.append(f"Integrity/replay/unauthenticated verdicts = {ev.violations}")
            lines.append(f"Verified (identity-bound) traffic = {ev.attribution:.0%}")
            lines.append(f"Evidence: {update.reason}")
        lines += [f"Trust after = {after:.2f}",
                  f"Decision = {new.value.upper()} (from {prev.value.upper()})",
                  f"Rule = {rule}", f"Actions = {', '.join(ENTRY_ACTIONS[new])}"]  # fmt: skip
        return "\n".join(lines)


_LADDER = [S.NORMAL, S.MONITOR, S.RESTRICT, S.REAUTHENTICATE, S.QUARANTINE]
