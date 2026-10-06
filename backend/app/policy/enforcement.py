"""Policy enforcement at the receivers (ingress filter) + session-level actions.

* RESTRICT and more severe: token-bucket rate limit on the source's data and auth
  packets; privileged COMMAND packets from the source are dropped.
* RE-AUTHENTICATE: all sessions of the drone are revoked; fresh D2DAP MAKA is needed.
* QUARANTINE: every packet from the source is dropped; the drone may not open sessions;
  a POLICY_NOTICE is broadcast (counted as overhead). After the minimum quarantine time
  the drone may attempt re-authentication (AUTH_REQUESTs pass the filter).
* ``block_until`` implements the one-window blocking of the naive IDS->block baseline.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from app.core.logging import get_logger
from app.models.enums import BROADCAST, PacketProtocol, SecurityState
from app.models.packet import Packet
from app.policy.engine import PolicyConfig, PolicyDecision
from app.services.secure_transport import DATA_PROTOCOLS
from app.services.swarm import SecureSwarm
from app.simulation.drone import Drone

log = get_logger(__name__)
S = SecurityState
NOTICE_BYTES = 48


@dataclass
class _Bucket:
    tokens: float
    last_ms: int


class PolicyEnforcer:
    def __init__(self, swarm: SecureSwarm, config: PolicyConfig, host: str = "D1",
                 enforce: bool = True) -> None:  # fmt: skip
        self.swarm = swarm
        self.config = config
        self.host = host
        self.enforce = enforce
        self.states: dict[str, SecurityState] = {}
        self.quarantined_at: dict[str, int] = {}
        self.blocked_until: dict[str, int] = {}
        self._buckets: dict[str, _Bucket] = {}
        self.dropped: Counter[str] = Counter()
        self.notice_bytes = 0

    def install(self) -> None:
        self.swarm.engine.network.add_filter("policy", self._filter)

    # ------------------------------------------------------------- filter
    def _rate_ok(self, src: str, t_ms: int) -> bool:
        c = self.config
        b = self._buckets.setdefault(src, _Bucket(c.restrict_burst, t_ms))
        b.tokens = min(c.restrict_burst, b.tokens + (t_ms - b.last_ms) / 1000 * c.restrict_rate_pps)
        b.last_ms = t_ms
        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return True
        return False

    def _probation(self, src: str, t_ms: int) -> bool:
        since = self.quarantined_at.get(src)
        return since is not None and t_ms - since >= self.config.quarantine_min_s * 1000

    def _filter(self, p: Packet, receiver: Drone) -> str | None:
        if not self.enforce or p.protocol in (PacketProtocol.TRUST_REPORT,
                                              PacketProtocol.POLICY_NOTICE):  # fmt: skip
            return None
        t = p.delivered_ms or p.timestamp_ms
        reason: str | None = None
        if self.blocked_until.get(p.src, -1) >= t:
            reason = "ids_block"
        else:
            st = self.states.get(p.src, S.NORMAL)
            if st is S.QUARANTINE:
                allowed = p.protocol is PacketProtocol.AUTH_REQUEST and self._probation(p.src, t)
                reason = None if allowed else "quarantine"
            elif st.severity >= S.RESTRICT.severity:
                if p.protocol is PacketProtocol.COMMAND:
                    reason = "privileged_blocked"
                elif (p.protocol in DATA_PROTOCOLS or p.protocol is PacketProtocol.AUTH_REQUEST
                      ) and not self._rate_ok(p.src, t):  # fmt: skip
                    reason = "rate_limited"
        if reason is not None:
            self.dropped[reason] += 1
            # Verify-then-drop: keep attribution of policy-dropped traffic.
            p.integrity_ok = self.swarm.transport.inspect(p, receiver)
        return reason

    # ------------------------------------------------------------- actions
    def block_until(self, src: str, t_ms: int) -> None:
        self.blocked_until[src] = t_ms

    def apply(self, decision: PolicyDecision) -> None:
        d, new, now = decision.drone_id, decision.new_state, decision.t_ms
        self.states[d] = new
        drone = self.swarm.engine.network.nodes.get(d)
        if drone is not None:
            drone.security_state = new
        if not self.enforce:
            return
        coord = self.swarm.coordinator
        registered = d in self.swarm.d2dap.agents
        if decision.previous_state is S.QUARANTINE and new is not S.QUARANTINE:
            coord.block_initiator(d, False)
            self.quarantined_at.pop(d, None)
        if new is S.REAUTHENTICATE and registered and drone is not None:
            coord.reauthenticate(d, now)
        if new is S.QUARANTINE:
            if registered and drone is not None:
                coord.revoke_sessions(d)
            coord.block_initiator(d, True)
            self.quarantined_at[d] = now
            self._notice(d, now)
        log.info("policy.decision", drone=d, state=new.value, t_ms=now,
                 trust=round(decision.trust_after, 3))  # fmt: skip

    def tick(self, now_ms: int) -> None:
        """Allow quarantined drones to attempt re-authentication after probation starts."""
        for d, since in self.quarantined_at.items():
            if now_ms - since >= self.config.quarantine_min_s * 1000:
                self.swarm.coordinator.block_initiator(d, False)

    def _notice(self, quarantined: str, now: int) -> None:
        host = self.swarm.engine.network.nodes.get(self.host)
        if host is None or not host.active:
            return
        proto = PacketProtocol.POLICY_NOTICE
        pkt = self.swarm.engine.factory.make(now, self.host, BROADCAST, proto, NOTICE_BYTES)
        pkt.meta["quarantined"] = quarantined
        self.notice_bytes += NOTICE_BYTES
        self.swarm.engine.network.send(pkt)
