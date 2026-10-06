"""Attacks by adversaries that are NOT legitimate members of the swarm.

Each attacker is a separate radio node (``X-<attack_id>``) that shadows the drone it
targets. All attacks act on real protocol messages and real packets.
"""

from __future__ import annotations

from typing import Any

from app.attacks.base import Attack, Stride
from app.core.rng import RandomStreams
from app.models.enums import PacketProtocol
from app.models.packet import Packet
from app.security.d2dap.agent import DroneSecurityAgent
from app.security.d2dap.config import D2DAPConfig
from app.security.d2dap.entities import ProtocolAbort
from app.security.d2dap.service import D2DAPSystem
from app.security.puf import BoundPUF, XORArbiterPUF
from app.services.auth_coordinator import AuthEvent
from app.services.secure_transport import DATA_PROTOCOLS


class _RateSource:
    """Poisson emission of attacker-crafted packets (builder callback per packet)."""

    def __init__(self, attack: Attack, rate_pps: float, build: Any) -> None:
        self.attack, self.rate, self.build = attack, rate_pps, build

    def generate(self, now_ms: int, dt_ms: int) -> list[Packet]:
        n = int(self.attack.rng.poisson(self.rate * dt_ms / 1000.0))
        out = []
        for _ in range(n):
            pkt = self.build(now_ms)
            if pkt is not None:
                self.attack.evidence.packets_attempted += 1
                out.append(pkt)
        return out


class _ExternalAttack(Attack):
    """Spawns the attacker node at start and removes it at the end."""

    def _start(self, now_ms: int) -> None:
        self.spawn_attacker_node(self.spec.target)
        self.on_start(now_ms)

    def on_start(self, now_ms: int) -> None:
        """Subclass hook."""

    def _on_tick(self, now_ms: int) -> None:
        self.follow()

    def _stop(self, now_ms: int) -> None:
        self.engine.leave(self.attacker_id)

    def victim_peer(self) -> str | None:
        peers = [p for p in self.peers_of(self.spec.target) if p != self.attacker_id]
        return peers[int(self.rng.integers(0, len(peers)))] if peers else None


class SpoofingAttack(_ExternalAttack):
    """Claims the identity of ``target``: forged data (with sniffed session ids) and
    forged AUTH_REQUESTs signed with the attacker's own random key."""

    kind = "spoofing"
    stride = (Stride.SPOOFING,)

    def on_start(self, now_ms: int) -> None:
        self.add_source(self.attacker_id, _RateSource(self, self.spec.rate_pps, self._build))

    def _build(self, now_ms: int) -> Packet | None:
        dst = self.victim_peer()
        if dst is None:
            return None
        if self.rng.random() < 0.1:  # forged authentication request
            size = self.auth_wire_size()
            return self.make_packet(dst, PacketProtocol.AUTH_REQUEST, size,
                                    payload=self.rng.bytes(size))  # fmt: skip
        victim = self.target_drone()
        sid = next(iter(victim.sessions.values())).session_id if victim.sessions else None
        size = int(self.rng.integers(60, 200))
        pkt = self.make_packet(dst, PacketProtocol.TELEMETRY, size)
        if sid is not None and self.rng.random() < 0.5:  # sniffed session id, forged payload
            pkt.session_id = sid
            pkt.payload = self.rng.bytes(size)
        return pkt


class ReplayAttack(_ExternalAttack):
    """Records the target's AUTH_REQUESTs and sealed data packets; replays them.

    ``params.window``: ``"in"`` replays M1 within Delta T of capture (observation O1/O2),
    ``"stale"`` replays only captures older than Delta T.
    """

    kind = "replay"
    stride = (Stride.SPOOFING, Stride.DENIAL_OF_SERVICE)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._auth: list[tuple[int, Packet]] = []
        self._data: list[Packet] = []
        self.network.add_observer(self._capture)
        self.evidence.extra.update(replayed_auth=0, replayed_data=0, auth_replays_accepted=0)

    def _capture(self, p: Packet) -> None:
        if p.src != self.spec.target or p.attack_id is not None:
            return
        if p.protocol is PacketProtocol.AUTH_REQUEST and p.payload is not None:
            self._auth.append((p.timestamp_ms, p))
            self._auth = self._auth[-20:]
        elif (
            p.protocol is not PacketProtocol.HEARTBEAT
            and p.dropped_reason is None
            and (p.session_id is not None or not self.swarm.transport.require_auth)
        ):  # sealed data (D2DAP) or plaintext data (no-authentication baseline)
            self._data.append(p)
            self._data = self._data[-200:]

    def on_start(self, now_ms: int) -> None:
        self.add_source(self.attacker_id, _RateSource(self, self.spec.rate_pps, self._build))

    def _clone(self, orig: Packet, now_ms: int) -> Packet:
        return self.make_packet(orig.dst, orig.protocol, orig.size_bytes, payload=orig.payload,
                                seq=orig.seq)  # fmt: skip

    def _build(self, now_ms: int) -> Packet | None:
        delta_t = self.swarm.d2dap.config.delta_t_ms
        fresh = self.spec.params.get("window", "in") == "in"
        auths = [(t, p) for t, p in self._auth
                 if (now_ms - t <= delta_t) == fresh]  # fmt: skip
        if auths and self.rng.random() < 0.5:
            _, orig = auths[int(self.rng.integers(0, len(auths)))]
            self.evidence.extra["replayed_auth"] += 1
            return self._clone(orig, now_ms)
        if self._data:
            orig = self._data[int(self.rng.integers(0, len(self._data)))]
            pkt = self._clone(orig, now_ms)
            pkt.seq = orig.seq  # identical nonce/AAD -> exact replay
            pkt.session_id = orig.session_id
            self.evidence.extra["replayed_data"] += 1
            return pkt
        return None

    def make_packet(self, dst: str, protocol: Any, size: int, **kw: Any) -> Packet:
        seq = kw.pop("seq", None)
        pkt = super().make_packet(dst, protocol, size, **kw)
        if seq is not None:
            pkt.seq = seq
        return pkt

    def _on_auth(self, event: AuthEvent) -> None:
        super()._on_auth(event)
        if self.active and self.attributes_auth(event) and event.success:
            self.evidence.extra["auth_replays_accepted"] += 1


class TamperingAttack(_ExternalAttack):
    """On-path attacker flipping ciphertext bits of packets sent by ``target``."""

    kind = "tampering"
    stride = (Stride.TAMPERING,)

    def on_start(self, now_ms: int) -> None:
        prob = float(self.spec.params.get("probability", 0.5))

        def tamper(p: Packet, receiver: Any) -> str | None:
            plaintext_data = (
                p.payload is None
                and p.protocol in DATA_PROTOCOLS
                and (not self.swarm.transport.require_auth)
            )
            if (self.active and p.src == self.spec.target and p.attack_id is None
                    and (p.payload or plaintext_data)
                    and self.rng.random() < prob):  # fmt: skip
                self.evidence.packets_attempted += 1
                if p.payload:
                    idx = int(self.rng.integers(0, len(p.payload)))
                    p.payload = (p.payload[:idx] + bytes([p.payload[idx] ^ 0x04])
                                 + p.payload[idx + 1 :])  # fmt: skip
                # A plaintext packet (no-authentication baseline) is modified silently:
                # there is no integrity check, so the receiver accepts the altered content.
                p.label, p.attack_id = self.kind, self.spec.attack_id
            return None

        self.network.add_filter(f"tamper-{self.spec.attack_id}", tamper)


class DosAuthFloodAttack(_ExternalAttack):
    """Floods ``target`` with bogus AUTH_REQUESTs (spoofed random claimed sources).

    Each request forces the victim to run D2DAP verification (trial decryption over the
    directory in ``trial`` mode): computational DoS on a resource-constrained drone.
    """

    kind = "dos"
    stride = (Stride.DENIAL_OF_SERVICE,)

    def on_start(self, now_ms: int) -> None:
        self.add_source(self.attacker_id, _RateSource(self, self.spec.rate_pps, self._build))

    def _build(self, now_ms: int) -> Packet | None:
        size = self.auth_wire_size()
        ids = sorted(i for i in self.network.nodes if not i.startswith("X-"))
        claimed = str(self.rng.choice(ids)) if self.spec.params.get("spoof_src", True) else (
            self.attacker_id)  # fmt: skip
        return self.make_packet(self.spec.target, PacketProtocol.AUTH_REQUEST, size,
                                payload=self.rng.bytes(size), src=claimed)  # fmt: skip


class ImpersonationAttack(_ExternalAttack):
    """Node-capture + cloning (D2DAP's GM4): the target is physically captured (leaves),
    its stored credentials are extracted, and a clone with a *different* PUF claims its
    identity, attempting MAKA with the target's former peers and sending data."""

    kind = "impersonation"
    stride = (Stride.SPOOFING, Stride.ELEVATION_OF_PRIVILEGE)

    def on_start(self, now_ms: int) -> None:
        self.clone: DroneSecurityAgent | None = None
        self._peers = self.peers_of(self.spec.target)
        anchor = self._peers[0] if self._peers else self.spec.target
        self._follow = anchor
        self.engine.leave(self.spec.target)  # the real drone has been captured
        self.add_source(self.attacker_id, _RateSource(self, self.spec.rate_pps, self._build))
        victim_agent = self.swarm.d2dap.agents.get(self.spec.target)
        if victim_agent is None or victim_agent.credentials is None:
            # No-authentication baseline: nothing to extract; the clone just claims the ID.
            self.evidence.extra["credentials_extracted"] = False
            return
        clone_puf = XORArbiterPUF(self.rng)  # attacker's own silicon
        sys = self.swarm.d2dap
        self.clone = DroneSecurityAgent(
            self.spec.target, BoundPUF(self.spec.target, clone_puf), sys.config,
            directory=sys.directory, revocation_list=sys.revocation_list,
            rand=self.swarm.streams.crypto(f"clone:{self.spec.attack_id}"),
        )  # fmt: skip
        self.clone.install(victim_agent.credentials.clone())
        self.evidence.extra["credentials_extracted"] = True

    def _build(self, now_ms: int) -> Packet | None:
        peers = [p for p in self.peers_of(self.attacker_id) if p != self.spec.target]
        if not peers:
            return None
        dst = peers[int(self.rng.integers(0, len(peers)))]
        if self.clone is not None and self.rng.random() < 0.3:
            self.clone.abort_pending(dst)
            try:
                m1 = self.clone.initiate(dst, now_ms)
            except ProtocolAbort:  # e.g. the clone ran out of extracted CRPs
                return None
            return self.make_packet(dst, PacketProtocol.AUTH_REQUEST, len(m1), payload=m1)
        return self.make_packet(dst, PacketProtocol.TELEMETRY, int(self.rng.integers(80, 160)))


class UnauthorizedAccessAttack(_ExternalAttack):
    """An unregistered (rogue) drone with its own key pair and CS tries to join."""

    kind = "unauthorized_access"
    stride = (Stride.SPOOFING, Stride.ELEVATION_OF_PRIVILEGE)

    def on_start(self, now_ms: int) -> None:
        cfg = D2DAPConfig(security_level=self.swarm.d2dap.config.security_level, crp_count=256)
        rogue_sys = D2DAPSystem(cfg, RandomStreams(int(self.rng.integers(1, 2**31))))
        rogue_sys.enroll(self.attacker_id)
        self.rogue = rogue_sys.agents[self.attacker_id]
        # The rogue can read the victim network's published public keys.
        for i, Y in self.swarm.d2dap.directory.keys.items():
            rogue_sys.directory.publish(i, Y)
        self.add_source(self.attacker_id, _RateSource(self, self.spec.rate_pps, self._build))

    def _build(self, now_ms: int) -> Packet | None:
        dst = self.victim_peer()
        if dst is None:
            return None
        if self.rng.random() < 0.3:
            self.rogue.abort_pending(dst)
            try:
                m1 = self.rogue.initiate(dst, now_ms)
            except ProtocolAbort:  # no published key for dst (no-authentication baseline)
                m1 = None
            if m1 is not None:
                return self.make_packet(dst, PacketProtocol.AUTH_REQUEST, len(m1), payload=m1,
                                        src=self.attacker_id)  # fmt: skip
        return self.make_packet(dst, PacketProtocol.COMMAND, 80, src=self.attacker_id)


class EavesdroppingAttack(_ExternalAttack):
    """Passive capture near ``target``: measures what an eavesdropper can learn.

    Sends nothing (undetectable by traffic-based IDS by construction).
    """

    kind = "eavesdropping"
    stride = (Stride.INFORMATION_DISCLOSURE,)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._seen: list[Packet] = []
        self.network.add_observer(self._sniff)

    def _sniff(self, p: Packet) -> None:
        if not self.active or p.attack_id is not None:
            return
        me = self.network.nodes.get(self.attacker_id)
        sender = self.network.nodes.get(p.true_src)
        if me is None or sender is None:
            return
        if self.network.channel.in_range(me.distance_to(sender)):
            self._seen.append(p)

    def _stop(self, now_ms: int) -> None:
        data = [p for p in self._seen if p.protocol in (PacketProtocol.TELEMETRY,
                PacketProtocol.VIDEO, PacketProtocol.COMMAND)]  # fmt: skip
        auth = [p for p in self._seen if p.protocol is PacketProtocol.AUTH_REQUEST and p.payload]
        ids = [i.encode() for i in self.network.nodes]
        self.evidence.extra.update(
            captured=len(self._seen),
            data_captured=len(data),
            data_plaintext_fraction=(
                sum(p.session_id is None for p in data) / len(data) if data else None
            ),
            auth_msgs_with_identity=sum(any(i in (p.payload or b"") for i in ids) for p in auth),
            auth_msgs_captured=len(auth),
            link_layer_src_exposed_fraction=1.0 if self._seen else None,
        )
        super()._stop(now_ms)


__all__ = [
    "DosAuthFloodAttack",
    "EavesdroppingAttack",
    "ImpersonationAttack",
    "ReplayAttack",
    "SpoofingAttack",
    "TamperingAttack",
    "UnauthorizedAccessAttack",
]
