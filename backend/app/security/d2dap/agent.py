"""On-drone D2DAP logic: registration response and the MAKA initiator/responder roles.

The order of checks follows Fig. 3 of the paper exactly:

* Responder (V1): decrypt CM -> freshness -> VerifySign -> pick (C_jk, b_jk), PUF ->
  RL check -> reconstruct A -> V_j check -> RL insert/broadcast -> DM, sign, SK ->
  delete (C_jk, b_jk).
* Initiator (V2): decrypt DM -> freshness -> RL membership -> reconstruct A ->
  V_i check -> VerifySign -> SK -> delete (C_ik, b_ik).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from app.core.rng import RandomSource
from app.security.crypto import CryptoSuite, OpCounter, Point
from app.security.d2dap.config import D2DAPConfig
from app.security.d2dap.entities import (
    DroneCredentials,
    FailureReason,
    PendingSession,
    ProtocolAbort,
    PublicDirectory,
    SessionRecord,
)
from app.security.d2dap.messages import AuthMessage, MalformedMessageError, ShareBody
from app.security.d2dap.revocation import RevocationList
from app.security.puf import BoundPUF
from app.security.secret_sharing import SecretSharingError, ShamirScheme
from app.security.signature import gen_sign, verify_sign


@dataclass
class ResponderResult:
    """Outcome of processing an M1 at the responder."""

    peer_id: str
    m2: bytes
    session: SessionRecord


@dataclass(frozen=True)
class _Candidate:
    peer_id: str
    key: bytes
    body: ShareBody
    Y: Point


class DroneSecurityAgent:
    """D2DAP protocol endpoint running on one drone."""

    def __init__(
        self,
        drone_id: str,
        puf: BoundPUF,
        config: D2DAPConfig,
        *,
        directory: PublicDirectory,
        revocation_list: RevocationList,
        rand: RandomSource,
    ) -> None:
        self.drone_id = drone_id
        self.id_bytes = drone_id.encode()
        self._puf = puf
        self.config = config
        self.directory = directory
        self.rl = revocation_list
        self._rand = rand
        self.suite = CryptoSuite(config.security_level, rand)
        self.shamir = ShamirScheme(self.suite.n, 2, self.suite.ops)
        self.credentials: DroneCredentials | None = None
        self.pending: dict[str, PendingSession] = {}
        self.sessions: dict[str, SessionRecord] = {}
        self._replay_cache: dict[bytes, int] = {}

    # ------------------------------------------------------------- helpers
    @property
    def ops(self) -> OpCounter:
        return self.suite.ops

    def _creds(self) -> DroneCredentials:
        if self.credentials is None:
            raise ProtocolAbort(FailureReason.NOT_REGISTERED, self.drone_id)
        return self.credentials

    def _puf_a(self, challenge: bytes) -> bytes:
        """``a = H(PUF(C) || ID)`` evaluated on this device's PUF (T_PUF + T_H)."""
        response = self._puf.evaluate(challenge, caller_id=self.drone_id)
        self.suite.ops.puf += 1
        return self.suite.H(response, self.id_bytes)

    def _free_challenges(self) -> list[bytes]:
        reserved = {p.challenge for p in self.pending.values()}
        return [c for c in self._creds().challenges if c not in reserved]

    def _pick_challenge(self) -> bytes:
        free = self._free_challenges()
        if not free:
            raise ProtocolAbort(FailureReason.CRP_EXHAUSTED, self.drone_id)
        return free[self._rand.randbelow(len(free))]

    def _shared_key(self, Y_peer: Point) -> bytes:
        return self.suite.kdf(self.suite.mul(Y_peer, self._creds().x))

    def _reconstruct_and_check(self, a_i: bytes, b_i: int, a_j: bytes, b_j: int) -> None:
        try:
            A = self.shamir.reconstruct(
                [(self.suite.to_scalar(a_i), b_i), (self.suite.to_scalar(a_j), b_j)]
            )
        except SecretSharingError as exc:
            raise ProtocolAbort(FailureReason.MALFORMED, str(exc)) from exc
        if (
            self.suite.H(A.to_bytes(self.suite.scalar_bytes, "big"), self.id_bytes)
            != self._creds().V
        ):
            raise ProtocolAbort(FailureReason.SECRET_MISMATCH)

    @staticmethod
    def _session_id(sk: bytes) -> str:
        """Public session label (not a protocol step; deliberately not op-counted)."""
        return hashlib.sha3_256(b"session-id" + sk).digest()[:8].hex()

    @property
    def crp_remaining(self) -> int:
        return 0 if self.credentials is None else len(self.credentials.challenges)

    # ------------------------------------------------------------- registration
    def registration_respond(self, challenges: list[bytes]) -> tuple[list[bytes], Point, int]:
        """Device side of registration: pick ``x_i``, compute ``Y_i`` and ``a_i``."""
        x = self.suite.rand_scalar()
        Y = self.suite.mul_g(x)
        a_list = [self._puf_a(c) for c in challenges]
        return a_list, Y, x

    def registration_a(self, challenge: bytes) -> bytes:
        """Device side of CRP re-provisioning: ``a = H(PUF(C) || ID)``."""
        return self._puf_a(challenge)

    def install(self, credentials: DroneCredentials) -> None:
        self.credentials = credentials
        self.pending.clear()

    # ------------------------------------------------------------- initiator
    def initiate(self, peer_id: str, now_ms: int) -> bytes:
        """Build M1 = {CM, sigma1, sigma2} for ``peer_id``."""
        creds = self._creds()
        Y_j = self.directory.get(peer_id)
        if Y_j is None:
            raise ProtocolAbort(FailureReason.UNKNOWN_PEER, peer_id)
        challenge = self._pick_challenge()
        key = self._shared_key(Y_j)
        a = self._puf_a(challenge)
        b = creds.share_for(challenge)
        body = ShareBody(a, b, now_ms)
        cm = self.suite.encrypt(key, body.to_bytes(self.suite))
        s1, s2 = gen_sign(self.suite, cm, a, body.t_bytes, creds.x)
        self.pending[peer_id] = PendingSession(peer_id, challenge, a, b, now_ms, key)
        return AuthMessage(cm, s1, s2).to_bytes(self.suite.scalar_bytes)

    # ------------------------------------------------------------- responder
    def _candidates(self, hint: str | None) -> list[str]:
        if self.config.peer_resolution == "hint":
            if hint is None or self.directory.get(hint) is None or hint == self.drone_id:
                raise ProtocolAbort(FailureReason.UNKNOWN_PEER, str(hint))
            return [hint]
        ids = [i for i in self.directory.ids() if i != self.drone_id]
        # Random trial order: expected cost (n-1)/2 key derivations, no positional bias.
        for i in range(len(ids) - 1, 0, -1):
            j = self._rand.randbelow(i + 1)
            ids[i], ids[j] = ids[j], ids[i]
        return ids

    def _resolve(self, msg: AuthMessage, now_ms: int, hint: str | None) -> _Candidate:
        """Find the sender key: decrypt -> freshness -> VerifySign (per candidate)."""
        sig_failures = 0
        for peer in self._candidates(hint):
            Y = self.directory.get(peer)
            key = self._shared_key(Y)
            try:
                body = ShareBody.from_bytes(self.suite.decrypt(key, msg.body), self.suite)
            except MalformedMessageError:
                continue
            if abs(now_ms - body.t_ms) > self.config.delta_t_ms:
                continue
            if not verify_sign(
                self.suite,
                msg.body,
                (msg.sigma_a, msg.sigma_b),
                a=body.a,
                t_bytes=body.t_bytes,
                Y=Y,
            ):
                sig_failures += 1
                continue
            return _Candidate(peer, key, body, Y)
        reason = FailureReason.SIGNATURE if sig_failures else FailureReason.FRESHNESS
        raise ProtocolAbort(reason)

    def respond(self, m1: bytes, now_ms: int, hint: str | None = None) -> ResponderResult:
        """Process M1 and return M2 plus the new session (raises ProtocolAbort)."""
        creds = self._creds()
        try:
            msg = AuthMessage.from_bytes(m1, self.suite)
        except MalformedMessageError as exc:
            raise ProtocolAbort(FailureReason.MALFORMED, str(exc)) from exc
        digest = self.suite.H(b"replay-cache", m1) if self.config.replay_cache else b""
        if self.config.replay_cache:
            self._replay_cache = {
                d: t
                for d, t in self._replay_cache.items()
                if now_ms - t <= 2 * self.config.delta_t_ms
            }
            if digest in self._replay_cache:
                raise ProtocolAbort(FailureReason.REPLAY_DETECTED)
        cand = self._resolve(msg, now_ms, hint)
        challenge = self._pick_challenge()
        a_j = self._puf_a(challenge)
        b_j = creds.share_for(challenge)
        rl_entry = self.suite.H(cand.body.a, a_j)
        if rl_entry in self.rl:
            raise ProtocolAbort(FailureReason.REVOKED_PAIR)
        self._reconstruct_and_check(cand.body.a, cand.body.b, a_j, b_j)
        self.rl.insert(rl_entry)
        body = ShareBody(a_j, b_j, now_ms)
        dm = self.suite.encrypt(cand.key, body.to_bytes(self.suite))
        s3, s4 = gen_sign(self.suite, dm, a_j, body.t_bytes, creds.x)
        sk = self.suite.H(cand.body.a, a_j, cand.body.t_bytes, body.t_bytes)
        creds.remove_pair(challenge)
        if self.config.replay_cache:
            self._replay_cache[digest] = now_ms
        session = SessionRecord(cand.peer_id, self._session_id(sk), sk, now_ms, "responder")
        self.sessions[cand.peer_id] = session
        return ResponderResult(
            cand.peer_id, AuthMessage(dm, s3, s4).to_bytes(self.suite.scalar_bytes), session
        )

    # ------------------------------------------------------------- initiator (V2)
    def complete(self, m2: bytes, now_ms: int) -> SessionRecord:
        """Process M2 at the initiator and establish the session (raises ProtocolAbort)."""
        creds = self._creds()
        if not self.pending:
            raise ProtocolAbort(FailureReason.NO_PENDING_SESSION)
        try:
            msg = AuthMessage.from_bytes(m2, self.suite)
        except MalformedMessageError as exc:
            raise ProtocolAbort(FailureReason.MALFORMED, str(exc)) from exc
        match: tuple[PendingSession, ShareBody] | None = None
        for pend in list(self.pending.values()):
            try:
                body = ShareBody.from_bytes(self.suite.decrypt(pend.key, msg.body), self.suite)
            except MalformedMessageError:
                continue
            if abs(now_ms - body.t_ms) <= self.config.delta_t_ms:
                match = (pend, body)
                break
        if match is None:
            raise ProtocolAbort(FailureReason.FRESHNESS)
        pend, body = match
        del self.pending[pend.peer_id]  # the session attempt ends here (success or abort)
        if self.suite.H(pend.a, body.a) not in self.rl:
            raise ProtocolAbort(FailureReason.NOT_IN_RL)
        self._reconstruct_and_check(pend.a, pend.b, body.a, body.b)
        Y_j = self.directory.get(pend.peer_id)
        if Y_j is None or not verify_sign(
            self.suite, msg.body, (msg.sigma_a, msg.sigma_b), a=body.a, t_bytes=body.t_bytes, Y=Y_j
        ):
            raise ProtocolAbort(FailureReason.SIGNATURE)
        sk = self.suite.H(pend.a, body.a, pend.t_ms.to_bytes(8, "big"), body.t_bytes)
        creds.remove_pair(pend.challenge)
        session = SessionRecord(pend.peer_id, self._session_id(sk), sk, now_ms, "initiator")
        self.sessions[pend.peer_id] = session
        return session

    def abort_pending(self, peer_id: str) -> None:
        self.pending.pop(peer_id, None)
