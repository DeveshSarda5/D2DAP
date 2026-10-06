"""Unit/integration tests of the D2DAP protocol simulation (Phase 4).

Covers the success path at all security levels and both peer-resolution modes, every
abort condition of Fig. 3, physical-attack (clone) resistance, and our observations
O1 (in-window replay), O2 (CRP consumption) and O3 (insider recovery of A).
"""

from __future__ import annotations

import numpy as np
import pytest

from app.core.errors import PUFAccessError, RegistrationError
from app.core.rng import RandomStreams
from app.security.crypto import SecurityLevel
from app.security.d2dap.agent import DroneSecurityAgent
from app.security.d2dap.config import D2DAPConfig, PUFConfig
from app.security.d2dap.entities import FailureReason, ProtocolAbort
from app.security.d2dap.messages import AuthMessage
from app.security.d2dap.revocation import RevocationList
from app.security.d2dap.service import D2DAPSystem, NoAuthService
from app.security.puf import BoundPUF, XORArbiterPUF


def make_system(n: int = 4, seed: int = 7, **cfg: object) -> D2DAPSystem:
    system = D2DAPSystem(D2DAPConfig(**cfg), RandomStreams(seed))  # type: ignore[arg-type]
    for i in range(1, n + 1):
        system.enroll(f"D{i}")
    return system


def flip(data: bytes, index: int) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


class TestSuccessPath:
    @pytest.mark.parametrize("mode", ["trial", "hint"])
    def test_mutual_authentication_and_common_key(self, mode: str) -> None:
        s = make_system(peer_resolution=mode)
        r = s.authenticate("D1", "D3", 1_000, (2, 2))
        assert r.success, r.failure_reason
        k1 = s.session_key("D1", "D3")
        k3 = s.session_key("D3", "D1")
        assert k1 is not None
        assert k1 == k3
        assert s.agents["D1"].sessions["D3"].session_id == r.session_id
        assert r.messages == 2

    @pytest.mark.parametrize("level", list(SecurityLevel))
    def test_all_security_levels(self, level: SecurityLevel) -> None:
        s = make_system(n=2, security_level=level, crp_count=4)
        r = s.authenticate("D1", "D2", 0)
        assert r.success
        expected = AuthMessage.wire_size(s.agents["D1"].suite)
        assert r.message_bytes == [expected, expected]

    def test_crp_consumed_and_rl_updated(self) -> None:
        s = make_system(crp_count=8)
        s.authenticate("D1", "D2", 0)
        assert s.agents["D1"].crp_remaining == 7
        assert s.agents["D2"].crp_remaining == 7
        assert len(s.revocation_list) == 1
        assert s.authenticate("D1", "D2", 5000).rl_broadcasts == 1

    def test_hint_mode_exact_operation_counts(self) -> None:
        """Instrumented counts equal the hand count of Sec. IV (docs/research-understanding)."""
        s = make_system(peer_resolution="hint")
        r = s.authenticate("D1", "D2", 0)
        expected = {
            "point_mul": 5, "point_add": 1, "hash": 9, "sym_enc": 1, "sym_dec": 1,
            "puf": 1, "ss_gen": 0, "ss_rec": 1, "rand": 1, "mod_inv": 2,
        }  # fmt: skip
        assert r.ops_initiator == expected
        assert r.ops_responder == expected

    def test_trial_mode_costs_more_at_responder(self) -> None:
        s = make_system(n=10, peer_resolution="trial")
        pm = [
            s.authenticate("D1", f"D{j}", 10_000 * j).ops_responder["point_mul"]
            for j in range(2, 10)
        ]
        assert min(pm) >= 5
        assert max(pm) > 5  # extra K derivations for wrong candidates

    def test_no_identity_on_the_wire(self) -> None:
        s = make_system(n=2)
        m1 = s.agents["D1"].initiate("D2", 0)
        assert b"D1" not in m1
        assert b"D2" not in m1

    def test_sessions_are_unlinkable_across_runs(self) -> None:
        s = make_system(n=2)
        m1a = s.agents["D1"].initiate("D2", 0)
        s.agents["D1"].abort_pending("D2")
        m1b = s.agents["D1"].initiate("D2", 0)
        assert m1a != m1b


class TestAbortConditions:
    def test_unknown_peer(self) -> None:
        s = make_system(n=2)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D1"].initiate("GHOST", 0)
        assert exc.value.reason is FailureReason.UNKNOWN_PEER

    def test_not_registered(self) -> None:
        s = make_system(n=2)
        s.create_agent("NEW")
        r = s.authenticate("NEW", "D1", 0)
        assert (r.success, r.failure_reason, r.failure_stage) == (
            False,
            "not_registered",
            "initiate",
        )

    def test_double_registration_rejected(self) -> None:
        s = make_system(n=2)
        with pytest.raises(RegistrationError):
            s.cs.register(s.agents["D1"])

    @pytest.mark.parametrize("mode", ["trial", "hint"])
    def test_freshness_violation(self, mode: str) -> None:
        s = make_system(peer_resolution=mode, delta_t_ms=500)
        r = s.authenticate("D1", "D2", 0, delays_ms=(800, 0))
        assert r.failure_reason == FailureReason.FRESHNESS.value
        assert r.failure_stage == "respond"

    def test_freshness_violation_on_m2(self) -> None:
        s = make_system(delta_t_ms=500)
        r = s.authenticate("D1", "D2", 0, delays_ms=(0, 800))
        assert r.failure_reason == FailureReason.FRESHNESS.value
        assert r.failure_stage == "complete"

    @pytest.mark.parametrize("offset", [20, 60, 100, 130])
    def test_tampered_m1_rejected(self, offset: int) -> None:
        """Bit flips in the ciphertext (a, b or T) or signature are detected."""
        s = make_system(peer_resolution="hint")
        m1 = s.agents["D1"].initiate("D2", 0)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D2"].respond(flip(m1, offset), 5, hint="D1")
        assert exc.value.reason in {FailureReason.SIGNATURE, FailureReason.FRESHNESS}
        assert s.agents["D2"].crp_remaining == 32  # no CRP consumed

    def test_tampered_m2_rejected(self) -> None:
        s = make_system(peer_resolution="hint")
        m1 = s.agents["D1"].initiate("D2", 0)
        out = s.agents["D2"].respond(m1, 5, hint="D1")
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D1"].complete(flip(out.m2, 140), 10)
        assert exc.value.reason is FailureReason.SIGNATURE

    def test_malformed_message(self) -> None:
        s = make_system(n=2)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D2"].respond(b"\x00" * 10, 0, hint="D1")
        assert exc.value.reason is FailureReason.MALFORMED

    def test_unsolicited_m2(self) -> None:
        s = make_system(n=3)
        m1 = s.agents["D1"].initiate("D2", 0)
        out = s.agents["D2"].respond(m1, 1)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D3"].complete(out.m2, 2)
        assert exc.value.reason is FailureReason.NO_PENDING_SESSION

    def test_crp_exhaustion(self) -> None:
        s = make_system(n=2, crp_count=2)
        assert s.authenticate("D1", "D2", 0).success
        assert s.authenticate("D1", "D2", 10_000).success
        r = s.authenticate("D1", "D2", 20_000)
        assert r.failure_reason == FailureReason.CRP_EXHAUSTED.value
        assert s.cs.reprovision(s.agents["D1"]) == 2
        assert s.cs.reprovision(s.agents["D2"]) == 2
        assert s.authenticate("D1", "D2", 30_000).success

    def test_revoked_pair(self) -> None:
        s = make_system(n=2, crp_count=1)
        i, j = s.agents["D1"], s.agents["D2"]
        assert i.credentials is not None
        assert j.credentials is not None
        a_i = i.registration_a(i.credentials.challenges[0])
        a_j = j.registration_a(j.credentials.challenges[0])
        s.revocation_list.insert(i.suite.H(a_i, a_j))
        r = s.authenticate("D1", "D2", 0)
        assert r.failure_reason == FailureReason.REVOKED_PAIR.value

    def test_missing_rl_broadcast_breaks_initiator(self) -> None:
        """Dependence on the paper's immediate RL dissemination assumption."""
        s = make_system(n=2)
        s.agents["D1"].rl = RevocationList()  # D1 never receives D2's RL broadcast
        r = s.authenticate("D1", "D2", 0)
        assert r.failure_reason == FailureReason.NOT_IN_RL.value
        assert r.failure_stage == "complete"


class TestAdversaries:
    def test_unregistered_attacker_cannot_authenticate(self) -> None:
        s = make_system(n=3)
        rogue_sys = make_system(n=1, seed=99)  # a different network (keys, A, B)
        rogue = rogue_sys.agents["D1"]
        rogue.directory = s.directory  # attacker knows the victim network's public keys
        m1 = rogue.initiate("D2", 0)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D2"].respond(m1, 1)
        assert exc.value.reason in {
            FailureReason.FRESHNESS,
            FailureReason.SIGNATURE,
            FailureReason.SECRET_MISMATCH,
        }

    def test_clone_with_extracted_credentials_fails(self) -> None:
        """GM4: Extract(D_i) gives {ID, x, b, C, RL, V} but not the PUF."""
        s = make_system(n=3, peer_resolution="hint")
        victim = s.agents["D1"]
        assert victim.credentials is not None
        clone_puf = XORArbiterPUF(np.random.default_rng(12345))  # different silicon
        clone = DroneSecurityAgent(
            "D1",
            BoundPUF("D1", clone_puf),
            s.config,
            directory=s.directory,
            revocation_list=s.revocation_list,
            rand=s.streams.crypto("clone"),
        )
        clone.install(victim.credentials.clone())
        m1 = clone.initiate("D2", 0)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D2"].respond(m1, 1, hint="D1")
        assert exc.value.reason is FailureReason.SECRET_MISMATCH

    def test_puf_cannot_be_queried_remotely(self) -> None:
        s = make_system(n=2)
        with pytest.raises(PUFAccessError):
            s.agents["D1"]._puf.evaluate(b"\x00" * 16, caller_id="D2")

    def test_o1_replay_inside_window_is_accepted_by_responder(self) -> None:
        """Observation O1: no responder replay cache in the paper."""
        s = make_system(delta_t_ms=2000)
        m1 = s.agents["D1"].initiate("D2", 0)
        assert s.agents["D2"].respond(m1, 10).peer_id == "D1"
        replayed = s.agents["D2"].respond(m1, 500)  # attacker replays within Delta T
        assert replayed.peer_id == "D1"
        assert s.agents["D2"].crp_remaining == 30  # O2: two CRPs consumed

    def test_replay_outside_window_rejected(self) -> None:
        s = make_system(delta_t_ms=2000)
        m1 = s.agents["D1"].initiate("D2", 0)
        s.agents["D2"].respond(m1, 10)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D2"].respond(m1, 5000)
        assert exc.value.reason is FailureReason.FRESHNESS

    def test_replay_cache_hardening(self) -> None:
        s = make_system(replay_cache=True)
        m1 = s.agents["D1"].initiate("D2", 0)
        s.agents["D2"].respond(m1, 10)
        with pytest.raises(ProtocolAbort) as exc:
            s.agents["D2"].respond(m1, 500)
        assert exc.value.reason is FailureReason.REPLAY_DETECTED

    def test_o3_insider_recovers_master_secret(self) -> None:
        """Observation O3: two own shares + own PUF determine A (and B)."""
        s = make_system(n=2)
        insider = s.agents["D1"]
        creds = insider.credentials
        assert creds is not None
        n = insider.suite.n
        (c1, b1), (c2, b2) = list(zip(creds.challenges, creds.b, strict=True))[:2]
        x1 = insider.suite.to_scalar(insider.registration_a(c1))
        x2 = insider.suite.to_scalar(insider.registration_a(c2))
        A = insider.shamir.reconstruct([(x1, b1), (x2, b2)])
        assert s.cs._poly.secret == A
        assert insider.suite.H(A.to_bytes(insider.suite.scalar_bytes, "big"), b"D1") == creds.V
        B = (b1 - A) * pow(x1, -1, n) % n
        assert s.cs._poly.coeffs[1] == B


class TestPUFNoise:
    def test_noisy_puf_breaks_authentication(self) -> None:
        """D2DAP has no error correction: unstable PUF bits change a_ik (SECRET_MISMATCH)."""
        s = make_system(n=2, puf=PUFConfig(noise_sigma=1.0))
        results = [s.authenticate("D1", "D2", t * 10_000) for t in range(3)]
        assert not any(r.success for r in results)
        assert {r.failure_reason for r in results} <= {"secret_mismatch", "signature"}


class TestBaseline:
    def test_noauth_accepts_anyone(self) -> None:
        svc = NoAuthService()
        r = svc.authenticate("ATTACKER", "D1", 0)
        assert r.success
        assert r.messages == 0
        assert r.as_record()["total_bytes"] == 0
