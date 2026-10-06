"""Integration tests of the attack simulator (Phase 7): every attack yields evidence."""

from __future__ import annotations

import pytest

from app.attacks.base import AttackEvidence, AttackSpec
from app.attacks.manager import ATTACK_TYPES, TRAFFIC_ATTACKS, AttackManager, stride_of
from app.core.errors import SimulationError
from app.services.swarm import SecureSwarm, build_secure_swarm
from app.simulation.config import SimulationConfig

pytestmark = pytest.mark.integration
AREA = {"x_m": 250, "y_m": 250, "z_min_m": 30, "z_max_m": 70}


def swarm(require_auth: bool = True, rekey: int | None = None, seed: int = 5) -> SecureSwarm:
    cfg = SimulationConfig(num_drones=6, area=AREA)  # type: ignore[arg-type]
    return build_secure_swarm(cfg, seed=seed, require_auth=require_auth, rekey_interval_ms=rekey)


def run_attack(kind: str, *, require_auth: bool = True, rekey: int | None = None,
               **params: object) -> tuple[SecureSwarm, AttackEvidence]:  # fmt: skip
    sw = swarm(require_auth, rekey)
    mgr = AttackManager(sw)
    mgr.launch(AttackSpec(kind=kind, target="D3", start_ms=5000, duration_ms=8000,
                          rate_pps=20, params=params))  # fmt: skip
    sw.run(15_000)
    return sw, mgr.evidence()[0]


class TestRegistry:
    def test_all_stride_letters_covered(self) -> None:
        letters = {s.value for k in ATTACK_TYPES for s in stride_of(k)}
        assert letters >= {"S", "T", "I", "D", "E"}  # R is analysed separately (no packets)

    def test_unknown_kind_and_target(self) -> None:
        mgr = AttackManager(swarm())
        with pytest.raises(SimulationError, match="unknown attack kind"):
            mgr.launch(AttackSpec(kind="teleport", target="D3"))
        with pytest.raises(SimulationError, match="unknown attack target"):
            mgr.launch(AttackSpec(kind="dos", target="D99"))

    @pytest.mark.parametrize("kind", TRAFFIC_ATTACKS)
    def test_every_traffic_attack_emits_labelled_packets(self, kind: str) -> None:
        sw, ev = run_attack(kind)
        assert ev.packets_sent > 0, kind
        df = sw.traffic_log.to_frame()
        assert (df.label == kind).sum() > 0
        assert set(df.loc[df.label == kind, "attack_id"]) == {ev.attack_id}


class TestExternalAttacksBlockedByD2DAP:
    def test_spoofing_blocked(self) -> None:
        _, ev = run_attack("spoofing")
        assert ev.packets_accepted == 0
        assert ev.dropped["unauthenticated"] + ev.dropped["no_session"] > 0

    def test_spoofing_succeeds_without_authentication(self) -> None:
        _, ev = run_attack("spoofing", require_auth=False)
        assert ev.packets_accepted > 0

    def test_tampering_detected_by_aead(self) -> None:
        _, ev = run_attack("tampering")
        assert ev.packets_sent > 0
        assert ev.packets_accepted == 0
        assert ev.dropped["integrity"] > 0

    def test_dos_burns_victim_cpu_but_never_authenticates(self) -> None:
        _, ev = run_attack("dos")
        assert ev.auth_attempts > 50
        assert ev.auth_accepted == 0
        assert ev.victim_compute_ms > 100.0  # crypto work forced on the victim

    def test_clone_fails_with_secret_mismatch(self) -> None:
        sw, ev = run_attack("impersonation")
        assert ev.extra["credentials_extracted"]
        assert ev.auth_failures["secret_mismatch"] > 0
        assert ev.auth_accepted == 0
        assert not sw.engine.network.get("D3").active  # the real drone was captured

    def test_unregistered_drone_rejected(self) -> None:
        _, ev = run_attack("unauthorized_access")
        assert ev.auth_attempts > 0
        assert ev.auth_accepted == 0
        assert ev.packets_accepted == 0


class TestReplay:
    def test_data_replays_blocked(self) -> None:
        _, ev = run_attack("replay", window="stale")
        assert ev.extra["replayed_data"] > 0
        assert ev.dropped["replay"] > 0
        assert ev.extra["auth_replays_accepted"] == 0

    def test_o1_in_window_auth_replay_accepted_and_consumes_crps(self) -> None:
        """With periodic re-keying, fresh M1s exist; in-window replays are accepted (O1/O2)."""
        _, ev = run_attack("replay", rekey=2000, window="in")
        assert ev.extra["replayed_auth"] > 0
        assert ev.extra["auth_replays_accepted"] > 0
        assert ev.crp_consumed > 0


class TestInsiderAttacksPassD2DAP:
    @pytest.mark.parametrize("kind", ["flooding", "privilege_escalation", "abnormal"])
    def test_insider_traffic_is_accepted(self, kind: str) -> None:
        """Observation O5: authentication cannot stop an authenticated insider."""
        sw, ev = run_attack(kind)
        assert ev.packets_accepted / ev.packets_sent > 0.9
        df = sw.traffic_log.to_frame()
        accepted = df[(df.label == kind) & df.dropped_reason.isna()]
        assert accepted.integrity_ok.all()  # validly sealed with D2DAP session keys

    def test_o3_master_secret_recovered_by_insider(self) -> None:
        _, ev = run_attack("privilege_escalation")
        assert ev.extra["master_secret_recovered"] is True


class TestEavesdropping:
    def test_d2dap_hides_payloads_and_identities(self) -> None:
        _, ev = run_attack("eavesdropping")
        assert ev.packets_sent == 0  # passive
        assert ev.extra["captured"] > 0
        assert ev.extra["data_plaintext_fraction"] == 0.0
        assert ev.extra["auth_msgs_with_identity"] == 0
        assert ev.extra["link_layer_src_exposed_fraction"] == 1.0  # documented limitation

    def test_noauth_exposes_payloads(self) -> None:
        _, ev = run_attack("eavesdropping", require_auth=False)
        assert ev.extra["data_plaintext_fraction"] == 1.0
