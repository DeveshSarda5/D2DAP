"""Control Server (CS): Setup and Registration phases of D2DAP.

The CS is *not* involved in MAKA (D2D authentication), exactly as in the paper.
"""

from __future__ import annotations

from app.core.errors import RegistrationError
from app.core.rng import RandomSource
from app.security.crypto import CryptoSuite, Point
from app.security.d2dap.agent import DroneSecurityAgent
from app.security.d2dap.config import D2DAPConfig
from app.security.d2dap.entities import DroneCredentials, PublicDirectory
from app.security.d2dap.revocation import RevocationList
from app.security.puf import CHALLENGE_BYTES
from app.security.secret_sharing import ShamirScheme


class ControlServer:
    """Runs Setup once and Registration per drone."""

    def __init__(self, config: D2DAPConfig, rand: RandomSource) -> None:
        self.config = config
        self.suite = CryptoSuite(config.security_level, rand)
        self._rand = rand
        self.shamir = ShamirScheme(self.suite.n, 2, self.suite.ops)
        # ---- Setup phase: F(x) = A + B x mod n, A kept secret
        self._poly = self.shamir.polynomial([self.suite.rand_scalar(), self.suite.rand_scalar()])
        self.revocation_list = RevocationList()
        self.directory = PublicDirectory()
        #: CS-side store {a_i, Y_i} per drone (as in the paper).
        self._store: dict[str, tuple[list[bytes], Point]] = {}

    @property
    def public_parameters(self) -> dict[str, str]:
        """``{q, E, P, H, Enc/Dec}`` announced publicly."""
        p = self.suite.params
        return {
            "curve": p.curve_name,
            "hash": p.hash_name,
            "cipher": f"AES-{p.aes_key_bytes * 8}-CTR",
        }

    def _verifier(self, drone_id: str) -> bytes:
        A = self._poly.secret.to_bytes(self.suite.scalar_bytes, "big")
        return self.suite.H(A, drone_id.encode())

    def _issue_shares(self, a_list: list[bytes]) -> list[int]:
        return [self.shamir.share(self._poly, self.suite.to_scalar(a))[1] for a in a_list]

    def _new_challenges(self) -> list[bytes]:
        challenges: list[bytes] = []
        seen: set[bytes] = set()
        while len(challenges) < self.config.crp_count:
            c = self._rand.randbytes(CHALLENGE_BYTES)
            if c not in seen:  # C_i1 != C_i2 != ... (paper)
                seen.add(c)
                challenges.append(c)
        return challenges

    def is_registered(self, drone_id: str) -> bool:
        return drone_id in self._store

    def register(self, agent: DroneSecurityAgent) -> DroneCredentials:
        """Registration phase over a secure channel (abstracted as a direct call)."""
        drone_id = agent.drone_id
        if drone_id in self._store:
            raise RegistrationError(f"{drone_id} is already registered")
        challenges = self._new_challenges()
        a_list, Y, x = agent.registration_respond(challenges)
        if len(a_list) != len(challenges):
            raise RegistrationError("registration response length mismatch")
        creds = DroneCredentials(
            drone_id=drone_id,
            x=x,
            challenges=challenges,
            b=self._issue_shares(a_list),
            V=self._verifier(drone_id),
        )
        self._store[drone_id] = (a_list, Y)
        self.directory.publish(drone_id, Y)
        agent.install(creds)
        return creds

    def reprovision(self, agent: DroneSecurityAgent) -> int:
        """Top up a registered drone with fresh CRPs (CRP exhaustion; our addition).

        New pairs are *appended*: pairs reserved by an in-flight MAKA stay valid.
        """
        if agent.credentials is None or agent.drone_id not in self._store:
            raise RegistrationError(f"{agent.drone_id} is not registered")
        existing = set(agent.credentials.challenges)
        challenges = [c for c in self._new_challenges() if c not in existing]
        a_list = [agent.registration_a(c) for c in challenges]
        agent.credentials.challenges.extend(challenges)
        agent.credentials.b.extend(self._issue_shares(a_list))
        old_a, Y = self._store[agent.drone_id]
        self._store[agent.drone_id] = ([*old_a, *a_list], Y)
        return len(challenges)

    def deregister(self, drone_id: str) -> None:
        """Withdraw a drone's public key (used by permanent quarantine; our addition)."""
        self._store.pop(drone_id, None)
        self.directory.withdraw(drone_id)
