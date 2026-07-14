# backend/app/authentication/authenticator.py
import time
from backend.app.authentication.exceptions import *
from backend.app.authentication.registration import DroneRegistry
from backend.app.authentication.nonce import NonceManager
from backend.app.authentication.crypto import CryptoSimulator
from backend.app.authentication.models import ChallengePayload, AuthResponsePayload

class Authenticator:
    def __init__(self, registry: DroneRegistry):
        self.registry = registry
        self.nonce_manager = NonceManager()

    def verify_request(self, drone_id: str, nonce: str) -> bool:
        if not self.registry.is_registered(drone_id):
            raise DroneNotRegisteredError(f"Drone {drone_id} is not registered.")
        if not self.nonce_manager.validate_and_record(nonce):
            raise NonceReuseError("Replay attack detected: Nonce reused.")
        return True

    def verify_response(self, response: AuthResponsePayload, challenge: ChallengePayload, drone_id: str) -> bool:
        if time.time() > challenge.expires_at:
            raise ChallengeExpiredError("Challenge TTL exceeded.")
            
        if not self.nonce_manager.validate_and_record(response.nonce):
            raise NonceReuseError("Replay attack detected: Nonce reused in response.")

        # Simulate cryptographic PUF evaluation
        expected_hash = CryptoSimulator.simulate_puf_response(challenge.challenge_value, drone_id)
        return CryptoSimulator.verify_signature(response.solved_value, expected_hash)