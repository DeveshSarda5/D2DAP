# backend/app/authentication/challenge.py
import uuid
import time
from backend.app.authentication.models import ChallengePayload

class ChallengeGenerator:
    def __init__(self, challenge_ttl: float = 30.0):
        self.ttl = challenge_ttl
        self._active_challenges: dict[str, ChallengePayload] = {}

    def generate(self) -> ChallengePayload:
        challenge_id = uuid.uuid4().hex
        value = uuid.uuid4().hex
        expires_at = time.time() + self.ttl
        
        challenge = ChallengePayload(challenge_id, value, expires_at)
        self._active_challenges[challenge_id] = challenge
        return challenge

    def get_and_consume(self, challenge_id: str) -> ChallengePayload | None:
        """Retrieves and immediately removes the challenge to ensure single-use."""
        return self._active_challenges.pop(challenge_id, None)