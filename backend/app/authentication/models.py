# backend/app/authentication/models.py
from dataclasses import dataclass, field
import time

@dataclass(frozen=True)
class DroneIdentity:
    drone_id: str
    pseudo_id: str
    public_key_sim: str
    registered_at: float = field(default_factory=time.time)

@dataclass(frozen=True)
class AuthRequestPayload:
    sender_id: str
    nonce: str
    timestamp: float = field(default_factory=time.time)

@dataclass(frozen=True)
class ChallengePayload:
    challenge_id: str
    challenge_value: str
    expires_at: float

@dataclass(frozen=True)
class AuthResponsePayload:
    challenge_id: str
    solved_value: str  # Simulated cryptographic hash of the challenge
    nonce: str
    timestamp: float = field(default_factory=time.time)