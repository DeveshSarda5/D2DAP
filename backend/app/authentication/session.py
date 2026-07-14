# backend/app/authentication/session.py
import logging
import uuid
from dataclasses import dataclass, field
import time

@dataclass
class SecureSession:
    session_id: str
    drone_a: str
    drone_b: str
    session_key: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600.0) # 1 hour TTL
    
    @property
    def is_active(self) -> bool:
        return time.time() < self.expires_at

class SessionManager:
    def __init__(self):
        # Maps a tuple of (drone_1, drone_2) to a Session
        self._sessions: dict[tuple[str, str], SecureSession] = {}

    def create_session(self, drone_a: str, drone_b: str, session_key: str) -> SecureSession:
        session = SecureSession(
            session_id=uuid.uuid4().hex,
            drone_a=drone_a,
            drone_b=drone_b,
            session_key=session_key
        )
        # Store symmetrically
        pair = tuple(sorted([drone_a, drone_b]))
        self._sessions[pair] = session
        logging.info(f"[SESSION] Secure session established between {drone_a} and {drone_b}")
        return session

    def has_active_session(self, drone_a: str, drone_b: str) -> bool:
        pair = tuple(sorted([drone_a, drone_b]))
        session = self._sessions.get(pair)
        if session and session.is_active:
            return True
        return False