# backend/app/authentication/session_key.py
import hashlib
import time
import uuid

class SessionKeyGenerator:
    @staticmethod
    def generate_session_key(drone_a: str, drone_b: str, nonce: str) -> str:
        """Simulates D2DAP session key derivation function."""
        raw_material = f"{drone_a}:{drone_b}:{nonce}:{time.time()}".encode('utf-8')
        return hashlib.sha256(raw_material).hexdigest()