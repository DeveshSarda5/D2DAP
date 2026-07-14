# backend/app/authentication/nonce.py
import uuid
import time

class NonceManager:
    """Tracks nonces to prevent replay attacks using O(1) lookups."""
    
    def __init__(self, ttl_seconds: float = 60.0):
        self._seen_nonces: dict[str, float] = {}
        self.ttl = ttl_seconds

    def generate_nonce(self) -> str:
        return uuid.uuid4().hex

    def validate_and_record(self, nonce: str) -> bool:
        current_time = time.time()
        self._cleanup_expired(current_time)
        
        if nonce in self._seen_nonces:
            return False
            
        self._seen_nonces[nonce] = current_time + self.ttl
        return True

    def _cleanup_expired(self, current_time: float) -> None:
        """Removes expired nonces to maintain memory efficiency."""
        expired = [n for n, exp in self._seen_nonces.items() if current_time > exp]
        for n in expired:
            del self._seen_nonces[n]