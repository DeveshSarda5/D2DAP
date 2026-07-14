# backend/app/authentication/crypto.py
import hashlib

class CryptoSimulator:
    """Simulates ECC and PUF operations for D2DAP workflow validation."""
    
    @staticmethod
    def simulate_puf_response(challenge_value: str, drone_id: str) -> str:
        """Simulates a PUF hardware response unique to the challenge and device."""
        raw_data = f"{challenge_value}:{drone_id}_PUF_SECRET".encode('utf-8')
        return hashlib.sha256(raw_data).hexdigest()

    @staticmethod
    def verify_signature(payload_hash: str, expected_hash: str) -> bool:
        """Simulates elliptic curve signature verification."""
        return payload_hash == expected_hash