# backend/app/authentication/exceptions.py

class AuthenticationError(Exception):
    """Base exception for authentication failures."""
    pass

class NonceReuseError(AuthenticationError):
    """Raised when a replay attack is detected via reused nonce."""
    pass

class ChallengeExpiredError(AuthenticationError):
    """Raised when a challenge response arrives after the TTL."""
    pass

class DroneNotRegisteredError(AuthenticationError):
    """Raised when an unknown drone attempts authentication."""
    pass