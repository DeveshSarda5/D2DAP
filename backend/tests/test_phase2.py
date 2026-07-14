import pytest
import time
from backend.app.authentication.auth_manager import AuthenticationManager
from backend.app.authentication.models import AuthRequestPayload, AuthResponsePayload
from backend.app.authentication.crypto import CryptoSimulator
from backend.app.authentication.nonce import NonceManager

@pytest.fixture
def auth_setup():
    manager = AuthenticationManager()
    manager.registry.register_drone("D1", "P1", "KEY1")
    manager.registry.register_drone("D2", "P2", "KEY2")
    return manager

def test_successful_authentication_flow(auth_setup):
    manager = auth_setup
    nonce_gen = NonceManager()
    
    # Request
    req = AuthRequestPayload(sender_id="D1", nonce=nonce_gen.generate_nonce())
    challenge = manager.handle_auth_request(req, "D2")
    assert challenge is not None
    
    # Response
    solved = CryptoSimulator.simulate_puf_response(challenge.challenge_value, "D1")
    resp = AuthResponsePayload(challenge.challenge_id, solved, nonce_gen.generate_nonce())
    
    # Verify
    success = manager.handle_auth_response(resp, "D1", "D2")
    assert success is True
    assert manager.session_manager.has_active_session("D1", "D2") is True

def test_unregistered_drone_rejected(auth_setup):
    manager = auth_setup
    req = AuthRequestPayload(sender_id="UNKNOWN_DRONE", nonce="nonce123")
    challenge = manager.handle_auth_request(req, "D2")
    assert challenge is None  # Fails and returns None

def test_replay_attack_rejected(auth_setup):
    manager = auth_setup
    reused_nonce = "stolen_nonce_123"
    
    req1 = AuthRequestPayload(sender_id="D1", nonce=reused_nonce)
    challenge1 = manager.handle_auth_request(req1, "D2")
    assert challenge1 is not None
    
    # Attacker attempts replay
    req2 = AuthRequestPayload(sender_id="D1", nonce=reused_nonce)
    challenge2 = manager.handle_auth_request(req2, "D2")
    assert challenge2 is None  # Rejected due to NonceReuseError