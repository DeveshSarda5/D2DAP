# backend/demo_phase2.py
# backend/demo_phase2.py
import logging
from backend.app.drones.drone_model import Drone
from backend.app.authentication.auth_manager import AuthenticationManager
from backend.app.authentication.models import AuthRequestPayload, AuthResponsePayload
from backend.app.authentication.crypto import CryptoSimulator
from backend.app.authentication.nonce import NonceManager


logging.basicConfig(level=logging.INFO, format='%(message)s')

def run_d2dap_simulation():
    print("=== D2DAP Authentication Simulation Phase 2 ===")
    
    # 1. Initialize Subsystems
    auth_manager = AuthenticationManager()
    nonce_gen = NonceManager()
    
    # 2. Register Drones (Simulating offline pre-flight phase)
    drone_a = Drone("UAV_ALPHA")
    drone_b = Drone("UAV_BETA")
    
    print("\n--- Phase: Registration ---")
    auth_manager.registry.register_drone(drone_a.drone_id, "PSEUDO_A", "PUB_KEY_A")
    auth_manager.registry.register_drone(drone_b.drone_id, "PSEUDO_B", "PUB_KEY_B")
    
    print("\n--- Phase: Authentication Request ---")
    # UAV_ALPHA initiates connection to UAV_BETA
    req_payload = AuthRequestPayload(sender_id=drone_a.drone_id, nonce=nonce_gen.generate_nonce())
    print(f"UAV_ALPHA -> AuthRequest(nonce={req_payload.nonce[:8]}...) -> UAV_BETA")
    
    print("\n--- Phase: Challenge Generation ---")
    challenge = auth_manager.handle_auth_request(req_payload, receiver_id=drone_b.drone_id)
    print(f"UAV_BETA -> Challenge(id={challenge.challenge_id[:8]}...) -> UAV_ALPHA")
    
    print("\n--- Phase: Authentication Response ---")
    # UAV_ALPHA computes PUF hash to solve challenge
    solved_hash = CryptoSimulator.simulate_puf_response(challenge.challenge_value, drone_a.drone_id)
    resp_payload = AuthResponsePayload(
        challenge_id=challenge.challenge_id,
        solved_value=solved_hash,
        nonce=nonce_gen.generate_nonce()
    )
    print(f"UAV_ALPHA -> AuthResponse(solved_hash={solved_hash[:8]}...) -> UAV_BETA")
    
    print("\n--- Phase: Verification & Session Creation ---")
    success = auth_manager.handle_auth_response(resp_payload, drone_a.drone_id, drone_b.drone_id)
    
    if success:
        drone_a.authenticated = True
        drone_b.authenticated = True
        print("\n=== Result: Communication Channel Unlocked ===")
    else:
        print("\n=== Result: Authentication Failed ===")

if __name__ == "__main__":
    run_d2dap_simulation()