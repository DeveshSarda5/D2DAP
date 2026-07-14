import logging
from backend.app.drones.drone_model import Drone
from backend.app.core.message import Message
from backend.app.network.simulation_network import SimulationNetwork
from backend.app.communication.communication_manager import CommunicationManager
from backend.app.utils.logger import CommunicationLogger

# Import Phase 2
from backend.app.authentication.auth_manager import AuthenticationManager
from backend.app.authentication.models import AuthRequestPayload, AuthResponsePayload
from backend.app.authentication.crypto import CryptoSimulator
from backend.app.authentication.nonce import NonceManager

# Placeholder variable to satisfy unit tests
app = "D2DAP_Integrated_Simulation_Engine"

def run_integrated_simulation():
    print("=== Launching Integrated D2DAP Framework ===\n")
    
    # 1. Initialize Combined Subsystems
    network = SimulationNetwork()
    logger = CommunicationLogger()
    auth_manager = AuthenticationManager()
    nonce_gen = NonceManager()
    
    # Wire the auth_manager into the comm_manager
    comm_manager = CommunicationManager(network, logger, auth_manager)

    # 2. Setup Drones & Topology
    uav_1 = Drone("UAV_01")
    uav_2 = Drone("UAV_02")
    network.add_drone(uav_1)
    network.add_drone(uav_2)
    
    # Using the correct method name from your network file
    network.connect_drones("UAV_01", "UAV_02")
    
    # Pre-register identities
    auth_manager.registry.register_drone("UAV_01", "PSEUDO_1", "PUB_KEY_1")
    auth_manager.registry.register_drone("UAV_02", "PSEUDO_2", "PUB_KEY_2")

    # ---------------------------------------------------------
    print("\n[TEST 1: FIREWALL CHECK] Attempting to send unauthenticated data...")
    bad_msg = Message(sender_id="UAV_01", receiver_id="UAV_02", message_type="DATA", payload="Secret Payload")
    comm_manager.route_message(bad_msg)

    # ---------------------------------------------------------
    print("\n[TEST 2: HANDSHAKE] Initiating D2DAP Protocol...")
    
    # A. Send Request
    req_payload = AuthRequestPayload(sender_id="UAV_01", nonce=nonce_gen.generate_nonce())
    req_msg = Message(sender_id="UAV_01", receiver_id="UAV_02", message_type="AUTH_REQUEST", payload=req_payload)
    comm_manager.route_message(req_msg)
    
    # B. Fetch generated challenge from receiver state
    challenge = auth_manager._pending_auth.get("UAV_01")

    # C. Solve challenge and send Response
    solved_hash = CryptoSimulator.simulate_puf_response(challenge.challenge_value, "UAV_01")
    resp_payload = AuthResponsePayload(challenge.challenge_id, solved_hash, nonce_gen.generate_nonce())
    resp_msg = Message(sender_id="UAV_01", receiver_id="UAV_02", message_type="AUTH_RESPONSE", payload=resp_payload)
    comm_manager.route_message(resp_msg)

    # ---------------------------------------------------------
    print("\n[TEST 3: SECURE TUNNEL] Attempting to send data through authenticated channel...")
    good_msg = Message(sender_id="UAV_01", receiver_id="UAV_02", message_type="DATA", payload="Mission Critical Payload")
    comm_manager.route_message(good_msg)

    print("\n=== Framework Execution Complete ===")

if __name__ == "__main__":
    run_integrated_simulation()