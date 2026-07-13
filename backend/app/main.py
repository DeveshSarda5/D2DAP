# backend/app/main.py
from backend.app.drones.drone_model import Drone
from backend.app.core.message import Message
from backend.app.network.simulation_network import SimulationNetwork
from backend.app.communication.communication_manager import CommunicationManager
from backend.app.utils.logger import CommunicationLogger

def run_phase1_simulation():
    print("=== Launching Base Internet of Drones (IoD) Emulation Engine ===")
    
    # Instantiate structural subsystems
    network = SimulationNetwork()
    logger = CommunicationLogger()
    manager = CommunicationManager(network, logger)

    print("\n[Step 1] Initializing Swarm Registry...")
    drones = [Drone(f"UAV_0{i}", initial_position=(float(i * 15), float(i * 20), 45.0)) for i in range(1, 4)]
    for uav in drones:
        network.add_drone(uav)
        print(f" Registered: {uav}")

    print("\n[Step 2] Building Communication Mesh Links...")
    # Link configuration: UAV_01 <---> UAV_02 <---> UAV_03
    network.connect_drones("UAV_01", "UAV_02")
    network.connect_drones("UAV_02", "UAV_03")
    print(" Mesh topology linked: UAV_01 <-> UAV_02 <-> UAV_03")

    print("\n[Step 3] Processing Communication Matrix...")
    
    # 1. Connected transmission path (Adjacent single-hop)
    m1 = Message("UAV_01", "UAV_02", "INIT_HELLO", message_type="HELLO")
    manager.route_message(m1)

    # Handshake reply return loop
    m2 = Message("UAV_02", "UAV_01", "ACK_HELLO", message_type="ACK")
    manager.route_message(m2)

    # 2. Out of range transmission trace (Non-adjacent node constraint test)
    print("\n[ATTEMPTING DIRECT ROUTING TO NON-ADJACENT NODE]")
    m3 = Message("UAV_01", "UAV_03", "BROADCAST_DATA_STREAM", message_type="DATA")
    manager.route_message(m3)

    print("\n=== Phase 1 Baseline Execution Complete. Data recorded to logs/ ===")

if __name__ == "__main__":
    run_phase1_simulation()