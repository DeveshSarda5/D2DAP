import pytest
import os
from backend.app.drones.drone_model import Drone
from backend.app.core.message import Message
from backend.app.network.simulation_network import SimulationNetwork
from backend.app.communication.communication_manager import CommunicationManager
from backend.app.utils.logger import CommunicationLogger
from backend.app.authentication.auth_manager import AuthenticationManager

def test_phase1_pipeline_integrity():
    # Setup isolated test dependencies
    network = SimulationNetwork()
    test_logger = CommunicationLogger(log_dir="test_logs", file_name="session_test.csv")
    auth_manager = AuthenticationManager()
    
    # Initialize manager with all three required arguments
    manager = CommunicationManager(network, test_logger, auth_manager)

    node_1 = Drone("UAV_T1")
    node_2 = Drone("UAV_T2")
    
    network.add_drone(node_1)
    network.add_drone(node_2)
    network.connect_drones("UAV_T1", "UAV_T2")

    # Assert neighborhood mapping logic works
    assert "UAV_T2" in network.get_neighbors("UAV_T1")

    # Assert message processing executes
    # Note: We use keyword arguments to prevent ordering mismatches
    msg = Message(sender_id="UAV_T1", receiver_id="UAV_T2", message_type="DATA", payload="TEST_PAYLOAD")
    status_check = manager.route_message(msg)
    
    # Since the Phase 2 Zero Trust firewall is now active, it will block this unauthenticated 
    # data transmission. Therefore, the expected routing status is now False.
    assert status_check is False
    assert os.path.exists(test_logger.file_path)

    # Clean runtime artifacts safely
    if os.path.exists(test_logger.file_path):
        os.remove(test_logger.file_path)
        try:
            os.rmdir("test_logs")
        except OSError:
            pass # Directory might not be empty if other tests ran concurrently