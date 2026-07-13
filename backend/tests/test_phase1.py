# tests/test_phase1.py
import pytest
import os
from backend.app.drones.drone_model import Drone
from backend.app.core.message import Message
from backend.app.network.simulation_network import SimulationNetwork
from backend.app.communication.communication_manager import CommunicationManager
from backend.app.utils.logger import CommunicationLogger

def test_phase1_pipeline_integrity():
    # Setup isolated test dependencies
    network = SimulationNetwork()
    test_logger = CommunicationLogger(log_dir="test_logs", file_name="session_test.csv")
    manager = CommunicationManager(network, test_logger)

    node_1 = Drone("UAV_T1")
    node_2 = Drone("UAV_T2")
    
    network.add_drone(node_1)
    network.add_drone(node_2)
    network.connect_drones("UAV_T1", "UAV_T2")

    # Assert neighborhood mapping logic works
    assert "UAV_T2" in network.get_neighbors("UAV_T1")

    # Assert message processing tracks correctly
    msg = Message("UAV_T1", "UAV_T2", "TEST_PAYLOAD", message_type="DATA")
    status_check = manager.route_message(msg)
    
    assert status_check is True
    assert os.path.exists(test_logger.file_path)

    # Clean runtime artifacts safely
    if os.path.exists(test_logger.file_path):
        os.remove(test_logger.file_path)
        os.rmdir("test_logs")