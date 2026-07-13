# backend/app/communication/communication_manager.py
import logging
from backend.app.network.simulation_network import SimulationNetwork
from backend.app.core.message import Message
from backend.app.utils.logger import CommunicationLogger

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CommunicationManager:
    def __init__(self, network: SimulationNetwork, logger: CommunicationLogger):
        self.network: SimulationNetwork = network
        self.logger: CommunicationLogger = logger

    def route_message(self, message: Message) -> bool:
        sender = self.network.get_drone(message.sender_id)
        receiver = self.network.get_drone(message.receiver_id)

        # Node online validation
        if not sender or not sender.is_online:
            self.logger.log_transmission(message, "FAILED_SENDER_OFFLINE")
            logging.error(f"Routing halted: Sender {message.sender_id} offline/unregistered.")
            return False

        if not receiver or not receiver.is_online:
            self.logger.log_transmission(message, "FAILED_RECEIVER_OFFLINE")
            logging.error(f"Routing halted: Receiver {message.receiver_id} offline/unregistered.")
            return False

        # Adjacency check (Proximity verification for single-hop topology)
        if message.receiver_id not in self.network.get_neighbors(message.sender_id):
            self.logger.log_transmission(message, "FAILED_OUT_OF_RANGE")
            logging.error(f"Routing halted: {message.receiver_id} out of transmission range from {message.sender_id}.")
            return False

        # Valid payload delivery track
        self.logger.log_transmission(message, "DELIVERED")
        logging.info(f"[ROUTED] {message.sender_id} -> ({message.message_type}) -> {message.receiver_id}")
        return True