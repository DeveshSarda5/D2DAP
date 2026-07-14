import logging
from backend.app.network.simulation_network import SimulationNetwork
from backend.app.core.message import Message
from backend.app.utils.logger import CommunicationLogger
from backend.app.authentication.auth_manager import AuthenticationManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class CommunicationManager:
    def __init__(self, network: SimulationNetwork, logger: CommunicationLogger, auth_manager: AuthenticationManager):
        self.network = network
        self.logger = logger
        self.auth_manager = auth_manager

    def route_message(self, message: Message) -> bool:
        sender = self.network.get_drone(message.sender_id)
        receiver = self.network.get_drone(message.receiver_id)

        # 1. Base Physical Validation (Online & 1-Hop Adjacency)
        if not sender or not sender.is_online:
            self.logger.log_transmission(message, "FAILED_SENDER_OFFLINE")
            return False
        if not receiver or not receiver.is_online:
            self.logger.log_transmission(message, "FAILED_RECEIVER_OFFLINE")
            return False
        if message.receiver_id not in self.network.get_neighbors(message.sender_id):
            self.logger.log_transmission(message, "FAILED_OUT_OF_RANGE")
            return False

        # 2. Authentication Firewall Integration
        if message.message_type == "AUTH_REQUEST":
            challenge = self.auth_manager.handle_auth_request(message.payload, message.receiver_id)
            if challenge:
                self.logger.log_transmission(message, "AUTH_CHALLENGE_ISSUED")
                return True
            return False

        elif message.message_type == "AUTH_RESPONSE":
            success = self.auth_manager.handle_auth_response(message.payload, message.sender_id, message.receiver_id)
            if success:
                sender.authenticated = True
                receiver.authenticated = True
                self.logger.log_transmission(message, "AUTH_SUCCESS")
                return True
            self.logger.log_transmission(message, "AUTH_FAILED")
            return False

        # 3. Standard Data Routing (Requires Active Session)
        else:
            if not self.auth_manager.session_manager.has_active_session(message.sender_id, message.receiver_id):
                logging.warning(f"Firewall Block: No secure D2DAP session between {message.sender_id} and {message.receiver_id}.")
                self.logger.log_transmission(message, "FAILED_UNAUTHORIZED")
                return False
            
            self.logger.log_transmission(message, "DELIVERED_SECURE")
            logging.info(f"[SECURE ROUTE] {message.sender_id} -> ({message.message_type}) -> {message.receiver_id}")
            return True