# backend/app/authentication/auth_manager.py
import logging
from backend.app.authentication.registration import DroneRegistry
from backend.app.authentication.challenge import ChallengeGenerator
from backend.app.authentication.authenticator import Authenticator
from backend.app.authentication.session_key import SessionKeyGenerator
from backend.app.authentication.session import SessionManager
from backend.app.authentication.models import AuthRequestPayload, AuthResponsePayload, ChallengePayload

class AuthenticationManager:
    def __init__(self):
        self.registry = DroneRegistry()
        self.challenge_gen = ChallengeGenerator()
        self.authenticator = Authenticator(self.registry)
        self.session_manager = SessionManager()
        
        # Temporary state mapping to hold challenges pending response
        self._pending_auth: dict[str, ChallengePayload] = {}

    def handle_auth_request(self, request: AuthRequestPayload, receiver_id: str) -> ChallengePayload | None:
        try:
            self.authenticator.verify_request(request.sender_id, request.nonce)
            challenge = self.challenge_gen.generate()
            self._pending_auth[request.sender_id] = challenge
            logging.info(f"[AUTH] {receiver_id} issued challenge to {request.sender_id}")
            return challenge
        except Exception as e:
            logging.error(f"[AUTH FAILED] Request rejected: {str(e)}")
            return None

    def handle_auth_response(self, response: AuthResponsePayload, sender_id: str, receiver_id: str) -> bool:
        challenge = self._pending_auth.pop(sender_id, None)
        if not challenge:
            logging.error(f"[AUTH FAILED] No pending challenge found for {sender_id}")
            return False
            
        try:
            is_valid = self.authenticator.verify_response(response, challenge, sender_id)
            if is_valid:
                session_key = SessionKeyGenerator.generate_session_key(sender_id, receiver_id, response.nonce)
                self.session_manager.create_session(sender_id, receiver_id, session_key)
                
                # Mark drones as authenticated (integration with Phase 1)
                logging.info(f"[AUTH SUCCESS] Mutual authentication complete for {sender_id} and {receiver_id}")
                return True
        except Exception as e:
            logging.error(f"[AUTH FAILED] Response rejected: {str(e)}")
            return False