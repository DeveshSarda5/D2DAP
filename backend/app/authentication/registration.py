import logging
from backend.app.authentication.models import DroneIdentity

class DroneRegistry:
    def __init__(self):
        self._registry: dict[str, DroneIdentity] = {}

    def register_drone(self, drone_id: str, pseudo_id: str, pub_key: str) -> DroneIdentity:
        identity = DroneIdentity(drone_id=drone_id, pseudo_id=pseudo_id, public_key_sim=pub_key)
        self._registry[drone_id] = identity
        logging.info(f"[REGISTRY] Registered Drone: {drone_id} as {pseudo_id}")
        return identity

    def is_registered(self, drone_id: str) -> bool:
        return drone_id in self._registry

    def get_identity(self, drone_id: str) -> DroneIdentity | None:
        return self._registry.get(drone_id)