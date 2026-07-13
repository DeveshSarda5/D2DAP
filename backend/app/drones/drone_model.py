# backend/app/drones/drone_model.py
from typing import Tuple

class Drone:
    def __init__(self, drone_id: str, initial_position: Tuple[float, float, float] = (0.0, 0.0, 0.0)):
        self.drone_id: str = drone_id
        self.position: Tuple[float, float, float] = initial_position
        self.is_online: bool = True
        self.authenticated: bool = False
        self.trust_score: float = 100.0

    def update_position(self, new_position: Tuple[float, float, float]) -> None:
        self.position = new_position

    def set_status(self, online: bool) -> None:
        self.is_online = online

    def __repr__(self) -> str:
        return f"Drone({self.drone_id}, Online={self.is_online}, Auth={self.authenticated}, Trust={self.trust_score})"