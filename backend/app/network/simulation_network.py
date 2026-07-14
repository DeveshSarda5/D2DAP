import networkx as nx
from typing import List, Dict
from backend.app.drones.drone_model import Drone

class SimulationNetwork:
    def __init__(self):
        self.graph: nx.Graph = nx.Graph()
        self.registry: Dict[str, Drone] = {}

    def add_drone(self, drone: Drone) -> None:
        if drone.drone_id not in self.registry:
            self.registry[drone.drone_id] = drone
            self.graph.add_node(drone.drone_id)

    def remove_drone(self, drone_id: str) -> None:
        if drone_id in self.registry:
            del self.registry[drone_id]
            self.graph.remove_node(drone_id)

    def connect_drones(self, drone_id_1: str, drone_id_2: str) -> None:
        if drone_id_1 in self.registry and drone_id_2 in self.registry:
            self.graph.add_edge(drone_id_1, drone_id_2)

    def disconnect_drones(self, drone_id_1: str, drone_id_2: str) -> None:
        if self.graph.has_edge(drone_id_1, drone_id_2):
            self.graph.remove_edge(drone_id_1, drone_id_2)

    def get_neighbors(self, drone_id: str) -> List[str]:
        if drone_id in self.graph:
            return list(self.graph.neighbors(drone_id))
        return []  # Shifted to the left by four spaces

    def get_drone(self, drone_id: str) -> Drone:
        return self.registry.get(drone_id)