"""Mobility models (random waypoint with pauses, static)."""

from __future__ import annotations

from typing import Protocol

import numpy as np

from app.simulation.config import AreaConfig, MobilityConfig
from app.simulation.drone import Drone, Vec3


class MobilityModel(Protocol):
    """Updates a drone's position/velocity for one time step."""

    def step(self, drone: Drone, now_ms: int, dt_s: float) -> float:
        """Move ``drone``; return distance travelled in metres."""
        ...


def random_position(area: AreaConfig, rng: np.random.Generator) -> Vec3:
    """Uniform random point inside the flight volume."""
    return np.array(
        [
            rng.uniform(0.0, area.x_m),
            rng.uniform(0.0, area.y_m),
            rng.uniform(area.z_min_m, area.z_max_m),
        ]
    )


class StaticMobility:
    """Drones hover in place."""

    def step(self, drone: Drone, now_ms: int, dt_s: float) -> float:
        drone.velocity = np.zeros(3)
        return 0.0


class RandomWaypointMobility:
    """Classic random-waypoint model: fly to a random point, pause, repeat."""

    def __init__(self, area: AreaConfig, cfg: MobilityConfig, rng: np.random.Generator) -> None:
        self._area = area
        self._cfg = cfg
        self._rng = rng

    def _new_waypoint(self, drone: Drone) -> Vec3:
        waypoint = random_position(self._area, self._rng)
        speed = self._rng.uniform(self._cfg.speed_min_mps, self._cfg.speed_max_mps)
        direction = waypoint - drone.position
        norm = float(np.linalg.norm(direction))
        drone.velocity = direction / norm * speed if norm > 0 else np.zeros(3)
        drone.waypoint = waypoint
        return waypoint

    def step(self, drone: Drone, now_ms: int, dt_s: float) -> float:
        if now_ms < drone.pause_until_ms:
            drone.velocity = np.zeros(3)
            return 0.0
        waypoint = drone.waypoint
        if waypoint is None or not np.any(drone.velocity):
            waypoint = self._new_waypoint(drone)
        to_target = waypoint - drone.position
        dist_left = float(np.linalg.norm(to_target))
        step_len = float(np.linalg.norm(drone.velocity)) * dt_s
        if step_len >= dist_left:
            drone.position = waypoint.copy()
            drone.waypoint = None
            drone.velocity = np.zeros(3)
            pause_ms = int(self._rng.uniform(0.0, self._cfg.pause_max_s) * 1000)
            drone.pause_until_ms = now_ms + pause_ms
            return dist_left
        drone.position = drone.position + drone.velocity * dt_s
        return step_len


def make_mobility(area: AreaConfig, cfg: MobilityConfig, rng: np.random.Generator) -> MobilityModel:
    """Factory selecting the configured mobility model."""
    if cfg.model == "static":
        return StaticMobility()
    return RandomWaypointMobility(area, cfg, rng)
