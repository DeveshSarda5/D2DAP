"""Configuration models for the drone simulator.

All physical constants here are *model parameters* of a software simulation, not
measurements of real hardware. Defaults are chosen to be plausible for small
multirotor swarms (Wi-Fi D2D links, ~100-300 m range) and are configurable.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class AreaConfig(BaseModel):
    """Axis-aligned 3-D flight volume in metres."""

    x_m: float = Field(500.0, gt=0)
    y_m: float = Field(500.0, gt=0)
    z_min_m: float = Field(30.0, ge=0)
    z_max_m: float = Field(120.0, gt=0)

    @model_validator(mode="after")
    def _check_z(self) -> AreaConfig:
        if self.z_max_m <= self.z_min_m:
            raise ValueError("z_max_m must exceed z_min_m")
        return self


class MobilityConfig(BaseModel):
    """Random-waypoint mobility parameters."""

    model: str = Field("random_waypoint", pattern="^(random_waypoint|static)$")
    speed_min_mps: float = Field(2.0, ge=0)
    speed_max_mps: float = Field(12.0, gt=0)
    pause_max_s: float = Field(3.0, ge=0)


class ChannelConfig(BaseModel):
    """Abstract wireless D2D channel."""

    comm_range_m: float = Field(250.0, gt=0)
    base_latency_ms: float = Field(2.0, ge=0)
    jitter_ms: float = Field(1.0, ge=0)
    bandwidth_mbps: float = Field(20.0, gt=0)
    base_loss: float = Field(0.005, ge=0, le=1)
    edge_loss: float = Field(0.05, ge=0, le=1)  # extra loss at the edge of range


class BatteryConfig(BaseModel):
    """Linear battery-drain *model* (percent units; not a hardware measurement)."""

    hover_pct_per_s: float = Field(0.01, ge=0)
    move_pct_per_m: float = Field(0.0005, ge=0)
    tx_pct_per_kb: float = Field(0.00002, ge=0)


class SimulationConfig(BaseModel):
    """Top-level simulator configuration."""

    num_drones: int = Field(10, ge=2, le=1000)
    tick_ms: int = Field(100, ge=1, le=10_000)
    leader_count: int = Field(1, ge=1)
    relay_fraction: float = Field(0.2, ge=0, le=1)
    history_size: int = Field(200, ge=1)
    area: AreaConfig = AreaConfig()
    mobility: MobilityConfig = MobilityConfig()
    channel: ChannelConfig = ChannelConfig()
    battery: BatteryConfig = BatteryConfig()

    @model_validator(mode="after")
    def _check_leaders(self) -> SimulationConfig:
        if self.leader_count >= self.num_drones:
            raise ValueError("leader_count must be smaller than num_drones")
        return self
