"""Framework exception hierarchy."""

from __future__ import annotations


class FrameworkError(Exception):
    """Base class for all framework errors."""


class ConfigError(FrameworkError):
    """Invalid or inconsistent configuration."""


class PUFAccessError(FrameworkError):
    """A PUF was evaluated by an entity that is not physically bound to it."""


class SimulationError(FrameworkError):
    """Invalid simulator operation (unknown drone, duplicate id, ...)."""


class RegistrationError(FrameworkError):
    """Drone registration with the control server failed."""
