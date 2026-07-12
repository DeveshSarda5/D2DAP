"""Common exception types for the backend application."""


class D2DAPError(Exception):
    """Base exception for project-specific application errors."""


class ConfigurationError(D2DAPError):
    """Raised when required configuration is missing or invalid."""
