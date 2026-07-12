"""Logging setup helpers for the backend application."""

from __future__ import annotations

import logging
from typing import Final

DEFAULT_LOG_FORMAT: Final[str] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def configure_logging() -> None:
    """Configure a basic application logger."""
    logging.basicConfig(level=logging.INFO, format=DEFAULT_LOG_FORMAT)
