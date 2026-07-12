"""Configuration helpers for the backend package."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def get_setting(name: str, default: str | None = None) -> str | None:
    """Return a configuration value from the environment."""
    return os.getenv(name, default)
