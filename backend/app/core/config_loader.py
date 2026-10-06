"""YAML configuration loading with deep-merge overrides.

Configuration models themselves are Pydantic models owned by each subsystem; the root
model is :class:`app.services.config.FrameworkConfig`. This module only deals with files.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from app.core.errors import ConfigError

ModelT = TypeVar("ModelT", bound=BaseModel)


def deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base``."""
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML mapping from ``path``."""
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"top-level YAML in {path} must be a mapping")
    return data


def build_model(model: type[ModelT], *layers: Mapping[str, Any]) -> ModelT:
    """Validate the deep-merge of ``layers`` (later layers win) into ``model``."""
    merged: dict[str, Any] = {}
    for layer in layers:
        merged = deep_merge(merged, layer)
    try:
        return model.model_validate(merged)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc


def dump_model(model: BaseModel, path: Path) -> None:
    """Write a resolved config to YAML (saved with every experiment for traceability)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(model.model_dump(mode="json"), fh, sort_keys=False)
