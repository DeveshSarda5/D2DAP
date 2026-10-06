"""Structured logging.

Usage::

    log = get_logger(__name__)
    log.info("auth.success", initiator="D1", responder="D2", latency_ms=12.3)

Each record carries an ``event`` name plus key/value fields. Output is either JSON lines
(machine-readable experiment logs) or a compact ``key=value`` console format.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

_FIELDS_ATTR = "structured_fields"


class StructuredLogger:
    """Thin wrapper turning keyword arguments into structured fields."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _log(self, level: int, event: str, fields: dict[str, Any]) -> None:
        if self._logger.isEnabledFor(level):
            self._logger.log(level, event, extra={_FIELDS_ATTR: fields}, stacklevel=3)

    def debug(self, event: str, **fields: Any) -> None:
        self._log(logging.DEBUG, event, fields)

    def info(self, event: str, **fields: Any) -> None:
        self._log(logging.INFO, event, fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._log(logging.WARNING, event, fields)

    def error(self, event: str, **fields: Any) -> None:
        self._log(logging.ERROR, event, fields)


class JsonFormatter(logging.Formatter):
    """Render records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": round(record.created, 6),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, _FIELDS_ATTR, {}))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable ``LEVEL logger event k=v ...`` lines."""

    def format(self, record: logging.LogRecord) -> str:
        fields = getattr(record, _FIELDS_ATTR, {})
        kv = " ".join(f"{k}={v}" for k, v in fields.items())
        return f"{record.levelname:<7} {record.name}: {record.getMessage()} {kv}".rstrip()


def configure_logging(
    level: str = "INFO", json_output: bool = False, log_file: Path | None = None
) -> None:
    """Configure the ``app`` logger hierarchy (idempotent)."""
    root = logging.getLogger("app")
    root.setLevel(level.upper())
    root.handlers.clear()
    root.propagate = False
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(JsonFormatter() if json_output else ConsoleFormatter())
    root.addHandler(console)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(JsonFormatter())
        root.addHandler(fh)


def get_logger(name: str) -> StructuredLogger:
    """Return a structured logger under the ``app`` hierarchy."""
    if not name.startswith("app"):
        name = f"app.{name}"
    return StructuredLogger(logging.getLogger(name))
