"""Stable JSON envelopes for machine consumers.

Every JSON document has ``schema`` (what it is) and ``schema_version`` (bumped only on breaking
changes). Output is ASCII-escaped so it survives any console code page and PowerShell 5.1's
``ConvertFrom-Json`` unchanged.
"""

from __future__ import annotations

import json
from typing import Any, Final, TextIO

from pydantic import BaseModel

from threatlens.correlation.process_network import connection_record
from threatlens.utils.time import utc_now

__all__ = ["JSON_SCHEMA_VERSION", "connection_record", "envelope", "json_line", "write_json"]

JSON_SCHEMA_VERSION: Final = 1


def envelope(schema: str, **payload: Any) -> dict[str, Any]:
    return {
        "schema": f"threatlens.{schema}",
        "schema_version": JSON_SCHEMA_VERSION,
        "timestamp": utc_now().isoformat(),
        **payload,
    }


def _default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def write_json(document: dict[str, Any], stream: TextIO) -> None:
    json.dump(document, stream, default=_default, ensure_ascii=True, indent=2)
    stream.write("\n")


def json_line(document: object) -> str:
    """Single-line JSON (JSON Lines) for streaming output such as ``monitor --json``."""
    return json.dumps(document, default=_default, ensure_ascii=True, separators=(",", ":"))
