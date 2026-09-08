"""Versioned JSON Schema contracts loaded from the repository ``schemas/`` tree.

Schema validation errors are rebuilt from the failing keyword and path only. The
raw ``jsonschema`` message embeds the offending instance value, which could be a
secret, so it is never forwarded.
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from stremioctl.errors import ValidationError

_SOURCE_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
_MAX_REPORTED_ERRORS = 25


@cache
def load_schema(name: str) -> dict[str, Any]:
    """Load and cache the schema document called ``<name>.schema.json``."""

    filename = f"{name}.schema.json"
    try:
        packaged = resources.files("stremioctl").joinpath("schema_data", filename)
        if packaged.is_file():
            text = packaged.read_text(encoding="utf-8")
        else:
            # Editable/source checkouts keep canonical schemas at repository
            # root. Hatch maps them into the package in built wheels.
            text = (_SOURCE_SCHEMA_DIR / filename).read_text(encoding="utf-8")
        data = json.loads(text)
    except OSError as exc:
        raise ValidationError(f"Schema is not available: {name}") from exc
    except json.JSONDecodeError as exc:  # pragma: no cover - would be a packaging bug
        raise ValidationError(f"Schema is malformed: {name}") from exc
    if not isinstance(data, dict):
        raise ValidationError(f"Schema is malformed: {name}")
    return data


def iter_schema_errors(instance: Any, name: str) -> list[str]:
    """Return safe, value-free descriptions of every schema violation."""

    validator = Draft202012Validator(load_schema(name))
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    messages: list[str] = []
    for error in errors[:_MAX_REPORTED_ERRORS]:
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        messages.append(f"{location}: fails the '{error.validator}' constraint")
    return messages


__all__ = ["iter_schema_errors", "load_schema"]
