"""Collection identity: canonical JSON plus the two fingerprint types from the spec.

* Collection fingerprint - SHA-256 of the canonical raw collection JSON. It is a
  one-way base-state guard for later phases. It is never printed in normal
  command output because it is derived directly from sensitive data.
* Display fingerprint - keyed HMAC, twelve hex characters, safe to show. Used to
  label endpoints and to give a collection a stable local nickname.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from stremioctl.privacy import display_fingerprint


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize *value* as canonical JSON: UTF-8, sorted keys, no extra spaces."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def collection_fingerprint(value: Any) -> str:
    """Return the SHA-256 hex digest of the canonical collection JSON."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def collection_display_fingerprint(value: Any, key: bytes) -> str:
    """Return the twelve-character keyed display fingerprint for a collection."""

    return display_fingerprint(canonical_json_bytes(value), key)


__all__ = [
    "canonical_json_bytes",
    "collection_display_fingerprint",
    "collection_fingerprint",
]
