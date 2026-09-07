from __future__ import annotations

import string

from _helpers import load_valid_collection
from stremioctl.fingerprints import (
    canonical_json_bytes,
    collection_display_fingerprint,
    collection_fingerprint,
)


def test_canonical_json_sorts_keys_and_is_compact() -> None:
    assert canonical_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_collection_fingerprint_is_sha256_hex_and_order_sensitive() -> None:
    payload = load_valid_collection()
    digest = collection_fingerprint(payload)
    assert len(digest) == 64
    assert set(digest) <= set(string.hexdigits.lower())
    assert collection_fingerprint(list(reversed(payload))) != digest


def test_display_fingerprint_is_keyed_and_twelve_hex() -> None:
    payload = load_valid_collection()
    a = collection_display_fingerprint(payload, b"a" * 32)
    b = collection_display_fingerprint(payload, b"b" * 32)
    assert a != b
    assert len(a) == 12
    assert set(a) <= set(string.hexdigits.lower())
