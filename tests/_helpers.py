"""Test-only helpers, importable because ``tests`` is on the pytest pythonpath."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"
VALID_COLLECTION = FIXTURES / "collection.synthetic.json"

# Every secret placeholder that appears anywhere in the fixtures.
SENTINELS = (
    "SENTINEL_MUST_NOT_LEAK",
    "SENTINEL_NESTED_API_KEY",
    "SENTINEL_QUERY_TOKEN",
)


def load_valid_collection() -> list[dict[str, Any]]:
    """Return a fresh mutable copy of the synthetic valid collection fixture."""

    data = json.loads(VALID_COLLECTION.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    return data


def assert_no_sentinels(*chunks: str) -> None:
    """Assert none of the fixture sentinels appears in any chunk of text."""

    blob = "\n".join(chunk for chunk in chunks if chunk)
    for sentinel in SENTINELS:
        assert sentinel not in blob, f"{sentinel} leaked into output"
    assert "SENTINEL_" not in blob, "an unexpected sentinel leaked into output"
