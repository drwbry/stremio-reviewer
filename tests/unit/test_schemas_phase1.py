from __future__ import annotations

import pytest

from _helpers import load_valid_collection
from stremioctl.errors import ValidationError
from stremioctl.schemas import iter_schema_errors, load_schema


def test_valid_collection_has_no_schema_errors() -> None:
    assert iter_schema_errors(load_valid_collection(), "addon-collection-v1") == []


def test_missing_required_keys_are_reported() -> None:
    errors = iter_schema_errors([{"manifest": {}}], "addon-collection-v1")
    assert errors
    assert all("fails the" in message for message in errors)


def test_schema_messages_never_include_instance_values() -> None:
    hostile = [
        {
            "manifest": {"id": ["SENTINEL_MUST_NOT_LEAK"]},
            "transportUrl": "",
        }
    ]
    errors = iter_schema_errors(hostile, "addon-collection-v1")
    assert errors  # id type and transportUrl minLength both fail
    joined = " ".join(errors)
    assert "SENTINEL" not in joined


def test_unknown_schema_name_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        load_schema("does-not-exist")
