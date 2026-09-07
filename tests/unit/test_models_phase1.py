from __future__ import annotations

import copy

import pytest

from _helpers import load_valid_collection
from stremioctl.errors import ValidationError
from stremioctl.models import parse_collection


def test_round_trip_is_deeply_equal() -> None:
    payload = load_valid_collection()
    original = copy.deepcopy(payload)
    collection = parse_collection(payload)
    assert collection.to_json() == original
    assert len(collection) == 8


def test_round_trip_preserves_nested_unknown_fields() -> None:
    collection = parse_collection(load_valid_collection())
    rebuilt = collection.to_json()
    assert rebuilt[1]["manifest"]["behaviorHints"] == {"configurable": True}
    assert rebuilt[7]["manifest"]["settings"] == {"apiKey": "SENTINEL_NESTED_API_KEY"}
    assert rebuilt[7]["transportUrl"].endswith("token=SENTINEL_QUERY_TOKEN")


def test_to_json_returns_independent_copy() -> None:
    collection = parse_collection(load_valid_collection())
    dump = collection.to_json()
    dump[0]["manifest"]["id"] = "mutated"
    assert collection.descriptors[0].manifest_id == "synthetic.catalog"


def test_unknown_descriptor_fields_are_reported_sorted() -> None:
    collection = parse_collection(
        [
            {
                "manifest": {"id": "a"},
                "transportUrl": "https://a.invalid/manifest.json",
                "zeta": 1,
                "alpha": 2,
            }
        ]
    )
    assert collection.descriptors[0].unknown_descriptor_fields == ["alpha", "zeta"]


def test_parse_rejects_non_array_root() -> None:
    with pytest.raises(ValidationError):
        parse_collection({"manifest": {}})


def test_parse_rejects_non_object_descriptor() -> None:
    with pytest.raises(ValidationError):
        parse_collection(
            [
                {"manifest": {"id": "x"}, "transportUrl": "https://x.invalid/manifest.json"},
                42,
            ]
        )
