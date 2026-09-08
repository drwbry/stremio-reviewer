from __future__ import annotations

import json
from typing import Any

import pytest

from _helpers import FIXTURES, load_valid_collection
from stremioctl.errors import ValidationError
from stremioctl.profiles import (
    build_starter_profile,
    check_profile,
    parse_profile,
)

KEY = b"k" * 32


def _codes(doc: Any, severity: str | None = None) -> set[str]:
    return {
        f.code for f in check_profile(doc) if severity is None or f.severity == severity
    }


def _profile(**addon_overrides: Any) -> dict[str, Any]:
    addon = {
        "key": "a",
        "match": {"manifestId": "synthetic.catalog"},
        "state": "present",
        "manage": ["state"],
    }
    addon.update(addon_overrides)
    return {"schemaVersion": 1, "name": "t", "addons": [addon]}


def test_converged_stub_fixture_parses_clean() -> None:
    doc = json.loads((FIXTURES / "desired.synthetic.json").read_text())
    profile, warnings = parse_profile(doc)
    assert profile.name == "synthetic"
    assert profile.addons == ()
    assert warnings == []
    assert profile.preserve_unmanaged is True


def test_schema_violation_is_an_error() -> None:
    assert "schema" in _codes({"schemaVersion": 2, "name": "x", "addons": []}, "error")


def test_non_object_root_is_rejected() -> None:
    assert "invalid_root" in _codes([1, 2, 3], "error")


def test_duplicate_keys_are_an_error() -> None:
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {"key": "dup", "match": {"manifestId": "one"}, "state": "present", "manage": []},
            {"key": "dup", "match": {"manifestId": "two"}, "state": "present", "manage": []},
        ],
    }
    assert "duplicate_key" in _codes(doc, "error")


def test_two_specs_claiming_the_same_selector_is_an_error() -> None:
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {"key": "x", "match": {"manifestId": "same"}, "state": "present", "manage": []},
            {"key": "y", "match": {"manifestId": "same"}, "state": "absent", "manage": []},
        ],
    }
    assert "duplicate_target" in _codes(doc, "error")


def test_same_manifest_id_with_distinct_fingerprints_is_allowed() -> None:
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "x",
                "match": {"manifestId": "same", "transportFingerprint": "0123456789ab"},
                "state": "present",
                "manage": [],
            },
            {
                "key": "y",
                "match": {"manifestId": "same", "transportFingerprint": "ffffffffffff"},
                "state": "present",
                "manage": [],
            },
        ],
    }
    assert "duplicate_target" not in _codes(doc, "error")


@pytest.mark.parametrize(
    "ref, ok",
    [
        ("env:STREMIOCTL_URL", True),
        ("env:lower_ok_too", True),
        ("env:1BAD", False),
        ("env:has-dash", False),
        ("file:/absolute/path", True),
        ("file:relative/path", False),
        ("vault:secret", False),
    ],
)
def test_secret_reference_syntax(ref: str, ok: bool) -> None:
    doc = _profile(endpoint={"secretRef": ref}, manage=["state", "endpoint"])
    codes = _codes(doc, "error")
    assert ("endpoint_secret_ref" not in codes) is ok


def test_public_url_must_be_http_s() -> None:
    doc = _profile(endpoint={"publicUrl": "ftp://nope.invalid/x"}, manage=["state", "endpoint"])
    assert "endpoint_public_url" in _codes(doc, "error")


def test_public_url_with_invalid_ipv6_is_reported_not_crashed() -> None:
    doc = _profile(endpoint={"publicUrl": "https://[invalid/manifest.json"}, manage=["endpoint"])
    assert "endpoint_public_url" in _codes(doc, "error")


def test_position_without_manage_is_a_warning_not_an_error() -> None:
    doc = _profile(position=3, manage=["state"])
    findings = check_profile(doc)
    assert [f for f in findings if f.severity == "error"] == []
    assert "position_unmanaged" in {f.code for f in findings if f.severity == "warning"}


def test_endpoint_without_manage_is_a_warning() -> None:
    doc = _profile(endpoint={"secretRef": "env:X"}, manage=["state"])
    assert "endpoint_unmanaged" in _codes(doc, "warning")


def test_absent_with_position_warns() -> None:
    doc = _profile(state="absent", position=1, manage=["state"])
    assert "absent_extras" in _codes(doc, "warning")


def test_parse_profile_raises_on_error_and_returns_warnings() -> None:
    with pytest.raises(ValidationError):
        parse_profile(_profile(endpoint={"secretRef": "bogus"}, manage=["state", "endpoint"]))

    _, warnings = parse_profile(_profile(position=9, manage=["state"]))
    assert any(w.code == "position_unmanaged" for w in warnings)


def test_parse_profile_applies_policy_defaults() -> None:
    profile, _ = parse_profile({"schemaVersion": 1, "name": "t", "addons": []})
    assert profile.policy["manifestTimeoutSeconds"] == 8
    assert profile.policy["maxConcurrentProbes"] == 4
    assert profile.policy["preserveUnmanagedAddons"] is True


def test_build_starter_profile_omits_endpoints_and_leaks_nothing() -> None:
    profile = build_starter_profile(load_valid_collection(), KEY)
    text = json.dumps(profile)
    assert "SENTINEL_" not in text
    assert "example.invalid" not in text  # no raw transport URL copied in
    assert all("endpoint" not in addon for addon in profile["addons"])
    assert [a["position"] for a in profile["addons"]] == list(range(8))
    # the generated profile satisfies its own contract
    assert [f for f in check_profile(profile) if f.severity == "error"] == []


def test_build_starter_profile_declare_public_copies_only_named_endpoint() -> None:
    profile = build_starter_profile(
        load_valid_collection(), KEY, declare_public=frozenset({"synthetic.catalog"})
    )
    by_id = {a["match"]["manifestId"]: a for a in profile["addons"]}
    assert by_id["synthetic.catalog"]["endpoint"] == {
        "publicUrl": "https://catalog.example.invalid/manifest.json"
    }
    assert "endpoint" in by_id["synthetic.catalog"]["manage"]
    assert "endpoint" not in by_id["synthetic.metadata"]


def test_build_starter_profile_disambiguates_duplicate_ids_with_fingerprint() -> None:
    dupes = json.loads((FIXTURES / "collection.synthetic-dupes.json").read_text())
    profile = build_starter_profile(dupes, KEY)
    dup_specs = [a for a in profile["addons"] if a["match"]["manifestId"] == "synthetic.dup"]
    assert len(dup_specs) == 2
    assert all("transportFingerprint" in a["match"] for a in dup_specs)
    assert len({a["key"] for a in dup_specs}) == 2  # unique local keys
    solo = [a for a in profile["addons"] if a["match"]["manifestId"] == "synthetic.solo"][0]
    assert "transportFingerprint" not in solo["match"]
