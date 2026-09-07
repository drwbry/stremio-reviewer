from __future__ import annotations

from _helpers import load_valid_collection
from stremioctl.validation import count_by_severity, validate_collection

KEY = b"k" * 32


def _codes(payload: object, severity: str | None = None) -> set[str]:
    findings = validate_collection(payload, KEY)
    return {f.code for f in findings if severity is None or f.severity == severity}


def test_valid_fixture_has_no_errors() -> None:
    findings = validate_collection(load_valid_collection(), KEY)
    assert [f for f in findings if f.severity == "error"] == []


def test_insecure_transport_is_warned_exactly_once() -> None:
    findings = validate_collection(load_valid_collection(), KEY)
    insecure = [f for f in findings if f.code == "insecure_transport"]
    assert len(insecure) == 1
    assert insecure[0].descriptor_index == 3
    assert insecure[0].severity == "warning"
    assert insecure[0].endpoint is not None
    assert "SENTINEL" not in insecure[0].endpoint
    assert "http://subtitles" not in insecure[0].message


def test_query_string_in_transport_url_is_warned() -> None:
    findings = validate_collection(load_valid_collection(), KEY)
    hits = [f for f in findings if f.code == "credential_in_url"]
    assert [f.descriptor_index for f in hits] == [7]


def test_wrong_root_type_reports_invalid_root() -> None:
    findings = validate_collection({"not": "an array"}, KEY)
    assert len(findings) == 1
    assert findings[0].code == "invalid_root"


def test_missing_manifest_id_is_an_error() -> None:
    payload = [
        {"manifest": {"name": "x", "version": "1"}, "transportUrl": "https://a.invalid/m.json"}
    ]
    assert "missing_manifest_id" in _codes(payload, "error")


def test_missing_manifest_fields_are_warnings_not_errors() -> None:
    payload = [{"manifest": {"id": "only-id"}, "transportUrl": "https://a.invalid/m.json"}]
    findings = validate_collection(payload, KEY)
    missing = {
        f.message for f in findings if f.code == "missing_manifest_field"
    }
    assert len(missing) == 4  # name, version, resources, types
    errors, _ = count_by_severity(findings)
    assert errors == 0


def test_duplicate_manifest_ids_are_an_error() -> None:
    payload = [
        {
            "manifest": {"id": "dup", "name": "a", "version": "1", "resources": [], "types": []},
            "transportUrl": "https://a.invalid/m.json",
        },
        {
            "manifest": {"id": "dup", "name": "b", "version": "1", "resources": [], "types": []},
            "transportUrl": "https://b.invalid/m.json",
        },
    ]
    dup = [f for f in validate_collection(payload, KEY) if f.code == "duplicate_manifest_id"]
    assert len(dup) == 1
    assert "dup" in dup[0].message
    assert "0, 1" in dup[0].message


def test_missing_transport_url_is_an_error() -> None:
    payload = [{"manifest": {"id": "a", "name": "a", "version": "1", "resources": [], "types": []}}]
    assert "missing_transport_url" in _codes(payload, "error")


def test_malformed_transport_url_is_an_error() -> None:
    payload = [{"manifest": {"id": "a"}, "transportUrl": "not-a-url"}]
    assert "malformed_transport_url" in _codes(payload, "error")


def test_unexpected_descriptor_key_is_warned() -> None:
    payload = [
        {
            "manifest": {"id": "a", "name": "a", "version": "1", "resources": [], "types": []},
            "transportUrl": "https://a.invalid/m.json",
            "weirdExtra": 1,
        }
    ]
    assert "unexpected_descriptor_field" in _codes(payload, "warning")


def test_non_object_descriptor_is_reported_and_skipped() -> None:
    payload = [
        {
            "manifest": {"id": "a", "name": "a", "version": "1", "resources": [], "types": []},
            "transportUrl": "https://a.invalid/m.json",
        },
        99,
    ]
    codes = _codes(payload)
    assert "invalid_descriptor" in codes


def test_non_object_flags_is_warned() -> None:
    payload = [
        {
            "manifest": {"id": "a", "name": "a", "version": "1", "resources": [], "types": []},
            "transportUrl": "https://a.invalid/m.json",
            "flags": "official",
        }
    ]
    assert "flags_type" in _codes(payload, "warning")
