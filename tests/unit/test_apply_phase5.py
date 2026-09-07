"""Phase 5 unit tests: secret resolution and local target construction.

No network: every function here is pure. The apply/rollback state machine is
exercised over mocked transports in ``tests/integration/test_apply_respx.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from stremioctl.apply import construct_target, resolve_endpoint_ref
from stremioctl.diff import build_change_plan
from stremioctl.errors import ValidationError
from stremioctl.fingerprints import collection_fingerprint
from stremioctl.models import parse_collection
from stremioctl.plans import build_plan_document
from stremioctl.privacy import redact_url
from stremioctl.profiles import parse_profile

KEY = b"k" * 32
HTTPS = "https://resolved.example.invalid/manifest.json"


def _desc(mid: str, *, url: str | None = None, protected: bool = False) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "manifest": {"id": mid, "name": mid, "version": "1.0.0", "resources": [], "types": []},
        "flags": {"official": False, "protected": protected},
    }
    if url is not None:
        descriptor["transportUrl"] = url
    return descriptor


def _url(mid: str) -> str:
    return f"https://{mid.replace('.', '-')}.example.invalid/manifest.json"


def _make_plan(current: list[dict[str, Any]], profile_doc: dict[str, Any]) -> dict[str, Any]:
    profile, warnings = parse_profile(profile_doc)
    return build_change_plan(
        current=current,
        profile=profile,
        key=KEY,
        created_at="2026-09-06T00:00:00Z",
        profile_warnings=[w.message for w in warnings],
    )


def _descriptors(collection: list[dict[str, Any]]) -> list[Any]:
    return list(parse_collection(collection).descriptors)


# --- resolve_endpoint_ref -------------------------------------------------------


def test_env_reference_resolves_to_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STREMIOCTL_TEST_EP", f"  {HTTPS}  ")
    assert resolve_endpoint_ref("env:STREMIOCTL_TEST_EP") == HTTPS


def test_env_reference_unset_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STREMIOCTL_TEST_EP", raising=False)
    with pytest.raises(ValidationError, match="resolves to nothing"):
        resolve_endpoint_ref("env:STREMIOCTL_TEST_EP")


def test_env_reference_bad_name_is_rejected() -> None:
    with pytest.raises(ValidationError, match="valid env variable"):
        resolve_endpoint_ref("env:not a name")


def test_unknown_scheme_is_rejected() -> None:
    with pytest.raises(ValidationError, match="start with 'env:' or 'file:'"):
        resolve_endpoint_ref("vault:/secret/x")


def test_file_reference_requires_absolute_path() -> None:
    with pytest.raises(ValidationError, match="absolute path"):
        resolve_endpoint_ref("file:relative/path")


def test_file_reference_reads_a_strict_permission_file(tmp_path: Path) -> None:
    secret = tmp_path / "ep.url"
    secret.write_text(HTTPS + "\n")
    secret.chmod(0o600)
    assert resolve_endpoint_ref(f"file:{secret}") == HTTPS


def test_file_reference_empty_is_rejected(tmp_path: Path) -> None:
    secret = tmp_path / "empty.url"
    secret.write_text("   \n")
    secret.chmod(0o600)
    with pytest.raises(ValidationError, match="empty file"):
        resolve_endpoint_ref(f"file:{secret}")


def test_resolved_value_must_be_a_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STREMIOCTL_TEST_EP", "not-a-url")
    with pytest.raises(ValidationError, match="not a valid http"):
        resolve_endpoint_ref("env:STREMIOCTL_TEST_EP")


def test_resolved_plain_http_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STREMIOCTL_TEST_EP", "http://insecure.example.invalid/manifest.json")
    with pytest.raises(ValidationError, match="must use https"):
        resolve_endpoint_ref("env:STREMIOCTL_TEST_EP")


def test_error_never_contains_the_resolved_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STREMIOCTL_TEST_EP", "ftp://secret-host.invalid/creds")
    with pytest.raises(ValidationError) as excinfo:
        resolve_endpoint_ref("env:STREMIOCTL_TEST_EP")
    assert "secret-host" not in str(excinfo.value)


# --- construct_target ---------------------------------------------------------


def test_remove_and_preserve_build_a_contiguous_target() -> None:
    current = [_desc("org.a", url=_url("org.a")), _desc("org.b", url=_url("org.b")),
               _desc("org.c", url=_url("org.c"))]
    plan = _make_plan(
        current,
        {
            "schemaVersion": 1,
            "name": "t",
            "addons": [
                {"key": "b", "match": {"manifestId": "org.b"}, "state": "absent",
                 "manage": ["state"]}
            ],
        },
    )
    target = construct_target(plan, _descriptors(current), KEY)
    assert [d["manifest"]["id"] for d in target] == ["org.a", "org.c"]
    assert collection_fingerprint(target) == collection_fingerprint([current[0], current[2]])


def test_unknown_descriptor_fields_survive_target_construction() -> None:
    exotic = _desc("org.a", url=_url("org.a"))
    exotic["transportName"] = "keep-me"
    exotic["x-vendor"] = {"nested": True}
    current = [exotic, _desc("org.b", url=_url("org.b"))]
    plan = _make_plan(
        current,
        {
            "schemaVersion": 1,
            "name": "t",
            "addons": [
                {"key": "b", "match": {"manifestId": "org.b"}, "state": "absent",
                 "manage": ["state"]}
            ],
        },
    )
    target = construct_target(plan, _descriptors(current), KEY)
    assert target[0]["transportName"] == "keep-me"
    assert target[0]["x-vendor"] == {"nested": True}
    # a deep copy: mutating the target must not touch the source descriptor
    target[0]["x-vendor"]["nested"] = False
    assert exotic["x-vendor"]["nested"] is True


def test_replace_endpoint_via_secret_ref_overrides_the_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STREMIOCTL_A_EP", HTTPS)
    current = [_desc("org.a", url=_url("org.a")), _desc("org.b", url=_url("org.b"))]
    plan = _make_plan(
        current,
        {
            "schemaVersion": 1,
            "name": "t",
            "addons": [
                {"key": "a", "match": {"manifestId": "org.a"}, "state": "present",
                 "position": 0, "endpoint": {"secretRef": "env:STREMIOCTL_A_EP"},
                 "manage": ["state", "endpoint"]}
            ],
        },
    )
    target = construct_target(plan, _descriptors(current), KEY)
    assert target[0]["transportUrl"] == HTTPS
    assert target[1]["transportUrl"] == _url("org.b")


def test_add_operation_is_refused() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _make_plan(
        current,
        {
            "schemaVersion": 1,
            "name": "t",
            "addons": [
                {"key": "new", "match": {"manifestId": "org.new"}, "state": "present",
                 "position": 1, "endpoint": {"secretRef": "env:NEW_EP"},
                 "manage": ["state", "position", "endpoint"]}
            ],
        },
    )
    with pytest.raises(ValidationError, match="adds an add-on"):
        construct_target(plan, _descriptors(current), KEY)


def test_replace_endpoint_with_only_a_public_label_is_refused() -> None:
    current = [_desc("org.a", url=_url("org.a")), _desc("org.b", url=_url("org.b"))]
    plan = _make_plan(
        current,
        {
            "schemaVersion": 1,
            "name": "t",
            "addons": [
                {"key": "a", "match": {"manifestId": "org.a"}, "state": "present",
                 "position": 0,
                 "endpoint": {"publicUrl": "https://replacement.example.invalid/manifest.json"},
                 "manage": ["state", "endpoint"]}
            ],
        },
    )
    with pytest.raises(ValidationError, match="declared as a public URL"):
        construct_target(plan, _descriptors(current), KEY)


def test_removing_a_protected_addon_is_refused() -> None:
    current = [
        _desc("org.a", url=_url("org.a")),
        _desc("org.b", url=_url("org.b"), protected=True),
    ]
    plan = _make_plan(
        current,
        {
            "schemaVersion": 1,
            "name": "t",
            "addons": [
                {"key": "b", "match": {"manifestId": "org.b"}, "state": "absent",
                 "manage": ["state"]}
            ],
        },
    )
    with pytest.raises(ValidationError, match="protected add-on"):
        construct_target(plan, _descriptors(current), KEY)


def _hand_plan(ops: list[dict[str, Any]], base: str) -> dict[str, Any]:
    return build_plan_document(
        created_at="2026-09-06T00:00:00Z",
        base_collection_fingerprint=base,
        desired_profile_fingerprint="0" * 64,
        operations=ops,
        warnings=[],
    )


def test_preserve_reference_with_no_current_match_is_rejected() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [{"op": "preserve", "manifestId": "org.zzz", "finalIndex": 0}],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="stale"):
        construct_target(plan, _descriptors(current), KEY)


def test_ambiguous_preserve_reference_is_rejected() -> None:
    current = [_desc("org.dup"), _desc("org.dup")]  # no transport URL to tell them apart
    plan = _hand_plan(
        [
            {"op": "preserve", "manifestId": "org.dup", "finalIndex": 0},
            {"op": "preserve", "manifestId": "org.dup", "finalIndex": 1},
        ],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="more than one"):
        construct_target(plan, _descriptors(current), KEY)


def test_non_contiguous_target_is_rejected() -> None:
    current = [_desc("org.a", url=_url("org.a")), _desc("org.b", url=_url("org.b"))]
    label_a = redact_url(_url("org.a"), KEY)
    plan = _hand_plan(
        [
            {"op": "preserve", "manifestId": "org.a", "finalIndex": 0, "endpoint": label_a},
            {"op": "preserve", "manifestId": "org.b", "finalIndex": 2,
             "endpoint": redact_url(_url("org.b"), KEY)},
        ],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="contiguous"):
        construct_target(plan, _descriptors(current), KEY)


def test_replace_endpoint_landing_on_the_wrong_slot_is_refused() -> None:
    current = [_desc("org.a", url=_url("org.a")), _desc("org.b", url=_url("org.b"))]
    plan = _hand_plan(
        [
            {"op": "preserve", "manifestId": "org.a", "finalIndex": 0,
             "endpoint": redact_url(_url("org.a"), KEY)},
            {"op": "preserve", "manifestId": "org.b", "finalIndex": 1,
             "endpoint": redact_url(_url("org.b"), KEY)},
            {"op": "replaceEndpoint", "manifestId": "org.a", "finalIndex": 1,
             "endpointRef": "env:SHOULD_NOT_BE_READ"},
        ],
        collection_fingerprint(current),
    )

    def _no_resolve(_ref: str) -> str:  # pragma: no cover - must not be called
        raise AssertionError("the secret reference must never be resolved on a bad slot")

    with pytest.raises(ValidationError, match="lands on a slot holding"):
        construct_target(plan, _descriptors(current), KEY, resolver=_no_resolve)


def test_plan_load_rejects_a_non_object() -> None:
    from stremioctl.apply import _load_validated_plan

    with pytest.raises(ValidationError, match="JSON object"):
        _load_validated_plan([1, 2, 3])


def test_plan_load_rejects_a_schema_violation() -> None:
    from stremioctl.apply import _load_validated_plan

    with pytest.raises(ValidationError, match="change-plan-v1"):
        _load_validated_plan({"schemaVersion": 1, "operations": "not-a-list"})


def test_corrupt_plan_hash_is_rejected_by_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    # tampering with the body after the hash was computed must be caught on load
    from stremioctl.apply import _load_validated_plan

    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [{"op": "preserve", "manifestId": "org.a", "finalIndex": 0}],
        collection_fingerprint(current),
    )
    plan = json.loads(json.dumps(plan))
    plan["warnings"] = ["injected after hashing"]
    with pytest.raises(ValidationError, match="corrupt"):
        _load_validated_plan(plan)
