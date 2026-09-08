"""Phase 5 unit tests: secret resolution and local target construction.

No network: every function here is pure. The apply/rollback state machine is
exercised over mocked transports in ``tests/integration/test_apply_respx.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from stremioctl.account import PulledCollection
from stremioctl.apply import (
    _write_snapshot,
    construct_target,
    resolve_endpoint_ref,
    resolve_target_manifest,
)
from stremioctl.diff import build_change_plan
from stremioctl.errors import DriftError, NetworkError, SecurityError, ValidationError
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


def test_same_second_snapshots_get_distinct_names() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    pulled = PulledCollection(
        addons=current,
        last_modified=None,
        fingerprint=collection_fingerprint(current),
        base_url="https://api.strem.io",
    )
    first = _write_snapshot(pulled, "2026-09-06T00:00:00Z", "pre-apply")
    second = _write_snapshot(pulled, "2026-09-06T00:00:00Z", "pre-apply")
    assert first != second
    assert first.exists() and second.exists()


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


def test_target_manifest_is_refetched_and_bound_to_reviewed_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {
        "id": "org.target",
        "name": "Target",
        "version": "2.0.0",
        "resources": [],
        "types": [],
    }
    monkeypatch.setattr(
        "stremioctl.apply.probe_manifest_url",
        lambda *_args, **_kwargs: ({"status": "healthy"}, manifest),
    )
    assert resolve_target_manifest(
        HTTPS, "org.target", collection_fingerprint(manifest), KEY
    ) == manifest


def test_target_manifest_drift_or_probe_failure_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = {"id": "org.target"}
    monkeypatch.setattr(
        "stremioctl.apply.probe_manifest_url",
        lambda *_args, **_kwargs: ({"status": "healthy"}, manifest),
    )
    with pytest.raises(DriftError, match="changed since planning"):
        resolve_target_manifest(HTTPS, "org.target", "0" * 64, KEY)

    monkeypatch.setattr(
        "stremioctl.apply.probe_manifest_url",
        lambda *_args, **_kwargs: ({"status": "unreachable"}, None),
    )
    with pytest.raises(NetworkError, match="apply-time manifest check"):
        resolve_target_manifest(HTTPS, "org.target", "0" * 64, KEY)


def test_malformed_resolved_url_is_rejected_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STREMIOCTL_TEST_EP", "https://[secret-invalid")
    with pytest.raises(ValidationError, match="not a valid http") as excinfo:
        resolve_endpoint_ref("env:STREMIOCTL_TEST_EP")
    assert "secret-invalid" not in str(excinfo.value)


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


def test_replace_endpoint_via_declared_public_url_overrides_the_slot() -> None:
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
    replacement = "https://replacement.example.invalid/manifest.json"
    assert next(op for op in plan["operations"] if op["op"] == "replaceEndpoint")[
        "publicUrl"
    ] == replacement
    target = construct_target(plan, _descriptors(current), KEY)
    assert target[0]["transportUrl"] == replacement


def test_replace_endpoint_via_declared_public_http_url_is_refused() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _make_plan(
        current,
        {
            "schemaVersion": 1,
            "name": "t",
            "addons": [
                {
                    "key": "a",
                    "match": {"manifestId": "org.a"},
                    "state": "present",
                    "endpoint": {"publicUrl": "http://replacement.example.invalid/manifest.json"},
                    "manage": ["state", "endpoint"],
                }
            ],
        },
    )
    with pytest.raises(ValidationError, match="must use https"):
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


def test_remove_with_out_of_range_index_is_rejected() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [{"op": "remove", "manifestId": "org.a", "fromIndex": 4, "reason": "test"}],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="out of range"):
        construct_target(plan, _descriptors(current), KEY)


def test_remove_whose_manifest_does_not_match_index_is_rejected() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [{"op": "remove", "manifestId": "org.other", "fromIndex": 0, "reason": "test"}],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="does not line up"):
        construct_target(plan, _descriptors(current), KEY)


def test_preserve_with_non_integer_final_index_is_rejected() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [{"op": "preserve", "manifestId": "org.a", "finalIndex": "zero"}],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="valid finalIndex"):
        construct_target(plan, _descriptors(current), KEY)


def test_replace_endpoint_without_a_preserved_slot_is_rejected() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [
            {
                "op": "replaceEndpoint",
                "manifestId": "org.a",
                "finalIndex": 0,
                "endpointRef": "env:SHOULD_NOT_BE_READ",
            }
        ],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="no preserved add-on"):
        construct_target(plan, _descriptors(current), KEY)


def test_replace_endpoint_with_two_sources_is_rejected() -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [
            {
                "op": "replaceEndpoint",
                "manifestId": "org.a",
                "finalIndex": 0,
                "endpointRef": "env:SHOULD_NOT_BE_READ",
                "publicUrl": "https://public.example.invalid/manifest.json",
            }
        ],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="exactly one endpoint"):
        construct_target(plan, _descriptors(current), KEY)


def test_snapshot_security_error_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    current = [_desc("org.a", url=_url("org.a"))]
    pulled = PulledCollection(
        addons=current,
        last_modified=None,
        fingerprint=collection_fingerprint(current),
        base_url="https://api.strem.io",
    )

    def fail_securely(*_args: Any, **_kwargs: Any) -> None:
        raise SecurityError("unsafe output")

    monkeypatch.setattr("stremioctl.apply.atomic_write_text", fail_securely)
    with pytest.raises(SecurityError, match="unsafe output"):
        _write_snapshot(pulled, "2026-09-06T00:00:00Z", "pre-apply")


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


def test_plan_load_rejects_two_endpoint_sources() -> None:
    from stremioctl.apply import _load_validated_plan

    current = [_desc("org.a", url=_url("org.a"))]
    plan = _hand_plan(
        [
            {
                "op": "replaceEndpoint",
                "manifestId": "org.a",
                "finalIndex": 0,
                "endpointRef": "env:STREMIOCTL_TEST_EP",
                "publicUrl": HTTPS,
            }
        ],
        collection_fingerprint(current),
    )
    with pytest.raises(ValidationError, match="change-plan-v1"):
        _load_validated_plan(plan)


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
