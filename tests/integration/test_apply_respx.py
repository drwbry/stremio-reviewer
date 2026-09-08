"""Phase 5 failure-injection tests for the apply / rollback state machine.

Every transition in SPEC section 12 is forced over a mocked transport: the
drift guard, the mandatory pre-apply snapshot, the single push, the verifying
pull, and the single rollback attempt with its succeeded / failed / unknown
outcomes.
"""

from __future__ import annotations

import json
import stat
from typing import Any

import httpx
import pytest
import respx

from stremioctl.account import AccountConfig
from stremioctl.apply import apply_plan, rollback_snapshot
from stremioctl.diff import build_change_plan
from stremioctl.errors import DriftError, ValidationError
from stremioctl.fingerprints import collection_fingerprint
from stremioctl.io import private_app_path
from stremioctl.profiles import parse_profile

KEY = b"k" * 32
SENTINEL_KEY = "SENTINEL_MUST_NOT_LEAK"
GET_URL = "https://api.strem.io/api/addonCollectionGet"
SET_URL = "https://api.strem.io/api/addonCollectionSet"
NOW = "2026-09-06T12:00:00Z"


def _url(mid: str) -> str:
    return f"https://{mid.replace('.', '-')}.example.invalid/manifest.json"


def _desc(mid: str, *, url: str | None = None, protected: bool = False) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "manifest": {"id": mid, "name": mid, "version": "1.0.0", "resources": [], "types": []},
        "flags": {"official": False, "protected": protected},
    }
    if url is not None:
        descriptor["transportUrl"] = url
    return descriptor


ABC = [_desc("org.a", url=_url("org.a")), _desc("org.b", url=_url("org.b")),
       _desc("org.c", url=_url("org.c"))]
AC = [ABC[0], ABC[2]]
JUNK = [_desc("org.a", url=_url("org.a"))]

REMOVE_B_PROFILE = {
    "schemaVersion": 1,
    "name": "t",
    "addons": [
        {"key": "b", "match": {"manifestId": "org.b"}, "state": "absent", "manage": ["state"]}
    ],
}


def _plan(current: list[dict[str, Any]], profile_doc: dict[str, Any]) -> dict[str, Any]:
    profile, warnings = parse_profile(profile_doc)
    return build_change_plan(
        current=current,
        profile=profile,
        key=KEY,
        created_at="2026-09-06T00:00:00Z",
        profile_warnings=[w.message for w in warnings],
    )


def _get(addons: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"result": {"addons": addons, "lastModified": NOW}})


def _set_ok() -> httpx.Response:
    return httpx.Response(200, json={"result": {"success": True}})


def _apply(plan: dict[str, Any], **kw: Any) -> Any:
    return apply_plan(
        plan=plan,
        confirm=plan["planHash"],
        key=KEY,
        auth_key=SENTINEL_KEY,
        cfg=AccountConfig(),
        now=NOW,
        **kw,
    )


def _snapshots(prefix: str) -> list[Any]:
    return sorted((private_app_path() / "snapshots").glob(f"{prefix}-*.json"))


def _no_key_leak(lines: list[str]) -> None:
    assert SENTINEL_KEY not in "\n".join(lines)


# --- happy path -------------------------------------------------------------


@respx.mock
def test_apply_writes_a_snapshot_then_pushes_once_and_verifies() -> None:
    get = respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(AC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])
    outcome = _apply(_plan(ABC, REMOVE_B_PROFILE))

    assert outcome.exit_code == 0
    assert outcome.pushed and outcome.verified
    assert outcome.rollback == "not_attempted"
    assert get.call_count == 2
    assert set_.call_count == 1

    pushed = json.loads(set_.calls[0].request.content)
    assert [d["manifest"]["id"] for d in pushed["addons"]] == ["org.a", "org.c"]

    snaps = _snapshots("pre-apply")
    assert len(snaps) == 1
    assert stat.S_IMODE(snaps[0].stat().st_mode) == 0o600
    snapshot = json.loads(snaps[0].read_text())
    assert snapshot["collectionFingerprint"] == collection_fingerprint(ABC)
    _no_key_leak(outcome.lines)


@respx.mock
def test_apply_that_removes_every_addon_prints_an_explicit_warning() -> None:
    remove_all = {
        "schemaVersion": 1,
        "name": "empty",
        "addons": [
            {
                "key": f"remove-{index}",
                "match": {"manifestId": descriptor["manifest"]["id"]},
                "state": "absent",
                "manage": ["state"],
            }
            for index, descriptor in enumerate(ABC)
        ],
    }
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get([])])
    respx.post(SET_URL).mock(side_effect=[_set_ok()])
    outcome = _apply(_plan(ABC, remove_all))
    assert outcome.exit_code == 0
    assert any("remove all 3 add-ons" in line for line in outcome.lines)


@respx.mock
def test_replace_endpoint_via_secret_ref_is_resolved_only_at_apply_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = "https://resolved.example.invalid/manifest.json"
    monkeypatch.setenv("STREMIOCTL_A_EP", resolved)
    profile = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {"key": "a", "match": {"manifestId": "org.a"}, "state": "present", "position": 0,
             "endpoint": {"secretRef": "env:STREMIOCTL_A_EP"}, "manage": ["state", "endpoint"]}
        ],
    }
    plan = _plan(ABC, profile)
    target = [_desc("org.a", url=resolved), ABC[1], ABC[2]]
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(target)])

    outcome = _apply(plan)
    assert outcome.exit_code == 0 and outcome.verified
    pushed = json.loads(set_.calls[0].request.content)
    assert pushed["addons"][0]["transportUrl"] == resolved
    # the resolved secret URL never appears in anything shown to the user
    assert "resolved.example.invalid" not in "\n".join(outcome.lines)


# --- no-write paths --------------------------------------------------------


@respx.mock
def test_a_converged_plan_makes_no_write() -> None:
    plan = _plan(ABC, {"schemaVersion": 1, "name": "t", "addons": []})
    assert plan["operations"] == []
    get = respx.post(GET_URL).mock(side_effect=[_get(ABC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    outcome = _apply(plan)
    assert outcome.exit_code == 0
    assert get.call_count == 1
    assert set_.call_count == 0
    assert not outcome.wrote_snapshot
    assert _snapshots("pre-apply") == []


@respx.mock
def test_a_preserve_only_plan_whose_target_matches_makes_no_write() -> None:
    from stremioctl.plans import build_plan_document
    from stremioctl.privacy import redact_url

    ops = [
        {"op": "preserve", "manifestId": "org.a", "finalIndex": 0,
         "endpoint": redact_url(_url("org.a"), KEY)},
        {"op": "preserve", "manifestId": "org.c", "finalIndex": 1,
         "endpoint": redact_url(_url("org.c"), KEY)},
    ]
    plan = build_plan_document(
        created_at="2026-09-06T00:00:00Z",
        base_collection_fingerprint=collection_fingerprint(AC),
        desired_profile_fingerprint="0" * 64,
        operations=ops,
        warnings=[],
    )
    get = respx.post(GET_URL).mock(side_effect=[_get(AC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    outcome = _apply(plan)
    assert outcome.exit_code == 0
    assert get.call_count == 1
    assert set_.call_count == 0
    assert not outcome.wrote_snapshot
    assert any("already matches" in line for line in outcome.lines)


@respx.mock
def test_semantically_equivalent_verification_still_rolls_back() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    # same (id, transportUrl) shape as the target, but an extra field => new hash
    normalized = [dict(ABC[0], transportName="server-added"), ABC[2]]
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(normalized), _get(ABC)])
    respx.post(SET_URL).mock(side_effect=[_set_ok(), _set_ok()])

    outcome = _apply(plan)
    assert outcome.exit_code == 6
    assert outcome.rollback == "succeeded"
    assert any("semantically equivalent" in line for line in outcome.lines)


@respx.mock
def test_a_stale_plan_exits_5_and_makes_no_write() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)  # base fingerprint is for [a, b, c]
    respx.post(GET_URL).mock(side_effect=[_get(AC)])  # the account already moved on
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    with pytest.raises(DriftError):
        _apply(plan)
    assert set_.call_count == 0
    assert _snapshots("pre-apply") == []


@respx.mock
def test_reapplying_the_same_plan_twice_exits_5_on_the_second_run() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    # run 1 pulls [a,b,c] then verifies [a,c]; run 2 pulls [a,c] and stops on drift
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(AC), _get(AC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    first = _apply(plan)
    assert first.exit_code == 0
    assert set_.call_count == 1

    with pytest.raises(DriftError):
        _apply(plan)
    assert set_.call_count == 1  # the stale re-run added no write


@respx.mock
def test_initial_pull_failure_propagates_as_network_error() -> None:
    from stremioctl.errors import NetworkError

    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[httpx.ConnectError("dropped")])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])
    with pytest.raises(NetworkError):
        _apply(plan)
    assert set_.call_count == 0
    assert _snapshots("pre-apply") == []


@respx.mock
def test_rejected_key_on_the_initial_pull_propagates_as_auth_error() -> None:
    from stremioctl.errors import AuthenticationError

    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[httpx.Response(403)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])
    with pytest.raises(AuthenticationError):
        _apply(plan)
    assert set_.call_count == 0


@respx.mock
def test_wrong_confirmation_hash_exits_2_before_any_network() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    get = respx.post(GET_URL).mock(side_effect=[_get(ABC)])
    with pytest.raises(ValidationError, match="--confirm"):
        apply_plan(
            plan=plan, confirm="deadbeef", key=KEY, auth_key=SENTINEL_KEY,
            cfg=AccountConfig(), now=NOW,
        )
    assert get.call_count == 0


# --- write attempted: verification and rollback --------------------------


@respx.mock
def test_push_error_but_write_actually_landed_is_a_success() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(AC)])
    respx.post(SET_URL).mock(side_effect=[httpx.ReadTimeout("timed out")])

    outcome = _apply(plan)
    assert outcome.exit_code == 0
    assert outcome.verified
    assert any("reported" in line for line in outcome.lines)


@respx.mock
def test_push_failed_and_write_did_not_land_exits_6_without_rollback() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(ABC)])
    set_ = respx.post(SET_URL).mock(side_effect=[httpx.Response(500)])

    outcome = _apply(plan)
    assert outcome.exit_code == 6
    assert outcome.rollback == "not_attempted"
    assert set_.call_count == 1  # no rollback write
    assert any("did not take effect" in line for line in outcome.lines)


@respx.mock
def test_verification_mismatch_triggers_one_rollback_that_succeeds() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(JUNK), _get(ABC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok(), _set_ok()])

    outcome = _apply(plan)
    assert outcome.exit_code == 6
    assert outcome.rollback == "succeeded"
    assert set_.call_count == 2  # apply push + one rollback push
    assert any("restored" in line for line in outcome.lines)
    _no_key_leak(outcome.lines)


@respx.mock
def test_verification_mismatch_then_rollback_push_fails() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(JUNK)])
    respx.post(SET_URL).mock(side_effect=[_set_ok(), httpx.Response(502)])

    outcome = _apply(plan)
    assert outcome.exit_code == 6
    assert outcome.rollback == "failed"
    assert any("restore write failed" in line for line in outcome.lines)


@respx.mock
def test_verification_mismatch_then_rollback_verify_fails_is_unknown() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(
        side_effect=[_get(ABC), _get(JUNK), httpx.ConnectError("dropped")]
    )
    respx.post(SET_URL).mock(side_effect=[_set_ok(), _set_ok()])

    outcome = _apply(plan)
    assert outcome.exit_code == 6
    assert outcome.rollback == "unknown"
    assert any("could not be verified" in line for line in outcome.lines)


@respx.mock
def test_verification_mismatch_then_rollback_lands_wrong_state_is_failed() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(JUNK), _get(JUNK)])
    respx.post(SET_URL).mock(side_effect=[_set_ok(), _set_ok()])

    outcome = _apply(plan)
    assert outcome.exit_code == 6
    assert outcome.rollback == "failed"
    assert any("did not return to the snapshot" in line for line in outcome.lines)


@respx.mock
def test_post_write_pull_failure_is_unknown_state_and_rolls_back() -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(
        side_effect=[_get(ABC), httpx.ConnectError("dropped"), _get(ABC)]
    )
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok(), _set_ok()])

    outcome = _apply(plan)
    assert outcome.exit_code == 6
    assert outcome.rollback == "succeeded"
    assert set_.call_count == 2
    assert any("remote state is unknown" in line for line in outcome.lines)


@respx.mock
def test_snapshot_write_failure_aborts_before_any_push(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(ABC, REMOVE_B_PROFILE)
    respx.post(GET_URL).mock(side_effect=[_get(ABC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("stremioctl.apply.atomic_write_text", boom)
    from stremioctl.errors import ApplyError

    with pytest.raises(ApplyError, match="pre-apply snapshot"):
        _apply(plan)
    assert set_.call_count == 0


# --- standalone rollback --------------------------------------------------


def _snapshot_doc(addons: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "artifact": "account-snapshot",
        "pulledAt": NOW,
        "baseUrl": "https://api.strem.io",
        "lastModified": None,
        "collectionFingerprint": collection_fingerprint(addons),
        "collection": addons,
    }


def _rollback(doc: dict[str, Any], **kw: Any) -> Any:
    return rollback_snapshot(
        snapshot=doc,
        confirm=doc["collectionFingerprint"],
        auth_key=SENTINEL_KEY,
        cfg=AccountConfig(),
        now=NOW,
        **kw,
    )


@respx.mock
def test_standalone_rollback_snapshots_current_state_then_restores() -> None:
    doc = _snapshot_doc(ABC)
    respx.post(GET_URL).mock(side_effect=[_get(AC), _get(ABC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    outcome = _rollback(doc)
    assert outcome.exit_code == 0
    assert outcome.rollback == "succeeded"
    assert set_.call_count == 1
    guards = _snapshots("pre-rollback")
    assert len(guards) == 1
    assert stat.S_IMODE(guards[0].stat().st_mode) == 0o600


@respx.mock
def test_standalone_rollback_aborts_if_the_pre_rollback_snapshot_cannot_be_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from stremioctl.errors import ApplyError

    doc = _snapshot_doc(ABC)
    respx.post(GET_URL).mock(side_effect=[_get(AC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("stremioctl.apply.atomic_write_text", boom)
    with pytest.raises(ApplyError, match="pre-rollback snapshot"):
        _rollback(doc)
    assert set_.call_count == 0


@respx.mock
def test_standalone_rollback_rejects_a_wrong_confirmation() -> None:
    doc = _snapshot_doc(ABC)
    get = respx.post(GET_URL).mock(side_effect=[_get(AC)])
    with pytest.raises(ValidationError, match="collectionFingerprint"):
        rollback_snapshot(
            snapshot=doc, confirm="0" * 64, auth_key=SENTINEL_KEY,
            cfg=AccountConfig(), now=NOW,
        )
    assert get.call_count == 0


@respx.mock
def test_standalone_rollback_is_a_noop_when_already_matching() -> None:
    doc = _snapshot_doc(ABC)
    respx.post(GET_URL).mock(side_effect=[_get(ABC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])

    outcome = _rollback(doc)
    assert outcome.exit_code == 0
    assert set_.call_count == 0
    assert any("nothing to restore" in line for line in outcome.lines)


@respx.mock
def test_standalone_rollback_reports_a_failed_restore() -> None:
    doc = _snapshot_doc(ABC)
    respx.post(GET_URL).mock(side_effect=[_get(AC)])
    respx.post(SET_URL).mock(side_effect=[httpx.Response(500)])

    outcome = _rollback(doc)
    assert outcome.exit_code == 6
    assert outcome.rollback == "failed"


def test_standalone_rollback_rejects_a_corrupt_snapshot() -> None:
    doc = _snapshot_doc(ABC)
    doc["collection"] = AC  # fingerprint no longer matches the collection
    with pytest.raises(ValidationError, match="corrupt"):
        rollback_snapshot(
            snapshot=doc, confirm=doc["collectionFingerprint"], auth_key=SENTINEL_KEY,
            cfg=AccountConfig(), now=NOW,
        )
