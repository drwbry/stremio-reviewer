from __future__ import annotations

import json
from typing import Any

import pytest

from _helpers import FIXTURES, load_valid_collection
from stremioctl.diff import build_change_plan
from stremioctl.errors import ValidationError
from stremioctl.privacy import display_fingerprint
from stremioctl.profiles import parse_profile

KEY = b"k" * 32
CREATED_AT = "2026-09-06T00:00:00Z"


def _collection(ids: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "manifest": {
                "id": mid,
                "name": mid,
                "version": "1.0.0",
                "resources": [],
                "types": [],
            },
            "transportUrl": f"https://{mid.replace('.', '-')}.example.invalid/manifest.json",
        }
        for mid in ids
    ]


def _plan(current: list[dict[str, Any]], profile_doc: dict[str, Any]) -> dict[str, Any]:
    profile, warnings = parse_profile(profile_doc)
    return build_change_plan(
        current=current,
        profile=profile,
        key=KEY,
        created_at=CREATED_AT,
        profile_warnings=[w.message for w in warnings],
    )


def _present(key: str, mid: str, position: int) -> dict[str, Any]:
    return {
        "key": key,
        "match": {"manifestId": mid},
        "state": "present",
        "position": position,
        "manage": ["state", "position"],
    }


def _target_manifest(plan: dict[str, Any]) -> list[str]:
    """Reconstruct the target collection order from `preserve` + `add` entries."""

    slots: dict[int, str] = {}
    for op in plan["operations"]:
        if op["op"] in {"preserve", "add"}:
            assert op["finalIndex"] not in slots, "two ops claim the same target index"
            slots[op["finalIndex"]] = op["manifestId"]
    assert sorted(slots) == list(range(len(slots))), "target manifest is not contiguous"
    return [slots[i] for i in sorted(slots)]


# --- acceptance: converged profile -> no operations, exit 0 semantics ---


def test_converged_profile_produces_no_operations() -> None:
    current = _collection(["a", "b", "c"])
    doc = json.loads((FIXTURES / "desired.synthetic.json").read_text())
    plan = _plan(current, doc)
    assert plan["operations"] == []


def test_profile_that_only_reasserts_current_order_is_converged() -> None:
    current = _collection(["a", "b", "c"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [_present("ka", "a", 0), _present("kb", "b", 1), _present("kc", "c", 2)],
    }
    assert _plan(current, doc)["operations"] == []


# --- acceptance: byte-identical re-run except createdAt ---


def test_rerun_is_byte_identical_except_created_at() -> None:
    current = load_valid_collection()
    doc = json.loads((FIXTURES / "desired.synthetic-changes.json").read_text())
    profile, _ = parse_profile(doc)
    a = build_change_plan(
        current=current, profile=profile, key=KEY, created_at="2026-01-01T00:00:00Z"
    )
    b = build_change_plan(
        current=current, profile=profile, key=KEY, created_at="2026-06-30T12:00:00Z"
    )
    assert json.dumps(a) != json.dumps(b)  # createdAt differs
    assert a["planHash"] == b["planHash"]
    a.pop("createdAt")
    b.pop("createdAt")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --- acceptance: changed profile -> redacted plan, mutating ops present ---


def test_changes_plan_is_redacted_and_lists_mutations() -> None:
    plan = _plan(
        load_valid_collection(),
        json.loads((FIXTURES / "desired.synthetic-changes.json").read_text()),
    )
    blob = json.dumps(plan)
    assert "SENTINEL_" not in blob
    assert "/manifest.json" not in blob  # no complete transport URL
    kinds = {op["op"] for op in plan["operations"]}
    assert "remove" in kinds
    assert "move" in kinds
    assert "preserve" in kinds  # full target manifest once there is a mutation
    # preserve + add rebuild the whole 7-descriptor target (8 minus one removal)
    assert _target_manifest(plan) == ["synthetic.stream"] + [
        m
        for m in [
            "synthetic.catalog",
            "synthetic.metadata",
            "synthetic.extra.one",
            "synthetic.extra.two",
            "synthetic.extra.three",
            "synthetic.secret",
        ]
    ]


# --- acceptance: duplicate manifest ids -> ambiguity unless disambiguated ---


def test_duplicate_manifest_ids_raise_actionable_ambiguity() -> None:
    dupes = json.loads((FIXTURES / "collection.synthetic-dupes.json").read_text())
    doc = json.loads((FIXTURES / "desired.synthetic-ambiguous.json").read_text())
    with pytest.raises(ValidationError) as excinfo:
        _plan(dupes, doc)
    message = str(excinfo.value)
    assert "synthetic.dup" in message
    assert "transportFingerprint" in message


def test_duplicate_manifest_ids_are_planned_when_disambiguated() -> None:
    dupes = json.loads((FIXTURES / "collection.synthetic-dupes.json").read_text())
    fingerprint = display_fingerprint("https://dup-b.example.invalid/manifest.json", KEY)
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "dupb",
                "match": {"manifestId": "synthetic.dup", "transportFingerprint": fingerprint},
                "state": "absent",
                "manage": ["state"],
            }
        ],
    }
    plan = _plan(dupes, doc)
    removes = [op for op in plan["operations"] if op["op"] == "remove"]
    assert len(removes) == 1
    assert removes[0]["fromIndex"] == 1  # dup-b, not dup-a
    assert any("duplicate manifest ids" in w for w in plan["warnings"])


# --- acceptance: structural problems still block ---


def test_two_specs_resolving_to_the_same_descriptor_is_rejected() -> None:
    # Distinct selectors (one bare manifestId, one with a fingerprint) pass the
    # profile's duplicate-target check but land on the same descriptor.
    current = _collection(["a", "b"])
    fingerprint = display_fingerprint(current[0]["transportUrl"], KEY)
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {"key": "one", "match": {"manifestId": "a"}, "state": "present", "manage": ["state"]},
            {
                "key": "two",
                "match": {"manifestId": "a", "transportFingerprint": fingerprint},
                "state": "absent",
                "manage": ["state"],
            },
        ],
    }
    with pytest.raises(ValidationError, match="claimed by both"):
        _plan(current, doc)


def test_structural_error_in_current_collection_is_rejected() -> None:
    broken = [{"manifest": {"id": "a"}, "transportUrl": "not-a-url"}]
    with pytest.raises(ValidationError):
        _plan(broken, {"schemaVersion": 1, "name": "t", "addons": []})


# --- add / remove / move / replaceEndpoint ---


def test_present_spec_without_match_or_endpoint_is_rejected() -> None:
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "new",
                "match": {"manifestId": "ghost"},
                "state": "present",
                "manage": ["state"],
            }
        ],
    }
    with pytest.raises(ValidationError):
        _plan(_collection(["a"]), doc)


def test_present_spec_with_secret_ref_endpoint_is_an_add() -> None:
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "new",
                "match": {"manifestId": "ghost"},
                "state": "present",
                "position": 0,
                "endpoint": {"secretRef": "env:STREMIOCTL_NEW_URL"},
                "manage": ["state", "position", "endpoint"],
            }
        ],
    }
    plan = _plan(_collection(["a", "b"]), doc)
    adds = [op for op in plan["operations"] if op["op"] == "add"]
    assert adds[0]["endpointRef"] == "env:STREMIOCTL_NEW_URL"
    assert "endpoint" not in adds[0]  # no resolved URL


def test_replace_endpoint_when_public_url_differs() -> None:
    current = _collection(["a"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "ka",
                "match": {"manifestId": "a"},
                "state": "present",
                "endpoint": {"publicUrl": "https://replacement.example.invalid/manifest.json"},
                "manage": ["state", "endpoint"],
            }
        ],
    }
    plan = _plan(current, doc)
    repl = [op for op in plan["operations"] if op["op"] == "replaceEndpoint"]
    assert len(repl) == 1
    assert repl[0]["endpoint"].startswith("https://replacement.example.invalid/<redacted>#")


def test_no_replace_endpoint_when_public_url_already_matches() -> None:
    current = _collection(["a"])
    url = current[0]["transportUrl"]
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "ka",
                "match": {"manifestId": "a"},
                "state": "present",
                "endpoint": {"publicUrl": url},
                "manage": ["state", "endpoint"],
            }
        ],
    }
    assert _plan(current, doc)["operations"] == []


def test_secret_ref_endpoint_is_unverifiable_offline() -> None:
    current = _collection(["a"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "ka",
                "match": {"manifestId": "a"},
                "state": "present",
                "endpoint": {"secretRef": "env:STREMIOCTL_A_URL"},
                "manage": ["state", "endpoint"],
            }
        ],
    }
    plan = _plan(current, doc)
    repl = [op for op in plan["operations"] if op["op"] == "replaceEndpoint"]
    assert repl[0]["reason"] == "offline-unverifiable"
    assert repl[0]["endpointRef"] == "env:STREMIOCTL_A_URL"
    assert any("could not be compared offline" in w for w in plan["warnings"])


def test_secret_ref_with_matching_transport_fingerprint_converges() -> None:
    current = _collection(["a"])
    fingerprint = display_fingerprint(current[0]["transportUrl"], KEY)
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "ka",
                "match": {"manifestId": "a", "transportFingerprint": fingerprint},
                "state": "present",
                "endpoint": {"secretRef": "env:STREMIOCTL_A_URL"},
                "manage": ["state", "endpoint"],
            }
        ],
    }
    assert _plan(current, doc)["operations"] == []


# --- table-driven reorder coverage (managed + unmanaged) ---


@pytest.mark.parametrize(
    "ids, anchors, expected_order",
    [
        # no-op
        (["a", "b", "c"], {}, ["a", "b", "c"]),
        # move one managed item to the front; unmanaged keep relative order
        (["a", "b", "c", "d"], {"c": 0}, ["c", "a", "b", "d"]),
        # move one managed item to the back
        (["a", "b", "c", "d"], {"a": 3}, ["b", "c", "d", "a"]),
        # two anchors, order swap
        (["a", "b", "c"], {"a": 2, "c": 0}, ["c", "b", "a"]),
        # anchor that lands where it already is -> converged
        (["a", "b", "c"], {"b": 1}, ["a", "b", "c"]),
    ],
)
def test_reorder_table(
    ids: list[str], anchors: dict[str, int], expected_order: list[str]
) -> None:
    current = _collection(ids)
    addons = [
        _present(f"k_{mid}", mid, pos)
        for mid, pos in anchors.items()
    ]
    doc = {"schemaVersion": 1, "name": "t", "addons": addons}
    plan = _plan(current, doc)

    if expected_order == ids:
        assert plan["operations"] == []
    else:
        # preserve + add must rebuild the whole target collection, contiguously
        assert _target_manifest(plan) == expected_order
        preserved = sorted(
            op["manifestId"] for op in plan["operations"] if op["op"] == "preserve"
        )
        assert preserved == sorted(ids)


def test_unmanaged_shift_is_reported_with_a_warning() -> None:
    current = _collection(["a", "b", "c"])
    doc = {"schemaVersion": 1, "name": "t", "addons": [_present("kc", "c", 0)]}
    plan = _plan(current, doc)
    shifts = [
        op for op in plan["operations"] if op["op"] == "move" and op["reason"] == "unmanaged-shift"
    ]
    assert {op["manifestId"] for op in shifts} == {"a", "b"}
    assert any("unmanaged" in w for w in plan["warnings"])


def test_position_out_of_range_is_rejected() -> None:
    current = _collection(["a", "b"])
    doc = {"schemaVersion": 1, "name": "t", "addons": [_present("ka", "a", 5)]}
    with pytest.raises(ValidationError):
        _plan(current, doc)


def test_two_managed_items_on_the_same_position_is_rejected() -> None:
    current = _collection(["a", "b", "c"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [_present("ka", "a", 1), _present("kb", "b", 1)],
    }
    with pytest.raises(ValidationError):
        _plan(current, doc)


# --- removal semantics ---


def test_preserve_unmanaged_false_removes_unmentioned_descriptors() -> None:
    current = _collection(["a", "b", "c"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [_present("ka", "a", 0)],
        "policy": {"preserveUnmanagedAddons": False},
    }
    plan = _plan(current, doc)
    removed = {op["manifestId"] for op in plan["operations"] if op["op"] == "remove"}
    assert removed == {"b", "c"}
    assert any("preserveUnmanagedAddons is false" in w for w in plan["warnings"])


def test_absent_spec_matching_nothing_is_a_no_op() -> None:
    current = _collection(["a", "b"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "gone",
                "match": {"manifestId": "ghost"},
                "state": "absent",
                "manage": ["state"],
            }
        ],
    }
    assert _plan(current, doc)["operations"] == []


def test_absent_state_is_advisory_when_state_is_not_managed() -> None:
    current = _collection(["a", "b"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "keep-a",
                "match": {"manifestId": "a"},
                "state": "absent",
                "manage": [],
            }
        ],
    }
    assert _plan(current, doc)["operations"] == []


def test_present_state_does_not_add_when_state_is_not_managed() -> None:
    current = _collection(["a"])
    doc = {
        "schemaVersion": 1,
        "name": "t",
        "addons": [
            {
                "key": "advisory-new",
                "match": {"manifestId": "new"},
                "state": "present",
                "endpoint": {"publicUrl": "https://new.example.invalid/manifest.json"},
                "manage": [],
            }
        ],
    }
    assert _plan(current, doc)["operations"] == []


# --- fingerprints on the plan ---


def test_plan_carries_raw_sha256_base_fingerprint() -> None:
    current = _collection(["a", "b"])
    plan = _plan(current, {"schemaVersion": 1, "name": "t", "addons": []})
    assert len(plan["baseCollectionFingerprint"]) == 64
    assert len(plan["desiredProfileFingerprint"]) == 64
    # changing the collection changes the base fingerprint
    other = _plan(_collection(["a", "b", "c"]), {"schemaVersion": 1, "name": "t", "addons": []})
    assert plan["baseCollectionFingerprint"] != other["baseCollectionFingerprint"]
