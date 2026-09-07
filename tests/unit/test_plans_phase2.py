from __future__ import annotations

from stremioctl.plans import build_plan_document, compute_plan_hash, order_operations


def _plan(**overrides: object) -> dict[str, object]:
    base = dict(
        created_at="2026-09-06T00:00:00Z",
        base_collection_fingerprint="a" * 64,
        desired_profile_fingerprint="b" * 64,
        operations=[],
        warnings=[],
    )
    base.update(overrides)
    return build_plan_document(**base)  # type: ignore[arg-type]


def test_plan_hash_ignores_created_at() -> None:
    early = _plan(created_at="2026-01-01T00:00:00Z")
    late = _plan(created_at="2026-12-31T23:59:59Z")
    assert early["createdAt"] != late["createdAt"]
    assert early["planHash"] == late["planHash"]
    # everything except createdAt is byte-identical
    early.pop("createdAt")
    late.pop("createdAt")
    assert early == late


def test_plan_hash_omits_its_own_field() -> None:
    plan = _plan()
    recomputed = compute_plan_hash(plan)
    assert plan["planHash"] == recomputed
    # tampering with planHash does not change what compute_plan_hash returns
    tampered = dict(plan, planHash="0" * 64)
    assert compute_plan_hash(tampered) == recomputed


def test_plan_hash_changes_with_operations() -> None:
    empty = _plan()
    with_op = _plan(
        operations=[{"op": "remove", "manifestId": "x", "fromIndex": 0}],
    )
    assert empty["planHash"] != with_op["planHash"]


def test_operations_are_ordered_by_type_then_identity() -> None:
    ops = [
        {"op": "preserve", "manifestId": "z", "finalIndex": 2},
        {"op": "remove", "manifestId": "b", "fromIndex": 1},
        {"op": "add", "manifestId": "a", "finalIndex": 0},
        {"op": "remove", "manifestId": "a", "fromIndex": 0},
        {"op": "move", "manifestId": "m", "fromIndex": 3, "finalIndex": 1},
    ]
    ordered = order_operations(ops)
    assert [o["op"] for o in ordered] == ["remove", "remove", "add", "move", "preserve"]
    # remove group is sorted by manifestId
    assert [o["manifestId"] for o in ordered[:2]] == ["a", "b"]


def test_warnings_are_deduped_and_sorted() -> None:
    plan = _plan(warnings=["second", "first", "second"])
    assert plan["warnings"] == ["first", "second"]
