"""Change plan v1: the operation vocabulary, canonicalization, and ``planHash``.

A plan is data, not behavior. It is built by :mod:`stremioctl.diff` and consumed
(in later phases) by an apply path. The only logic here is turning an ordered
list of operations into the canonical plan document and computing its hash.
"""

from __future__ import annotations

import hashlib
from typing import Any

from stremioctl.fingerprints import canonical_json_bytes

# Deterministic review order. The apply path (SPEC section 12) constructs the
# whole target locally in one set operation, so this ordering is for humans, not
# execution.
_OP_RANK = {"remove": 0, "add": 1, "move": 2, "replaceEndpoint": 3, "preserve": 4}

# Fields excluded from the planHash input: the hash identifies the *operations*
# a human reviewed, so wall-clock time is left out and the hash omits itself.
_HASH_EXCLUDED = frozenset({"planHash", "createdAt"})


def _op_sort_key(operation: dict[str, Any]) -> tuple[int, str, str, int]:
    return (
        _OP_RANK.get(str(operation.get("op")), 99),
        str(operation.get("manifestId", "")),
        str(operation.get("key", "")),
        int(operation.get("finalIndex", operation.get("fromIndex", -1))),
    )


def order_operations(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return *operations* in the canonical, deterministic review order."""

    return sorted(operations, key=_op_sort_key)


def compute_plan_hash(plan: dict[str, Any]) -> str:
    """Return the SHA-256 of the canonical plan JSON, minus time and the hash itself."""

    material = {k: v for k, v in plan.items() if k not in _HASH_EXCLUDED}
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def build_plan_document(
    *,
    created_at: str,
    base_collection_fingerprint: str,
    desired_profile_fingerprint: str,
    operations: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    """Assemble a complete change plan document, including its ``planHash``."""

    plan: dict[str, Any] = {
        "schemaVersion": 1,
        "createdAt": created_at,
        "baseCollectionFingerprint": base_collection_fingerprint,
        "desiredProfileFingerprint": desired_profile_fingerprint,
        "operations": order_operations(operations),
        "warnings": sorted(set(warnings)),
    }
    plan["planHash"] = compute_plan_hash(plan)
    return plan


__all__ = [
    "build_plan_document",
    "compute_plan_hash",
    "order_operations",
]
