"""Offline diff: match a current collection to a desired profile, emit a plan.

This module is pure and makes no network calls. It never resolves a secret
reference; an endpoint given only as ``secretRef`` is opaque here, and the plan
records the reference verbatim for a later phase to resolve.

Matching order follows SPEC section 10:

1. explicit local key mapping in private state - not populated until a later
   phase, so it is skipped here;
2. ``manifest.id`` plus the keyed display transport fingerprint
   (``match.transportFingerprint``);
3. a unique ``manifest.id``;
4. otherwise the selector is ambiguous and planning stops.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from stremioctl.errors import ValidationError
from stremioctl.fingerprints import canonical_json_bytes, collection_fingerprint
from stremioctl.models import parse_collection
from stremioctl.plans import build_plan_document
from stremioctl.privacy import display_fingerprint, redact_url
from stremioctl.profiles import AddonSpec, DesiredProfile, Endpoint
from stremioctl.validation import validate_collection

# A current collection with any of these problems cannot be planned against.
# `duplicate_manifest_id` is deliberately absent: it is surfaced as a plan
# warning so a `match.transportFingerprint` selector can still disambiguate.
_STRUCTURAL_ERROR_CODES = frozenset(
    {
        "invalid_root",
        "invalid_descriptor",
        "schema",
        "missing_manifest",
        "missing_manifest_id",
        "missing_transport_url",
        "malformed_transport_url",
    }
)
_MUTATING_OPS = frozenset({"add", "remove", "move", "replaceEndpoint"})


@dataclass
class _Item:
    """A descriptor that survives into the target, or a brand-new addition."""

    origin_index: int | None
    manifest_id: str
    spec: AddonSpec | None
    anchor_pos: int | None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _attach_endpoint(op: dict[str, Any], endpoint: Endpoint | None, key: bytes) -> None:
    if endpoint is None:
        return
    if endpoint.public_url is not None:
        op["endpoint"] = redact_url(endpoint.public_url, key)
    elif endpoint.secret_ref is not None:
        op["endpointRef"] = endpoint.secret_ref


def _resolve_matches(
    profile: DesiredProfile,
    manifest_ids: list[str],
    fingerprints: list[str | None],
) -> tuple[dict[str, int | None], dict[int, str]]:
    matched: dict[str, int | None] = {}
    claimed_by: dict[int, str] = {}
    for spec in profile.addons:
        candidates = [i for i, mid in enumerate(manifest_ids) if mid == spec.manifest_id]
        if spec.transport_fingerprint is not None:
            candidates = [i for i in candidates if fingerprints[i] == spec.transport_fingerprint]
        if len(candidates) > 1:
            listed = ", ".join(str(i) for i in candidates)
            raise ValidationError(
                f"desired addon '{spec.key}' selector manifestId '{spec.manifest_id}' matches "
                f"{len(candidates)} descriptors (indexes {listed}); add a "
                f"match.transportFingerprint to disambiguate. The fingerprint is the value "
                f"after '#' in the endpoint label from `stremioctl backup inspect --json`."
            )
        chosen = candidates[0] if candidates else None
        if chosen is not None:
            if chosen in claimed_by:
                raise ValidationError(
                    f"descriptor index {chosen} is claimed by both desired addons "
                    f"'{claimed_by[chosen]}' and '{spec.key}'"
                )
            claimed_by[chosen] = spec.key
        matched[spec.key] = chosen
    return matched, claimed_by


def _place(survivors: list[_Item]) -> list[_Item]:
    """Order *survivors* by their managed anchor positions, keeping the rest stable."""

    size = len(survivors)
    anchors = [(item, item.anchor_pos) for item in survivors if item.anchor_pos is not None]
    wanted = [pos for _, pos in anchors]
    if len(set(wanted)) != len(wanted):
        raise ValidationError("two managed add-ons request the same position")
    for _, pos in anchors:
        assert pos is not None
        if pos < 0 or pos >= size:
            raise ValidationError(
                f"managed position {pos} is out of range for a target collection of {size}"
            )

    final: list[_Item | None] = [None] * size
    for item, pos in anchors:
        assert pos is not None
        final[pos] = item
    rest = [item for item in survivors if item.anchor_pos is None]
    cursor = 0
    for slot in range(size):
        if final[slot] is None:
            final[slot] = rest[cursor]
            cursor += 1
    return [item for item in final if item is not None]


def build_change_plan(
    *,
    current: Any,
    profile: DesiredProfile,
    key: bytes,
    created_at: str,
    profile_warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Return a change plan v1 document describing how to reach *profile*."""

    collection = parse_collection(current)  # non-array / non-object -> ValidationError (exit 2)

    findings = validate_collection(current, key)
    blocking = sorted(
        {f.code for f in findings if f.severity == "error" and f.code in _STRUCTURAL_ERROR_CODES}
    )
    if blocking:
        raise ValidationError(
            "current collection cannot be planned against: " + ", ".join(blocking)
        )

    warnings: list[str] = list(profile_warnings or [])
    if any(f.code == "duplicate_manifest_id" for f in findings):
        warnings.append(
            "current collection contains duplicate manifest ids; a selector that targets one "
            "needs a match.transportFingerprint"
        )

    descriptors = list(collection)
    manifest_ids: list[str] = []
    for descriptor in descriptors:
        mid = descriptor.manifest_id
        assert mid is not None  # guaranteed by the structural gate above
        manifest_ids.append(mid)
    current_fp = [
        display_fingerprint(d.transport_url, key) if d.transport_url else None for d in descriptors
    ]
    current_label = [
        redact_url(d.transport_url, key) if d.transport_url else None for d in descriptors
    ]

    matched, claimed_by = _resolve_matches(profile, manifest_ids, current_fp)
    specs_by_key = {spec.key: spec for spec in profile.addons}

    operations: list[dict[str, Any]] = []
    removed: set[int] = set()

    for spec in profile.addons:
        if spec.state != "absent":
            continue
        index = matched[spec.key]
        if index is None:
            continue
        removed.add(index)
        operations.append(
            {
                "op": "remove",
                "key": spec.key,
                "manifestId": spec.manifest_id,
                "fromIndex": index,
                "reason": "absent-in-profile",
            }
        )

    if not profile.preserve_unmanaged:
        stragglers = [
            i for i in range(len(descriptors)) if i not in removed and i not in claimed_by
        ]
        for i in stragglers:
            removed.add(i)
            operations.append(
                {
                    "op": "remove",
                    "manifestId": manifest_ids[i],
                    "fromIndex": i,
                    "reason": "not-in-profile",
                }
            )
        if stragglers:
            warnings.append(
                "policy.preserveUnmanagedAddons is false; descriptors missing from the profile "
                "are being removed"
            )

    survivors: list[_Item] = []
    for i, mid in enumerate(manifest_ids):
        if i in removed:
            continue
        owner = specs_by_key.get(claimed_by.get(i, ""))
        anchor = (
            owner.position
            if owner is not None and owner.manages_position and owner.position is not None
            else None
        )
        survivors.append(_Item(origin_index=i, manifest_id=mid, spec=owner, anchor_pos=anchor))

    for spec in profile.addons:
        if spec.state != "present" or matched[spec.key] is not None:
            continue
        if spec.endpoint is None:
            raise ValidationError(
                f"desired addon '{spec.key}' is 'present' but matches no current descriptor and "
                f"declares no endpoint to add"
            )
        anchor = spec.position if spec.manages_position and spec.position is not None else None
        survivors.append(
            _Item(origin_index=None, manifest_id=spec.manifest_id, spec=spec, anchor_pos=anchor)
        )

    ordered = _place(survivors)
    before_index = {id(item): idx for idx, item in enumerate(survivors)}
    final_index = {id(item): idx for idx, item in enumerate(ordered)}

    pending_preserve: list[dict[str, Any]] = []
    for item in survivors:
        final_pos = final_index[id(item)]
        managed_pos = item.anchor_pos is not None

        if item.origin_index is None:
            assert item.spec is not None
            add_op: dict[str, Any] = {
                "op": "add",
                "key": item.spec.key,
                "manifestId": item.manifest_id,
                "finalIndex": final_pos,
            }
            _attach_endpoint(add_op, item.spec.endpoint, key)
            operations.append(add_op)
            continue

        moved = final_pos != before_index[id(item)]

        if moved:
            move_op: dict[str, Any] = {
                "op": "move",
                "manifestId": item.manifest_id,
                "fromIndex": item.origin_index,
                "finalIndex": final_pos,
                "reason": "managed" if managed_pos else "unmanaged-shift",
            }
            if item.spec is not None:
                move_op["key"] = item.spec.key
            operations.append(move_op)
            if not managed_pos:
                warnings.append(
                    "a managed reorder shifted at least one unmanaged add-on; see the "
                    "'unmanaged-shift' move operations"
                )

        owner = item.spec
        if owner is not None and owner.manages_endpoint and owner.endpoint is not None:
            desired_fp = owner.endpoint.identity_fingerprint(key)
            if desired_fp is None and owner.transport_fingerprint is not None:
                desired_fp = owner.transport_fingerprint
            here = current_fp[item.origin_index]
            if desired_fp is None:
                rep_op: dict[str, Any] = {
                    "op": "replaceEndpoint",
                    "key": owner.key,
                    "manifestId": item.manifest_id,
                    "finalIndex": final_pos,
                    "reason": "offline-unverifiable",
                }
                _attach_endpoint(rep_op, owner.endpoint, key)
                operations.append(rep_op)
                warnings.append(
                    "an endpoint managed only by secret reference could not be compared offline; "
                    "apply will resolve and verify it"
                )
            elif desired_fp != here:
                rep_op = {
                    "op": "replaceEndpoint",
                    "key": owner.key,
                    "manifestId": item.manifest_id,
                    "finalIndex": final_pos,
                }
                _attach_endpoint(rep_op, owner.endpoint, key)
                operations.append(rep_op)

        # Every surviving existing descriptor gets a `preserve` entry carrying its
        # target index, so `{preserve} + {add}` is a complete map of the target
        # collection. `move` / `replaceEndpoint` are delta annotations on top.
        preserve_op: dict[str, Any] = {
            "op": "preserve",
            "manifestId": item.manifest_id,
            "finalIndex": final_pos,
        }
        if item.spec is not None:
            preserve_op["key"] = item.spec.key
        label = current_label[item.origin_index]
        if label is not None:
            preserve_op["endpoint"] = label
        pending_preserve.append(preserve_op)

    # A converged profile emits nothing at all; `preserve` entries appear only
    # once there is a real change for them to complete into a target manifest.
    if any(op["op"] in _MUTATING_OPS for op in operations):
        operations.extend(pending_preserve)

    return build_plan_document(
        created_at=created_at,
        base_collection_fingerprint=collection_fingerprint(current),
        desired_profile_fingerprint=_sha256_hex(canonical_json_bytes(profile.raw)),
        operations=operations,
        warnings=warnings,
    )


def render_plan_human(plan: dict[str, Any], console: Console) -> None:
    """Print a redacted, human-readable summary of a change plan."""

    operations = plan["operations"]
    counts: dict[str, int] = {}
    for op in operations:
        counts[op["op"]] = counts.get(op["op"], 0) + 1

    if not operations:
        console.print("plan: no changes; the collection already matches the profile")
    else:
        summary = ", ".join(f"{counts[name]} {name}" for name in sorted(counts))
        console.print(f"plan: {summary}")
        # `preserve` covers every retained descriptor; the mutating ops are what a
        # reviewer needs line by line, so only those are printed in detail.
        for op in operations:
            if op["op"] == "preserve":
                continue
            where = f" -> {op['finalIndex']}" if "finalIndex" in op else ""
            src = f" from {op['fromIndex']}" if "fromIndex" in op else ""
            target = op.get("key") or op["manifestId"]
            reason = f" ({op['reason']})" if "reason" in op else ""
            endpoint = ""
            if "endpoint" in op:
                endpoint = f" endpoint={op['endpoint']}"
            elif "endpointRef" in op:
                endpoint = f" endpointRef={op['endpointRef']}"
            console.print(f"  {op['op']}: {target}{src}{where}{reason}{endpoint}")

    if plan["warnings"]:
        console.print(f"warnings: {len(plan['warnings'])}")
        for warning in plan["warnings"]:
            console.print(f"  - {warning}")
    console.print(f"planHash: {plan['planHash']}")


__all__ = ["build_change_plan", "render_plan_human"]
