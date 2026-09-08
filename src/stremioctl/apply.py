"""Account write safety: drift guard, target construction, apply, and rollback.

This module owns the SPEC section 12 state machine. Nothing here executes a list
of per-add-on mutations: the whole target collection is built locally and pushed
once with ``addonCollectionSet``.

Secret resolution is *delayed*. Endpoint secret references are read only after the
current-state drift guard has passed, so a stale plan never causes a secret to be
opened. A newly written endpoint (a ``replaceEndpoint`` resolved from a secret
reference) must be ``https``; a plain ``http`` target is refused because installing
an insecure endpoint is an active choice, not an inherited one.

One plan operation cannot be applied in v1 and is refused with an actionable
message:

* ``add`` - the plan carries no manifest for a brand-new add-on.

``replaceEndpoint`` supports either a delayed secret reference or a URL that was
explicitly declared public in the desired profile. Newly written endpoints must
use HTTPS.
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from stremioctl.account import (
    AccountConfig,
    PulledCollection,
    build_snapshot,
    fetch_addon_collection,
    push_addon_collection,
)
from stremioctl.errors import (
    ApplyError,
    DriftError,
    NetworkError,
    StremioctlError,
    ValidationError,
)
from stremioctl.fingerprints import collection_fingerprint
from stremioctl.io import (
    atomic_write_text,
    ensure_private_app_dir,
    ensure_private_directory,
    private_app_path,
    read_secret_file,
)
from stremioctl.models import parse_collection
from stremioctl.plans import compute_plan_hash
from stremioctl.privacy import display_fingerprint
from stremioctl.probing import ProbeConfig, probe_manifest_url
from stremioctl.schemas import iter_schema_errors

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Rollback outcomes, kept distinct so the report never conceals the result.
ROLLBACK_NOT_ATTEMPTED = "not_attempted"
ROLLBACK_SUCCEEDED = "succeeded"
ROLLBACK_FAILED = "failed"
ROLLBACK_UNKNOWN = "unknown"
TargetManifestResolver = Callable[[str, str, str, bytes], dict[str, Any]]


@dataclass
class ApplyOutcome:
    """The result of an apply or a standalone rollback, ready for the CLI to print."""

    exit_code: int
    lines: list[str] = field(default_factory=list)
    wrote_snapshot: bool = False
    snapshot_path: Path | None = None
    pushed: bool = False
    verified: bool = False
    rollback: str = ROLLBACK_NOT_ATTEMPTED


def resolve_endpoint_ref(ref: str) -> str:
    """Resolve a secret reference to an ``https`` URL at apply time.

    ``env:NAME`` reads an environment variable; ``file:/abs/path`` reads a
    strict-permission file (:func:`stremioctl.io.read_secret_file`). The resolved
    value must be a well-formed ``https`` URL. The value itself never appears in
    an error message.
    """

    if ref.startswith("env:"):
        name = ref[4:]
        if not _ENV_NAME.match(name):
            raise ValidationError(f"secret reference '{ref}' does not name a valid env variable")
        raw = os.environ.get(name)
        if raw is None or not raw.strip():
            raise ValidationError(
                f"secret reference '{ref}' resolves to nothing: {name} is not set"
            )
        resolved = raw.strip()
    elif ref.startswith("file:"):
        path = ref[5:]
        if not path.startswith("/"):
            raise ValidationError(f"secret reference '{ref}' must use an absolute path")
        resolved = read_secret_file(Path(path)).strip()
        if not resolved:
            raise ValidationError(f"secret reference '{ref}' points at an empty file")
    else:
        raise ValidationError("a secret reference must start with 'env:' or 'file:'")

    try:
        parts = urlsplit(resolved)
    except ValueError as exc:
        raise ValidationError(
            "a resolved endpoint reference is not a valid http(s) URL"
        ) from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname:
        raise ValidationError("a resolved endpoint reference is not a valid http(s) URL")
    if scheme != "https":
        raise ValidationError(
            "a resolved endpoint reference uses plain http; a newly written endpoint must "
            "use https"
        )
    return resolved


def _validated_public_endpoint(value: Any) -> str:
    """Validate a declared-public endpoint carried verbatim in a reviewed plan."""

    if not isinstance(value, str):
        raise ValidationError("a public endpoint in the plan must be a string")
    try:
        parts = urlsplit(value)
    except ValueError:
        parts = None
    if parts is None or parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValidationError("a public endpoint in the plan is not a valid http(s) URL")
    if parts.scheme.lower() != "https":
        raise ValidationError("a newly written public endpoint must use https")
    return value


def resolve_target_manifest(
    endpoint: str,
    expected_id: str,
    expected_fingerprint: str,
    key: bytes,
) -> dict[str, Any]:
    """Fetch and verify the exact target manifest bound into a reviewed plan."""

    entry, manifest = probe_manifest_url(endpoint, expected_id, key, ProbeConfig())
    if entry["status"] not in {"healthy", "warning"} or manifest is None:
        raise NetworkError(
            "the replacement endpoint failed its apply-time manifest check: "
            + str(entry["status"])
        )
    if collection_fingerprint(manifest) != expected_fingerprint:
        raise DriftError(
            "the replacement endpoint's manifest changed since planning; create and review a "
            "new plan"
        )
    return manifest


def _structure(descriptors: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Return the ordered ``(manifest id, transport URL)`` shape of a collection.

    Used only to explain an exact-fingerprint mismatch: if the structure matches
    but the hash does not, the server returned a semantically equivalent but not
    byte-identical collection (see ``BACKLOG.md``).
    """

    rows: list[tuple[str, str]] = []
    for item in descriptors:
        manifest = item.get("manifest") if isinstance(item, dict) else None
        mid = manifest.get("id") if isinstance(manifest, dict) else None
        turl = item.get("transportUrl") if isinstance(item, dict) else None
        rows.append((str(mid), str(turl)))
    return rows


def _load_validated_plan(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise ValidationError("the plan file must be a JSON object")
    errors = iter_schema_errors(doc, "change-plan-v1")
    if errors:
        raise ValidationError("the plan file does not match change-plan-v1: " + "; ".join(errors))
    if doc.get("planHash") != compute_plan_hash(doc):
        raise ValidationError("the plan file is corrupt: its planHash does not match its body")
    return doc


def _load_validated_snapshot(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise ValidationError("the snapshot file must be a JSON object")
    errors = iter_schema_errors(doc, "account-snapshot-v1")
    if errors:
        raise ValidationError(
            "the snapshot file does not match account-snapshot-v1: " + "; ".join(errors)
        )
    if doc.get("collectionFingerprint") != collection_fingerprint(doc.get("collection")):
        raise ValidationError(
            "the snapshot file is corrupt: its collectionFingerprint does not match its collection"
        )
    return doc


def _match_current_index(op: dict[str, Any], descriptors: list[Any], key: bytes) -> int:
    """Find which current descriptor a ``preserve`` op refers to.

    A ``preserve`` op carries no ``fromIndex`` - it identifies its descriptor by
    ``manifestId`` and, when the descriptor has a transport URL, the keyed
    fingerprint carried in its redacted ``endpoint`` label.
    """

    mid = op.get("manifestId")
    candidates = [i for i, d in enumerate(descriptors) if d.manifest_id == mid]
    label = op.get("endpoint")
    if label is not None and "#" in label:
        want = label.rsplit("#", 1)[-1]
        candidates = [
            i
            for i in candidates
            if descriptors[i].transport_url is not None
            and display_fingerprint(descriptors[i].transport_url, key) == want
        ]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ValidationError(
            f"the plan preserves add-on '{mid}', which is not in the current collection; the "
            f"plan is stale - create a new one"
        )
    raise ValidationError(
        f"the plan's reference to add-on '{mid}' matches more than one current entry and cannot "
        f"be resolved; create a new plan"
    )


def construct_target(
    plan: dict[str, Any],
    descriptors: list[Any],
    key: bytes,
    *,
    resolver: Callable[[str], str] = resolve_endpoint_ref,
    target_manifest_resolver: TargetManifestResolver = resolve_target_manifest,
) -> list[dict[str, Any]]:
    """Build the complete ordered target collection locally from *plan*.

    Unknown descriptor fields are carried through untouched (a deep copy of the
    current descriptor). Raises :class:`ValidationError` (exit 2) for any
    operation v1 apply cannot honour or any internal inconsistency in the plan.
    """

    ops = plan["operations"]

    for op in ops:
        name = op["op"]
        if name == "add":
            raise ValidationError(
                "this plan adds an add-on, which v1 apply cannot do: the plan carries no "
                "manifest for a new add-on. Install it with a Stremio client, then re-pull "
                "and re-plan."
            )
        if name == "replaceEndpoint":
            endpoint_sources = {"endpointRef", "publicUrl"} & op.keys()
            if len(endpoint_sources) != 1:
                raise ValidationError(
                    "this plan replaces an endpoint but does not carry exactly one endpoint "
                    "reference or declared-public URL; create a new plan"
                )
            target_fields = {
                "targetManifestId",
                "targetManifestFingerprint",
            } & op.keys()
            if len(target_fields) not in {0, 2}:
                raise ValidationError(
                    "this plan's replacement manifest binding is incomplete; create a new plan"
                )

    for op in ops:
        if op["op"] != "remove":
            continue
        idx = op.get("fromIndex")
        if not isinstance(idx, int) or not 0 <= idx < len(descriptors):
            raise ValidationError(
                f"the plan removes index {idx}, out of range for the current collection; the "
                f"plan is stale - create a new one"
            )
        if descriptors[idx].manifest_id != op.get("manifestId"):
            raise ValidationError(
                "a plan 'remove' does not line up with the current collection; the plan is "
                "stale - create a new one"
            )
        flags = descriptors[idx].flags or {}
        if flags.get("protected") is True:
            raise ValidationError(
                f"the plan removes protected add-on '{op.get('manifestId')}'; Stremio does not "
                f"allow uninstalling a protected add-on. Clear the protected flag in a Stremio "
                f"client first, or drop that removal from the profile."
            )

    slots: dict[int, dict[str, Any]] = {}
    for op in ops:
        if op["op"] != "preserve":
            continue
        final = op.get("finalIndex")
        if not isinstance(final, int) or final < 0:
            raise ValidationError("a plan 'preserve' is missing a valid finalIndex")
        if final in slots:
            raise ValidationError(
                "the plan places two add-ons at the same target index; it is inconsistent"
            )
        src = _match_current_index(op, descriptors, key)
        slots[final] = copy.deepcopy(descriptors[src].data)

    for op in ops:
        if op["op"] != "replaceEndpoint":
            continue
        final = op.get("finalIndex")
        if final not in slots:
            raise ValidationError(
                "a plan 'replaceEndpoint' targets a slot with no preserved add-on; it is "
                "inconsistent"
            )
        slot_manifest = slots[final].get("manifest")
        slot_id = slot_manifest.get("id") if isinstance(slot_manifest, dict) else None
        if slot_id != op.get("manifestId"):
            # guard against a plan that would route one add-on's endpoint (and its
            # resolved secret) onto a different add-on's slot
            raise ValidationError(
                f"a plan 'replaceEndpoint' for '{op.get('manifestId')}' lands on a slot holding "
                f"'{slot_id}'; the plan is inconsistent - create a new one"
            )
        if "endpointRef" in op:
            target_url = resolver(op["endpointRef"])
        else:
            target_url = _validated_public_endpoint(op.get("publicUrl"))
        slots[final]["transportUrl"] = target_url
        if "targetManifestId" in op:
            slots[final]["manifest"] = target_manifest_resolver(
                target_url,
                op["targetManifestId"],
                op["targetManifestFingerprint"],
                key,
            )

    size = len(slots)
    if sorted(slots) != list(range(size)):
        raise ValidationError(
            f"the plan does not describe a contiguous target collection (indices {sorted(slots)}); "
            f"it is inconsistent"
        )
    return [slots[i] for i in range(size)]


def _snapshot_name(prefix: str, now: str, fingerprint: str) -> str:
    stamp = now.replace("-", "").replace(":", "")
    # ``now`` is deliberately second-precision in the snapshot contract. A
    # random suffix keeps two same-second operations individually durable.
    return f"{prefix}-{stamp}-{fingerprint[:12]}-{secrets.token_hex(4)}.json"


def _snapshot_text(snapshot: dict[str, Any]) -> str:
    text = json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    errors = iter_schema_errors(snapshot, "account-snapshot-v1")
    if errors:  # our own artifact failing its own contract is a defect
        raise RuntimeError("internal snapshot contract violation: " + "; ".join(errors))
    return text


def ensure_snapshots_dir() -> Path:
    ensure_private_app_dir()
    return ensure_private_directory(private_app_path() / "snapshots")


def _write_snapshot(pulled: Any, now: str, prefix: str) -> Path:
    """Persist a mandatory snapshot; a failure here means no write may proceed."""

    directory = ensure_snapshots_dir()
    document = build_snapshot(pulled, pulled_at=now)
    path = directory / _snapshot_name(prefix, now, pulled.fingerprint)
    try:
        atomic_write_text(path, _snapshot_text(document), mode=0o600)
    except StremioctlError:
        raise
    except OSError as exc:
        raise ApplyError(
            f"could not persist the mandatory {prefix} snapshot ({type(exc).__name__}); no write "
            f"was made"
        ) from None
    return path


def _rollback_to(
    auth_key: str,
    addons: list[dict[str, Any]],
    expected_fp: str,
    cfg: AccountConfig,
    transport: httpx.BaseTransport | None,
) -> tuple[str, list[str]]:
    """Push *addons* once and verify the account returns to *expected_fp*."""

    try:
        push_addon_collection(auth_key, addons, cfg, transport=transport)
    except StremioctlError as exc:
        return ROLLBACK_FAILED, [
            f"rollback: the restore write failed ({type(exc).__name__}); the account may be in "
            f"the half-applied state - check it in a Stremio client"
        ]
    try:
        after = fetch_addon_collection(auth_key, cfg, transport=transport)
    except StremioctlError as exc:
        return ROLLBACK_UNKNOWN, [
            f"rollback: the restore was sent but could not be verified ({type(exc).__name__}); "
            f"confirm the account state in a Stremio client"
        ]
    if after.fingerprint == expected_fp:
        return ROLLBACK_SUCCEEDED, [
            f"rollback: the account was restored to the snapshot (fingerprint {expected_fp[:12]})"
        ]
    if _structure(after.addons) == _structure(addons):
        return ROLLBACK_FAILED, [
            "rollback: the restore produced a semantically equivalent but not byte-identical "
            "collection (likely server-side normalization; see BACKLOG.md) - verify the account "
            "in a Stremio client"
        ]
    return ROLLBACK_FAILED, [
        "rollback: the account did not return to the snapshot state - check it in a Stremio client"
    ]


def apply_plan(
    *,
    plan: Any,
    confirm: str,
    key: bytes,
    auth_key: str,
    cfg: AccountConfig,
    now: str,
    transport: httpx.BaseTransport | None = None,
    resolver: Callable[[str], str] = resolve_endpoint_ref,
) -> ApplyOutcome:
    """Run the SPEC section 12 apply state machine and return a printable outcome.

    Raises :class:`ValidationError` (2) for a bad confirmation hash, a corrupt or
    unapplyable plan, or an unresolvable secret reference; :class:`DriftError` (5)
    when the account changed since the plan was built. Once a write has been
    attempted, every failure is reported as an :class:`ApplyOutcome` with exit
    code 6 and an explicit rollback status - never a concealed result.
    """

    doc = _load_validated_plan(plan)
    if confirm.strip().lower() != doc["planHash"]:
        raise ValidationError(
            "the --confirm value does not match this plan's planHash; re-check the hash printed "
            "with the plan"
        )

    # Verify the private snapshot location before auth or network work.
    ensure_snapshots_dir()

    pulled = fetch_addon_collection(auth_key, cfg, transport=transport)

    if pulled.fingerprint != doc["baseCollectionFingerprint"]:
        raise DriftError(
            f"the account changed since this plan was built (current {pulled.fingerprint[:12]} != "
            f"plan base {doc['baseCollectionFingerprint'][:12]}); create and review a new plan"
        )

    if not doc["operations"]:
        return ApplyOutcome(
            exit_code=0,
            lines=["the plan is already converged; the account matches it, nothing to apply"],
        )

    # Drift guard passed: only now is it safe to resolve secret references.
    descriptors = list(parse_collection(pulled.addons).descriptors)
    target = construct_target(doc, descriptors, key, resolver=resolver)
    target_fp = collection_fingerprint(target)

    if target_fp == pulled.fingerprint:
        return ApplyOutcome(
            exit_code=0,
            lines=["the plan's target already matches the account; no write needed"],
        )

    removes_everything = bool(pulled.addons) and not target

    snapshot_path = _write_snapshot(pulled, now, "pre-apply")
    lines = [
        f"wrote pre-apply snapshot to {snapshot_path} "
        f"({len(pulled.addons)} add-ons, fingerprint {pulled.fingerprint[:12]})"
    ]
    if removes_everything:
        lines.append(f"warning: this apply will remove all {len(pulled.addons)} add-ons")

    push_error: str | None = None
    try:
        push_addon_collection(auth_key, target, cfg, transport=transport)
    except StremioctlError as exc:
        push_error = type(exc).__name__

    verify_error = ""
    after: PulledCollection | None
    try:
        after = fetch_addon_collection(auth_key, cfg, transport=transport)
    except StremioctlError as exc:
        after = None
        verify_error = type(exc).__name__

    base_fp = pulled.fingerprint

    if after is not None and after.fingerprint == target_fp:
        if push_error:
            lines.append(
                f"the write call reported {push_error}, but the account now matches the plan "
                f"target"
            )
        lines.append(
            f"the account now matches the plan target (fingerprint {target_fp[:12]})"
        )
        return ApplyOutcome(
            exit_code=0,
            lines=lines,
            wrote_snapshot=True,
            snapshot_path=snapshot_path,
            pushed=True,
            verified=True,
        )

    if after is not None and (
        after.fingerprint == base_fp or _structure(after.addons) == _structure(pulled.addons)
    ):
        lines.append(
            f"the write did not take effect; the account is unchanged from the pre-apply "
            f"snapshot ({'reported ' + push_error if push_error else 'no error was reported'})"
        )
        return ApplyOutcome(
            exit_code=6,
            lines=lines,
            wrote_snapshot=True,
            snapshot_path=snapshot_path,
            pushed=True,
            verified=False,
            rollback=ROLLBACK_NOT_ATTEMPTED,
        )

    if after is None:
        lines.append(
            f"the post-write pull failed ({verify_error}); the remote state is unknown, "
            f"attempting a single rollback"
        )
    elif _structure(after.addons) == _structure(target):
        lines.append(
            "verification failed: the account holds a semantically equivalent but not "
            "byte-identical form of the target (likely server-side normalization; see "
            "BACKLOG.md), attempting a single rollback"
        )
    else:
        lines.append(
            "verification failed: the account matches neither the target nor the pre-apply "
            "snapshot, attempting a single rollback"
        )

    status, rollback_lines = _rollback_to(auth_key, list(pulled.addons), base_fp, cfg, transport)
    lines.extend(rollback_lines)
    return ApplyOutcome(
        exit_code=6,
        lines=lines,
        wrote_snapshot=True,
        snapshot_path=snapshot_path,
        pushed=True,
        verified=False,
        rollback=status,
    )


def rollback_snapshot(
    *,
    snapshot: Any,
    confirm: str,
    auth_key: str,
    cfg: AccountConfig,
    now: str,
    transport: httpx.BaseTransport | None = None,
) -> ApplyOutcome:
    """Restore the account to *snapshot* after verifying its fingerprint.

    This is a deliberate restore, so there is no current-state drift guard. It
    still takes a mandatory pre-rollback snapshot of the current state first, so
    every write this tool makes is preceded by a persisted snapshot.
    """

    doc = _load_validated_snapshot(snapshot)
    expected_fp = doc["collectionFingerprint"]
    if confirm.strip().lower() != expected_fp:
        raise ValidationError(
            "the --confirm value does not match the snapshot's collectionFingerprint"
        )

    ensure_snapshots_dir()
    before = fetch_addon_collection(auth_key, cfg, transport=transport)
    guard_path = _write_snapshot(before, now, "pre-rollback")
    lines = [
        f"wrote pre-rollback snapshot to {guard_path} "
        f"({len(before.addons)} add-ons, fingerprint {before.fingerprint[:12]})"
    ]

    if before.fingerprint == expected_fp:
        lines.append(
            f"the account already matches the snapshot (fingerprint {expected_fp[:12]}); "
            f"nothing to restore"
        )
        return ApplyOutcome(
            exit_code=0,
            lines=lines,
            wrote_snapshot=True,
            snapshot_path=guard_path,
        )

    status, rollback_lines = _rollback_to(
        auth_key, list(doc["collection"]), expected_fp, cfg, transport
    )
    lines.extend(rollback_lines)
    return ApplyOutcome(
        exit_code=0 if status == ROLLBACK_SUCCEEDED else 6,
        lines=lines,
        wrote_snapshot=True,
        snapshot_path=guard_path,
        pushed=True,
        verified=status == ROLLBACK_SUCCEEDED,
        rollback=status,
    )


__all__ = [
    "ApplyOutcome",
    "apply_plan",
    "construct_target",
    "ensure_snapshots_dir",
    "resolve_endpoint_ref",
    "resolve_target_manifest",
    "rollback_snapshot",
]
