"""Desired profile v1: parsing, secret-reference syntax, and ``profile init``.

A desired profile is a secret-free statement of the add-on collection a user
wants. This module loads one, checks it against ``desired-profile-v1`` plus a set
of semantic rules, and can generate a starter profile from an existing export.

Nothing here resolves a secret reference. ``env:NAME`` and ``file:/path`` are
validated for *syntax* only; reading the variable or the file, and the POSIX
permission checks required by SPEC section 7.2, are deferred to the account
phases that actually need the value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from stremioctl.errors import ValidationError
from stremioctl.privacy import display_fingerprint
from stremioctl.schemas import iter_schema_errors

_MANAGE_TOKENS = ("state", "position", "endpoint")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DEFAULT_POLICY: dict[str, Any] = {
    "requireHttps": True,
    "manifestTimeoutSeconds": 8,
    "maxConcurrentProbes": 4,
    "allowPrivateNetwork": False,
    "preserveUnmanagedAddons": True,
}


@dataclass(frozen=True)
class ProfileFinding:
    """A single profile validation observation."""

    severity: str  # "error" or "warning"
    code: str
    message: str
    addon_key: str | None = None

    def render(self) -> str:
        where = "" if self.addon_key is None else f" [{self.addon_key}]"
        return f"{self.severity}: {self.code}{where} - {self.message}"


@dataclass(frozen=True)
class Endpoint:
    """A desired endpoint: exactly one of a declared-public URL or a secret ref."""

    public_url: str | None = None
    secret_ref: str | None = None

    def identity_fingerprint(self, key: bytes) -> str | None:
        """Return the keyed display fingerprint this endpoint resolves to, if known.

        A declared-public URL is fingerprinted directly. A secret reference is
        opaque offline, so ``None`` is returned unless the caller has another
        selector (``match.transportFingerprint``).
        """

        if self.public_url is not None:
            return display_fingerprint(self.public_url, key)
        return None


@dataclass(frozen=True)
class AddonSpec:
    """One entry in a desired profile's ``addons`` array."""

    key: str
    manifest_id: str
    state: str
    transport_fingerprint: str | None = None
    position: int | None = None
    endpoint: Endpoint | None = None
    manage: frozenset[str] = field(default_factory=frozenset)

    @property
    def manages_state(self) -> bool:
        return "state" in self.manage

    @property
    def manages_position(self) -> bool:
        return "position" in self.manage

    @property
    def manages_endpoint(self) -> bool:
        return "endpoint" in self.manage


@dataclass(frozen=True)
class AIOStreamsPromotion:
    """Secret-reference-only primary/standby mapping for Phase 6 promotion."""

    manifest_id: str
    primary_ref: str
    standbys: dict[str, str]


@dataclass(frozen=True)
class DesiredProfile:
    """A parsed, structurally valid desired profile."""

    name: str
    addons: tuple[AddonSpec, ...]
    policy: dict[str, Any]
    aiostreams_promotion: AIOStreamsPromotion | None
    raw: dict[str, Any]

    @property
    def preserve_unmanaged(self) -> bool:
        return bool(self.policy.get("preserveUnmanagedAddons", True))


def _classify_secret_ref(ref: str) -> str | None:
    """Return an error message when *ref* is not a valid v1 secret reference."""

    if ref.startswith("env:"):
        name = ref[4:]
        if not _ENV_NAME.match(name):
            return "env: secret reference must be followed by a valid environment variable name"
        return None
    if ref.startswith("file:"):
        path = ref[5:]
        if not path.startswith("/"):
            return "file: secret reference must use an absolute path"
        return None
    return "secret reference must start with 'env:' or 'file:'"


def _endpoint_findings(
    raw: dict[str, Any], key: str
) -> tuple[Endpoint | None, list[ProfileFinding]]:
    public_url = raw.get("publicUrl")
    secret_ref = raw.get("secretRef")
    findings: list[ProfileFinding] = []

    if isinstance(public_url, str):
        try:
            parts = urlsplit(public_url)
        except ValueError:
            parts = None
        if parts is None or parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            findings.append(
                ProfileFinding(
                    "error",
                    "endpoint_public_url",
                    "endpoint.publicUrl is not a usable http(s) URL",
                    key,
                )
            )
        return Endpoint(public_url=public_url), findings

    if isinstance(secret_ref, str):
        problem = _classify_secret_ref(secret_ref)
        if problem is not None:
            findings.append(ProfileFinding("error", "endpoint_secret_ref", problem, key))
        return Endpoint(secret_ref=secret_ref), findings

    return None, findings


def _semantic_findings(doc: dict[str, Any]) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []
    addons = doc.get("addons")
    if not isinstance(addons, list):
        return findings  # schema already reported this

    seen_keys: dict[str, int] = {}
    seen_targets: dict[tuple[str, str | None], str] = {}
    for entry in addons:
        if not isinstance(entry, dict):
            continue
        key = entry.get("key")
        key_str = key if isinstance(key, str) else "<unknown>"
        if isinstance(key, str):
            seen_keys[key] = seen_keys.get(key, 0) + 1

        match_raw = entry.get("match")
        match: dict[str, Any] = match_raw if isinstance(match_raw, dict) else {}
        manifest_id = match.get("manifestId")
        fingerprint = match.get("transportFingerprint")
        target = (
            manifest_id if isinstance(manifest_id, str) else "<unknown>",
            fingerprint if isinstance(fingerprint, str) else None,
        )
        if isinstance(manifest_id, str):
            if target in seen_targets:
                findings.append(
                    ProfileFinding(
                        "error",
                        "duplicate_target",
                        (
                            f"selector manifestId '{target[0]}'"
                            + (f" + fingerprint '{target[1]}'" if target[1] else "")
                            + f" is already claimed by key '{seen_targets[target]}'"
                        ),
                        key_str,
                    )
                )
            else:
                seen_targets[target] = key_str

        manage = entry.get("manage")
        manage_set = set(manage) if isinstance(manage, list) else set()
        state = entry.get("state")
        endpoint_raw = entry.get("endpoint")

        if isinstance(endpoint_raw, dict):
            _, endpoint_findings = _endpoint_findings(endpoint_raw, key_str)
            findings.extend(endpoint_findings)

        if "position" in entry and "position" not in manage_set:
            findings.append(
                ProfileFinding(
                    "warning",
                    "position_unmanaged",
                    "position is set but 'position' is not in manage, so it will not be enforced",
                    key_str,
                )
            )
        if isinstance(endpoint_raw, dict) and "endpoint" not in manage_set:
            findings.append(
                ProfileFinding(
                    "warning",
                    "endpoint_unmanaged",
                    "endpoint is set but 'endpoint' is not in manage, so it will not be enforced",
                    key_str,
                )
            )
        if state == "absent" and (
            "position" in entry or isinstance(endpoint_raw, dict) or manage_set - {"state"}
        ):
            findings.append(
                ProfileFinding(
                    "warning",
                    "absent_extras",
                    "state is 'absent'; position, endpoint, and non-state manage entries "
                    "are ignored",
                    key_str,
                )
            )

    for name, count in sorted(seen_keys.items()):
        if count > 1:
            findings.append(
                ProfileFinding(
                    "error",
                    "duplicate_key",
                    f"key '{name}' is used {count} times; keys must be unique",
                    name,
                )
            )

    promotion = doc.get("aiostreamsPromotion")
    if isinstance(promotion, dict):
        refs: list[tuple[str, str]] = []
        primary = promotion.get("primary")
        if isinstance(primary, dict) and isinstance(primary.get("secretRef"), str):
            refs.append(("primary", primary["secretRef"]))
        standbys = promotion.get("standbys")
        if isinstance(standbys, dict):
            for standby_key, raw_endpoint in standbys.items():
                if isinstance(raw_endpoint, dict) and isinstance(
                    raw_endpoint.get("secretRef"), str
                ):
                    refs.append((f"standby '{standby_key}'", raw_endpoint["secretRef"]))

        for label, ref in refs:
            problem = _classify_secret_ref(ref)
            if problem is not None:
                findings.append(
                    ProfileFinding(
                        "error",
                        "aiostreams_secret_ref",
                        f"{label}: {problem}",
                    )
                )
        by_ref: dict[str, str] = {}
        for label, ref in refs:
            if ref in by_ref:
                findings.append(
                    ProfileFinding(
                        "error",
                        "aiostreams_duplicate_ref",
                        f"{label} reuses the same secret reference as {by_ref[ref]}",
                    )
                )
            else:
                by_ref[ref] = label
    return findings


def check_profile(doc: Any) -> list[ProfileFinding]:
    """Return every schema and semantic finding for *doc* without raising."""

    if not isinstance(doc, dict):
        return [ProfileFinding("error", "invalid_root", "Desired profile must be a JSON object")]
    findings = [
        ProfileFinding("error", "schema", message)
        for message in iter_schema_errors(doc, "desired-profile-v1")
    ]
    findings.extend(_semantic_findings(doc))
    return findings


def _build_addon_spec(entry: dict[str, Any]) -> AddonSpec:
    match = entry["match"]
    endpoint_raw = entry.get("endpoint")
    endpoint: Endpoint | None = None
    if isinstance(endpoint_raw, dict):
        endpoint, _ = _endpoint_findings(endpoint_raw, str(entry.get("key")))
    position = entry.get("position")
    return AddonSpec(
        key=entry["key"],
        manifest_id=match["manifestId"],
        state=entry["state"],
        transport_fingerprint=match.get("transportFingerprint"),
        position=position if isinstance(position, int) else None,
        endpoint=endpoint,
        manage=frozenset(entry.get("manage", ())),
    )


def parse_profile(doc: Any) -> tuple[DesiredProfile, list[ProfileFinding]]:
    """Parse *doc* into a :class:`DesiredProfile`, raising on any error finding.

    Returns the profile and the list of *warning* findings so a caller can fold
    them into a plan.
    """

    findings = check_profile(doc)
    errors = [f for f in findings if f.severity == "error"]
    if errors:
        joined = "; ".join(f.render() for f in errors)
        raise ValidationError(f"Desired profile is invalid: {joined}")

    assert isinstance(doc, dict)
    policy = dict(_DEFAULT_POLICY)
    if isinstance(doc.get("policy"), dict):
        policy.update(doc["policy"])
    addons = tuple(_build_addon_spec(entry) for entry in doc["addons"])
    promotion_raw = doc.get("aiostreamsPromotion")
    promotion: AIOStreamsPromotion | None = None
    if isinstance(promotion_raw, dict):
        promotion = AIOStreamsPromotion(
            manifest_id=promotion_raw["manifestId"],
            primary_ref=promotion_raw["primary"]["secretRef"],
            standbys={
                key: endpoint["secretRef"]
                for key, endpoint in promotion_raw["standbys"].items()
            },
        )
    profile = DesiredProfile(
        name=doc["name"],
        addons=addons,
        policy=policy,
        aiostreams_promotion=promotion,
        raw=doc,
    )
    return profile, [f for f in findings if f.severity == "warning"]


def _slugify(manifest_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", manifest_id.lower()).strip("-")
    return slug or "addon"


def build_starter_profile(
    collection: list[Any],
    key: bytes,
    *,
    declare_public: frozenset[str] = frozenset(),
    name: str = "default",
) -> dict[str, Any]:
    """Generate a desired profile from *collection*.

    Every descriptor becomes a ``present`` addon managing ``state`` and
    ``position``. A raw transport URL is copied into ``endpoint.publicUrl`` only
    for a manifest id named in *declare_public*; every other endpoint is left out
    of the profile entirely, so no configured URL from the source export leaks
    into a committable file.
    """

    id_counts: dict[str, int] = {}
    for descriptor in collection:
        if isinstance(descriptor, dict) and isinstance(descriptor.get("manifest"), dict):
            manifest_id = descriptor["manifest"].get("id")
            if isinstance(manifest_id, str):
                id_counts[manifest_id] = id_counts.get(manifest_id, 0) + 1

    used_keys: set[str] = set()
    addons: list[dict[str, Any]] = []
    for index, descriptor in enumerate(collection):
        if not isinstance(descriptor, dict):
            continue
        manifest = descriptor.get("manifest")
        manifest_id = manifest.get("id") if isinstance(manifest, dict) else None
        if not isinstance(manifest_id, str) or not manifest_id:
            continue

        base_key = _slugify(manifest_id)
        local_key = base_key
        suffix = 2
        while local_key in used_keys:
            local_key = f"{base_key}-{suffix}"
            suffix += 1
        used_keys.add(local_key)

        match: dict[str, Any] = {"manifestId": manifest_id}
        transport_url = descriptor.get("transportUrl")
        if id_counts.get(manifest_id, 0) > 1 and isinstance(transport_url, str):
            match["transportFingerprint"] = display_fingerprint(transport_url, key)

        manage = ["state", "position"]
        addon: dict[str, Any] = {
            "key": local_key,
            "match": match,
            "state": "present",
            "position": index,
        }
        if manifest_id in declare_public and isinstance(transport_url, str):
            addon["endpoint"] = {"publicUrl": transport_url}
            manage.append("endpoint")
        addon["manage"] = manage
        addons.append(addon)

    return {
        "schemaVersion": 1,
        "name": name,
        "addons": addons,
        "policy": dict(_DEFAULT_POLICY),
    }


__all__ = [
    "AddonSpec",
    "AIOStreamsPromotion",
    "DesiredProfile",
    "Endpoint",
    "ProfileFinding",
    "build_starter_profile",
    "check_profile",
    "parse_profile",
]
