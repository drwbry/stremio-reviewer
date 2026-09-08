"""AIOStreams native-backup handling and guarded standby promotion.

Native exports are AIOStreams ``UserData`` objects, not Stremio collections and
not server-dashboard settings. Parsing is lossless and forward-compatible;
redaction is deliberately conservative because upstream's credential exclusion
does not cover custom URLs or arbitrary free text.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from stremioctl.apply import resolve_endpoint_ref
from stremioctl.diff import build_change_plan
from stremioctl.errors import NetworkError, ValidationError
from stremioctl.fingerprints import canonical_json_bytes, collection_fingerprint
from stremioctl.plans import build_plan_document, compute_plan_hash
from stremioctl.privacy import REDACTED, redact_url, sanitize_text
from stremioctl.probing import ProbeConfig, Resolver, probe_manifest_url
from stremioctl.profiles import DesiredProfile, parse_profile
from stremioctl.schemas import iter_schema_errors

_TOP_LEVEL_SECRETS = frozenset(
    {
        "ip",
        "uuid",
        "accessKey",
        "encryptedPassword",
        "tmdbAccessToken",
        "tmdbApiKey",
        "tvdbApiKey",
        "rpdbApiKey",
        "topPosterApiKey",
        "aioratingsApiKey",
        "aioratingsProfileId",
        "openposterdbApiKey",
        "openposterdbUrl",
        "openposterdbParameters",
    }
)
_SENSITIVE_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "authorization",
    "credential",
    "privatekey",
    "sessionid",
    "cookie",
    "bearer",
)
_FREE_TEXT_TOKENS = (
    "script",
    "expression",
    "regex",
    "pattern",
    "template",
    "formatter",
    "webhook",
)
_TOP_LEVEL_FREE_TEXT = frozenset({"addonName", "addonDescription"})
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
_COMPLETE_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EndpointResolver = Callable[[str], str]


@dataclass(frozen=True)
class BackupFinding:
    """A value-free observation about a native backup."""

    severity: str
    code: str
    message: str

    def render(self) -> str:
        return f"{self.severity}: {self.code} - {self.message}"


@dataclass(frozen=True)
class AIOStreamsBackup:
    """A validated, lossless native AIOStreams backup."""

    raw: dict[str, Any]

    def to_document(self) -> dict[str, Any]:
        """Return a deep copy so callers cannot mutate the parsed source."""

        return copy.deepcopy(self.raw)


def _normalized(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _has_value(value: Any) -> bool:
    if isinstance(value, str) and REDACTED in value:
        return False
    return value not in (None, "", [], {})


def _suspicious_name(name: str) -> bool:
    normalized = _normalized(name)
    return any(token in normalized for token in _SENSITIVE_TOKENS)


def _walk(
    node: Any, path: tuple[str | int, ...] = ()
) -> list[tuple[tuple[str | int, ...], Any]]:
    leaves: list[tuple[tuple[str | int, ...], Any]] = []
    if isinstance(node, dict):
        for name, child in node.items():
            leaves.extend(_walk(child, (*path, str(name))))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            leaves.extend(_walk(child, (*path, index)))
    else:
        leaves.append((path, node))
    return leaves


def check_backup(doc: Any) -> list[BackupFinding]:
    """Return structural and privacy findings without including input values."""

    if not isinstance(doc, dict):
        return [
            BackupFinding("error", "invalid_root", "native AIOStreams backup must be an object")
        ]

    findings = [
        BackupFinding("error", "schema", message)
        for message in iter_schema_errors(doc, "aiostreams-backup-v1")
    ]
    if "metadata" in doc:
        findings.append(
            BackupFinding(
                "error",
                "template_artifact",
                "file looks like an AIOStreams template, not a native configuration backup",
            )
        )
    if {"settings", "maskedSecretKeys"} <= set(doc):
        findings.append(
            BackupFinding(
                "error",
                "dashboard_artifact",
                "file is a server-dashboard settings export, not an add-on configuration backup",
            )
        )

    sensitive_paths = 0
    url_count = 0
    free_text_count = 0
    for path, value in _walk(doc):
        names = [part for part in path if isinstance(part, str)]
        leaf = names[-1] if names else ""
        top = names[0] if names else ""
        in_credentials = "credentials" in names
        in_proxy_secret = bool(
            names
            and names[0] == "proxy"
            and leaf in {"credentials", "url", "publicUrl", "publicIp"}
        )
        if _has_value(value) and (
            top in _TOP_LEVEL_SECRETS
            or in_credentials
            or in_proxy_secret
            or _suspicious_name(leaf)
        ):
            sensitive_paths += 1
        safely_redacted = isinstance(value, str) and REDACTED in value
        if isinstance(value, str) and not safely_redacted and _URL_PATTERN.match(value):
            url_count += 1
        if isinstance(value, str) and not safely_redacted and any(
            token in _normalized(leaf) for token in _FREE_TEXT_TOKENS
        ):
            free_text_count += 1

    if sensitive_paths:
        findings.append(
            BackupFinding(
                "error",
                "credential_values",
                f"found {sensitive_paths} populated credential-like field(s)",
            )
        )
    if url_count:
        findings.append(
            BackupFinding(
                "warning",
                "url_review_required",
                f"found {url_count} URL value(s); redact-backup will mask every complete URL",
            )
        )
    if free_text_count:
        findings.append(
            BackupFinding(
                "warning",
                "free_text_review_required",
                f"found {free_text_count} script/expression/pattern value(s)",
            )
        )
    if "uuid" in doc or "trusted" in doc:
        findings.append(
            BackupFinding(
                "warning",
                "import_only_fields",
                "uuid/trusted fields are discarded by the current upstream UI import",
            )
        )
    return findings


def parse_backup(doc: Any) -> tuple[AIOStreamsBackup, list[BackupFinding]]:
    """Validate *doc* and return a lossless model plus non-blocking warnings."""

    findings = check_backup(doc)
    errors = [finding for finding in findings if finding.severity == "error"]
    if errors:
        raise ValidationError(
            "AIOStreams backup is invalid: " + "; ".join(item.render() for item in errors)
        )
    assert isinstance(doc, dict)
    return AIOStreamsBackup(copy.deepcopy(doc)), [
        finding for finding in findings if finding.severity == "warning"
    ]


def _redacted_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return REDACTED
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    return None


def redact_backup(doc: Any, key: bytes) -> tuple[dict[str, Any], int]:
    """Return a shape-preserving, shareable copy and the number of changed leaves."""

    findings = check_backup(doc)
    blocking = [
        finding
        for finding in findings
        if finding.severity == "error" and finding.code != "credential_values"
    ]
    if blocking:
        raise ValidationError(
            "AIOStreams backup is invalid: " + "; ".join(item.render() for item in blocking)
        )
    assert isinstance(doc, dict)
    backup = AIOStreamsBackup(copy.deepcopy(doc))
    changed = 0

    def visit(node: Any, path: tuple[str | int, ...] = (), *, forced: bool = False) -> Any:
        nonlocal changed
        if isinstance(node, dict):
            result: dict[str, Any] = {}
            for raw_name, child in node.items():
                name = str(raw_name)
                names = [part for part in (*path, name) if isinstance(part, str)]
                top = names[0] if names else ""
                normalized = _normalized(name)
                child_forced = forced or top in _TOP_LEVEL_SECRETS or _suspicious_name(name)
                child_forced = child_forced or top in _TOP_LEVEL_FREE_TEXT
                child_forced = child_forced or name == "credentials"
                child_forced = child_forced or (
                    top == "proxy" and name in {"credentials", "url", "publicUrl", "publicIp"}
                )
                child_forced = child_forced or (top == "presets" and name == "options")
                child_forced = child_forced or any(
                    token in normalized for token in _FREE_TEXT_TOKENS
                )
                result[name] = visit(child, (*path, name), forced=child_forced)
            return result
        if isinstance(node, list):
            return [
                visit(child, (*path, index), forced=forced)
                for index, child in enumerate(node)
            ]
        if forced:
            replacement = _redacted_scalar(node)
        elif isinstance(node, str):
            without_urls = _COMPLETE_URL_PATTERN.sub(
                lambda match: redact_url(match.group(0), key, hide_host=True), node
            )
            replacement = sanitize_text(without_urls, key)
        else:
            replacement = node
        if replacement != node:
            changed += 1
        return replacement

    return visit(backup.to_document()), changed


def build_promotion_plan(
    *,
    current: list[dict[str, Any]],
    profile: DesiredProfile,
    standby_key: str,
    key: bytes,
    created_at: str,
    resolver: EndpointResolver = resolve_endpoint_ref,
    probe_resolver: Resolver | None = None,
) -> dict[str, Any]:
    """Probe a configured standby and build a normal, secret-free change plan."""

    promotion = profile.aiostreams_promotion
    if promotion is None:
        raise ValidationError("desired profile has no aiostreamsPromotion configuration")
    if standby_key not in promotion.standbys:
        choices = ", ".join(sorted(promotion.standbys))
        raise ValidationError(f"unknown AIOStreams standby key; configured keys: {choices}")

    primary_url = resolver(promotion.primary_ref)
    standby_url = resolver(promotion.standbys[standby_key])
    if primary_url == standby_url:
        raise ValidationError("AIOStreams primary and selected standby resolve to the same URL")

    probe_cfg = ProbeConfig(
        overall_timeout=float(profile.policy["manifestTimeoutSeconds"]),
        concurrency=int(profile.policy["maxConcurrentProbes"]),
        allow_private_network=bool(profile.policy["allowPrivateNetwork"]),
    )
    entry, standby_manifest = probe_manifest_url(
        standby_url,
        None,
        key,
        probe_cfg,
        resolver=probe_resolver,
    )
    if entry["status"] not in {"healthy", "warning"}:
        raise NetworkError(
            "selected AIOStreams standby failed its manifest probe: " + str(entry["status"])
        )
    if standby_manifest is None:
        raise NetworkError("selected AIOStreams standby returned no usable manifest")
    standby_manifest_id = standby_manifest.get("id")
    if not isinstance(standby_manifest_id, str) or not standby_manifest_id:
        raise NetworkError("selected AIOStreams standby returned no usable manifest identity")

    acceptable_ids = {promotion.manifest_id, standby_manifest_id}
    matches = [
        item
        for item in current
        if isinstance(item.get("manifest"), dict)
        and item["manifest"].get("id") in acceptable_ids
    ]
    if len(matches) != 1:
        raise ValidationError(
            "AIOStreams promotion requires exactly one installed descriptor matching the "
            f"configured primary or selected standby identity; found {len(matches)}"
        )
    installed = matches[0]
    installed_manifest = installed["manifest"]
    installed_id = installed_manifest.get("id")
    installed_url = installed.get("transportUrl")
    if not isinstance(installed_url, str):
        raise ValidationError("installed AIOStreams descriptor has no transport URL")
    is_primary = installed_id == promotion.manifest_id and installed_url == primary_url
    is_selected_standby = (
        installed_id == standby_manifest_id and installed_url == standby_url
    )
    if not is_primary and not is_selected_standby:
        raise ValidationError(
            "installed AIOStreams descriptor matches neither the configured primary nor the "
            "selected standby identity and endpoint; stop and review the profile"
        )

    profile_fingerprint = hashlib.sha256(canonical_json_bytes(profile.raw)).hexdigest()
    if is_selected_standby:
        return build_plan_document(
            created_at=created_at,
            base_collection_fingerprint=collection_fingerprint(current),
            desired_profile_fingerprint=profile_fingerprint,
            operations=[],
            warnings=[],
        )
    promotion_doc = {
        "schemaVersion": 1,
        "name": f"{profile.name}-promote-{standby_key}",
        "addons": [
            {
                "key": "aiostreams-promotion",
                "match": {"manifestId": promotion.manifest_id},
                "state": "present",
                "endpoint": {"secretRef": promotion.standbys[standby_key]},
                "manage": ["endpoint"],
            }
        ],
        "policy": {"preserveUnmanagedAddons": True},
    }
    desired, warnings = parse_profile(promotion_doc)
    plan = build_change_plan(
        current=current,
        profile=desired,
        key=key,
        created_at=created_at,
        profile_warnings=[finding.message for finding in warnings],
    )
    replacement = next(
        operation for operation in plan["operations"] if operation["op"] == "replaceEndpoint"
    )
    replacement["targetManifestId"] = standby_manifest_id
    replacement["targetManifestFingerprint"] = collection_fingerprint(standby_manifest)
    plan["desiredProfileFingerprint"] = profile_fingerprint
    plan["planHash"] = compute_plan_hash(plan)
    return plan


__all__ = [
    "AIOStreamsBackup",
    "BackupFinding",
    "build_promotion_plan",
    "check_backup",
    "parse_backup",
    "redact_backup",
]
