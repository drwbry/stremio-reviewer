"""Semantic validation of an add-on collection.

Structural shape is checked with the ``addon-collection-v1`` JSON Schema; this
module adds the domain rules and produces :class:`Finding` records. Findings
carry redacted endpoint labels only - never a complete transport URL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from stremioctl.models import KNOWN_DESCRIPTOR_KEYS
from stremioctl.privacy import redact_url
from stremioctl.schemas import iter_schema_errors

_REQUIRED_MANIFEST_FIELDS: tuple[tuple[str, type[object]], ...] = (
    ("name", str),
    ("version", str),
    ("resources", list),
    ("types", list),
)


@dataclass(frozen=True)
class Finding:
    """A single validation observation."""

    severity: str  # "error" or "warning"
    code: str
    message: str
    descriptor_index: int | None = None
    manifest_id: str | None = None
    endpoint: str | None = None

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.descriptor_index is not None:
            payload["descriptorIndex"] = self.descriptor_index
        if self.manifest_id is not None:
            payload["manifestId"] = self.manifest_id
        if self.endpoint is not None:
            payload["endpoint"] = self.endpoint
        return payload


def _endpoint_label(url: Any, key: bytes) -> str | None:
    if isinstance(url, str) and url:
        return redact_url(url, key)
    return None


def validate_collection(payload: Any, key: bytes) -> list[Finding]:
    """Return every structural and semantic finding for *payload*."""

    if not isinstance(payload, list):
        return [Finding("error", "invalid_root", "Add-on collection root must be a JSON array")]

    findings: list[Finding] = [
        Finding("error", "schema", message)
        for message in iter_schema_errors(payload, "addon-collection-v1")
    ]

    seen_ids: dict[str, list[int]] = {}
    for index, descriptor in enumerate(payload):
        if not isinstance(descriptor, dict):
            findings.append(
                Finding(
                    "error",
                    "invalid_descriptor",
                    "Descriptor is not a JSON object",
                    descriptor_index=index,
                )
            )
            continue

        manifest = descriptor.get("manifest")
        raw_url = descriptor.get("transportUrl")
        endpoint = _endpoint_label(raw_url, key)

        manifest_id: str | None = None
        if isinstance(manifest, dict):
            candidate = manifest.get("id")
            if isinstance(candidate, str) and candidate.strip():
                manifest_id = candidate

        if not isinstance(manifest, dict):
            findings.append(
                Finding(
                    "error",
                    "missing_manifest",
                    "Descriptor has no manifest object",
                    descriptor_index=index,
                    endpoint=endpoint,
                )
            )
        else:
            if manifest_id is None:
                findings.append(
                    Finding(
                        "error",
                        "missing_manifest_id",
                        "Manifest has no non-empty string id",
                        descriptor_index=index,
                        endpoint=endpoint,
                    )
                )
            else:
                seen_ids.setdefault(manifest_id, []).append(index)
            for field, expected_type in _REQUIRED_MANIFEST_FIELDS:
                if field not in manifest:
                    findings.append(
                        Finding(
                            "warning",
                            "missing_manifest_field",
                            f"Manifest field '{field}' is missing",
                            descriptor_index=index,
                            manifest_id=manifest_id,
                            endpoint=endpoint,
                        )
                    )
                elif not isinstance(manifest[field], expected_type):
                    findings.append(
                        Finding(
                            "warning",
                            "manifest_field_type",
                            f"Manifest field '{field}' has an unexpected type",
                            descriptor_index=index,
                            manifest_id=manifest_id,
                            endpoint=endpoint,
                        )
                    )

        findings.extend(
            _transport_findings(raw_url, index, manifest_id, endpoint)
        )

        unexpected = sorted(set(descriptor) - KNOWN_DESCRIPTOR_KEYS)
        if unexpected:
            findings.append(
                Finding(
                    "warning",
                    "unexpected_descriptor_field",
                    f"Descriptor carries unexpected keys: {', '.join(unexpected)}",
                    descriptor_index=index,
                    manifest_id=manifest_id,
                )
            )

        flags = descriptor.get("flags")
        if flags is not None and not isinstance(flags, dict):
            findings.append(
                Finding(
                    "warning",
                    "flags_type",
                    "Descriptor flags is not an object",
                    descriptor_index=index,
                    manifest_id=manifest_id,
                )
            )

    for manifest_id, indexes in sorted(seen_ids.items()):
        if len(indexes) > 1:
            positions = ", ".join(str(i) for i in indexes)
            message = (
                f"Manifest id '{manifest_id}' appears {len(indexes)} times "
                f"at indexes {positions}"
            )
            findings.append(Finding("error", "duplicate_manifest_id", message))
    return findings


def _transport_findings(
    raw_url: Any,
    index: int,
    manifest_id: str | None,
    endpoint: str | None,
) -> list[Finding]:
    if not isinstance(raw_url, str) or not raw_url:
        return [
            Finding(
                "error",
                "missing_transport_url",
                "Descriptor has no transportUrl string",
                descriptor_index=index,
                manifest_id=manifest_id,
            )
        ]

    try:
        parts = urlsplit(raw_url)
        hostname = parts.hostname
    except ValueError:
        parts = None
        hostname = None

    if parts is None or parts.scheme.lower() not in {"http", "https"} or not hostname:
        return [
            Finding(
                "error",
                "malformed_transport_url",
                "transportUrl is not a usable http(s) URL",
                descriptor_index=index,
                manifest_id=manifest_id,
                endpoint=endpoint,
            )
        ]

    findings: list[Finding] = []
    if parts.scheme.lower() == "http":
        findings.append(
            Finding(
                "warning",
                "insecure_transport",
                "transportUrl uses http instead of https",
                descriptor_index=index,
                manifest_id=manifest_id,
                endpoint=endpoint,
            )
        )
    if parts.query:
        findings.append(
            Finding(
                "warning",
                "credential_in_url",
                "transportUrl carries a query string",
                descriptor_index=index,
                manifest_id=manifest_id,
                endpoint=endpoint,
            )
        )
    if parts.username or parts.password:
        findings.append(
            Finding(
                "warning",
                "userinfo_in_url",
                "transportUrl carries HTTP user-info",
                descriptor_index=index,
                manifest_id=manifest_id,
                endpoint=endpoint,
            )
        )
    return findings


def count_by_severity(findings: list[Finding]) -> tuple[int, int]:
    """Return ``(error_count, warning_count)``."""

    errors = sum(1 for finding in findings if finding.severity == "error")
    warnings = sum(1 for finding in findings if finding.severity == "warning")
    return errors, warnings


__all__ = ["Finding", "count_by_severity", "validate_collection"]
