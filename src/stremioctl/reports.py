"""Build and render the ``backup inspect`` / ``backup validate`` reports.

The JSON reports conform to ``schemas/backup-report-v1.schema.json``. Endpoints
appear only as keyed redaction labels.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from rich.console import Console
from rich.table import Table

from stremioctl.fingerprints import collection_display_fingerprint
from stremioctl.models import parse_collection
from stremioctl.privacy import redact_url
from stremioctl.validation import count_by_severity, validate_collection

_KNOWN_MANIFEST_KEYS = frozenset(
    {
        "id",
        "name",
        "version",
        "resources",
        "types",
        "catalogs",
        "addonCatalogs",
        "background",
        "behaviorHints",
        "contactEmail",
        "description",
        "idPrefixes",
        "logo",
    }
)


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _describe_transport(url: str | None, key: bytes) -> dict[str, Any]:
    if not url:
        return {
            "scheme": None,
            "secure": False,
            "label": None,
            "hasQuery": False,
            "hasUserinfo": False,
        }
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower() or None
        has_query = bool(parts.query)
        has_userinfo = bool(parts.username or parts.password)
    except ValueError:
        scheme = None
        has_query = False
        has_userinfo = False
    return {
        "scheme": scheme,
        "secure": scheme == "https",
        "label": redact_url(url, key),
        "hasQuery": has_query,
        "hasUserinfo": has_userinfo,
    }


def build_inspect_report(payload: Any, key: bytes) -> dict[str, Any]:
    """Return the JSON-safe ``inspect`` report for a parseable collection."""

    collection = parse_collection(payload)
    findings = validate_collection(payload, key)
    errors, warnings = count_by_severity(findings)

    descriptors: list[dict[str, Any]] = []
    https = insecure = other = 0
    for index, descriptor in enumerate(collection):
        transport = _describe_transport(descriptor.transport_url, key)
        if transport["scheme"] == "https":
            https += 1
        elif transport["scheme"] == "http":
            insecure += 1
        else:
            other += 1

        manifest = descriptor.manifest or {}
        resources = manifest.get("resources")
        descriptors.append(
            {
                "index": index,
                "manifestId": descriptor.manifest_id,
                "name": _string_or_none(manifest.get("name")),
                "version": _string_or_none(manifest.get("version")),
                "resourceCount": len(resources) if isinstance(resources, list) else None,
                "types": manifest["types"] if isinstance(manifest.get("types"), list) else [],
                "transport": transport,
                "unknownDescriptorFields": descriptor.unknown_descriptor_fields,
                "unknownManifestFields": sorted(
                    name for name in manifest if name not in _KNOWN_MANIFEST_KEYS
                ),
            }
        )

    return {
        "schemaVersion": 1,
        "report": "inspect",
        "descriptorCount": len(collection),
        "collectionFingerprint": collection_display_fingerprint(collection.to_json(), key),
        "transports": {"https": https, "insecure": insecure, "other": other},
        "descriptors": descriptors,
        "findings": [finding.to_json() for finding in findings],
        "errorCount": errors,
        "warningCount": warnings,
    }


def build_validate_report(payload: Any, key: bytes) -> dict[str, Any]:
    """Return the JSON-safe ``validate`` report for any payload."""

    findings = validate_collection(payload, key)
    errors, warnings = count_by_severity(findings)
    return {
        "schemaVersion": 1,
        "report": "validate",
        "valid": errors == 0,
        "descriptorCount": len(payload) if isinstance(payload, list) else 0,
        "findings": [finding.to_json() for finding in findings],
        "errorCount": errors,
        "warningCount": warnings,
    }


def _render_findings(findings: list[dict[str, Any]], console: Console) -> None:
    if not findings:
        console.print("findings: none")
        return
    console.print(f"findings: {len(findings)}")
    for finding in findings:
        index = finding.get("descriptorIndex")
        where = "" if index is None else f" (descriptor {index})"
        console.print(
            f"  {finding['severity']}: {finding['code']}{where} - {finding['message']}"
        )


def render_inspect_human(report: dict[str, Any], console: Console) -> None:
    """Print the human ``inspect`` report as a table plus a short summary."""

    table = Table(title=f"Add-on collection ({report['descriptorCount']} descriptors)")
    table.add_column("#", justify="right")
    table.add_column("Manifest ID")
    table.add_column("Name")
    table.add_column("Ver")
    table.add_column("Res", justify="right")
    table.add_column("Types")
    table.add_column("Transport")
    for row in report["descriptors"]:
        transport = row["transport"]
        scheme = transport["scheme"]
        if transport["secure"]:
            marker = ""
        elif scheme == "http":
            marker = "  (insecure)"
        else:
            marker = "  (no transport)" if scheme is None else "  (unknown scheme)"
        types = ", ".join(str(item) for item in row["types"]) or "-"
        resource_count = row["resourceCount"]
        table.add_row(
            str(row["index"]),
            row["manifestId"] or "<missing>",
            row["name"] or "-",
            row["version"] or "-",
            "-" if resource_count is None else str(resource_count),
            types,
            f"{transport['label'] or '<none>'}{marker}",
        )
    console.print(table)

    transports = report["transports"]
    console.print(
        f"transports: {transports['https']} https, "
        f"{transports['insecure']} insecure, {transports['other']} other"
    )
    console.print(f"collection label: {report['collectionFingerprint']}")
    _render_findings(report["findings"], console)


def render_validate_human(report: dict[str, Any], console: Console) -> None:
    """Print the human ``validate`` report: findings then a verdict line."""

    _render_findings(report["findings"], console)
    if report["valid"]:
        console.print(f"VALID ({report['warningCount']} warnings)")
    else:
        console.print(
            f"INVALID ({report['errorCount']} errors, {report['warningCount']} warnings)"
        )


__all__ = [
    "build_inspect_report",
    "build_validate_report",
    "render_inspect_human",
    "render_validate_human",
]
