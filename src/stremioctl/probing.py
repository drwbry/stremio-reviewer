"""Read-only manifest probing and the audit report.

`probe collection` fetches each descriptor's transport URL with a bounded,
redirect-restricted GET, parses the manifest, and compares its identity to the
descriptor. It never requests catalog/meta/stream/subtitles routes, never follows
a cross-origin redirect, and refuses loopback / link-local / multicast / private
destinations unless private networking is explicitly allowed.

The audit report carries identifiers, statuses, timings, warnings, and redacted
endpoint labels only. It never contains a complete transport URL, a response
body, a header value, or an auth key.
"""

from __future__ import annotations

import ipaddress
import json
import random
import socket
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from rich.console import Console
from rich.table import Table

from stremioctl.errors import ValidationError
from stremioctl.privacy import redact_url, sanitize_text
from stremioctl.validation import validate_collection

# Statuses from SPEC section 11. `insecure_transport` is the terminal status for
# an otherwise-healthy probe over plain http; a connectivity or content problem
# outranks it. `insecure_transport` also always appears in an entry's `warnings`
# and is reflected in `secure`, so the layering loses no information.
STATUS_HEALTHY = "healthy"
STATUS_WARNING = "warning"
STATUS_UNREACHABLE = "unreachable"
STATUS_INVALID_MANIFEST = "invalid_manifest"
STATUS_IDENTITY_MISMATCH = "identity_mismatch"
STATUS_INSECURE_TRANSPORT = "insecure_transport"
STATUS_BLOCKED_DESTINATION = "blocked_destination"

_OK_STATUSES = frozenset({STATUS_HEALTHY, STATUS_WARNING})
_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
_RETRYABLE_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)
_RECOMMENDED_MANIFEST_FIELDS = ("name", "version", "resources", "types")
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

Resolver = Callable[[str, int], list[str]]
SleepFn = Callable[[float], None]
JitterFn = Callable[[], float]


class _Blocked(Exception):
    """A destination failed the address safety check (maps to blocked_destination)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class _Unreachable(Exception):
    """A destination could not be resolved or contacted (maps to unreachable)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True)
class ProbeConfig:
    """Bounded probe parameters. Ranges follow SPEC section 11."""

    overall_timeout: float = 8.0
    connect_timeout: float = 3.0
    concurrency: int = 4
    max_bytes: int = 2 * 1024 * 1024
    attempts: int = 2
    allow_private_network: bool = False

    def __post_init__(self) -> None:
        if not 1.0 <= self.overall_timeout <= 30.0:
            raise ValidationError("probe timeout must be between 1 and 30 seconds")
        if not 1 <= self.concurrency <= 10:
            raise ValidationError("probe concurrency must be between 1 and 10")
        if self.attempts < 1:
            raise ValidationError("probe attempts must be at least 1")


@dataclass
class ProbeEntry:
    """One descriptor's audit outcome."""

    index: int
    manifest_id: str | None
    endpoint: str | None
    secure: bool
    status: str
    http_status: int | None = None
    latency_ms: int | None = None
    attempts: int = 0
    redirects: int = 0
    warnings: list[str] = field(default_factory=list)
    detail: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "manifestId": self.manifest_id,
            "endpoint": self.endpoint,
            "secure": self.secure,
            "status": self.status,
            "httpStatus": self.http_status,
            "latencyMs": self.latency_ms,
            "attempts": self.attempts,
            "redirects": self.redirects,
            "warnings": list(self.warnings),
            "detail": self.detail,
        }


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port or None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _address_block_reason(raw_ip: str, *, allow_private: bool) -> str | None:
    """Return a short reason if *raw_ip* must not be contacted, else ``None``.

    ``allow_private=True`` deliberately unblocks loopback, link-local, and
    private ranges together (they overlap in ``ipaddress``); multicast,
    unspecified, and reserved addresses stay blocked regardless.
    """

    try:
        ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        return "unresolvable address"
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _address_block_reason(str(mapped), allow_private=allow_private)
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_loopback:
        return None if allow_private else "loopback address"
    if ip.is_link_local:
        return None if allow_private else "link-local address"
    if ip.is_private:
        return None if allow_private else "private address"
    if ip.is_reserved:
        return "reserved address"
    return None


def _guard_destination(url: str, resolver: Resolver, *, allow_private: bool) -> None:
    """Resolve *url*'s host and raise :class:`_Blocked` if any address is unsafe."""

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise _Blocked("non-http(s) scheme")
    if parts.username or parts.password:
        raise _Blocked("url carries embedded credentials")
    host = parts.hostname
    if not host:
        raise _Blocked("url has no host")
    port = parts.port or (443 if scheme == "https" else 80)

    if _looks_like_ip(host):
        reason = _address_block_reason(host, allow_private=allow_private)
        if reason is not None:
            raise _Blocked(reason)
        return

    try:
        addresses = resolver(host, port)
    except OSError:
        raise _Unreachable("dns resolution failed") from None
    if not addresses:
        raise _Unreachable("dns resolution returned no records")
    for address in addresses:
        reason = _address_block_reason(address, allow_private=allow_private)
        if reason is not None:
            raise _Blocked(reason)


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    da = pa.port or (443 if pa.scheme.lower() == "https" else 80)
    db = pb.port or (443 if pb.scheme.lower() == "https" else 80)
    return (pa.scheme.lower(), (pa.hostname or "").lower(), da) == (
        pb.scheme.lower(),
        (pb.hostname or "").lower(),
        db,
    )


def read_capped_body(response: httpx.Response, cap: int) -> bytes | None:
    """Return the body, or ``None`` once it streams past *cap* bytes."""

    total = 0
    chunks: list[bytes] = []
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > cap:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _classify_manifest(
    body: bytes, expected_id: str | None
) -> tuple[str, list[str], str | None]:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return STATUS_INVALID_MANIFEST, [], "response body is not JSON"
    if not isinstance(parsed, dict):
        return STATUS_INVALID_MANIFEST, [], "manifest is not a JSON object"
    found_id = parsed.get("id")
    if not isinstance(found_id, str) or not found_id.strip():
        return STATUS_INVALID_MANIFEST, [], "manifest has no string id"
    warnings: list[str] = []
    missing = [f for f in _RECOMMENDED_MANIFEST_FIELDS if f not in parsed]
    if missing:
        warnings.append(f"manifest is missing recommended field(s): {', '.join(missing)}")
    if expected_id is not None and found_id != expected_id:
        return (
            STATUS_IDENTITY_MISMATCH,
            warnings,
            "fetched manifest id differs from the descriptor",
        )
    return STATUS_HEALTHY, warnings, None


@dataclass
class _Attempted:
    response: httpx.Response | None
    attempts: int
    latency_ms: int | None
    transient_detail: str | None


def _backoff(attempt: int, jitter: JitterFn) -> float:
    return min(0.5 * attempt + jitter(), 2.0)


def _fetch_with_retry(
    client: httpx.Client,
    url: str,
    cfg: ProbeConfig,
    sleep: SleepFn,
    jitter: JitterFn,
) -> _Attempted:
    detail: str | None = None
    for attempt in range(1, cfg.attempts + 1):
        started = time.perf_counter()
        try:
            response = client.send(client.build_request("GET", url), stream=True)
        except _RETRYABLE_ERRORS as exc:
            detail = sanitize_text(f"{type(exc).__name__}: {exc}")
            if attempt < cfg.attempts:
                sleep(_backoff(attempt, jitter))
                continue
            return _Attempted(None, attempt, None, detail)
        latency = max(0, round((time.perf_counter() - started) * 1000))
        if response.status_code in _RETRYABLE_STATUS and attempt < cfg.attempts:
            response.close()
            detail = f"received retryable status {response.status_code}"
            sleep(_backoff(attempt, jitter))
            continue
        return _Attempted(response, attempt, latency, None)
    return _Attempted(None, cfg.attempts, None, detail)  # pragma: no cover


def _run_probe(
    entry: ProbeEntry,
    url: str,
    cfg: ProbeConfig,
    client: httpx.Client,
    resolver: Resolver,
    sleep: SleepFn,
    jitter: JitterFn,
) -> None:
    current = url
    origin = url
    while True:
        _guard_destination(current, resolver, allow_private=cfg.allow_private_network)
        attempted = _fetch_with_retry(client, current, cfg, sleep, jitter)
        entry.attempts += attempted.attempts
        if attempted.response is None:
            entry.status = STATUS_UNREACHABLE
            entry.detail = attempted.transient_detail or "request failed"
            return
        response = attempted.response
        if response.is_redirect:
            response.close()
            location = response.headers.get("location", "")
            target = urljoin(str(response.url), location) if location else ""
            if not target:
                entry.status = STATUS_UNREACHABLE
                entry.detail = "redirect without a location"
                return
            if not _same_origin(origin, target):
                entry.status = STATUS_UNREACHABLE
                entry.detail = "cross-origin redirect not followed"
                return
            if entry.redirects >= 1:
                entry.status = STATUS_UNREACHABLE
                entry.detail = "too many redirects"
                return
            entry.redirects += 1
            current = target
            continue

        entry.http_status = response.status_code
        entry.latency_ms = attempted.latency_ms
        try:
            if response.status_code >= 400:
                entry.status = STATUS_UNREACHABLE
                entry.detail = f"server responded with status {response.status_code}"
                return
            body = read_capped_body(response, cfg.max_bytes)
            content_type = response.headers.get("content-type", "")
        finally:
            response.close()

        if body is None:
            entry.status = STATUS_INVALID_MANIFEST
            entry.detail = (
                f"response body exceeded the {cfg.max_bytes // (1024 * 1024)} MiB limit"
            )
            return
        if "json" not in content_type.lower():
            entry.warnings.append("response content-type is not JSON")
        status, warnings, detail = _classify_manifest(body, entry.manifest_id)
        entry.warnings.extend(warnings)
        entry.detail = detail
        entry.status = _finalize_status(status, entry)
        return


def _finalize_status(base: str, entry: ProbeEntry) -> str:
    if base != STATUS_HEALTHY:
        return base
    if not entry.secure:
        return STATUS_INSECURE_TRANSPORT
    if entry.warnings:
        return STATUS_WARNING
    return STATUS_HEALTHY


def _probe_one(
    index: int,
    descriptor: dict[str, Any],
    key: bytes,
    cfg: ProbeConfig,
    resolver: Resolver,
    sleep: SleepFn,
    jitter: JitterFn,
) -> ProbeEntry:
    manifest = descriptor.get("manifest")
    manifest_id = manifest.get("id") if isinstance(manifest, dict) else None
    if not isinstance(manifest_id, str):
        manifest_id = None
    raw_url = descriptor.get("transportUrl")
    url = raw_url if isinstance(raw_url, str) else ""
    secure = urlsplit(url).scheme.lower() == "https" if url else False

    entry = ProbeEntry(
        index=index,
        manifest_id=manifest_id,
        endpoint=redact_url(url, key) if url else None,
        secure=secure,
        status=STATUS_UNREACHABLE,
    )
    if url and not secure:
        entry.warnings.append("transport uses http instead of https")

    timeout = httpx.Timeout(cfg.overall_timeout, connect=cfg.connect_timeout)
    try:
        with httpx.Client(follow_redirects=False, timeout=timeout, http2=False) as client:
            _run_probe(entry, url, cfg, client, resolver, sleep, jitter)
    except _Blocked as blocked:
        entry.status = STATUS_BLOCKED_DESTINATION
        entry.detail = blocked.detail
    except _Unreachable as unreachable:
        entry.status = STATUS_UNREACHABLE
        entry.detail = unreachable.detail
    except Exception as exc:  # never let one probe abort the batch; never leak a raw URL
        entry.status = STATUS_UNREACHABLE
        entry.detail = sanitize_text(f"{type(exc).__name__}: {exc}")
    return entry


def probe_collection(
    payload: Any,
    key: bytes,
    cfg: ProbeConfig | None = None,
    *,
    generated_at: str,
    resolver: Resolver | None = None,
    sleep: SleepFn = time.sleep,
    jitter: JitterFn | None = None,
) -> dict[str, Any]:
    """Probe every descriptor in *payload* and return an audit report v1 document."""

    config = cfg or ProbeConfig()
    resolve = resolver or _default_resolver
    jitter_fn = jitter or (lambda: random.uniform(0.0, 0.25))

    if not isinstance(payload, list):
        raise ValidationError("Add-on collection root must be a JSON array")
    blocking = sorted(
        {
            f.code
            for f in validate_collection(payload, key)
            if f.severity == "error" and f.code in _STRUCTURAL_ERROR_CODES
        }
    )
    if blocking:
        raise ValidationError("collection cannot be probed: " + ", ".join(blocking))

    descriptors = [(i, d) for i, d in enumerate(payload) if isinstance(d, dict)]
    with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
        entries = list(
            pool.map(
                lambda pair: _probe_one(
                    pair[0], pair[1], key, config, resolve, sleep, jitter_fn
                ),
                descriptors,
            )
        )

    status_counts: dict[str, int] = {}
    for entry in entries:
        status_counts[entry.status] = status_counts.get(entry.status, 0) + 1

    return {
        "schemaVersion": 1,
        "report": "audit",
        "generatedAt": generated_at,
        "descriptorCount": len(entries),
        "statusCounts": status_counts,
        "entries": [entry.to_json() for entry in entries],
    }


def audit_exit_code(report: dict[str, Any]) -> int:
    """Return ``0`` when every entry is healthy or a plain warning, else ``3``."""

    statuses = {entry["status"] for entry in report["entries"]}
    return 0 if statuses <= _OK_STATUSES else 3


def render_audit_human(report: dict[str, Any], console: Console) -> None:
    """Print the audit report as a table plus a status summary."""

    table = Table(title=f"Manifest audit ({report['descriptorCount']} descriptors)")
    table.add_column("#", justify="right")
    table.add_column("Manifest ID")
    table.add_column("Status")
    table.add_column("HTTP", justify="right")
    table.add_column("ms", justify="right")
    table.add_column("Endpoint")
    for entry in report["entries"]:
        table.add_row(
            str(entry["index"]),
            entry["manifestId"] or "<missing>",
            entry["status"],
            "-" if entry["httpStatus"] is None else str(entry["httpStatus"]),
            "-" if entry["latencyMs"] is None else str(entry["latencyMs"]),
            entry["endpoint"] or "<none>",
        )
    console.print(table)

    counts = ", ".join(
        f"{count} {status}" for status, count in sorted(report["statusCounts"].items())
    )
    console.print(f"statuses: {counts}")
    for entry in report["entries"]:
        notes = list(entry["warnings"])
        if entry["detail"]:
            notes.append(entry["detail"])
        if notes:
            console.print(f"  [{entry['index']}] {entry['status']}: {'; '.join(notes)}")


__all__ = [
    "ProbeConfig",
    "ProbeEntry",
    "Resolver",
    "audit_exit_code",
    "probe_collection",
    "read_capped_body",
    "render_audit_human",
]
