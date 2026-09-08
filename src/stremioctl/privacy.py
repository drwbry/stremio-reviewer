"""Centralized secret-safe rendering and exception sanitization."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from stremioctl.errors import SecurityError
from stremioctl.io import ensure_private_app_dir

REDACTED = "<redacted>"
_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_SENTINEL_PATTERN = re.compile(r"\bSENTINEL_[A-Z0-9_]+\b")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(token|key|secret|password|authorization|credential|cookie|auth)"
    r"(?:[_-][a-z0-9_-]+)?\s*[:=]\s*(['\"]?)[^\s,;]+\2"
)
_SENSITIVE_NAME = re.compile(
    r"(?:token|key|secret|password|authorization|credential|cookie|auth)(?:[_-]?value)?",
    re.IGNORECASE,
)

# Tighter list for the `backup redact` walker. It deliberately omits a bare
# "auth" token so an ordinary manifest key like "author" is not mangled, while
# still catching "authorization" and "authToken" (via "token").
_REDACT_KEY_TOKENS = (
    "token",
    "secret",
    "password",
    "passwd",
    "authorization",
    "apikey",
    "credential",
    "bearer",
    "privatekey",
    "accesskey",
    "sessionid",
)


def is_sensitive_key(name: str) -> bool:
    """Return True when a mapping key name suggests it holds a secret value."""

    normalized = re.sub(r"[\s_\-]+", "", name).lower()
    if not normalized:
        return False
    if normalized == "key" or normalized.endswith("key"):
        return True
    return any(token in normalized for token in _REDACT_KEY_TOKENS)


def assert_no_sentinels(text: str) -> None:
    """Fail closed if a leak sentinel reached an output path."""

    if _SENTINEL_PATTERN.search(text):
        raise SecurityError("Refusing to emit output that still contains a leak sentinel")


def redact_document(value: Any, key: bytes, *, hide_hosts: bool = False) -> Any:
    """Return a copy of JSON-like *value* with URLs and secret values removed.

    Structure and non-sensitive metadata are preserved so the result is still
    useful for debugging. Complete ``http(s)`` URLs anywhere in a string become
    keyed redaction labels, and values under suspicious key names are replaced
    outright.
    """

    def walk(node: Any) -> Any:
        if isinstance(node, Mapping):
            rendered: dict[str, Any] = {}
            for name, child in node.items():
                text_name = str(name)
                rendered[text_name] = REDACTED if is_sensitive_key(text_name) else walk(child)
            return rendered
        if isinstance(node, str):
            replaced = _URL_PATTERN.sub(
                lambda match: redact_url(match.group(0), key, hide_host=hide_hosts), node
            )
            return _SENTINEL_PATTERN.sub(REDACTED, replaced)
        if isinstance(node, Sequence) and not isinstance(node, (bytes, bytearray)):
            return [walk(child) for child in node]
        return node

    return walk(value)


def display_fingerprint(value: str | bytes, key: bytes) -> str:
    """Return the stable twelve-character HMAC display fingerprint."""

    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hmac.new(key, payload, hashlib.sha256).hexdigest()[:12]


def _safe_netloc(parts: SplitResult) -> str:
    try:
        host = parts.hostname or "<host>"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return host
    except ValueError:
        return "<host>"


def redact_url(url: str, key: bytes, *, hide_host: bool = False) -> str:
    """Render a complete URL without exposing credentials or its path/query."""

    fingerprint = display_fingerprint(url, key)
    try:
        parts = urlsplit(url)
    except ValueError:
        return f"<redacted-url>#{fingerprint}"
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return f"<redacted-url>#{fingerprint}"
    host = "<host>" if hide_host else _safe_netloc(parts)
    return f"{parts.scheme.lower()}://{host}/<redacted>#{fingerprint}"


def _replace_text(text: str, key: bytes, secrets_to_hide: Sequence[str]) -> str:
    result = text
    for secret in sorted((item for item in secrets_to_hide if item), key=len, reverse=True):
        result = result.replace(secret, REDACTED)
    result = _URL_PATTERN.sub(lambda match: redact_url(match.group(0), key), result)
    result = _SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}={REDACTED}", result)
    return _SENTINEL_PATTERN.sub(REDACTED, result)


def render_secret_safe(value: Any, key: bytes, *, hide_hosts: bool = False) -> Any:
    """Recursively redact sensitive values and complete URLs from JSON-like data."""

    def render(item: Any, field_name: str | None = None) -> Any:
        if field_name is not None and _SENSITIVE_NAME.search(field_name):
            return REDACTED
        if isinstance(item, Mapping):
            return {str(name): render(child, str(name)) for name, child in item.items()}
        if isinstance(item, str):
            if hide_hosts:
                return _replace_text_with_host_option(item)
            return _replace_text(item, key, ())
        if isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray)):
            return [render(child) for child in item]
        return item

    def _replace_text_with_host_option(text: str) -> str:
        result = _URL_PATTERN.sub(
            lambda match: redact_url(match.group(0), key, hide_host=True), text
        )
        return _SENTINEL_PATTERN.sub(REDACTED, result)

    return render(value)


def sanitize_text(
    text: str, key: bytes | None = None, *, secrets_to_hide: Sequence[str] = ()
) -> str:
    """Sanitize arbitrary exception/log text without exposing URL or sentinel data."""

    render_key = key or hashlib.sha256(b"stremioctl-safe-message").digest()
    return _replace_text(str(text), render_key, secrets_to_hide)


def sanitize_exception(error: BaseException, key: bytes | None = None) -> str:
    """Return a safe, single-line description for an exception boundary."""

    return sanitize_text(str(error).replace("\n", " "), key)


def _key_path(app_dir: Path) -> Path:
    return app_dir / "redaction.key"


def load_or_create_redaction_key(app_dir: Path | None = None) -> bytes:
    """Load a local HMAC key, creating it with mode 0600 on first use."""

    directory = ensure_private_app_dir(app_dir)
    path = _key_path(directory)
    if path.exists():
        if path.is_symlink():
            raise SecurityError("Refusing symlink for redaction key")
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise SecurityError("Redaction key must be a regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise SecurityError("Redaction key is not owned by the current user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise SecurityError("Redaction key must not be accessible by group or other")
            data = path.read_bytes()
        except OSError as exc:
            raise SecurityError("Unable to read the local redaction key") from exc
        if len(data) != 32:
            raise SecurityError("Local redaction key is invalid")
        return data

    data = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)
    except FileExistsError:
        return load_or_create_redaction_key(directory)
    except OSError as exc:
        raise SecurityError("Unable to create the local redaction key") from exc
    return data


def safe_json(value: Any, key: bytes) -> str:
    """Serialize a value after centralized redaction, for safe diagnostics."""

    return json.dumps(render_secret_safe(value, key), ensure_ascii=False, sort_keys=True)


__all__ = [
    "REDACTED",
    "assert_no_sentinels",
    "display_fingerprint",
    "is_sensitive_key",
    "load_or_create_redaction_key",
    "redact_document",
    "redact_url",
    "render_secret_safe",
    "safe_json",
    "sanitize_exception",
    "sanitize_text",
]
