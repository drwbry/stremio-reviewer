"""Authenticated Stremio account collection access.

The read path uses ``addonCollectionGet`` and the guarded Phase 5 write path uses
``addonCollectionSet``. The auth key is read only inside these functions, only from the
``STREMIO_AUTH_KEY`` environment variable or a strict-permission file, and is
never placed in a URL, a header, a log line, or an exception message.

The wire contract is recorded in ``docs/stremio-api-contract.md``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from stremioctl.errors import AuthenticationError, NetworkError, ValidationError
from stremioctl.fingerprints import collection_fingerprint
from stremioctl.io import read_secret_file
from stremioctl.privacy import sanitize_text
from stremioctl.probing import read_capped_body

DEFAULT_BASE_URL = "https://api.strem.io"
AUTH_ENV = "STREMIO_AUTH_KEY"
INSECURE_LOOPBACK_ENV = "STREMIOCTL_INSECURE_LOOPBACK"
_GET_METHOD = "addonCollectionGet"
_SET_METHOD = "addonCollectionSet"
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


@dataclass(frozen=True)
class AccountConfig:
    """Where and how to reach the Stremio collection API."""

    base_url: str = DEFAULT_BASE_URL
    timeout: float = 15.0

    def __post_init__(self) -> None:
        try:
            parts = urlsplit(self.base_url)
        except ValueError as exc:
            raise ValidationError("account base URL must be an http(s) URL") from exc
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            raise ValidationError("account base URL must be an http(s) URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValidationError(
                "account base URL must not contain user-info, a query string, or a fragment"
            )
        if scheme == "http":
            loopback = parts.hostname in _LOOPBACK_HOSTS
            allowed = os.environ.get(INSECURE_LOOPBACK_ENV) == "1"
            if not (loopback and allowed):
                raise ValidationError(
                    "account base URL must use https; plain http is accepted only for a "
                    f"loopback host with {INSECURE_LOOPBACK_ENV}=1"
                )
        if not 1.0 <= self.timeout <= 120.0:
            raise ValidationError("account timeout must be between 1 and 120 seconds")

    def _api_url(self, method: str) -> str:
        return self.base_url.rstrip("/") + "/api/" + method

    @property
    def collection_get_url(self) -> str:
        return self._api_url(_GET_METHOD)

    @property
    def collection_set_url(self) -> str:
        return self._api_url(_SET_METHOD)


@dataclass(frozen=True)
class PulledCollection:
    """The result of a successful ``addonCollectionGet``."""

    addons: list[dict[str, Any]]
    last_modified: str | None
    fingerprint: str
    base_url: str


def resolve_auth_key(*, auth_key_file: Path | None = None) -> str:
    """Return the auth key from a strict file or ``STREMIO_AUTH_KEY``.

    Exactly one source may be used. The value is never logged or echoed.
    """

    env_raw = os.environ.get(AUTH_ENV)
    env_present = bool(env_raw and env_raw.strip())
    if auth_key_file is not None and env_present:
        raise ValidationError(
            f"both {AUTH_ENV} and --auth-key-file are set; provide exactly one"
        )
    if auth_key_file is not None:
        key = read_secret_file(auth_key_file).strip()
        if not key:
            raise AuthenticationError("the auth-key file is empty")
        return key
    if env_present:
        assert env_raw is not None
        return env_raw.strip()
    raise AuthenticationError(
        f"no auth key found: set {AUTH_ENV} or pass --auth-key-file PATH"
    )


def _sanitize(message: str, auth_key: str) -> str:
    return sanitize_text(message, secrets_to_hide=(auth_key,))


def fetch_addon_collection(
    auth_key: str,
    cfg: AccountConfig | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> PulledCollection:
    """Perform ``addonCollectionGet`` and return the parsed collection.

    Raises :class:`AuthenticationError` (exit 4) for a rejected key or an API
    error body, and :class:`NetworkError` (exit 3) for transport failures or a
    malformed response. Every message is scrubbed of the auth key.
    """

    config = cfg or AccountConfig()
    body = {"type": "AddonCollectionGet", "authKey": auth_key, "update": True}
    timeout = httpx.Timeout(config.timeout, connect=min(config.timeout, 10.0))
    try:
        with httpx.Client(
            follow_redirects=False, timeout=timeout, transport=transport, http2=False
        ) as client:
            with client.stream(
                "POST",
                config.collection_get_url,
                json=body,
                headers={"accept": "application/json"},
            ) as response:
                status = response.status_code
                if status in (401, 403):
                    raise AuthenticationError(f"the API rejected the auth key (HTTP {status})")
                if status >= 400:
                    raise NetworkError(f"the API request failed (HTTP {status})")
                raw = read_capped_body(response, _MAX_RESPONSE_BYTES)
    except (AuthenticationError, NetworkError):
        raise
    except httpx.HTTPError as exc:
        raise NetworkError(
            _sanitize(f"could not reach the API: {type(exc).__name__}", auth_key)
        ) from None
    except Exception as exc:  # pragma: no cover - defensive; keep every path typed and scrubbed
        raise NetworkError(
            _sanitize(f"unexpected API client error: {type(exc).__name__}", auth_key)
        ) from None

    if raw is None:
        raise NetworkError("the API response exceeded the size limit")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise NetworkError("the API returned a non-JSON response") from None
    if not isinstance(payload, dict):
        raise NetworkError("the API returned an unexpected response shape")

    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        code = error.get("code")
        detail = _sanitize(message, auth_key) if isinstance(message, str) else "no message"
        code_note = f" (code {code})" if isinstance(code, int) else ""
        raise AuthenticationError(f"the API returned an error{code_note}: {detail}")

    result = payload.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("addons"), list):
        raise NetworkError("the API response did not contain an add-on collection")

    addons: list[dict[str, Any]] = result["addons"]
    last_modified = result.get("lastModified")
    return PulledCollection(
        addons=addons,
        last_modified=last_modified if isinstance(last_modified, str) else None,
        fingerprint=collection_fingerprint(addons),
        base_url=config.base_url,
    )


def build_snapshot(pulled: PulledCollection, *, pulled_at: str) -> dict[str, Any]:
    """Assemble the private ``account-snapshot`` document.

    This is a *raw* artifact: it holds the collection verbatim, including any
    credential-bearing transport URLs. It is only ever written under a private
    directory with mode ``0600`` and is never redacted.
    """

    return {
        "schemaVersion": 1,
        "artifact": "account-snapshot",
        "pulledAt": pulled_at,
        "baseUrl": pulled.base_url,
        "lastModified": pulled.last_modified,
        "collectionFingerprint": pulled.fingerprint,
        "collection": pulled.addons,
    }


def push_addon_collection(
    auth_key: str,
    addons: list[dict[str, Any]],
    cfg: AccountConfig | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Perform ``addonCollectionSet`` with the complete ordered collection.

    Returns ``None`` on a ``{"result": {"success": true}}`` acknowledgement.
    Raises :class:`AuthenticationError` (exit 4) for a rejected key or an API
    error body, and :class:`NetworkError` (exit 3) for a transport failure, a
    non-``success`` body, or any malformed response. Every message is scrubbed of
    the auth key.

    The whole target collection is sent in one request (SPEC section 12): an
    apply never issues a sequence of per-add-on mutations.
    """

    config = cfg or AccountConfig()
    body = {"type": "AddonCollectionSet", "authKey": auth_key, "addons": addons}
    timeout = httpx.Timeout(config.timeout, connect=min(config.timeout, 10.0))
    try:
        with httpx.Client(
            follow_redirects=False, timeout=timeout, transport=transport, http2=False
        ) as client:
            with client.stream(
                "POST",
                config.collection_set_url,
                json=body,
                headers={"accept": "application/json"},
            ) as response:
                status = response.status_code
                if status in (401, 403):
                    raise AuthenticationError(f"the API rejected the auth key (HTTP {status})")
                if status >= 400:
                    raise NetworkError(f"the API request failed (HTTP {status})")
                raw = read_capped_body(response, _MAX_RESPONSE_BYTES)
    except (AuthenticationError, NetworkError):
        raise
    except httpx.HTTPError as exc:
        raise NetworkError(
            _sanitize(f"could not reach the API: {type(exc).__name__}", auth_key)
        ) from None
    except Exception as exc:  # pragma: no cover - defensive; keep every path typed and scrubbed
        raise NetworkError(
            _sanitize(f"unexpected API client error: {type(exc).__name__}", auth_key)
        ) from None

    if raw is None:
        raise NetworkError("the API response exceeded the size limit")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise NetworkError("the API returned a non-JSON response") from None
    if not isinstance(payload, dict):
        raise NetworkError("the API returned an unexpected response shape")

    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        code = error.get("code")
        detail = _sanitize(message, auth_key) if isinstance(message, str) else "no message"
        code_note = f" (code {code})" if isinstance(code, int) else ""
        raise AuthenticationError(f"the API returned an error{code_note}: {detail}")

    result = payload.get("result")
    if not isinstance(result, dict) or result.get("success") is not True:
        raise NetworkError("the API did not confirm the collection write")


__all__ = [
    "AUTH_ENV",
    "DEFAULT_BASE_URL",
    "INSECURE_LOOPBACK_ENV",
    "AccountConfig",
    "PulledCollection",
    "build_snapshot",
    "fetch_addon_collection",
    "push_addon_collection",
    "resolve_auth_key",
]
