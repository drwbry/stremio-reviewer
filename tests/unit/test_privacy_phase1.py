from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from _helpers import load_valid_collection
from stremioctl.errors import SecurityError
from stremioctl.io import ensure_private_directory
from stremioctl.privacy import (
    assert_no_sentinels,
    is_sensitive_key,
    load_or_create_redaction_key,
    redact_document,
    redact_url,
    render_secret_safe,
    safe_json,
)

KEY = b"k" * 32


@pytest.mark.parametrize(
    "name",
    [
        "token",
        "apiKey",
        "api_key",
        "API-KEY",
        "password",
        "clientSecret",
        "Authorization",
        "x_auth_token",
        "accessKey",
        "sessionId",
        "refresh_token",
    ],
)
def test_is_sensitive_key_true(name: str) -> None:
    assert is_sensitive_key(name)


@pytest.mark.parametrize(
    "name",
    ["author", "name", "id", "types", "resources", "description", "idPrefixes", "contactEmail"],
)
def test_is_sensitive_key_false(name: str) -> None:
    assert not is_sensitive_key(name)


def test_redact_document_removes_urls_and_secret_values() -> None:
    redacted = redact_document(load_valid_collection(), KEY)
    blob = json.dumps(redacted)
    assert_no_sentinels_in(blob)
    assert "/manifest.json" not in blob
    assert redacted[7]["manifest"]["settings"]["apiKey"] == "<redacted>"
    assert redacted[7]["transportUrl"].startswith("https://secret.example.invalid/<redacted>#")
    # non-sensitive metadata is retained for debugging
    assert redacted[0]["manifest"]["id"] == "synthetic.catalog"
    assert redacted[0]["manifest"]["version"] == "1.0.0"
    assert redacted[3]["transportUrl"].startswith("http://subtitles.example.invalid/<redacted>#")


def test_redact_document_hide_hosts() -> None:
    redacted = redact_document(load_valid_collection(), KEY, hide_hosts=True)
    for descriptor in redacted:
        assert descriptor["transportUrl"].startswith(("https://<host>/", "http://<host>/"))
    # non-URL text such as a contact email keeps its host; only URLs are masked
    assert redacted[7]["manifest"]["contactEmail"] == "fixture@example.invalid"


def test_redact_document_scrubs_embedded_sentinel_in_free_text() -> None:
    redacted = redact_document({"note": "internal ref SENTINEL_MUST_NOT_LEAK end"}, KEY)
    assert redacted["note"] == "internal ref <redacted> end"


def test_assert_no_sentinels_raises_and_passes() -> None:
    with pytest.raises(SecurityError):
        assert_no_sentinels("value SENTINEL_LEAK here")
    assert_no_sentinels("perfectly clean text")


def test_redact_url_non_http_scheme_is_fully_masked() -> None:
    out = redact_url("ftp://host.invalid/path", KEY)
    assert out.startswith("<redacted-url>#")


def test_redact_url_unparseable_ipv6_falls_back_to_placeholder_host() -> None:
    out = redact_url("https://[::1", KEY)
    assert "#" in out
    assert "SENTINEL" not in out


def test_render_secret_safe_hide_hosts_option() -> None:
    rendered = render_secret_safe(
        {"u": "see https://h.invalid/x/SENTINEL_MUST_NOT_LEAK now"}, KEY, hide_hosts=True
    )
    assert "SENTINEL" not in json.dumps(rendered)
    assert "<host>" in rendered["u"]


def test_safe_json_redacts_urls_and_sentinels() -> None:
    out = safe_json({"transportUrl": "https://h.invalid/SENTINEL_MUST_NOT_LEAK"}, KEY)
    assert "SENTINEL" not in out
    assert "h.invalid" in out


def _fresh_private_dir(tmp_path: Path) -> Path:
    return ensure_private_directory(tmp_path / "private")


def test_redaction_key_is_stable_and_private(tmp_path: Path) -> None:
    directory = _fresh_private_dir(tmp_path)
    first = load_or_create_redaction_key(directory)
    second = load_or_create_redaction_key(directory)
    assert first == second
    assert stat.S_IMODE((directory / "redaction.key").stat().st_mode) == 0o600


def test_redaction_key_rejects_group_readable_file(tmp_path: Path) -> None:
    directory = _fresh_private_dir(tmp_path)
    load_or_create_redaction_key(directory)
    os.chmod(directory / "redaction.key", 0o644)
    with pytest.raises(SecurityError):
        load_or_create_redaction_key(directory)


def test_redaction_key_rejects_wrong_length(tmp_path: Path) -> None:
    directory = _fresh_private_dir(tmp_path)
    key_path = directory / "redaction.key"
    key_path.write_bytes(b"too-short")
    os.chmod(key_path, 0o600)
    with pytest.raises(SecurityError):
        load_or_create_redaction_key(directory)


def test_redaction_key_rejects_symlink(tmp_path: Path) -> None:
    directory = _fresh_private_dir(tmp_path)
    real = tmp_path / "real.key"
    real.write_bytes(b"x" * 32)
    os.chmod(real, 0o600)
    (directory / "redaction.key").symlink_to(real)
    with pytest.raises(SecurityError):
        load_or_create_redaction_key(directory)


def test_redaction_key_rejects_non_regular_file(tmp_path: Path) -> None:
    directory = _fresh_private_dir(tmp_path)
    (directory / "redaction.key").mkdir()
    with pytest.raises(SecurityError, match="regular file"):
        load_or_create_redaction_key(directory)


def test_redaction_key_rejects_wrong_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _fresh_private_dir(tmp_path)
    load_or_create_redaction_key(directory)
    monkeypatch.setattr("stremioctl.privacy.ensure_private_app_dir", lambda _path: directory)
    monkeypatch.setattr(os, "getuid", lambda: directory.stat().st_uid + 1)
    with pytest.raises(SecurityError, match="Redaction key is not owned"):
        load_or_create_redaction_key(directory)


def assert_no_sentinels_in(blob: str) -> None:
    assert "SENTINEL_" not in blob
