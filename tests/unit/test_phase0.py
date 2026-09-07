from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from stremioctl.errors import ConfigurationError, SecurityError, ValidationError
from stremioctl.io import ensure_private_directory
from stremioctl.privacy import (
    display_fingerprint,
    load_or_create_redaction_key,
    redact_url,
    render_secret_safe,
    sanitize_exception,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_synthetic_fixture_has_observed_collection_shape() -> None:
    collection = json.loads((FIXTURES / "collection.synthetic.json").read_text())
    assert isinstance(collection, list)
    assert len(collection) == 8
    assert all(isinstance(item["manifest"], dict) for item in collection)
    assert all("transportUrl" in item for item in collection)


def test_private_directory_is_created_with_mode_0700(tmp_path: Path) -> None:
    private = ensure_private_directory(tmp_path / "private")
    assert private.is_dir()
    if hasattr(os, "getuid"):
        assert stat.S_IMODE(private.stat().st_mode) == 0o700


def test_private_directory_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "private"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(SecurityError):
        ensure_private_directory(link)


def test_redaction_key_is_private_and_stable(tmp_path: Path) -> None:
    first = load_or_create_redaction_key(tmp_path / "private")
    second = load_or_create_redaction_key(tmp_path / "private")
    assert first == second
    assert stat.S_IMODE((tmp_path / "private" / "redaction.key").stat().st_mode) == 0o600


def test_renderer_removes_sentinels_and_complete_urls() -> None:
    key = b"k" * 32
    source = json.loads((FIXTURES / "collection.synthetic.json").read_text())
    rendered = render_secret_safe(source, key)
    output = json.dumps(rendered, sort_keys=True)
    assert "SENTINEL_MUST_NOT_LEAK" not in output
    assert "SENTINEL_NESTED_API_KEY" not in output
    assert "SENTINEL_QUERY_TOKEN" not in output
    assert (
        "https://metadata.example.invalid/config/SENTINEL_MUST_NOT_LEAK/manifest.json"
        not in output
    )
    assert "https://metadata.example.invalid/<redacted>#" in output


def test_url_fingerprint_is_keyed_and_stable() -> None:
    url = "https://example.invalid/private/SENTINEL_MUST_NOT_LEAK?token=x"
    first = redact_url(url, b"a" * 32)
    second = redact_url(url, b"b" * 32)
    assert first != second
    assert first.startswith("https://example.invalid/<redacted>#")
    assert "SENTINEL_MUST_NOT_LEAK" not in first
    assert len(display_fingerprint(url, b"a" * 32)) == 12


def test_exception_sanitizer_does_not_leak_url_or_sentinel() -> None:
    error = RuntimeError(
        "request failed for https://example.invalid/SENTINEL_MUST_NOT_LEAK?token=SENTINEL_TOKEN "
        "password=SENTINEL_PASSWORD"
    )
    message = sanitize_exception(error)
    assert "SENTINEL_" not in message
    assert "https://example.invalid/SENTINEL_MUST_NOT_LEAK" not in message
    assert "password=SENTINEL_PASSWORD" not in message


def test_typed_errors_have_stable_exit_codes() -> None:
    assert ConfigurationError("bad").exit_code == 2
    assert ValidationError("bad").exit_code == 2
    assert SecurityError("bad").exit_code == 2
