from __future__ import annotations

from pathlib import Path

import pytest

from stremioctl.account import (
    AUTH_ENV,
    INSECURE_LOOPBACK_ENV,
    AccountConfig,
    PulledCollection,
    build_snapshot,
    resolve_auth_key,
)
from stremioctl.errors import AuthenticationError, SecurityError, ValidationError
from stremioctl.fingerprints import collection_fingerprint

# --- AccountConfig ---


def test_default_config_targets_https_api() -> None:
    cfg = AccountConfig()
    assert cfg.base_url == "https://api.strem.io"
    assert cfg.collection_get_url == "https://api.strem.io/api/addonCollectionGet"


def test_custom_https_base_url_is_accepted() -> None:
    cfg = AccountConfig(base_url="https://api.example.test")
    assert cfg.collection_get_url == "https://api.example.test/api/addonCollectionGet"


def test_http_base_url_is_rejected_by_default() -> None:
    with pytest.raises(ValidationError):
        AccountConfig(base_url="http://api.example.test")


def test_http_loopback_needs_the_insecure_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_LOOPBACK_ENV, raising=False)
    with pytest.raises(ValidationError):
        AccountConfig(base_url="http://127.0.0.1:8000")
    monkeypatch.setenv(INSECURE_LOOPBACK_ENV, "1")
    AccountConfig(base_url="http://127.0.0.1:8000")  # now allowed


def test_http_non_loopback_stays_rejected_even_with_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(INSECURE_LOOPBACK_ENV, "1")
    with pytest.raises(ValidationError):
        AccountConfig(base_url="http://10.0.0.5:8000")


def test_non_http_scheme_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AccountConfig(base_url="ftp://api.strem.io")


@pytest.mark.parametrize("timeout", [0.5, 121, 999])
def test_out_of_range_timeout_is_rejected(timeout: float) -> None:
    with pytest.raises(ValidationError):
        AccountConfig(timeout=timeout)


# --- resolve_auth_key ---


def test_auth_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUTH_ENV, "  key-from-env  ")
    assert resolve_auth_key() == "key-from-env"


def test_missing_auth_key_is_exit_4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUTH_ENV, raising=False)
    with pytest.raises(AuthenticationError):
        resolve_auth_key()


def test_auth_key_from_strict_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUTH_ENV, raising=False)
    keyfile = tmp_path / "auth.key"
    keyfile.write_text("file-key\n")
    keyfile.chmod(0o600)
    assert resolve_auth_key(auth_key_file=keyfile) == "file-key"


def test_both_sources_set_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUTH_ENV, "env-key")
    keyfile = tmp_path / "auth.key"
    keyfile.write_text("file-key")
    keyfile.chmod(0o600)
    with pytest.raises(ValidationError):
        resolve_auth_key(auth_key_file=keyfile)


def test_group_readable_key_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(AUTH_ENV, raising=False)
    keyfile = tmp_path / "auth.key"
    keyfile.write_text("file-key")
    keyfile.chmod(0o640)
    with pytest.raises(SecurityError):
        resolve_auth_key(auth_key_file=keyfile)


def test_symlinked_key_file_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUTH_ENV, raising=False)
    real = tmp_path / "real.key"
    real.write_text("k")
    real.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(real)
    with pytest.raises(SecurityError):
        resolve_auth_key(auth_key_file=link)


def test_empty_key_file_is_exit_4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUTH_ENV, raising=False)
    keyfile = tmp_path / "auth.key"
    keyfile.write_text("   \n")
    keyfile.chmod(0o600)
    with pytest.raises(AuthenticationError):
        resolve_auth_key(auth_key_file=keyfile)


# --- build_snapshot ---


def test_snapshot_carries_raw_collection_and_matching_fingerprint() -> None:
    addons = [
        {"manifest": {"id": "a"}, "transportUrl": "https://a.invalid/manifest.json"},
        {"manifest": {"id": "b"}, "transportUrl": "https://b.invalid/manifest.json"},
    ]
    pulled = PulledCollection(
        addons=addons,
        last_modified="2026-09-06T00:00:00Z",
        fingerprint=collection_fingerprint(addons),
        base_url="https://api.strem.io",
    )
    snap = build_snapshot(pulled, pulled_at="2026-09-06T12:00:00Z")
    assert snap["artifact"] == "account-snapshot"
    assert snap["collection"] == addons  # verbatim, not redacted
    assert snap["collectionFingerprint"] == collection_fingerprint(addons)
    assert len(snap["collectionFingerprint"]) == 64
