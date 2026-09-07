"""Phase 5 CLI tests for `account apply` and `account rollback`."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from stremioctl.cli import app
from stremioctl.fingerprints import collection_fingerprint

runner = CliRunner()
GET_URL = "https://api.strem.io/api/addonCollectionGet"
SET_URL = "https://api.strem.io/api/addonCollectionSet"
SENTINEL_KEY = "SENTINEL_MUST_NOT_LEAK"


def _url(mid: str) -> str:
    return f"https://{mid.replace('.', '-')}.example.invalid/manifest.json"


def _desc(mid: str) -> dict[str, Any]:
    return {
        "manifest": {"id": mid, "name": mid, "version": "1.0.0", "resources": [], "types": []},
        "transportUrl": _url(mid),
        "flags": {"official": False, "protected": False},
    }


ABC = [_desc("org.a"), _desc("org.b"), _desc("org.c")]
AC = [ABC[0], ABC[2]]

REMOVE_B = {
    "schemaVersion": 1,
    "name": "t",
    "addons": [
        {"key": "b", "match": {"manifestId": "org.b"}, "state": "absent", "manage": ["state"]}
    ],
}


def _outputs(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    try:
        stderr = getattr(result, "stderr", "") or ""
    except ValueError:  # pragma: no cover
        stderr = ""
    return stdout + "\n" + stderr


def _get(addons: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(
        200, json={"result": {"addons": addons, "lastModified": "2026-09-06T00:00:00Z"}}
    )


def _set_ok() -> httpx.Response:
    return httpx.Response(200, json={"result": {"success": True}})


@pytest.fixture
def env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STREMIO_AUTH_KEY", SENTINEL_KEY)


def _real_plan(tmp_path: Path) -> tuple[Path, str]:
    """Build a plan with the CLI's own redaction key so the confirm hash lines up."""
    from stremioctl.diff import build_change_plan
    from stremioctl.privacy import load_or_create_redaction_key
    from stremioctl.profiles import parse_profile

    key = load_or_create_redaction_key()
    profile, warnings = parse_profile(REMOVE_B)
    plan = build_change_plan(
        current=ABC,
        profile=profile,
        key=key,
        created_at="2026-09-06T00:00:00Z",
        profile_warnings=[w.message for w in warnings],
    )
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    return path, plan["planHash"]


@respx.mock
def test_apply_happy_path_exits_zero_and_writes_a_private_snapshot(
    tmp_path: Path, env_key: None
) -> None:
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(AC)])
    respx.post(SET_URL).mock(side_effect=[_set_ok()])
    plan_path, plan_hash = _real_plan(tmp_path)

    result = runner.invoke(app, ["account", "apply", str(plan_path), "--confirm", plan_hash])
    assert result.exit_code == 0, _outputs(result)
    assert SENTINEL_KEY not in _outputs(result)

    from stremioctl.io import private_app_path

    snaps = list((private_app_path() / "snapshots").glob("pre-apply-*.json"))
    assert len(snaps) == 1
    assert stat.S_IMODE(snaps[0].stat().st_mode) == 0o600


@respx.mock
def test_apply_with_a_wrong_confirm_exits_2_and_makes_no_request(
    tmp_path: Path, env_key: None
) -> None:
    get = respx.post(GET_URL).mock(side_effect=[_get(ABC)])
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])
    plan_path, _ = _real_plan(tmp_path)

    result = runner.invoke(app, ["account", "apply", str(plan_path), "--confirm", "nope"])
    assert result.exit_code == 2
    assert get.call_count == 0
    assert set_.call_count == 0


@respx.mock
def test_apply_on_a_stale_plan_exits_5(tmp_path: Path, env_key: None) -> None:
    respx.post(GET_URL).mock(side_effect=[_get(AC)])  # account already moved on
    set_ = respx.post(SET_URL).mock(side_effect=[_set_ok()])
    plan_path, plan_hash = _real_plan(tmp_path)

    result = runner.invoke(app, ["account", "apply", str(plan_path), "--confirm", plan_hash])
    assert result.exit_code == 5
    assert set_.call_count == 0


@respx.mock
def test_apply_verification_mismatch_exits_6_and_reports_rollback(
    tmp_path: Path, env_key: None
) -> None:
    junk = [_desc("org.a")]
    respx.post(GET_URL).mock(side_effect=[_get(ABC), _get(junk), _get(ABC)])
    respx.post(SET_URL).mock(side_effect=[_set_ok(), _set_ok()])
    plan_path, plan_hash = _real_plan(tmp_path)

    result = runner.invoke(app, ["account", "apply", str(plan_path), "--confirm", plan_hash])
    assert result.exit_code == 6, _outputs(result)
    assert "rollback" in _outputs(result)
    assert "restored" in _outputs(result)


@respx.mock
def test_rollback_happy_path_exits_zero(tmp_path: Path, env_key: None) -> None:
    snapshot = {
        "schemaVersion": 1,
        "artifact": "account-snapshot",
        "pulledAt": "2026-09-06T00:00:00Z",
        "collectionFingerprint": collection_fingerprint(ABC),
        "collection": ABC,
    }
    snap_path = tmp_path / "snap.json"
    snap_path.write_text(json.dumps(snapshot))
    respx.post(GET_URL).mock(side_effect=[_get(AC), _get(ABC)])
    respx.post(SET_URL).mock(side_effect=[_set_ok()])

    result = runner.invoke(
        app,
        ["account", "rollback", str(snap_path), "--confirm", collection_fingerprint(ABC)],
    )
    assert result.exit_code == 0, _outputs(result)
    assert SENTINEL_KEY not in _outputs(result)


def test_rollback_checks_the_private_dir_before_reading_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No auth key configured: if the snapshot-dir check ran after key resolution
    # this would exit 4. A symlinked data dir must be refused first (exit 2).
    monkeypatch.delenv("STREMIO_AUTH_KEY", raising=False)
    real = tmp_path / "real_data"
    real.mkdir()
    linked = tmp_path / "linked_data"
    linked.symlink_to(real)
    monkeypatch.setenv("STREMIOCTL_DATA_DIR", str(linked))

    snapshot = {
        "schemaVersion": 1,
        "artifact": "account-snapshot",
        "pulledAt": "2026-09-06T00:00:00Z",
        "collectionFingerprint": collection_fingerprint(ABC),
        "collection": ABC,
    }
    snap_path = tmp_path / "snap.json"
    snap_path.write_text(json.dumps(snapshot))

    result = runner.invoke(
        app, ["account", "rollback", str(snap_path), "--confirm", collection_fingerprint(ABC)]
    )
    assert result.exit_code == 2


@respx.mock
def test_rollback_with_a_wrong_confirm_exits_2(tmp_path: Path, env_key: None) -> None:
    snapshot = {
        "schemaVersion": 1,
        "artifact": "account-snapshot",
        "pulledAt": "2026-09-06T00:00:00Z",
        "collectionFingerprint": collection_fingerprint(ABC),
        "collection": ABC,
    }
    snap_path = tmp_path / "snap.json"
    snap_path.write_text(json.dumps(snapshot))
    get = respx.post(GET_URL).mock(side_effect=[_get(AC)])

    result = runner.invoke(
        app, ["account", "rollback", str(snap_path), "--confirm", "0" * 64]
    )
    assert result.exit_code == 2
    assert get.call_count == 0


def test_apply_and_rollback_help_have_no_raw_key_option() -> None:
    for cmd, needle in (("apply", "--confirm"), ("rollback", "--confirm")):
        result = runner.invoke(app, ["account", cmd, "--help"])
        text = _outputs(result)
        assert needle in text
        assert "--auth-key-file" in text
        assert "--auth-key " not in text
