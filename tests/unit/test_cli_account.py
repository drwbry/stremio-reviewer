from __future__ import annotations

import json
import stat
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from _helpers import FIXTURES
from stremioctl.cli import app
from stremioctl.schemas import iter_schema_errors

runner = CliRunner()
URL = "https://api.strem.io/api/addonCollectionGet"
SENTINEL_KEY = "SENTINEL_MUST_NOT_LEAK"

ADDONS = [
    {
        "manifest": {"id": "org.a", "name": "A", "version": "1.0.0", "resources": [], "types": []},
        "transportUrl": "https://a.example.invalid/config/SECRETPATH/manifest.json",
        "flags": {"official": False, "protected": False},
    }
]


def _outputs(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    try:
        stderr = getattr(result, "stderr", "") or ""
    except ValueError:  # pragma: no cover
        stderr = ""
    return stdout + "\n" + stderr


def _ok() -> httpx.Response:
    return httpx.Response(
        200, json={"result": {"addons": ADDONS, "lastModified": "2026-09-06T00:00:00Z"}}
    )


@pytest.fixture
def env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STREMIO_AUTH_KEY", SENTINEL_KEY)


# --- account pull ---


@respx.mock
def test_account_pull_writes_private_0600_snapshot(tmp_path: Path, env_key: None) -> None:
    respx.post(URL).mock(return_value=_ok())
    out = tmp_path / "private" / "snapshot.json"  # parent created 0700 by the tool
    result = runner.invoke(app, ["account", "pull", "--out", str(out)])
    assert result.exit_code == 0, _outputs(result)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert stat.S_IMODE(out.parent.stat().st_mode) == 0o700
    snapshot = json.loads(out.read_text())
    assert iter_schema_errors(snapshot, "account-snapshot-v1") == []
    assert snapshot["collection"] == ADDONS  # raw, not redacted
    # the auth key never appears in what the user sees
    assert SENTINEL_KEY not in _outputs(result)


def test_account_pull_refuses_a_world_readable_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # no auth key configured: the output-path check must fire first, before the
    # key is resolved or the network is touched.
    monkeypatch.delenv("STREMIO_AUTH_KEY", raising=False)
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    result = runner.invoke(app, ["account", "pull", "--out", str(shared / "snap.json")])
    assert result.exit_code == 2
    assert "STREMIOCTL_DATA_DIR" in _outputs(result)


def test_account_pull_without_a_key_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("STREMIO_AUTH_KEY", raising=False)
    result = runner.invoke(app, ["account", "pull", "--out", str(tmp_path / "p" / "s.json")])
    assert result.exit_code == 4


@respx.mock
def test_account_pull_rejects_overwriting_a_non_snapshot(tmp_path: Path, env_key: None) -> None:
    respx.post(URL).mock(return_value=_ok())
    victim = tmp_path / "notes.json"
    victim.write_text('{"hand": "written"}')
    result = runner.invoke(app, ["account", "pull", "--out", str(victim)])
    assert result.exit_code == 2
    assert victim.read_text() == '{"hand": "written"}'


@respx.mock
def test_account_pull_may_refresh_its_own_snapshot(tmp_path: Path, env_key: None) -> None:
    respx.post(URL).mock(return_value=_ok())
    out = tmp_path / "p" / "s.json"
    assert runner.invoke(app, ["account", "pull", "--out", str(out)]).exit_code == 0
    assert runner.invoke(app, ["account", "pull", "--out", str(out)]).exit_code == 0


@respx.mock
def test_account_pull_auth_rejection_exits_4_without_leaking(tmp_path: Path, env_key: None) -> None:
    respx.post(URL).mock(
        return_value=httpx.Response(200, json={"error": {"message": "bad session", "code": 1}})
    )
    result = runner.invoke(app, ["account", "pull", "--out", str(tmp_path / "p" / "s.json")])
    assert result.exit_code == 4
    assert SENTINEL_KEY not in _outputs(result)
    assert "bad session" in _outputs(result)


def test_account_pull_rejects_http_base_url(tmp_path: Path, env_key: None) -> None:
    result = runner.invoke(
        app,
        ["account", "pull", "--out", str(tmp_path / "p" / "s.json"), "--base-url", "http://evil.test"],
    )
    assert result.exit_code == 2


# --- account plan ---


@respx.mock
def test_account_plan_converged_exits_zero(tmp_path: Path, env_key: None) -> None:
    respx.post(URL).mock(return_value=_ok())
    plan_out = tmp_path / "plan.json"
    result = runner.invoke(
        app,
        [
            "account",
            "plan",
            "--desired",
            str(FIXTURES / "desired.synthetic.json"),
            "--out",
            str(plan_out),
        ],
    )
    assert result.exit_code == 0, _outputs(result)
    plan = json.loads(plan_out.read_text())
    assert iter_schema_errors(plan, "change-plan-v1") == []
    assert plan["operations"] == []


@respx.mock
def test_account_plan_with_changes_exits_ten_and_is_redacted(tmp_path: Path, env_key: None) -> None:
    respx.post(URL).mock(return_value=_ok())
    desired = tmp_path / "desired.json"
    desired.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "name": "t",
                "addons": [
                    {
                        "key": "a",
                        "match": {"manifestId": "org.a"},
                        "state": "absent",
                        "manage": ["state"],
                    }
                ],
            }
        )
    )
    plan_out = tmp_path / "plan.json"
    result = runner.invoke(
        app, ["account", "plan", "--desired", str(desired), "--out", str(plan_out)]
    )
    assert result.exit_code == 10, _outputs(result)
    text = plan_out.read_text()
    assert "SECRETPATH" not in text  # transport path is redacted in the plan
    assert "/config/" not in text
    assert SENTINEL_KEY not in _outputs(result)


@respx.mock
def test_account_plan_auth_rejection_exits_4(tmp_path: Path, env_key: None) -> None:
    respx.post(URL).mock(return_value=httpx.Response(403))
    result = runner.invoke(
        app,
        [
            "account",
            "plan",
            "--desired",
            str(FIXTURES / "desired.synthetic.json"),
            "--out",
            str(tmp_path / "plan.json"),
        ],
    )
    assert result.exit_code == 4
    assert SENTINEL_KEY not in _outputs(result)


def test_account_help_has_no_auth_key_value_option() -> None:
    for cmd in ("pull", "plan"):
        result = runner.invoke(app, ["account", cmd, "--help"])
        text = _outputs(result)
        assert "--auth-key-file" in text
        assert "--auth-key " not in text  # never a raw value option
        assert "--base-url" in text
