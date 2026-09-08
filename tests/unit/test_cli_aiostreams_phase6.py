"""Phase 6 CLI tests with no public network access."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from _helpers import FIXTURES
from stremioctl.account import PulledCollection
from stremioctl.cli import app
from stremioctl.fingerprints import collection_fingerprint

runner = CliRunner()
FIXTURE = FIXTURES / "aiostreams.synthetic.json"
SENTINEL = "SENTINEL_MUST_NOT_LEAK"
PRIMARY = "https://primary.example.invalid/config/manifest.json"
STANDBY = "https://standby.example.invalid/config/manifest.json"
MANIFEST_ID = "com.example.aiostreams.primary"
STANDBY_MANIFEST_ID = "com.example.aiostreams.standby"


def _output(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    try:
        stderr = getattr(result, "stderr", "") or ""
    except ValueError:  # pragma: no cover
        stderr = ""
    return stdout + stderr


def _promotion_profile(tmp_path: Path) -> Path:
    path = tmp_path / "desired.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "name": "promotion",
                "addons": [],
                "aiostreamsPromotion": {
                    "manifestId": MANIFEST_ID,
                    "primary": {"secretRef": "env:PHASE6_PRIMARY"},
                    "standbys": {
                        "secondary": {"secretRef": "env:PHASE6_SECONDARY"}
                    },
                },
            }
        )
    )
    return path


def _pulled() -> PulledCollection:
    addons = [
        {
            "manifest": {
                "id": MANIFEST_ID,
                "name": "AIOStreams",
                "version": "1.0.0",
                "resources": [],
                "types": [],
            },
            "transportUrl": PRIMARY,
        }
    ]
    return PulledCollection(
        addons=addons,
        last_modified=None,
        fingerprint=collection_fingerprint(addons),
        base_url="https://api.strem.io",
    )


def _standby_manifest() -> dict[str, Any]:
    return {
        "id": STANDBY_MANIFEST_ID,
        "name": "AIOStreams",
        "version": "2.34.0",
        "resources": [],
        "types": [],
    }


def test_validate_backup_reports_only_counts_and_codes() -> None:
    result = runner.invoke(app, ["aiostreams", "validate-backup", str(FIXTURE)])
    assert result.exit_code == 0, _output(result)
    assert "VALID" in result.stdout
    assert "url_review_required" in result.stdout
    assert "example.invalid" not in _output(result)


def test_validate_backup_rejects_credential_values_without_echoing_them(
    tmp_path: Path,
) -> None:
    payload = json.loads(FIXTURE.read_text())
    payload["accessKey"] = SENTINEL
    path = tmp_path / "private.json"
    path.write_text(json.dumps(payload))
    result = runner.invoke(app, ["aiostreams", "validate-backup", str(path)])
    assert result.exit_code == 2
    assert "credential_values" in result.stdout
    assert SENTINEL not in _output(result)


def test_redact_backup_writes_private_sentinel_free_copy(tmp_path: Path) -> None:
    payload = json.loads(FIXTURE.read_text())
    payload["services"][0]["credentials"] = {"apiKey": SENTINEL}
    source = tmp_path / "source.json"
    source.write_text(json.dumps(payload))
    out = tmp_path / "redacted.json"
    result = runner.invoke(
        app, ["aiostreams", "redact-backup", str(source), "--out", str(out)]
    )
    assert result.exit_code == 0, _output(result)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert SENTINEL not in out.read_text()
    assert "values masked" in result.stdout


def test_redact_backup_refuses_every_existing_output(tmp_path: Path) -> None:
    out = tmp_path / "existing.json"
    out.write_text("keep")
    result = runner.invoke(
        app, ["aiostreams", "redact-backup", str(FIXTURE), "--out", str(out)]
    )
    assert result.exit_code == 2
    assert out.read_text() == "keep"


def test_promote_writes_normal_secret_ref_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _promotion_profile(tmp_path)
    out = tmp_path / "promotion.json"
    monkeypatch.setenv("STREMIO_AUTH_KEY", SENTINEL)
    monkeypatch.setenv("PHASE6_PRIMARY", PRIMARY)
    monkeypatch.setenv("PHASE6_SECONDARY", STANDBY)
    monkeypatch.setattr("stremioctl.cli.fetch_addon_collection", lambda *_args: _pulled())
    monkeypatch.setattr(
        "stremioctl.aiostreams.probe_manifest_url",
        lambda *_args, **_kwargs: ({"status": "healthy"}, _standby_manifest()),
    )

    result = runner.invoke(
        app,
        [
            "aiostreams",
            "promote",
            "--profile",
            str(profile),
            "--standby",
            "secondary",
            "--out-plan",
            str(out),
        ],
    )
    assert result.exit_code == 10, _output(result)
    plan_text = out.read_text()
    assert SENTINEL not in plan_text + _output(result)
    assert PRIMARY not in plan_text
    assert STANDBY not in plan_text
    plan = json.loads(plan_text)
    replacement = next(op for op in plan["operations"] if op["op"] == "replaceEndpoint")
    assert replacement["endpointRef"] == "env:PHASE6_SECONDARY"
    assert replacement["targetManifestId"] == STANDBY_MANIFEST_ID
    assert STANDBY_MANIFEST_ID in result.stdout
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_unknown_standby_fails_before_auth_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _promotion_profile(tmp_path)
    out = tmp_path / "promotion.json"
    monkeypatch.delenv("STREMIO_AUTH_KEY", raising=False)

    def no_fetch(*_args: Any) -> Any:
        raise AssertionError("account pull must not run")

    monkeypatch.setattr("stremioctl.cli.fetch_addon_collection", no_fetch)
    result = runner.invoke(
        app,
        [
            "aiostreams",
            "promote",
            "--profile",
            str(profile),
            "--standby",
            "missing",
            "--out-plan",
            str(out),
        ],
    )
    assert result.exit_code == 2
    assert "unknown" in _output(result)
    assert not out.exists()
