from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from _helpers import SENTINELS, VALID_COLLECTION, load_valid_collection
from stremioctl.cli import app
from stremioctl.schemas import iter_schema_errors

runner = CliRunner()


def _outputs(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    try:
        stderr = getattr(result, "stderr", "") or ""
    except ValueError:  # pragma: no cover - stderr always captured in this click build
        stderr = ""
    return stdout + "\n" + stderr


def _no_sentinels(result: object) -> None:
    blob = _outputs(result)
    for sentinel in SENTINELS:
        assert sentinel not in blob
    assert "SENTINEL_" not in blob


def test_version_reports_current_release() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.3.0"


def test_no_args_shows_help() -> None:
    # typer's no_args_is_help prints usage and exits 2 (a usage condition, not a crash).
    result = runner.invoke(app, [])
    assert result.exit_code == 2
    assert "Usage" in result.stdout or "Usage" in _outputs(result)


def test_backup_no_args_shows_help() -> None:
    result = runner.invoke(app, ["backup"])
    assert result.exit_code == 2
    assert "inspect" in _outputs(result)


def test_inspect_human_output_is_clean(tmp_path: Path) -> None:
    result = runner.invoke(app, ["backup", "inspect", str(VALID_COLLECTION)])
    assert result.exit_code == 0, result.stdout
    assert "8 descriptors" in result.stdout
    assert "7 https, 1 insecure" in result.stdout
    assert "/manifest.json" not in result.stdout
    _no_sentinels(result)


def test_inspect_json_matches_schema_and_counts() -> None:
    result = runner.invoke(app, ["backup", "inspect", str(VALID_COLLECTION), "--json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["descriptorCount"] == 8
    assert report["transports"] == {"https": 7, "insecure": 1, "other": 0}
    assert iter_schema_errors(report, "backup-report-v1") == []
    insecure = [f for f in report["findings"] if f["code"] == "insecure_transport"]
    assert len(insecure) == 1
    _no_sentinels(result)
    assert "/manifest.json" not in result.stdout


def test_validate_valid_fixture_exits_zero() -> None:
    result = runner.invoke(app, ["backup", "validate", str(VALID_COLLECTION), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["valid"] is True


def test_validate_invalid_collection_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "dupes.json"
    bad.write_text(
        json.dumps(
            [
                {"manifest": {"id": "dup"}, "transportUrl": "https://a.invalid/m.json"},
                {"manifest": {"id": "dup"}, "transportUrl": "https://b.invalid/m.json"},
            ]
        )
    )
    result = runner.invoke(app, ["backup", "validate", str(bad)])
    assert result.exit_code == 2
    assert "INVALID" in result.stdout


def test_malformed_json_exits_two_and_does_not_leak(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text('[{"transportUrl": "https://h.invalid/SENTINEL_MUST_NOT_LEAK" ')
    result = runner.invoke(app, ["backup", "inspect", str(broken)])
    assert result.exit_code == 2
    blob = _outputs(result)
    assert "SENTINEL" not in blob
    assert "https://h.invalid/SENTINEL_MUST_NOT_LEAK" not in blob


def test_non_array_root_inspect_exits_two(tmp_path: Path) -> None:
    doc = tmp_path / "obj.json"
    doc.write_text('{"manifest": {"id": "x"}}')
    result = runner.invoke(app, ["backup", "inspect", str(doc)])
    assert result.exit_code == 2


def test_redact_writes_private_atomic_file(tmp_path: Path) -> None:
    out = tmp_path / "redacted.json"
    result = runner.invoke(app, ["backup", "redact", str(VALID_COLLECTION), "--out", str(out)])
    assert result.exit_code == 0, _outputs(result)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    text = out.read_text()
    assert "SENTINEL" not in text
    assert "/manifest.json" not in text
    redacted = json.loads(text)
    assert len(redacted) == len(load_valid_collection())
    assert redacted[7]["manifest"]["settings"]["apiKey"] == "<redacted>"
    assert "redacted collection to" in result.stdout


def test_redact_hide_hosts_masks_transport_hostnames(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    result = runner.invoke(
        app, ["backup", "redact", str(VALID_COLLECTION), "--out", str(out), "--hide-hosts"]
    )
    assert result.exit_code == 0
    redacted = json.loads(out.read_text())
    for descriptor in redacted:
        assert descriptor["transportUrl"].startswith(("https://<host>/", "http://<host>/"))
    # a non-URL contact email is not a transport endpoint and is left intact
    assert redacted[7]["manifest"]["contactEmail"] == "fixture@example.invalid"


def test_redact_refuses_to_overwrite_input() -> None:
    result = runner.invoke(
        app, ["backup", "redact", str(VALID_COLLECTION), "--out", str(VALID_COLLECTION)]
    )
    assert result.exit_code == 2
    assert VALID_COLLECTION.read_text() == VALID_COLLECTION.read_text()  # unchanged


def test_redact_refuses_to_overwrite_any_existing_output(tmp_path: Path) -> None:
    out = tmp_path / "notes.json"
    original = '{"keep": true}\n'
    out.write_text(original)
    result = runner.invoke(app, ["backup", "redact", str(VALID_COLLECTION), "--out", str(out)])
    assert result.exit_code == 2
    assert out.read_text() == original


@pytest.mark.parametrize("command", ["inspect", "validate"])
def test_reports_never_emit_sentinels(command: str) -> None:
    result = runner.invoke(app, ["backup", command, str(VALID_COLLECTION), "--json"])
    _no_sentinels(result)


def test_redact_tolerates_a_malformed_descriptor(tmp_path: Path) -> None:
    src = tmp_path / "wonky.json"
    src.write_text(
        json.dumps(
            [
                {
                    "manifest": {"id": "a"},
                    "transportUrl": "https://a.invalid/SENTINEL_MUST_NOT_LEAK/manifest.json",
                },
                42,
            ]
        )
    )
    out = tmp_path / "out.json"
    result = runner.invoke(app, ["backup", "redact", str(src), "--out", str(out)])
    assert result.exit_code == 0, _outputs(result)
    redacted = json.loads(out.read_text())
    assert redacted[1] == 42
    assert "SENTINEL" not in out.read_text()
    assert "/manifest.json" not in out.read_text()


def test_redact_rejects_non_array_root(tmp_path: Path) -> None:
    src = tmp_path / "obj.json"
    src.write_text('{"manifest": {"id": "x"}}')
    result = runner.invoke(app, ["backup", "redact", str(src), "--out", str(tmp_path / "o.json")])
    assert result.exit_code == 2
