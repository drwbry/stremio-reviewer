from __future__ import annotations

import json
from typing import Any

import httpx
import respx
from typer.testing import CliRunner

import stremioctl.probing as probing
from _helpers import FIXTURES
from stremioctl.cli import app
from stremioctl.schemas import iter_schema_errors

runner = CliRunner()
VALID_COLLECTION = FIXTURES / "collection.synthetic.json"


def _offline_resolver(host: str, port: int) -> list[str]:
    raise OSError("offline")


def _outputs(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    try:
        stderr = getattr(result, "stderr", "") or ""
    except ValueError:  # pragma: no cover
        stderr = ""
    return stdout + "\n" + stderr


def _manifest(addon_id: str) -> dict[str, Any]:
    return {"id": addon_id, "name": "M", "version": "1", "resources": [], "types": []}


def test_probe_help_lists_only_documented_options() -> None:
    result = runner.invoke(app, ["probe", "collection", "--help"])
    assert result.exit_code == 0
    text = _outputs(result)
    assert "--json" in text
    assert "--allow-private-network" in text
    assert "--timeout" not in text  # not in the SPEC section 9 contract
    assert "--concurrency" not in text


def test_probe_synthetic_fixture_offline_is_all_unreachable(monkeypatch: Any) -> None:
    # force DNS failure so the test is hermetic; nothing is contacted.
    monkeypatch.setattr(probing, "_default_resolver", _offline_resolver)
    result = runner.invoke(app, ["probe", "collection", str(VALID_COLLECTION), "--json"])
    assert result.exit_code == 3, _outputs(result)
    report = json.loads(result.stdout)
    assert iter_schema_errors(report, "audit-report-v1") == []
    assert {e["status"] for e in report["entries"]} == {"unreachable"}
    assert "SENTINEL_" not in result.stdout
    assert "/manifest.json" not in result.stdout


@respx.mock
def test_probe_all_healthy_exits_zero(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(probing, "_default_resolver", lambda h, p: ["93.184.216.34"])
    collection = [
        {
            "manifest": {"id": f"a.{i}", "name": "n", "version": "1", "resources": [], "types": []},
            "transportUrl": f"https://a{i}.test/manifest.json",
        }
        for i in range(3)
    ]
    for i in range(3):
        respx.get(f"https://a{i}.test/manifest.json").mock(
            return_value=httpx.Response(200, json=_manifest(f"a.{i}"))
        )
    path = tmp_path / "c.json"
    path.write_text(json.dumps(collection))
    result = runner.invoke(app, ["probe", "collection", str(path), "--json"])
    assert result.exit_code == 0, _outputs(result)
    report = json.loads(result.stdout)
    assert {e["status"] for e in report["entries"]} == {"healthy"}


def test_probe_human_output_is_redacted(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(probing, "_default_resolver", _offline_resolver)
    collection = [
        {
            "manifest": {"id": "a.0", "name": "n", "version": "1", "resources": [], "types": []},
            "transportUrl": "https://host.example.invalid/config/SENTINEL_MUST_NOT_LEAK/manifest.json",
        }
    ]
    path = tmp_path / "c.json"
    path.write_text(json.dumps(collection))
    result = runner.invoke(app, ["probe", "collection", str(path)])
    assert result.exit_code == 3
    blob = _outputs(result)
    assert "SENTINEL_MUST_NOT_LEAK" not in blob
    assert "/config/" not in blob


def test_probe_rejects_non_array_root(tmp_path: Any) -> None:
    path = tmp_path / "obj.json"
    path.write_text('{"manifest": {"id": "x"}}')
    result = runner.invoke(app, ["probe", "collection", str(path)])
    assert result.exit_code == 2
