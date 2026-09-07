from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from _helpers import FIXTURES
from stremioctl.cli import app

runner = CliRunner()

VALID_COLLECTION = FIXTURES / "collection.synthetic.json"
CONVERGED_PROFILE = FIXTURES / "desired.synthetic.json"
CHANGES_PROFILE = FIXTURES / "desired.synthetic-changes.json"


def _outputs(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    try:
        stderr = getattr(result, "stderr", "") or ""
    except ValueError:  # pragma: no cover
        stderr = ""
    return stdout + "\n" + stderr


def _no_sentinels(*chunks: str) -> None:
    blob = "\n".join(chunks)
    assert "SENTINEL_" not in blob


# --- profile init ---


def test_profile_init_writes_private_file_without_raw_urls(tmp_path: Path) -> None:
    out = tmp_path / "profile.json"
    result = runner.invoke(
        app, ["profile", "init", "--from", str(VALID_COLLECTION), "--out", str(out)]
    )
    assert result.exit_code == 0, _outputs(result)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    text = out.read_text()
    _no_sentinels(text, _outputs(result))
    assert "example.invalid" not in text
    profile = json.loads(text)
    assert len(profile["addons"]) == 8


def test_profile_init_declare_public_includes_only_named_endpoint(tmp_path: Path) -> None:
    out = tmp_path / "profile.json"
    result = runner.invoke(
        app,
        [
            "profile",
            "init",
            "--from",
            str(VALID_COLLECTION),
            "--out",
            str(out),
            "--declare-public",
            "synthetic.catalog",
        ],
    )
    assert result.exit_code == 0, _outputs(result)
    profile = json.loads(out.read_text())
    declared = [a for a in profile["addons"] if "endpoint" in a]
    assert [a["match"]["manifestId"] for a in declared] == ["synthetic.catalog"]


def test_profile_init_refuses_to_overwrite_input(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["profile", "init", "--from", str(VALID_COLLECTION), "--out", str(VALID_COLLECTION)],
    )
    assert result.exit_code == 2


# --- profile validate ---


def test_profile_validate_accepts_the_generated_profile(tmp_path: Path) -> None:
    out = tmp_path / "profile.json"
    runner.invoke(app, ["profile", "init", "--from", str(VALID_COLLECTION), "--out", str(out)])
    result = runner.invoke(app, ["profile", "validate", str(out)])
    assert result.exit_code == 0
    assert "VALID" in result.stdout


def test_profile_validate_rejects_a_broken_profile(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schemaVersion": 1, "name": "x", "addons": [{"key": "k"}]}))
    result = runner.invoke(app, ["profile", "validate", str(bad)])
    assert result.exit_code == 2
    assert "INVALID" in result.stdout


def test_profile_validate_reports_warnings_but_stays_valid(tmp_path: Path) -> None:
    doc = {
        "schemaVersion": 1,
        "name": "x",
        "addons": [
            {
                "key": "k",
                "match": {"manifestId": "m"},
                "state": "present",
                "position": 2,
                "manage": ["state"],
            }
        ],
    }
    path = tmp_path / "warn.json"
    path.write_text(json.dumps(doc))
    result = runner.invoke(app, ["profile", "validate", str(path)])
    assert result.exit_code == 0
    assert "position_unmanaged" in result.stdout


# --- profile diff ---


def test_diff_converged_exits_zero(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "profile",
            "diff",
            "--current",
            str(VALID_COLLECTION),
            "--desired",
            str(CONVERGED_PROFILE),
        ],
    )
    assert result.exit_code == 0, _outputs(result)
    assert "no changes" in result.stdout


def test_diff_with_changes_exits_ten_and_writes_private_plan(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    result = runner.invoke(
        app,
        [
            "profile",
            "diff",
            "--current",
            str(VALID_COLLECTION),
            "--desired",
            str(CHANGES_PROFILE),
            "--out-plan",
            str(plan_path),
        ],
    )
    assert result.exit_code == 10, _outputs(result)
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o600
    text = plan_path.read_text()
    _no_sentinels(text, _outputs(result))
    assert "/manifest.json" not in text
    from stremioctl.schemas import iter_schema_errors

    assert iter_schema_errors(json.loads(text), "change-plan-v1") == []


def test_diff_is_byte_identical_across_runs_except_created_at(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    for target in (first, second):
        result = runner.invoke(
            app,
            [
                "profile",
                "diff",
                "--current",
                str(VALID_COLLECTION),
                "--desired",
                str(CHANGES_PROFILE),
                "--out-plan",
                str(target),
            ],
        )
        assert result.exit_code == 10, _outputs(result)

    a = json.loads(first.read_text())
    b = json.loads(second.read_text())
    assert a["planHash"] == b["planHash"]
    a.pop("createdAt")
    b.pop("createdAt")
    assert a == b


def test_diff_ambiguous_selector_exits_two_with_actionable_message() -> None:
    result = runner.invoke(
        app,
        [
            "profile",
            "diff",
            "--current",
            str(FIXTURES / "collection.synthetic-dupes.json"),
            "--desired",
            str(FIXTURES / "desired.synthetic-ambiguous.json"),
        ],
    )
    assert result.exit_code == 2
    assert "transportFingerprint" in _outputs(result)


def test_diff_does_not_resolve_secret_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "STREMIOCTL_LEAKTEST_URL", "https://leak.invalid/SENTINEL_MUST_NOT_LEAK/manifest.json"
    )
    profile = {
        "schemaVersion": 1,
        "name": "leak",
        "addons": [
            {
                "key": "catalog",
                "match": {"manifestId": "synthetic.catalog"},
                "state": "present",
                "endpoint": {"secretRef": "env:STREMIOCTL_LEAKTEST_URL"},
                "manage": ["state", "endpoint"],
            }
        ],
    }
    profile_path = tmp_path / "leak.json"
    profile_path.write_text(json.dumps(profile))
    plan_path = tmp_path / "plan.json"
    result = runner.invoke(
        app,
        [
            "profile",
            "diff",
            "--current",
            str(VALID_COLLECTION),
            "--desired",
            str(profile_path),
            "--out-plan",
            str(plan_path),
        ],
    )
    assert result.exit_code == 10, _outputs(result)
    blob = plan_path.read_text() + _outputs(result)
    assert "SENTINEL_MUST_NOT_LEAK" not in blob
    assert "leak.invalid" not in blob
    plan = json.loads(plan_path.read_text())
    repl = [op for op in plan["operations"] if op["op"] == "replaceEndpoint"]
    assert repl[0]["endpointRef"] == "env:STREMIOCTL_LEAKTEST_URL"


def test_diff_out_plan_refuses_to_overwrite_an_input(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "profile",
            "diff",
            "--current",
            str(VALID_COLLECTION),
            "--desired",
            str(CHANGES_PROFILE),
            "--out-plan",
            str(CHANGES_PROFILE),
        ],
    )
    assert result.exit_code == 2


def _diff_to(target: Path) -> object:
    return runner.invoke(
        app,
        [
            "profile",
            "diff",
            "--current",
            str(VALID_COLLECTION),
            "--desired",
            str(CHANGES_PROFILE),
            "--out-plan",
            str(target),
        ],
    )


def test_diff_out_plan_refuses_to_overwrite_an_unrelated_file(tmp_path: Path) -> None:
    victim = tmp_path / "notes.json"
    victim.write_text('{"important": "hand-written"}')
    result = _diff_to(victim)
    assert result.exit_code == 2
    assert victim.read_text() == '{"important": "hand-written"}'  # untouched


def test_diff_out_plan_may_refresh_an_existing_plan(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    assert _diff_to(plan_path).exit_code == 10
    # re-running over the plan it just wrote is allowed
    assert _diff_to(plan_path).exit_code == 10


def test_profile_init_refuses_to_overwrite_an_unrelated_file(tmp_path: Path) -> None:
    victim = tmp_path / "keep.json"
    victim.write_text('["not a profile"]')
    result = runner.invoke(
        app, ["profile", "init", "--from", str(VALID_COLLECTION), "--out", str(victim)]
    )
    assert result.exit_code == 2
    assert victim.read_text() == '["not a profile"]'
