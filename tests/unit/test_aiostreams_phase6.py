"""Phase 6 native-backup and promotion unit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from _helpers import FIXTURES
from stremioctl.aiostreams import (
    build_promotion_plan,
    check_backup,
    parse_backup,
    redact_backup,
)
from stremioctl.apply import construct_target
from stremioctl.errors import NetworkError, ValidationError
from stremioctl.models import parse_collection
from stremioctl.profiles import parse_profile
from stremioctl.schemas import iter_schema_errors

KEY = b"k" * 32
SENTINEL = "SENTINEL_MUST_NOT_LEAK"
PRIMARY = "https://primary.example.invalid/config/manifest.json"
STANDBY = "https://standby.example.invalid/config/manifest.json"
MANIFEST_ID = "com.example.aiostreams.primary"
STANDBY_MANIFEST_ID = "com.example.aiostreams.standby"


def _fixture() -> dict[str, Any]:
    return json.loads((FIXTURES / "aiostreams.synthetic.json").read_text())


def _profile_doc() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "name": "promotion",
        "addons": [],
        "policy": {
            "manifestTimeoutSeconds": 7,
            "maxConcurrentProbes": 2,
            "allowPrivateNetwork": False,
        },
        "aiostreamsPromotion": {
            "manifestId": MANIFEST_ID,
            "primary": {"secretRef": "env:PRIMARY_URL"},
            "standbys": {
                "secondary": {"secretRef": "file:/private/secondary.url"}
            },
        },
    }


def _current(url: str = PRIMARY, *, count: int = 1) -> list[dict[str, Any]]:
    manifest_id = STANDBY_MANIFEST_ID if url == STANDBY else MANIFEST_ID
    return [
        {
            "manifest": {
                "id": manifest_id,
                "name": "AIOStreams",
                "version": "1.0.0",
                "resources": [],
                "types": [],
            },
            "transportUrl": url,
        }
        for _ in range(count)
    ]


def _resolver(ref: str) -> str:
    return PRIMARY if ref == "env:PRIMARY_URL" else STANDBY


def _standby_manifest() -> dict[str, Any]:
    return {
        "id": STANDBY_MANIFEST_ID,
        "name": "AIOStreams",
        "version": "2.34.0",
        "resources": [],
        "types": [],
    }


def _probe_result(
    status: str = "healthy",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    manifest = _standby_manifest() if status in {"healthy", "warning"} else None
    return {"status": status}, manifest


def test_native_backup_round_trip_is_lossless_and_independent() -> None:
    original = _fixture()
    backup, warnings = parse_backup(original)
    rendered = backup.to_document()
    assert rendered == original
    assert warnings
    rendered["futureField"]["nested"][0] = False
    assert original["futureField"]["nested"][0] is True


@pytest.mark.parametrize(
    ("document", "code"),
    [
        ([], "invalid_root"),
        ({"metadata": {}, "config": {}}, "template_artifact"),
        ({"settings": {}, "maskedSecretKeys": []}, "dashboard_artifact"),
    ],
)
def test_wrong_backup_shapes_are_rejected(document: Any, code: str) -> None:
    assert code in {finding.code for finding in check_backup(document)}
    with pytest.raises(ValidationError):
        parse_backup(document)


def test_redaction_masks_credentials_urls_and_free_text_without_losing_shape() -> None:
    source = _fixture()
    source["accessKey"] = SENTINEL
    source["services"][0]["credentials"] = {"token": SENTINEL}
    source["proxy"] = {
        "url": f"https://proxy.example.invalid/{SENTINEL}",
        "credentials": {"password": SENTINEL},
    }
    source["presets"][0]["options"]["apiToken"] = SENTINEL
    source["presets"][0]["options"]["opaqueOption"] = SENTINEL
    source["variants"][0]["script"] = SENTINEL
    source["futureField"]["unknownUrl"] = f"https://custom.invalid/{SENTINEL}"

    redacted, changed = redact_backup(source, KEY)
    text = json.dumps(redacted)
    assert changed >= 6
    assert SENTINEL not in text
    assert "https://proxy.example.invalid/" not in text
    assert set(redacted) == set(source)
    assert redacted["futureField"]["nested"] == source["futureField"]["nested"]
    assert not any(f.code == "credential_values" for f in check_backup(redacted))


def test_sensitive_backup_is_invalid_for_sharing_but_can_still_be_redacted() -> None:
    source = _fixture()
    source["tmdbApiKey"] = SENTINEL
    findings = check_backup(source)
    assert any(f.code == "credential_values" and f.severity == "error" for f in findings)
    with pytest.raises(ValidationError):
        parse_backup(source)
    redacted, _ = redact_backup(source, KEY)
    assert SENTINEL not in json.dumps(redacted)


def test_profile_parses_promotion_contract() -> None:
    profile, warnings = parse_profile(_profile_doc())
    assert not warnings
    assert profile.aiostreams_promotion is not None
    assert profile.aiostreams_promotion.standbys["secondary"].startswith("file:")


def test_profile_rejects_duplicate_or_malformed_promotion_refs() -> None:
    duplicate = _profile_doc()
    duplicate["aiostreamsPromotion"]["standbys"]["secondary"]["secretRef"] = (
        "env:PRIMARY_URL"
    )
    with pytest.raises(ValidationError, match="duplicate_ref"):
        parse_profile(duplicate)

    malformed = _profile_doc()
    malformed["aiostreamsPromotion"]["primary"]["secretRef"] = "relative.file"
    with pytest.raises(ValidationError, match="aiostreams_secret_ref"):
        parse_profile(malformed)


def test_promotion_builds_only_secret_ref_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _ = parse_profile(_profile_doc())
    observed: dict[str, Any] = {}

    def fake_probe(
        url: str, expected_id: str | None, key: bytes, cfg: Any, **kwargs: Any
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        observed.update(
            url=url, expected_id=expected_id, key=key, cfg=cfg, kwargs=kwargs
        )
        return _probe_result()

    monkeypatch.setattr("stremioctl.aiostreams.probe_manifest_url", fake_probe)
    plan = build_promotion_plan(
        current=_current(),
        profile=profile,
        standby_key="secondary",
        key=KEY,
        created_at="2026-09-07T00:00:00Z",
        resolver=_resolver,
    )
    replacements = [op for op in plan["operations"] if op["op"] == "replaceEndpoint"]
    assert len(replacements) == 1
    assert replacements[0]["endpointRef"] == "file:/private/secondary.url"
    assert replacements[0]["targetManifestId"] == STANDBY_MANIFEST_ID
    assert len(replacements[0]["targetManifestFingerprint"]) == 64
    assert PRIMARY not in json.dumps(plan)
    assert STANDBY not in json.dumps(plan)
    assert observed["url"] == STANDBY
    assert observed["expected_id"] is None
    assert observed["cfg"].overall_timeout == 7
    assert observed["cfg"].concurrency == 2
    assert iter_schema_errors(plan, "change-plan-v1") == []
    target = construct_target(
        plan,
        list(parse_collection(_current()).descriptors),
        KEY,
        resolver=lambda _ref: STANDBY,
        target_manifest_resolver=lambda *_args: _standby_manifest(),
    )
    assert target[0]["transportUrl"] == STANDBY
    assert target[0]["manifest"]["id"] == STANDBY_MANIFEST_ID


def test_promotion_is_converged_when_standby_is_already_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _ = parse_profile(_profile_doc())
    monkeypatch.setattr(
        "stremioctl.aiostreams.probe_manifest_url",
        lambda *_args, **_kwargs: _probe_result(),
    )
    plan = build_promotion_plan(
        current=_current(STANDBY),
        profile=profile,
        standby_key="secondary",
        key=KEY,
        created_at="2026-09-07T00:00:00Z",
        resolver=_resolver,
    )
    assert plan["operations"] == []


@pytest.mark.parametrize("count", [0, 2])
def test_promotion_requires_exactly_one_installed_match(
    count: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, _ = parse_profile(_profile_doc())
    monkeypatch.setattr(
        "stremioctl.aiostreams.probe_manifest_url",
        lambda *_args, **_kwargs: _probe_result(),
    )
    with pytest.raises(ValidationError, match=f"found {count}"):
        build_promotion_plan(
            current=_current(count=count),
            profile=profile,
            standby_key="secondary",
            key=KEY,
            created_at="2026-09-07T00:00:00Z",
            resolver=_resolver,
        )


def test_promotion_rejects_equal_resolved_urls() -> None:
    profile, _ = parse_profile(_profile_doc())
    with pytest.raises(ValidationError, match="same URL"):
        build_promotion_plan(
            current=_current(),
            profile=profile,
            standby_key="secondary",
            key=KEY,
            created_at="2026-09-07T00:00:00Z",
            resolver=lambda _ref: PRIMARY,
        )


def test_promotion_rejects_unknown_key_without_resolving() -> None:
    profile, _ = parse_profile(_profile_doc())

    def must_not_resolve(_ref: str) -> str:
        raise AssertionError("resolver must not run")

    with pytest.raises(ValidationError, match="unknown"):
        build_promotion_plan(
            current=_current(),
            profile=profile,
            standby_key="missing",
            key=KEY,
            created_at="2026-09-07T00:00:00Z",
            resolver=must_not_resolve,
        )


def test_promotion_rejects_failed_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    profile, _ = parse_profile(_profile_doc())
    monkeypatch.setattr(
        "stremioctl.aiostreams.probe_manifest_url",
        lambda *_args, **_kwargs: _probe_result("identity_mismatch"),
    )
    with pytest.raises(NetworkError, match="identity_mismatch"):
        build_promotion_plan(
            current=_current(),
            profile=profile,
            standby_key="secondary",
            key=KEY,
            created_at="2026-09-07T00:00:00Z",
            resolver=_resolver,
        )


def test_promotion_rejects_unexpected_installed_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _ = parse_profile(_profile_doc())
    monkeypatch.setattr(
        "stremioctl.aiostreams.probe_manifest_url",
        lambda *_args, **_kwargs: _probe_result(),
    )
    with pytest.raises(ValidationError, match="neither"):
        build_promotion_plan(
            current=_current("https://third.example.invalid/manifest.json"),
            profile=profile,
            standby_key="secondary",
            key=KEY,
            created_at="2026-09-07T00:00:00Z",
            resolver=_resolver,
        )


def test_fixture_copy_is_not_the_private_sample() -> None:
    fixture = _fixture()
    assert "futureField" in fixture
    assert "SENTINEL_" not in json.dumps(fixture)
    assert Path(FIXTURES / "aiostreams.synthetic.json").stat().st_size < 10_000
