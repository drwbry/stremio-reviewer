"""Phase 6 promotion tests through the real bounded probe engine."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from stremioctl.aiostreams import build_promotion_plan
from stremioctl.errors import NetworkError
from stremioctl.profiles import parse_profile

KEY = b"k" * 32
MANIFEST_ID = "com.example.aiostreams.primary"
STANDBY_MANIFEST_ID = "com.example.aiostreams.standby"
PRIMARY = "https://primary.example.invalid/config/manifest.json"
STANDBY = "https://standby.example.invalid/config/manifest.json"
PUBLIC_RESOLVER = lambda _host, _port: ["93.184.216.34"]  # noqa: E731


def _profile() -> Any:
    parsed, _ = parse_profile(
        {
            "schemaVersion": 1,
            "name": "promotion",
            "addons": [],
            "aiostreamsPromotion": {
                "manifestId": MANIFEST_ID,
                "primary": {"secretRef": "env:PRIMARY"},
                "standbys": {"secondary": {"secretRef": "env:SECONDARY"}},
            },
        }
    )
    return parsed


def _current() -> list[dict[str, Any]]:
    return [
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


def _resolve(ref: str) -> str:
    return PRIMARY if ref == "env:PRIMARY" else STANDBY


def _manifest(manifest_id: str = STANDBY_MANIFEST_ID) -> dict[str, Any]:
    return {
        "id": manifest_id,
        "name": "AIOStreams",
        "version": "2.34.0",
        "resources": [],
        "types": [],
    }


def _build() -> dict[str, Any]:
    return build_promotion_plan(
        current=_current(),
        profile=_profile(),
        standby_key="secondary",
        key=KEY,
        created_at="2026-09-07T00:00:00Z",
        resolver=_resolve,
        probe_resolver=PUBLIC_RESOLVER,
    )


@respx.mock
def test_healthy_standby_creates_a_promotion_plan() -> None:
    route = respx.get(STANDBY).mock(return_value=httpx.Response(200, json=_manifest()))
    plan = _build()
    assert route.call_count == 1
    replacement = next(op for op in plan["operations"] if op["op"] == "replaceEndpoint")
    assert replacement["targetManifestId"] == STANDBY_MANIFEST_ID


@respx.mock
def test_non_json_content_type_warning_is_still_usable() -> None:
    respx.get(STANDBY).mock(
        return_value=httpx.Response(
            200, headers={"content-type": "text/plain"}, json=_manifest()
        )
    )
    assert _build()["operations"]


@respx.mock
def test_missing_standby_identity_blocks_promotion() -> None:
    manifest = _manifest()
    del manifest["id"]
    respx.get(STANDBY).mock(return_value=httpx.Response(200, json=manifest))
    with pytest.raises(NetworkError, match="invalid_manifest"):
        _build()


@respx.mock
def test_invalid_json_blocks_promotion() -> None:
    respx.get(STANDBY).mock(return_value=httpx.Response(200, content=b"not-json"))
    with pytest.raises(NetworkError, match="invalid_manifest"):
        _build()


def test_private_destination_is_blocked_before_request() -> None:
    def private_ref(ref: str) -> str:
        return PRIMARY if ref == "env:PRIMARY" else "https://127.0.0.1/manifest.json"

    with pytest.raises(NetworkError, match="blocked_destination"):
        build_promotion_plan(
            current=_current(),
            profile=_profile(),
            standby_key="secondary",
            key=KEY,
            created_at="2026-09-07T00:00:00Z",
            resolver=private_ref,
        )
