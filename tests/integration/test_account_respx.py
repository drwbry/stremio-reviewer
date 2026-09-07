"""respx-backed contract tests for `addonCollectionGet`. No real network."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from stremioctl.account import AccountConfig, fetch_addon_collection, push_addon_collection
from stremioctl.diff import build_change_plan
from stremioctl.errors import AuthenticationError, NetworkError
from stremioctl.fingerprints import collection_fingerprint
from stremioctl.profiles import parse_profile

URL = "https://api.strem.io/api/addonCollectionGet"
SET_URL = "https://api.strem.io/api/addonCollectionSet"
SENTINEL_KEY = "SENTINEL_MUST_NOT_LEAK"

ADDONS = [
    {
        "manifest": {"id": "org.a", "name": "A", "version": "1.0.0", "resources": [], "types": []},
        "transportUrl": "https://a.example.invalid/manifest.json",
        "flags": {"official": True, "protected": False},
    },
    {
        "manifest": {"id": "org.b", "name": "B", "version": "1.0.0", "resources": [], "types": []},
        "transportUrl": "https://b.example.invalid/manifest.json",
        "flags": {"official": False, "protected": False},
    },
]


def _ok_body() -> dict[str, object]:
    return {"result": {"addons": ADDONS, "lastModified": "2026-09-06T09:00:00.000Z"}}


@respx.mock
def test_successful_pull_uses_the_exact_documented_request() -> None:
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=_ok_body()))
    pulled = fetch_addon_collection(SENTINEL_KEY, AccountConfig())

    assert route.called
    request = route.calls[0].request
    assert request.method == "POST"
    assert str(request.url) == URL
    assert "authorization" not in {k.lower() for k in request.headers}
    assert SENTINEL_KEY not in str(request.url)

    body = json.loads(request.content)
    assert body == {"type": "AddonCollectionGet", "authKey": SENTINEL_KEY, "update": True}

    assert pulled.addons == ADDONS
    assert pulled.last_modified == "2026-09-06T09:00:00.000Z"
    assert pulled.fingerprint == collection_fingerprint(ADDONS)


@respx.mock
def test_api_error_body_is_authentication_failure_with_code() -> None:
    respx.post(URL).mock(
        return_value=httpx.Response(
            200, json={"error": {"message": "Session does not exist", "code": 1}}
        )
    )
    with pytest.raises(AuthenticationError) as excinfo:
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())
    assert "code 1" in str(excinfo.value)
    assert "Session does not exist" in str(excinfo.value)
    assert SENTINEL_KEY not in str(excinfo.value)


@respx.mock
def test_http_401_is_authentication_failure() -> None:
    respx.post(URL).mock(return_value=httpx.Response(401, json={"error": {"message": "nope"}}))
    with pytest.raises(AuthenticationError):
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())


@respx.mock
def test_http_500_is_network_failure() -> None:
    respx.post(URL).mock(return_value=httpx.Response(500))
    with pytest.raises(NetworkError):
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())


@respx.mock
def test_malformed_result_is_network_failure() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json={"result": {"nope": 1}}))
    with pytest.raises(NetworkError):
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())


@respx.mock
def test_non_json_body_is_network_failure() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, content=b"<html>502</html>"))
    with pytest.raises(NetworkError):
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())


@respx.mock
def test_json_array_response_is_network_failure() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    with pytest.raises(NetworkError):
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())


@respx.mock
def test_connection_error_is_network_failure_and_sanitized() -> None:
    respx.post(URL).mock(
        side_effect=httpx.ConnectError(f"failed to connect using key {SENTINEL_KEY}")
    )
    with pytest.raises(NetworkError) as excinfo:
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())
    assert SENTINEL_KEY not in str(excinfo.value)


@respx.mock
def test_oversized_response_is_network_failure() -> None:
    huge = b'{"result": {"addons": [], "padding": "' + b"x" * (9 * 1024 * 1024) + b'"}}'
    respx.post(URL).mock(return_value=httpx.Response(200, content=huge))
    with pytest.raises(NetworkError) as excinfo:
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())
    assert "size limit" in str(excinfo.value)


@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={"error": {"message": SENTINEL_KEY, "code": 2}}),
        httpx.Response(200, json={"result": {"nope": 1}}),
        httpx.Response(503),
        httpx.Response(200, content=b"not json"),
    ],
)
def test_no_failure_mode_leaks_the_auth_key(response: httpx.Response) -> None:
    respx.post(URL).mock(return_value=response)
    with pytest.raises((AuthenticationError, NetworkError)) as excinfo:
        fetch_addon_collection(SENTINEL_KEY, AccountConfig())
    assert SENTINEL_KEY not in str(excinfo.value)


@respx.mock
def test_snapshot_and_plan_fingerprints_agree() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json=_ok_body()))
    pulled = fetch_addon_collection(SENTINEL_KEY, AccountConfig())

    profile, _ = parse_profile({"schemaVersion": 1, "name": "t", "addons": []})
    plan = build_change_plan(
        current=pulled.addons,
        profile=profile,
        key=b"k" * 32,
        created_at="2026-09-06T00:00:00Z",
    )
    assert plan["baseCollectionFingerprint"] == pulled.fingerprint


@respx.mock
def test_custom_base_url_is_honoured() -> None:
    custom = "https://api.example.test/api/addonCollectionGet"
    route = respx.post(custom).mock(return_value=httpx.Response(200, json=_ok_body()))
    fetch_addon_collection(SENTINEL_KEY, AccountConfig(base_url="https://api.example.test"))
    assert route.called


# --- addonCollectionSet (Phase 5) -----------------------------------------


@respx.mock
def test_push_sends_the_exact_documented_request() -> None:
    route = respx.post(SET_URL).mock(
        return_value=httpx.Response(200, json={"result": {"success": True}})
    )
    push_addon_collection(SENTINEL_KEY, ADDONS, AccountConfig())

    request = route.calls[0].request
    assert request.method == "POST"
    assert str(request.url) == SET_URL
    assert "authorization" not in {k.lower() for k in request.headers}
    body = json.loads(request.content)
    assert body == {"type": "AddonCollectionSet", "authKey": SENTINEL_KEY, "addons": ADDONS}


@respx.mock
def test_push_without_success_true_is_a_network_failure() -> None:
    respx.post(SET_URL).mock(return_value=httpx.Response(200, json={"result": {"success": False}}))
    with pytest.raises(NetworkError, match="did not confirm"):
        push_addon_collection(SENTINEL_KEY, ADDONS, AccountConfig())


@respx.mock
def test_push_error_body_is_authentication_failure() -> None:
    respx.post(SET_URL).mock(
        return_value=httpx.Response(200, json={"error": {"message": "no session", "code": 1}})
    )
    with pytest.raises(AuthenticationError):
        push_addon_collection(SENTINEL_KEY, ADDONS, AccountConfig())


@respx.mock
def test_push_http_403_is_authentication_failure() -> None:
    respx.post(SET_URL).mock(return_value=httpx.Response(403))
    with pytest.raises(AuthenticationError):
        push_addon_collection(SENTINEL_KEY, ADDONS, AccountConfig())


@respx.mock
def test_push_connection_error_is_sanitized_network_failure() -> None:
    respx.post(SET_URL).mock(
        side_effect=httpx.ConnectError(f"boom with key {SENTINEL_KEY}")
    )
    with pytest.raises(NetworkError) as excinfo:
        push_addon_collection(SENTINEL_KEY, ADDONS, AccountConfig())
    assert SENTINEL_KEY not in str(excinfo.value)
