"""respx-backed probe integration tests. No real network is touched."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from stremioctl.errors import ValidationError
from stremioctl.probing import ProbeConfig, probe_collection
from stremioctl.schemas import iter_schema_errors

KEY = b"k" * 32
PUBLIC_RESOLVER = lambda host, port: ["93.184.216.34"]  # noqa: E731
NO_SLEEP = lambda _seconds: None  # noqa: E731
NO_JITTER = lambda: 0.0  # noqa: E731
GENERATED_AT = "2026-09-06T00:00:00Z"


def _collection(*urls: str) -> list[dict[str, Any]]:
    return [
        {
            "manifest": {
                "id": f"addon.{i}",
                "name": f"Addon {i}",
                "version": "1.0.0",
                "resources": [],
                "types": [],
            },
            "transportUrl": url,
        }
        for i, url in enumerate(urls)
    ]


def _probe(collection: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    return probe_collection(
        collection,
        KEY,
        kwargs.pop("cfg", ProbeConfig(concurrency=2)),
        generated_at=GENERATED_AT,
        resolver=kwargs.pop("resolver", PUBLIC_RESOLVER),
        sleep=NO_SLEEP,
        jitter=NO_JITTER,
        **kwargs,
    )


def _manifest(addon_id: str) -> dict[str, Any]:
    return {
        "id": addon_id,
        "name": "M",
        "version": "1.0.0",
        "resources": ["catalog"],
        "types": ["movie"],
    }


@respx.mock
def test_healthy_manifest_over_https() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(200, json=_manifest("addon.0"))
    )
    report = _probe(_collection("https://a.test/manifest.json"))
    entry = report["entries"][0]
    assert entry["status"] == "healthy"
    assert entry["secure"] is True
    assert entry["httpStatus"] == 200
    assert entry["latencyMs"] is not None
    assert entry["attempts"] == 1
    assert iter_schema_errors(report, "audit-report-v1") == []
    assert report["generatedAt"] == GENERATED_AT


@respx.mock
def test_http_healthy_manifest_is_insecure_transport() -> None:
    respx.get("http://a.test/manifest.json").mock(
        return_value=httpx.Response(200, json=_manifest("addon.0"))
    )
    entry = _probe(_collection("http://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "insecure_transport"
    assert entry["secure"] is False
    assert "transport uses http instead of https" in entry["warnings"]


@respx.mock
def test_non_json_content_type_is_a_warning_but_still_parses() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(
            200, headers={"content-type": "text/plain"}, json=_manifest("addon.0")
        )
    )
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "warning"
    assert any("content-type is not JSON" in w for w in entry["warnings"])


@respx.mock
def test_invalid_json_body_is_invalid_manifest() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(200, content=b"<html>nope</html>")
    )
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "invalid_manifest"


@respx.mock
def test_oversized_body_is_invalid_manifest() -> None:
    huge = b'{"id":"addon.0","padding":"' + b"x" * (3 * 1024 * 1024) + b'"}'
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(200, content=huge)
    )
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "invalid_manifest"
    assert "2 MiB" in entry["detail"]


@respx.mock
def test_manifest_body_contents_never_reach_the_report() -> None:
    manifest = _manifest("addon.0")
    manifest["description"] = "SENTINEL_MUST_NOT_LEAK in a manifest field"
    respx.get("https://a.test/manifest.json").mock(return_value=httpx.Response(200, json=manifest))
    report = _probe(_collection("https://a.test/manifest.json"))
    assert report["entries"][0]["status"] == "healthy"
    assert "SENTINEL_MUST_NOT_LEAK" not in str(report)


@respx.mock
def test_identity_mismatch() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(200, json=_manifest("some.other.id"))
    )
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "identity_mismatch"


@respx.mock
def test_retryable_500_then_success() -> None:
    route = respx.get("https://a.test/manifest.json")
    route.side_effect = [
        httpx.Response(503),
        httpx.Response(200, json=_manifest("addon.0")),
    ]
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "healthy"
    assert entry["attempts"] == 2


@respx.mock
def test_retryable_status_exhausted_is_unreachable() -> None:
    respx.get("https://a.test/manifest.json").mock(return_value=httpx.Response(503))
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "unreachable"
    assert entry["attempts"] == 2
    assert entry["httpStatus"] == 503


@respx.mock
def test_connect_error_retried_then_unreachable() -> None:
    respx.get("https://a.test/manifest.json").mock(side_effect=httpx.ConnectError("no route"))
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "unreachable"
    assert entry["attempts"] == 2


@respx.mock
def test_4xx_is_not_retried() -> None:
    route = respx.get("https://a.test/manifest.json").mock(return_value=httpx.Response(404))
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "unreachable"
    assert entry["attempts"] == 1
    assert route.call_count == 1


@respx.mock
def test_single_same_origin_redirect_is_followed() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(302, headers={"location": "https://a.test/real.json"})
    )
    respx.get("https://a.test/real.json").mock(
        return_value=httpx.Response(200, json=_manifest("addon.0"))
    )
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "healthy"
    assert entry["redirects"] == 1


@respx.mock
def test_second_redirect_is_refused() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(302, headers={"location": "https://a.test/one.json"})
    )
    respx.get("https://a.test/one.json").mock(
        return_value=httpx.Response(302, headers={"location": "https://a.test/two.json"})
    )
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "unreachable"
    assert "too many redirects" in entry["detail"]


@respx.mock
def test_redirect_without_location_is_unreachable() -> None:
    respx.get("https://a.test/manifest.json").mock(return_value=httpx.Response(302))
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "unreachable"
    assert "location" in entry["detail"]


def test_probe_rejects_structurally_broken_collection() -> None:
    broken = [{"manifest": {"id": "a"}, "transportUrl": "not-a-url"}]
    with pytest.raises(ValidationError):
        _probe(broken)


@respx.mock
def test_cross_origin_redirect_is_not_followed() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.test/manifest.json"})
    )
    entry = _probe(_collection("https://a.test/manifest.json"))["entries"][0]
    assert entry["status"] == "unreachable"
    assert "cross-origin" in entry["detail"]
    # the cross-origin target was never requested
    assert not any("evil.test" in str(call.request.url) for call in respx.calls)


@respx.mock
def test_probe_never_requests_content_resource_routes() -> None:
    urls = [
        "https://a.test/manifest.json",
        "https://b.test/sub/manifest.json",
    ]
    for i, url in enumerate(urls):
        respx.get(url).mock(return_value=httpx.Response(200, json=_manifest(f"addon.{i}")))
    _probe(_collection(*urls))
    requested = {str(call.request.url) for call in respx.calls}
    assert requested == set(urls)
    for path in ("/catalog/", "/meta/", "/stream/", "/subtitles/"):
        assert not any(path in u for u in requested)


@respx.mock
def test_detail_never_leaks_a_url_with_a_sentinel() -> None:
    url = "https://a.test/config/SENTINEL_MUST_NOT_LEAK/manifest.json"
    respx.get(url).mock(side_effect=httpx.ConnectError(f"failed connecting to {url}"))
    report = _probe(_collection(url))
    blob = str(report)
    assert "SENTINEL_MUST_NOT_LEAK" not in blob
    assert "/config/" not in blob
    assert report["entries"][0]["status"] == "unreachable"


@respx.mock
def test_blocked_after_redirect_to_private_address() -> None:
    respx.get("https://a.test/manifest.json").mock(
        return_value=httpx.Response(302, headers={"location": "https://a.test/internal.json"})
    )
    internal = respx.get("https://a.test/internal.json").mock(
        return_value=httpx.Response(200, json=_manifest("addon.0"))
    )

    calls = {"n": 0}

    def flipping_resolver(host: str, port: int) -> list[str]:
        # first hop resolves public; the redirect target resolves to the cloud
        # metadata address and must be refused after DNS resolution.
        calls["n"] += 1
        return ["93.184.216.34"] if calls["n"] == 1 else ["169.254.169.254"]

    entry = _probe(_collection("https://a.test/manifest.json"), resolver=flipping_resolver)[
        "entries"
    ][0]
    assert entry["status"] == "blocked_destination"
    assert entry["redirects"] == 1
    assert internal.call_count == 0  # the unsafe target was never contacted
