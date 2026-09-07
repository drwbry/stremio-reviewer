"""Real-socket probe tests against a loopback HTTP server.

respx covers the transport-level edge cases and the https-only statuses
(`healthy`, `warning`). This module proves the real path: actual sockets, the
thread pool, real redirect handling, and - most importantly - that a blocked
destination is refused *before* any connection is made.
"""

from __future__ import annotations

import json
import re
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from stremioctl.probing import ProbeConfig, probe_collection

KEY = b"k" * 32
GENERATED_AT = "2026-09-06T00:00:00Z"


class _Handler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def log_message(self, *args: Any) -> None:  # silence the default stderr spam
        pass

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - required name
        type(self).hits.append(self.path)
        if self.path == "/healthy/manifest.json":
            self._send_json(
                200,
                {"id": "addon.ok", "name": "OK", "version": "1", "resources": [], "types": []},
            )
        elif self.path == "/mismatch/manifest.json":
            self._send_json(200, {"id": "totally.different", "name": "X", "version": "1"})
        elif self.path == "/notjson/manifest.json":
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>not a manifest</html>")
        elif self.path == "/redirect/manifest.json":
            self.send_response(302)
            self.send_header("location", "/healthy/manifest.json")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def server() -> Iterator[tuple[str, type[_Handler]]]:
    _Handler.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _Handler
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def _descriptor(addon_id: str, url: str) -> dict[str, Any]:
    return {
        "manifest": {
            "id": addon_id,
            "name": addon_id,
            "version": "1.0.0",
            "resources": [],
            "types": [],
        },
        "transportUrl": url,
    }


def _probe(collection: list[dict[str, Any]], *, allow_private: bool) -> dict[str, Any]:
    return probe_collection(
        collection,
        KEY,
        ProbeConfig(concurrency=3, allow_private_network=allow_private),
        generated_at=GENERATED_AT,
        sleep=lambda _s: None,
        jitter=lambda: 0.0,
    )


def test_real_server_statuses(server: tuple[str, type[_Handler]]) -> None:
    base, _handler = server
    # a definitely-closed port for the unreachable case
    scratch = socket.socket()
    scratch.bind(("127.0.0.1", 0))
    closed_port = scratch.getsockname()[1]
    scratch.close()

    collection = [
        _descriptor("addon.ok", f"{base}/healthy/manifest.json"),
        _descriptor("addon.ok", f"{base}/mismatch/manifest.json"),
        _descriptor("addon.ok", f"{base}/notjson/manifest.json"),
        _descriptor("addon.ok", f"{base}/redirect/manifest.json"),
        _descriptor("addon.ok", f"http://127.0.0.1:{closed_port}/manifest.json"),
    ]
    report = _probe(collection, allow_private=True)
    statuses = [e["status"] for e in report["entries"]]

    assert statuses[0] == "insecure_transport"  # 200 + matching id, but http
    assert statuses[1] == "identity_mismatch"
    assert statuses[2] == "invalid_manifest"
    assert statuses[3] == "insecure_transport"  # followed one same-origin redirect
    assert report["entries"][3]["redirects"] == 1
    assert statuses[4] == "unreachable"
    # the redacted endpoint label keeps the host (SPEC 7.4), but no complete URL
    # path may appear anywhere in the report.
    blob = json.dumps(report)
    for path in ("/healthy/manifest.json", "/mismatch/", "/notjson/", "/redirect/"):
        assert path not in blob
    for entry in report["entries"]:
        assert re.fullmatch(r"https?://[^/]+/<redacted>#[0-9a-f]{12}", entry["endpoint"])


def test_loopback_is_blocked_by_default_and_no_request_is_made(
    server: tuple[str, type[_Handler]],
) -> None:
    base, handler = server
    collection = [_descriptor("addon.ok", f"{base}/healthy/manifest.json")]
    report = _probe(collection, allow_private=False)
    assert report["entries"][0]["status"] == "blocked_destination"
    assert report["entries"][0]["detail"] == "loopback address"
    assert handler.hits == []  # the guard fired before any socket connect
