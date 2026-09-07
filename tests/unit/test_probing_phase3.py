from __future__ import annotations

import json

import pytest

from stremioctl.errors import ValidationError
from stremioctl.probing import (
    ProbeConfig,
    _address_block_reason,
    _classify_manifest,
    _guard_destination,
    _same_origin,
    audit_exit_code,
)

KEY = b"k" * 32


# --- address safety classifier ---


@pytest.mark.parametrize(
    "ip, blocked_default",
    [
        ("8.8.8.8", False),
        ("93.184.216.34", False),
        ("127.0.0.1", True),
        ("10.0.0.5", True),
        ("192.168.1.1", True),
        ("172.16.0.1", True),
        ("169.254.169.254", True),  # cloud metadata endpoint
        ("0.0.0.0", True),
        ("224.0.0.1", True),  # multicast
        ("240.0.0.1", True),  # reserved
        ("::1", True),
        ("fe80::1", True),
        ("fc00::1", True),
        ("::ffff:127.0.0.1", True),  # ipv4-mapped loopback
        ("::ffff:8.8.8.8", False),
    ],
)
def test_address_block_reason_default(ip: str, blocked_default: bool) -> None:
    assert (_address_block_reason(ip, allow_private=False) is not None) is blocked_default


def test_allow_private_unblocks_loopback_and_private_but_not_multicast() -> None:
    assert _address_block_reason("127.0.0.1", allow_private=True) is None
    assert _address_block_reason("10.0.0.1", allow_private=True) is None
    assert _address_block_reason("169.254.169.254", allow_private=True) is None
    assert _address_block_reason("224.0.0.1", allow_private=True) is not None
    assert _address_block_reason("0.0.0.0", allow_private=True) is not None


def test_garbage_address_is_blocked() -> None:
    assert _address_block_reason("not-an-ip", allow_private=True) is not None


# --- _guard_destination ---


def test_guard_blocks_ip_literal_pointing_at_localhost() -> None:
    with pytest.raises(Exception) as exc:  # noqa: PT011 - _Blocked is module-private
        _guard_destination("http://127.0.0.1/manifest.json", lambda h, p: [], allow_private=False)
    assert "loopback" in str(exc.value)


def test_guard_blocks_when_dns_resolves_to_private_address() -> None:
    with pytest.raises(Exception) as exc:  # noqa: PT011
        _guard_destination(
            "https://sneaky.example/manifest.json",
            lambda h, p: ["10.1.2.3"],
            allow_private=False,
        )
    assert "private" in str(exc.value)


def test_guard_allows_public_resolution() -> None:
    _guard_destination(
        "https://good.example/manifest.json",
        lambda h, p: ["93.184.216.34"],
        allow_private=False,
    )


def test_guard_rejects_non_http_scheme_and_userinfo() -> None:
    with pytest.raises(Exception):  # noqa: PT011, B017
        _guard_destination("ftp://good.example/x", lambda h, p: ["8.8.8.8"], allow_private=False)
    with pytest.raises(Exception):  # noqa: PT011, B017
        _guard_destination(
            "https://user:pw@good.example/x", lambda h, p: ["8.8.8.8"], allow_private=False
        )


def test_guard_maps_dns_failure_to_unreachable_not_blocked() -> None:
    def boom(host: str, port: int) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(Exception) as exc:  # noqa: PT011
        _guard_destination("https://nope.example/x", boom, allow_private=False)
    assert "dns resolution failed" in str(exc.value)


def test_guard_maps_empty_dns_result_to_unreachable() -> None:
    with pytest.raises(Exception) as exc:  # noqa: PT011
        _guard_destination("https://nope.example/x", lambda h, p: [], allow_private=False)
    assert "no records" in str(exc.value)


# --- _same_origin ---


@pytest.mark.parametrize(
    "a, b, same",
    [
        ("https://h.example/a", "https://h.example/b", True),
        ("https://h.example/a", "https://h.example:443/b", True),
        ("http://h.example/a", "http://h.example:80/b", True),
        ("https://h.example/a", "http://h.example/b", False),
        ("https://h.example/a", "https://other.example/b", False),
        ("https://h.example/a", "https://h.example:8443/b", False),
    ],
)
def test_same_origin(a: str, b: str, same: bool) -> None:
    assert _same_origin(a, b) is same


# --- _classify_manifest ---


def test_classify_healthy_manifest() -> None:
    body = json.dumps(
        {"id": "x.addon", "name": "X", "version": "1.0.0", "resources": [], "types": []}
    ).encode()
    status, warnings, detail = _classify_manifest(body, "x.addon")
    assert status == "healthy"
    assert warnings == []
    assert detail is None


def test_classify_identity_mismatch() -> None:
    body = json.dumps({"id": "actually.other", "name": "X", "version": "1"}).encode()
    status, _, detail = _classify_manifest(body, "x.addon")
    assert status == "identity_mismatch"
    assert detail and "differs" in detail


def test_classify_missing_recommended_fields_is_warning_only() -> None:
    body = json.dumps({"id": "x.addon"}).encode()
    status, warnings, _ = _classify_manifest(body, "x.addon")
    assert status == "healthy"
    assert any("recommended field" in w for w in warnings)


@pytest.mark.parametrize("body", [b"not json", b"[1,2,3]", b'{"name": "no id"}'])
def test_classify_invalid_manifest(body: bytes) -> None:
    status, _, _ = _classify_manifest(body, "x.addon")
    assert status == "invalid_manifest"


# --- ProbeConfig bounds ---


@pytest.mark.parametrize("timeout", [0.5, 31, 100])
def test_probe_config_rejects_out_of_range_timeout(timeout: float) -> None:
    with pytest.raises(ValidationError):
        ProbeConfig(overall_timeout=timeout)


@pytest.mark.parametrize("concurrency", [0, 11, 50])
def test_probe_config_rejects_out_of_range_concurrency(concurrency: int) -> None:
    with pytest.raises(ValidationError):
        ProbeConfig(concurrency=concurrency)


def test_probe_config_accepts_edges() -> None:
    ProbeConfig(overall_timeout=1, concurrency=1)
    ProbeConfig(overall_timeout=30, concurrency=10)


def test_probe_config_rejects_zero_attempts() -> None:
    with pytest.raises(ValidationError):
        ProbeConfig(attempts=0)


# --- audit_exit_code ---


def test_exit_code_zero_for_healthy_and_warning_only() -> None:
    report = {"entries": [{"status": "healthy"}, {"status": "warning"}]}
    assert audit_exit_code(report) == 0


@pytest.mark.parametrize(
    "status",
    [
        "unreachable",
        "invalid_manifest",
        "identity_mismatch",
        "insecure_transport",
        "blocked_destination",
    ],
)
def test_exit_code_three_for_any_problem_status(status: str) -> None:
    report = {"entries": [{"status": "healthy"}, {"status": status}]}
    assert audit_exit_code(report) == 3
