"""Shared autouse guards.

* Private state is redirected into a temporary directory so a test run never
  writes to the real user profile.
* Outbound network access raises immediately, enforcing the spec rule that
  offline commands make no network calls.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

_ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost", ""}


@pytest.fixture(autouse=True)
def _private_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STREMIOCTL_DATA_DIR", str(tmp_path / "stremioctl-data"))


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _host_of(address: object) -> object:
        return address[0] if isinstance(address, tuple) and address else address

    def guard_connect(self: socket.socket, address: object) -> object:
        if _host_of(address) in _ALLOWED_HOSTS:
            return real_connect(self, address)
        raise RuntimeError(f"blocked network connect to {_host_of(address)!r} during tests")

    def guard_connect_ex(self: socket.socket, address: object) -> object:
        if _host_of(address) in _ALLOWED_HOSTS:
            return real_connect_ex(self, address)
        raise RuntimeError(f"blocked network connect_ex to {_host_of(address)!r} during tests")

    monkeypatch.setattr(socket.socket, "connect", guard_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guard_connect_ex)
    yield
