"""Opt-in live account read. Skipped unless explicitly authorised (SPEC section 14).

This performs a real, read-only ``addonCollectionGet`` against the configured
Stremio API. It runs only when ALL of the following hold:

* ``STREMIOCTL_LIVE_TESTS=1``
* ``STREMIO_AUTH_KEY`` is set to a real session key
* the process is attached to an interactive terminal

Nothing here writes to the account. Credentials must be supplied outside of any
assistant conversation.
"""

from __future__ import annotations

import os
import sys

import pytest

_ENABLED = (
    os.environ.get("STREMIOCTL_LIVE_TESTS") == "1"
    and bool(os.environ.get("STREMIO_AUTH_KEY"))
    and sys.stdin.isatty()
)

pytestmark = pytest.mark.skipif(
    not _ENABLED,
    reason="live account tests need STREMIOCTL_LIVE_TESTS=1, STREMIO_AUTH_KEY, and a TTY",
)


def test_live_account_pull_returns_a_collection() -> None:
    from stremioctl.account import AccountConfig, fetch_addon_collection, resolve_auth_key

    pulled = fetch_addon_collection(resolve_auth_key(), AccountConfig())
    assert isinstance(pulled.addons, list)
    assert len(pulled.fingerprint) == 64
    # never print the key; only shape is asserted.
