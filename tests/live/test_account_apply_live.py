"""Opt-in live account *mutation* test. Skipped unless explicitly authorised.

This performs a real ``addonCollectionSet`` and is destructive to whatever
account the supplied key belongs to. Per SPEC section 13 it runs only when ALL
of the following hold:

* ``STREMIOCTL_LIVE_TESTS=1``
* ``STREMIOCTL_DISPOSABLE_ACCOUNT=1`` - an explicit assertion that the key
  belongs to a throwaway account, never the user's primary one
* ``STREMIO_AUTH_KEY`` is set to that disposable account's session key
* the process is attached to an interactive terminal

The flow: pull, build a converged plan against the current state (so it makes no
write), then confirm ``apply`` is a no-op. A real mutating run is left to a human
operator with a disposable account; this test only proves the guardrails hold
against a live endpoint. Credentials must be supplied outside any assistant
conversation.
"""

from __future__ import annotations

import os
import sys

import pytest

_ENABLED = (
    os.environ.get("STREMIOCTL_LIVE_TESTS") == "1"
    and os.environ.get("STREMIOCTL_DISPOSABLE_ACCOUNT") == "1"
    and bool(os.environ.get("STREMIO_AUTH_KEY"))
    and sys.stdin.isatty()
)

pytestmark = pytest.mark.skipif(
    not _ENABLED,
    reason=(
        "live apply tests need STREMIOCTL_LIVE_TESTS=1, STREMIOCTL_DISPOSABLE_ACCOUNT=1, "
        "STREMIO_AUTH_KEY, and a TTY"
    ),
)


def test_live_converged_apply_makes_no_write() -> None:
    from stremioctl.account import AccountConfig, fetch_addon_collection, resolve_auth_key
    from stremioctl.apply import apply_plan
    from stremioctl.diff import build_change_plan
    from stremioctl.privacy import load_or_create_redaction_key
    from stremioctl.profiles import parse_profile

    key = load_or_create_redaction_key()
    auth_key = resolve_auth_key()
    cfg = AccountConfig()

    pulled = fetch_addon_collection(auth_key, cfg)
    profile, warnings = parse_profile({"schemaVersion": 1, "name": "live", "addons": []})
    plan = build_change_plan(
        current=pulled.addons,
        profile=profile,
        key=key,
        created_at="2026-09-06T00:00:00Z",
        profile_warnings=[w.message for w in warnings],
    )
    assert plan["operations"] == []

    outcome = apply_plan(
        plan=plan,
        confirm=plan["planHash"],
        key=key,
        auth_key=auth_key,
        cfg=cfg,
        now="2026-09-06T00:00:00Z",
    )
    assert outcome.exit_code == 0
    assert not outcome.pushed
