"""The stremioctl command-line entry point.

Phase 1 exposes offline ``backup`` sub-commands; Phase 2 adds offline ``profile``
sub-commands. Every command body runs inside a single error boundary that prints
sanitized messages to stderr and maps typed errors to their stable exit codes.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from stremioctl import __version__
from stremioctl.diff import build_change_plan, render_plan_human
from stremioctl.errors import StremioctlError, ValidationError
from stremioctl.io import atomic_write_text, load_json_document
from stremioctl.plans import compute_plan_hash
from stremioctl.privacy import (
    assert_no_sentinels,
    load_or_create_redaction_key,
    redact_document,
    sanitize_exception,
)
from stremioctl.profiles import build_starter_profile, check_profile, parse_profile
from stremioctl.reports import (
    build_inspect_report,
    build_validate_report,
    render_inspect_human,
    render_validate_human,
)
from stremioctl.schemas import iter_schema_errors

app = typer.Typer(add_completion=False, no_args_is_help=True)
backup_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Offline inspection, validation, and redaction of a collection export.",
)
app.add_typer(backup_app, name="backup")
profile_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Offline desired-profile authoring, validation, and deterministic diffs.",
)
app.add_typer(profile_app, name="profile")


def _stdout_console() -> Console:
    # Markup and syntax highlighting are disabled so that redacted labels and
    # finding text (which can contain "[" or "#") are printed verbatim. Rich
    # still drops ANSI colour automatically when stdout is not a TTY.
    return Console(markup=False, highlight=False)


def _stderr_console() -> Console:
    return Console(stderr=True, markup=False, highlight=False)


def _run(action: Callable[[], int]) -> None:
    """Execute *action*, translating every failure into a safe exit."""

    try:
        code = action()
    except typer.Exit:
        raise
    except StremioctlError as exc:
        _stderr_console().print(f"error: {sanitize_exception(exc)}")
        raise typer.Exit(exc.exit_code) from None
    except Exception as exc:  # last-resort boundary; exit 1 is the "uncaught defect" code
        _stderr_console().print(f"error: {sanitize_exception(exc)}")
        raise typer.Exit(1) from None
    if code:
        raise typer.Exit(code)


def _assert_report_contract(report: dict[str, object]) -> str:
    """Serialize a report, proving it is sentinel-free and matches its schema."""

    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    assert_no_sentinels(text)
    errors = iter_schema_errors(report, "backup-report-v1")
    if errors:  # our own output failed its own contract - a defect, not user error
        raise RuntimeError(f"internal report contract violation: {'; '.join(errors)}")
    return text


def _assert_plan_contract(plan: dict[str, object]) -> str:
    """Serialize a plan, proving it is sentinel-free, schema-valid, and hash-stable."""

    text = json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True)
    assert_no_sentinels(text)
    errors = iter_schema_errors(plan, "change-plan-v1")
    if errors:
        raise RuntimeError(f"internal plan contract violation: {'; '.join(errors)}")
    if plan.get("planHash") != compute_plan_hash(plan):  # defensive: hash must match its body
        raise RuntimeError("internal plan contract violation: planHash does not match plan body")
    return text


def _utc_now_z() -> str:
    """Return the current UTC time as ``YYYY-MM-DDTHH:MM:SSZ`` (second precision)."""

    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _guard_output_path(path: Path, reserved: tuple[Path, ...], *, expect: str) -> None:
    """Refuse to write over an input, or over an unrelated existing file.

    An existing target is only overwritten when it already parses as a stremioctl
    artifact of the expected kind (``"profile"`` or ``"plan"``), so re-running a
    command to refresh its own output is fine but clobbering a hand-written file
    is not.
    """

    for other in reserved:
        if path.resolve() == other.resolve():
            raise ValidationError("Refusing to overwrite an input file; choose a different path")
    if not path.exists():
        return
    existing = load_json_document(path)  # bounded read; non-JSON -> ValidationError
    recognized = isinstance(existing, dict) and existing.get("schemaVersion") == 1 and (
        "planHash" in existing if expect == "plan" else "addons" in existing
    )
    if not recognized:
        raise ValidationError(
            f"Refusing to overwrite {path.name}: it exists and is not a stremioctl {expect}"
        )


def _version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the stremioctl version and exit.",
            callback=_version,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Safely inspect and manage Stremio add-on collections."""


@backup_app.command("inspect")
def backup_inspect(
    path: Annotated[Path, typer.Argument(help="Path to a Stremio add-on collection export.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emit a JSON report.")] = False,
) -> None:
    """Summarize a collection export without revealing complete transport URLs."""

    def action() -> int:
        key = load_or_create_redaction_key()
        payload = load_json_document(path)
        report = build_inspect_report(payload, key)
        if json_output:
            sys.stdout.write(_assert_report_contract(report) + "\n")
        else:
            assert_no_sentinels(json.dumps(report, ensure_ascii=False))
            render_inspect_human(report, _stdout_console())
        return 0

    _run(action)


@backup_app.command("validate")
def backup_validate(
    path: Annotated[Path, typer.Argument(help="Path to a Stremio add-on collection export.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emit a JSON report.")] = False,
) -> None:
    """Check a collection export against the v1 contract. Exit 2 when invalid."""

    def action() -> int:
        key = load_or_create_redaction_key()
        payload = load_json_document(path)
        report = build_validate_report(payload, key)
        if json_output:
            sys.stdout.write(_assert_report_contract(report) + "\n")
        else:
            assert_no_sentinels(json.dumps(report, ensure_ascii=False))
            render_validate_human(report, _stdout_console())
        return 0 if report["valid"] else 2

    _run(action)


@backup_app.command("redact")
def backup_redact(
    path: Annotated[Path, typer.Argument(help="Path to a Stremio add-on collection export.")],
    out: Annotated[Path, typer.Option("--out", help="Destination path for the redacted copy.")],
    hide_hosts: Annotated[
        bool, typer.Option("--hide-hosts", help="Also mask endpoint host names.")
    ] = False,
) -> None:
    """Write a shareable copy with transport URLs and secret values removed."""

    def action() -> int:
        key = load_or_create_redaction_key()
        if out.resolve() == path.resolve():
            raise ValidationError(
                "Refusing to overwrite the input file; choose a different --out path"
            )
        payload = load_json_document(path)
        # redact is the most permissive of the three commands: anyone with a
        # slightly malformed export still needs a safe copy to share. Only a
        # non-array root is refused, because the rest of this path treats the
        # payload as a descriptor list.
        if not isinstance(payload, list):
            raise ValidationError("Add-on collection root must be a JSON array")
        redacted = redact_document(payload, key, hide_hosts=hide_hosts)
        text = json.dumps(redacted, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        assert_no_sentinels(text)
        atomic_write_text(out, text, mode=0o600)
        endpoints = sum(
            1
            for item in payload
            if isinstance(item, dict) and isinstance(item.get("transportUrl"), str)
        )
        _stdout_console().print(
            f"Wrote redacted collection to {out} "
            f"({len(payload)} descriptors, {endpoints} transport URLs redacted)."
        )
        return 0

    _run(action)


@profile_app.command("init")
def profile_init(
    from_path: Annotated[
        Path, typer.Option("--from", help="Collection export to derive the profile from.")
    ],
    out: Annotated[Path, typer.Option("--out", help="Destination path for the generated profile.")],
    declare_public: Annotated[
        list[str] | None,
        typer.Option(
            "--declare-public",
            help=(
                "Manifest id whose transport URL may be written into the profile as a public "
                "endpoint. Repeatable. Everything else is left out."
            ),
        ),
    ] = None,
) -> None:
    """Generate a starter desired profile. Configured URLs stay out unless declared public."""

    def action() -> int:
        key = load_or_create_redaction_key()
        _guard_output_path(out, (from_path,), expect="profile")
        payload = load_json_document(from_path)
        if not isinstance(payload, list):
            raise ValidationError("Add-on collection root must be a JSON array")
        profile = build_starter_profile(
            payload, key, declare_public=frozenset(declare_public or ())
        )
        errors = check_profile(profile)
        blocking = [f for f in errors if f.severity == "error"]
        if blocking:  # a generated profile that fails its own contract is a defect
            raise RuntimeError(
                "internal profile contract violation: "
                + "; ".join(f.render() for f in blocking)
            )
        text = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
        assert_no_sentinels(text)
        atomic_write_text(out, text, mode=0o600)
        declared = len([a for a in profile["addons"] if "endpoint" in a])
        _stdout_console().print(
            f"Wrote desired profile to {out} "
            f"({len(profile['addons'])} add-ons, {declared} declared-public endpoints)."
        )
        return 0

    _run(action)


@profile_app.command("validate")
def profile_validate(
    path: Annotated[Path, typer.Argument(help="Path to a desired profile.")],
) -> None:
    """Check a desired profile against the v1 contract. Exit 2 when invalid."""

    def action() -> int:
        payload = load_json_document(path)
        findings = check_profile(payload)
        console = _stdout_console()
        if not findings:
            console.print("findings: none")
        else:
            console.print(f"findings: {len(findings)}")
            for finding in findings:
                console.print(f"  {finding.render()}")
        errors = sum(1 for f in findings if f.severity == "error")
        warnings = sum(1 for f in findings if f.severity == "warning")
        if errors:
            console.print(f"INVALID ({errors} errors, {warnings} warnings)")
            return 2
        console.print(f"VALID ({warnings} warnings)")
        return 0

    _run(action)


@profile_app.command("diff")
def profile_diff(
    current: Annotated[
        Path, typer.Option("--current", help="Current collection export.")
    ],
    desired: Annotated[Path, typer.Option("--desired", help="Desired profile.")],
    out_plan: Annotated[
        Path | None,
        typer.Option("--out-plan", help="Write the change plan JSON to this path (mode 0600)."),
    ] = None,
) -> None:
    """Produce a deterministic change plan. Exit 0 when converged, 10 when changes are planned."""

    def action() -> int:
        key = load_or_create_redaction_key()
        current_doc = load_json_document(current)
        desired_doc = load_json_document(desired)
        profile, profile_warnings = parse_profile(desired_doc)
        plan = build_change_plan(
            current=current_doc,
            profile=profile,
            key=key,
            created_at=_utc_now_z(),
            profile_warnings=[f.message for f in profile_warnings],
        )
        text = _assert_plan_contract(plan) + "\n"
        if out_plan is not None:
            _guard_output_path(out_plan, (current, desired), expect="plan")
            atomic_write_text(out_plan, text, mode=0o600)
        render_plan_human(plan, _stdout_console())
        return 10 if plan["operations"] else 0

    _run(action)


def main() -> None:
    """Run the CLI."""

    app()


__all__ = ["app", "backup_app", "main", "profile_app"]
