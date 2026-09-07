"""The stremioctl command-line entry point.

Phase 1 exposes offline ``backup`` sub-commands. Every command body runs inside a
single error boundary that prints sanitized messages to stderr and maps typed
errors to their stable exit codes.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from stremioctl import __version__
from stremioctl.errors import StremioctlError, ValidationError
from stremioctl.io import atomic_write_text, load_json_document
from stremioctl.privacy import (
    assert_no_sentinels,
    load_or_create_redaction_key,
    redact_document,
    sanitize_exception,
)
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


def main() -> None:
    """Run the CLI."""

    app()


__all__ = ["app", "backup_app", "main"]
