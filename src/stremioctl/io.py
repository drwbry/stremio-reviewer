"""Private local paths, safe file reads, and atomic writes.

This module deliberately contains no collection parsing or network behavior.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir

from stremioctl.errors import SecurityError, ValidationError

# A generous ceiling. A real collection export is a few tens of kilobytes; this
# only exists so a hostile or accidental multi-gigabyte file cannot be slurped
# into memory during an offline command.
_MAX_INPUT_BYTES = 16 * 1024 * 1024


def private_app_path(app_name: str = "stremioctl") -> Path:
    """Return the private application directory path.

    ``STREMIOCTL_DATA_DIR`` overrides the platform location. It exists mainly so
    tests can redirect private state into a temporary directory instead of the
    real user profile.
    """

    override = os.environ.get("STREMIOCTL_DATA_DIR")
    if override:
        return Path(override)
    return Path(user_data_dir(app_name))


def ensure_private_directory(path: Path) -> Path:
    """Create *path* and require that it is owned and private.

    Existing symlinks are rejected so a private artifact path cannot be redirected
    outside the application directory.  On POSIX, group/other permissions are
    checked explicitly; on other platforms, the best available mode check is used.
    """

    path = Path(path)
    if path.is_symlink():
        raise SecurityError(f"Refusing symlink for private directory: {path.name}")

    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
        info = path.stat()
    except OSError as exc:
        raise SecurityError("Unable to create a private application directory") from exc

    if not stat.S_ISDIR(info.st_mode):
        raise SecurityError("Private application path is not a directory")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise SecurityError("Private application directory is not owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SecurityError(
            "Private application directory must not be accessible by group or other"
        )
    return path


def ensure_private_app_dir(path: Path | None = None) -> Path:
    """Create or verify the application data directory."""

    return ensure_private_directory(path or private_app_path())


def load_json_document(path: Path) -> Any:
    """Read and parse a JSON file with bounded size and sanitized errors.

    Every failure is raised as :class:`ValidationError` so the command boundary
    maps it to exit code 2. The messages name only the file and the JSON parser's
    positional complaint, never file contents.
    """

    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValidationError(f"Cannot access input file: {path.name}") from exc
    if size > _MAX_INPUT_BYTES:
        raise ValidationError("Input file is larger than the safe processing limit")

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"Input file is not valid UTF-8 text: {path.name}") from exc
    except OSError as exc:
        raise ValidationError(f"Cannot read input file: {path.name}") from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"Input file is not valid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})"
        ) from exc


def _fsync_directory(directory: Path) -> None:
    try:
        directory_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write *data* to *path* atomically: same-directory temp file, fsync, rename."""

    path = Path(path)
    directory = path.parent
    if not directory.is_dir():
        raise SecurityError("Output directory does not exist")
    if path.is_symlink():
        raise SecurityError("Refusing to write through a symlink")

    descriptor, temp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    temp_path = Path(temp_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        else:  # pragma: no cover - non-POSIX fallback
            os.chmod(temp_path, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
    _fsync_directory(directory)


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    """Atomically write UTF-8 *text* to *path*."""

    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


__all__ = [
    "atomic_write_bytes",
    "atomic_write_text",
    "ensure_private_app_dir",
    "ensure_private_directory",
    "load_json_document",
    "private_app_path",
]
