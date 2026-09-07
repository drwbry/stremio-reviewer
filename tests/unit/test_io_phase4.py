from __future__ import annotations

import stat
from pathlib import Path

import pytest

from stremioctl.errors import SecurityError
from stremioctl.io import assert_private_output_dir, read_secret_file

# --- assert_private_output_dir ---


def test_creates_a_missing_private_parent(tmp_path: Path) -> None:
    target = tmp_path / "new" / "snap.json"
    assert_private_output_dir(target)
    assert target.parent.is_dir()
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700


def test_accepts_an_existing_private_parent(tmp_path: Path) -> None:
    parent = tmp_path / "priv"
    parent.mkdir(mode=0o700)
    assert_private_output_dir(parent / "snap.json")  # no raise


def test_refuses_a_group_or_world_accessible_parent(tmp_path: Path) -> None:
    parent = tmp_path / "loose"
    parent.mkdir(mode=0o755)
    with pytest.raises(SecurityError, match="STREMIOCTL_DATA_DIR"):
        assert_private_output_dir(parent / "snap.json")


def test_refuses_a_symlinked_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(SecurityError):
        assert_private_output_dir(link / "snap.json")


def test_refuses_a_parent_that_is_not_a_directory(tmp_path: Path) -> None:
    not_dir = tmp_path / "afile"
    not_dir.write_text("x")
    with pytest.raises(SecurityError):
        assert_private_output_dir(not_dir / "snap.json")


# --- read_secret_file ---


def test_reads_a_strict_file(tmp_path: Path) -> None:
    f = tmp_path / "s"
    f.write_text("value\n")
    f.chmod(0o600)
    assert read_secret_file(f) == "value\n"


def test_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        read_secret_file(tmp_path / "nope")


def test_rejects_a_directory(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    with pytest.raises(SecurityError, match="regular file"):
        read_secret_file(d)


def test_rejects_group_readable(tmp_path: Path) -> None:
    f = tmp_path / "s"
    f.write_text("v")
    f.chmod(0o644)
    with pytest.raises(SecurityError, match="group or other"):
        read_secret_file(f)


def test_rejects_non_utf8(tmp_path: Path) -> None:
    f = tmp_path / "s"
    f.write_bytes(b"\xff\xfe\x00bad")
    f.chmod(0o600)
    with pytest.raises(SecurityError, match="UTF-8"):
        read_secret_file(f)


def test_rejects_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text("v")
    real.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(SecurityError):
        read_secret_file(link)
