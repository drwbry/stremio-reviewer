from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from stremioctl.errors import SecurityError, ValidationError
from stremioctl.io import atomic_write_text, load_json_document


def test_load_json_document_parses(tmp_path: Path) -> None:
    path = tmp_path / "doc.json"
    path.write_text(json.dumps([{"a": 1}]))
    assert load_json_document(path) == [{"a": 1}]


def test_load_json_document_rejects_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "doc.json"
    path.write_text("{ not json")
    with pytest.raises(ValidationError):
        load_json_document(path)


def test_load_json_document_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        load_json_document(tmp_path / "nope.json")


def test_load_json_document_rejects_non_utf8(tmp_path: Path) -> None:
    path = tmp_path / "doc.json"
    path.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ValidationError):
        load_json_document(path)


def test_load_json_document_rejects_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("stremioctl.io._MAX_INPUT_BYTES", 8)
    path = tmp_path / "doc.json"
    path.write_text(json.dumps({"lots": "of data here"}))
    with pytest.raises(ValidationError):
        load_json_document(path)


def test_atomic_write_text_sets_mode_and_replaces(tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    atomic_write_text(path, "first\n")
    atomic_write_text(path, "second\n")
    assert path.read_text() == "second\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".out.json.*"))  # no temp file left behind


def test_atomic_write_text_rejects_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(SecurityError):
        atomic_write_text(tmp_path / "missing" / "out.json", "x")


def test_atomic_write_text_rejects_symlink_target(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("x")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(SecurityError):
        atomic_write_text(link, "y")
