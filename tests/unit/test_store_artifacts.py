import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import os
import stat
import pytest
from hermes_security.store.artifacts import scan_dir, write_artifact, read_artifact
from hermes_security.errors import ValidationError, NotFound


def test_artifact_roundtrip_permissions_and_atomic_failure(tmp_path, monkeypatch):
    root = scan_dir(tmp_path, "scan_a")
    write_artifact(root, "exports/report.txt", "first")
    assert read_artifact(root, "exports/report.txt") == b"first"
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "exports").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "exports/report.txt").stat().st_mode) == 0o600

    def fail(*args, **kwargs):
        raise OSError("simulated failed rename")

    with monkeypatch.context() as m:
        m.setattr(os, "replace", fail)
        with pytest.raises(ValidationError):
            write_artifact(root, "exports/report.txt", b"new")
    assert read_artifact(root, "exports/report.txt") == b"first"
    assert list((root / "exports").iterdir()) == [root / "exports/report.txt"]
    write_artifact(root, "exports/report.txt", b"new")
    assert read_artifact(root, "exports/report.txt") == b"new"
    with pytest.raises(NotFound):
        read_artifact(root, "missing")


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "a/../b",
        "a\x00b",
        "a//b",
        "C:\\outside",
        "a\\b",
        "./x",
    ],
)
def test_bad_paths(tmp_path, path):
    root = scan_dir(tmp_path, "scan_a")
    with pytest.raises(ValidationError):
        write_artifact(root, path, b"x")
    with pytest.raises(ValidationError):
        read_artifact(root, path)
    with pytest.raises(ValidationError):
        scan_dir(tmp_path, path)


def test_symlink_components(tmp_path):
    root = scan_dir(tmp_path / "data", "scan_a")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target").write_text("untouched")
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "file").symlink_to(outside / "target")
    for rel in ("link/target", "file"):
        with pytest.raises(ValidationError):
            write_artifact(root, rel, b"bad")
        with pytest.raises(ValidationError):
            read_artifact(root, rel)
    assert (outside / "target").read_text() == "untouched"
    (root.parent / "bad").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValidationError):
        scan_dir(tmp_path / "data", "bad")
    (tmp_path / "alias").symlink_to(tmp_path / "data", target_is_directory=True)
    with pytest.raises(ValidationError):
        scan_dir(tmp_path / "alias", "scan_new")


def test_symlink_parent_swap_cannot_escape(tmp_path, monkeypatch):
    root = scan_dir(tmp_path / "data", "scan_a")
    write_artifact(root, "exports/report", "old")
    outside = tmp_path / "outside"
    outside.mkdir()
    replace = os.replace

    def swap(src, dst, **kwargs):
        (root / "exports").rename(root / "moved")
        (root / "exports").symlink_to(outside, target_is_directory=True)
        return replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", swap)
    write_artifact(root, "exports/report", "new")
    assert not (outside / "report").exists()
    assert (root / "moved/report").read_text() == "new"
