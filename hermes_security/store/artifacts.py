"""Contained artifact IO using no-follow directory descriptors and atomic rename.

Descriptor-relative operations prevent symlink swaps between validation and IO.
"""

from contextlib import contextmanager
import os
from pathlib import Path, PureWindowsPath
import stat
import uuid
from hermes_security.errors import ValidationError, NotFound


def _parts(rel):
    text = os.fspath(rel)
    if (
        not isinstance(text, str)
        or not text
        or "\x00" in text
        or "\\" in text
        or Path(text).is_absolute()
        or PureWindowsPath(text).is_absolute()
    ):
        raise ValidationError("artifact path must be a relative path")
    parts = text.split("/")
    if any(p in {"", "..", "."} for p in parts):
        raise ValidationError("artifact path contains unsafe components")
    return parts


@contextmanager
def _directory(path, create=False):
    """Walk every absolute component without following links (including ancestors)."""
    path = Path(path).absolute()
    if ".." in path.parts:
        raise ValidationError("unsafe directory path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    except (NotADirectoryError, OSError) as exc:
        if isinstance(exc, FileNotFoundError):
            raise NotFound("artifact directory not found") from exc
        raise ValidationError("unsafe or inaccessible artifact directory") from exc
    finally:
        os.close(fd)


def scan_dir(data_dir, scan_id):
    parts = _parts(scan_id)
    if len(parts) != 1:
        raise ValidationError("scan id must be a single component")
    root = Path(data_dir).absolute()
    result = root / "scans" / scan_id
    with _directory(root, create=True) as fd:
        os.fchmod(fd, 0o700)
    with _directory(root / "scans", create=True) as fd:
        os.fchmod(fd, 0o700)
    with _directory(result, create=True) as fd:
        os.fchmod(fd, 0o700)
    return result


@contextmanager
def _parent(root, parts, create=False):
    with _directory(root) as root_fd:
        fd = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                nxt = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                os.close(fd)
                fd = nxt
                if create:
                    os.fchmod(fd, 0o700)
            yield fd
        except FileNotFoundError as exc:
            raise NotFound("artifact not found") from exc
        except OSError as exc:
            raise ValidationError("unsafe or inaccessible artifact path") from exc
        finally:
            os.close(fd)


def write_artifact(scan_dir, rel, data):
    parts = _parts(rel)
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, bytes):
        raise ValidationError("artifact data must be bytes or text")
    with _parent(scan_dir, parts, create=True) as parent:
        try:
            mode = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False).st_mode
            if not stat.S_ISREG(mode):
                raise ValidationError("artifact target is not a regular file")
        except FileNotFoundError:
            pass
        tmp = ".tmp-" + uuid.uuid4().hex
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(tmp, dir_fd=parent)
            except FileNotFoundError:
                pass


def read_artifact(scan_dir, rel):
    parts = _parts(rel)
    with _parent(scan_dir, parts) as parent:
        fd = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
        )
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValidationError("artifact is not a regular file")
            return f.read()
