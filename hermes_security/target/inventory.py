"""Deterministic inventory with descriptor-relative, no-follow file reads.

POSIX openat pins every directory component against symlink-swap races. Windows
reparse-point races require native handle APIs and are not supported: fail closed
on platforms without dir_fd/O_NOFOLLOW rather than claim equivalent protection.
"""
import os
import stat
from pathlib import Path, PurePosixPath
from ..canonical import sha256_hex
from ..errors import TargetError
from .resolve import git_bytes
from .policy import classify, exclusion_reason, is_untrusted_instruction_file


class FileRejected(TargetError):
    pass


def validate_path(path):
    if not isinstance(path, str) or not path or '\x00' in path or '\\' in path or path.startswith('/') or ':' in path or any(p in {'', '.', '..'} for p in path.split('/')):
        raise FileRejected('invalid_path')
    try: path.encode('utf-8', 'strict')
    except UnicodeError as exc: raise FileRejected('invalid_encoding') from exc
    return PurePosixPath(path).parts


def safe_read(root, path, max_bytes=2_000_000):
    parts = validate_path(path)
    root = Path(root).resolve(strict=True)
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise FileRejected('unsupported_platform')
    # Checking every lstat also yields a stable human-readable exclusion reason.
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink(): raise FileRejected('symlink')
    try:
        current.resolve(strict=True).relative_to(root)
    except (ValueError, OSError, RuntimeError) as exc:
        raise FileRejected('outside_root_or_missing') from exc
    descriptors = []
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): raise FileRejected('not_regular')
        if before.st_size > max_bytes: raise FileRejected('too_large')
        chunks = []; total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk: break
            chunks.append(chunk); total += len(chunk)
            if total > max_bytes: raise FileRejected('too_large')
        after = os.fstat(fd)
        now = os.stat(current, follow_symlinks=False)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (now.st_dev, now.st_ino) != (after.st_dev, after.st_ino):
            raise FileRejected('changed_during_read')
        if current.is_symlink() or not current.resolve().is_relative_to(root): raise FileRejected('symlink')
        return b''.join(chunks), after
    except OSError as exc:
        raise FileRejected('unreadable') from exc
    finally:
        for fd in reversed(descriptors): os.close(fd)


def _directory_paths(root):
    def walk_error(exc):
        raise TargetError('Unable to enumerate target directory') from exc
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs.sort(); files.sort()
        for name in list(dirs):
            p = Path(parent) / name
            if name == '.git' or p.is_symlink():
                dirs.remove(name)
                yield p.relative_to(root).as_posix()
        for name in files:
            yield (Path(parent) / name).relative_to(root).as_posix()


def build_inventory(target, *, max_file_bytes=2_000_000, max_files=50_000):
    if not isinstance(max_file_bytes, int) or max_file_bytes < 1 or not isinstance(max_files, int) or max_files < 1:
        raise TargetError('Inventory limits must be positive integers')
    root = Path(target['root'])
    submodules = set()
    if target['kind'] == 'git':
        raw = git_bytes(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
        paths = {os.fsdecode(p) for p in raw.split(b'\x00') if p}
        stages = git_bytes(root, 'ls-files', '--stage', '-z')
        for entry in stages.split(b'\x00'):
            if entry.startswith(b'160000 '): submodules.add(os.fsdecode(entry.split(b'\t', 1)[1]))
        paths.add('.git')
    else:
        paths = set(_directory_paths(root))
    files = []; excluded = []; truncated = False
    for path in sorted(paths):
        try:
            validate_path(path)
            if path in submodules: raise FileRejected('submodule')
            if (root / path).is_symlink(): raise FileRejected('symlink')
            reason = exclusion_reason(path, target.get('scope', []))
            if reason: raise FileRejected(reason)
            if len(files) >= max_files:
                truncated = True
                raise FileRejected('max_files')
            data, st = safe_read(root, path, max_file_bytes)
            language, kind = classify(path, data)
            item = {'path': path, 'size': len(data), 'sha256': sha256_hex(data), 'language': language, 'kind': kind,
                    'lines': len(data.splitlines())}
            notes = []
            if st.st_nlink > 1: notes.append(f'nlink={st.st_nlink}')
            if is_untrusted_instruction_file(path): notes.append('untrusted_instruction_file')
            if notes: item['notes'] = notes
            files.append(item)
        except FileRejected as exc:
            # Backslash escapes serialize invalid bytes without surrogate JSON.
            display = path.encode('utf-8', 'backslashreplace').decode('utf-8')
            excluded.append({'path': display, 'reason': str(exc)})
    return {'files': files, 'excluded': excluded, 'truncated': truncated}
