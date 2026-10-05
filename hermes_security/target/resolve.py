"""Read-only Git discovery; repository configuration is never executable input."""
from pathlib import Path
import os
import subprocess
from ..canonical import canonical_json, sha256_hex
from ..errors import TargetError


def git_bytes(root, *args, optional=False):
    # Remove inherited Git routing/config variables, including indexed -c overrides.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0', LC_ALL='C')
    argv = ['git', '-c', 'core.quotepath=off', '-c', f'safe.directory={root}',
            '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
            '-c', 'diff.external=', '-C', str(root), *args]
    try:
        # Even status/name-only diff may invoke clean/process filters to compare
        # working-tree bytes. Enumerate filter drivers without reading file content
        # and neutralize all of them at command-line precedence before any command.
        prefix = argv[:-len(args)] if args else argv
        config = subprocess.run(prefix + ['config', '--null', '--name-only', '--get-regexp', r'^filter\..*\.(clean|smudge|process|required)$'],
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30)
        if config.returncode not in (0, 1): raise TargetError('Cannot inspect Git filters safely')
        drivers = set()
        for key in config.stdout.split(b'\x00'):
            if key:
                try: drivers.add(key.decode('utf-8').rsplit('.', 1)[0])
                except UnicodeError as exc: raise TargetError('Invalid Git filter configuration') from exc
        overrides = []
        for driver in sorted(drivers):
            for setting in ('clean=', 'smudge=', 'process=', 'required=false'):
                overrides.extend(['-c', driver + '.' + setting])
        argv = prefix + overrides + list(args)
        proc = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if optional: return None
        raise TargetError('Git operation unavailable') from exc
    if proc.returncode:
        if optional: return None
        raise TargetError('Git operation failed')
    return proc.stdout


def resolve_target(path, *, scope=None, base=None, head=None, mode='standard'):
    try:
        root = Path(path).expanduser().resolve(strict=True)
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        raise TargetError('Target must be an existing directory') from exc
    if not root.is_dir() or root == Path(root.anchor) or root == Path.home().resolve():
        raise TargetError('Refusing non-directory, filesystem root, or home directory')
    if scope is not None and (not isinstance(scope, list) or any(not isinstance(p, str) or not p or p.startswith('/') or '..' in p.split('/') for p in scope)):
        raise TargetError('Scope must contain relative globs')
    top = git_bytes(root, 'rev-parse', '--show-toplevel', optional=True)
    # A nested directory retains its explicit scope rather than scanning its parent.
    kind = 'git' if top and Path(os.fsdecode(top.rstrip(b'\n'))).resolve() == root else 'directory'
    revision = None
    dirty = False
    if kind == 'git':
        rev = git_bytes(root, 'rev-parse', '--verify', 'HEAD^{commit}', optional=True)
        revision = rev.decode('ascii').strip() if rev else None
        dirty = bool(git_bytes(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all'))
    if (base is not None or head is not None or mode == 'diff') and kind != 'git':
        raise TargetError('Diff requires a Git repository')
    def commit(value):
        if not isinstance(value, str) or not value or value.startswith('-') or '\x00' in value:
            raise TargetError('Invalid revision')
        return git_bytes(root, 'rev-parse', '--verify', '--end-of-options', value + '^{commit}').decode('ascii').strip()
    base_sha = commit(base or 'HEAD') if mode == 'diff' or base is not None or head is not None else None
    head_sha = commit(head) if head is not None else None
    remote = git_bytes(root, 'config', '--get', 'remote.origin.url', optional=True) if kind == 'git' else None
    return {'root': str(root), 'repoKey': sha256_hex(canonical_json([str(root), os.fsdecode(remote or b'').strip()]))[:24],
            'kind': kind, 'revision': revision, 'dirty': dirty, 'base': base_sha, 'head': head_sha, 'scope': scope or []}
