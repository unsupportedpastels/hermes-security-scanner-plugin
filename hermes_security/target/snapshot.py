"""Snapshot identities and no-filter Git diff manifests."""
import os
from ..canonical import canonical_json, sha256_hex
from ..errors import TargetError
from .resolve import git_bytes, resolve_target
from .inventory import build_inventory, validate_path
from .policy import matches_scope


def snapshot_digest(inventory, target):
    payload = {'files': sorted((f['path'], f['sha256']) for f in inventory['files']),
               'revision': target.get('revision'), 'base': target.get('base'), 'head': target.get('head'),
               'scope': sorted(target.get('scope', [])),
               'excluded': sorted(inventory.get('excluded', []), key=lambda e: (e['path'], e['reason'])),
               'truncated': inventory.get('truncated', False)}
    return 'sha256:' + sha256_hex(canonical_json(payload))


def is_snapshot_current(target, digest):
    try:
        current = resolve_target(target['root'], scope=target.get('scope'), base=target.get('base'), head=target.get('head'))
        return snapshot_digest(build_inventory(current), current) == digest
    except (TargetError, OSError, ValueError): return False


def diff_manifest(target):
    if target['kind'] != 'git': raise TargetError('Diff requires Git')
    root = target['root']; base = target.get('base') or target.get('revision'); head = target.get('head')
    if not base: raise TargetError('Diff requires an existing base commit')
    # --no-ext-diff and --no-textconv prohibit repository-supplied executable helpers.
    args = ['diff', '--name-status', '-z', '--no-renames', '--no-ext-diff', '--no-textconv', base]
    if head: args.append(head)
    args.append('--')
    fields = git_bytes(root, *args).split(b'\x00')
    changed = set(); deleted = set(); added = set()
    for i in range(0, len(fields)-1, 2):
        status, raw = fields[i:i+2]
        path = os.fsdecode(raw)
        try: validate_path(path)
        except TargetError: continue
        if not matches_scope(path, target.get('scope', [])): continue
        if status == b'D': deleted.add(path)
        elif status == b'A': added.add(path)
        else: changed.add(path)
    if head is None:
        for raw in git_bytes(root, 'ls-files', '-z', '--others', '--exclude-standard').split(b'\x00'):
            if not raw: continue
            path = os.fsdecode(raw)
            try: validate_path(path)
            except TargetError: continue
            if matches_scope(path, target.get('scope', [])): added.add(path)
    return {'base': base, 'head': head, 'changed': sorted(changed), 'deleted': sorted(deleted), 'added': sorted(added)}
