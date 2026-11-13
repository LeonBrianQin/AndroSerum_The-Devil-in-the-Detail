"""Bounded reuse of sealed mining assets without changing their file layout.

Hard links share a file, not a read-only capability.  In particular, setting a
Windows read-only attribute on a link would also alter the old snapshot.  This
module never does that.  Callers must use ``assert_writable`` at write entry
points; the persisted audit protects both hard-linked and fallback-copy assets.
External processes with write access remain outside this application guard.
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
from uuid import uuid4

from androserum.facts.identity import filesystem_path, sha256_file

VERSION = 'mining-sealed-storage.v1'
AUDIT_NAME = 'storage-reuse.json'
_NEVER_REUSE = {'ledger.sqlite', 'run.json', 'report.json', 'manifest.json'}


class StorageGateError(ValueError):
    """A finite storage or asset-integrity precondition was not met."""


def _nonnegative(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(name + ' must be a nonnegative integer')
    return value


def storage_preflight(*, logical_bytes, files, free_bytes, max_copy_bytes,
                      min_free_bytes=64 * 1024 * 1024,
                      prefer_hardlinks=True, metadata_bytes_per_file=4096):
    """Reserve bounded fallback space; no claim that hard links will succeed."""
    for name, value in dict(logical_bytes=logical_bytes, files=files,
                            free_bytes=free_bytes, max_copy_bytes=max_copy_bytes,
                            min_free_bytes=min_free_bytes,
                            metadata_bytes_per_file=metadata_bytes_per_file).items():
        _nonnegative(value, name)
    metadata = files * metadata_bytes_per_file
    copy_reserve = min(logical_bytes, max_copy_bytes) if prefer_hardlinks else logical_bytes
    reasons = []
    if not prefer_hardlinks and logical_bytes > max_copy_bytes:
        reasons.append('forced_copy_exceeds_explicit_copy_budget')
    if free_bytes < min_free_bytes + metadata + copy_reserve:
        reasons.append('insufficient_free_space_for_declared_reserve')
    return dict(state='blocked' if reasons else 'ready', reasons=reasons,
                logical_bytes=logical_bytes, files=files, free_bytes=free_bytes,
                max_copy_bytes=max_copy_bytes, copy_reserve_bytes=copy_reserve,
                metadata_reserve_bytes=metadata, min_free_bytes=min_free_bytes,
                required_free_bytes=min_free_bytes + metadata + copy_reserve,
                hardlink_success_assumed=False,
                gate_applies_to='this_continuation_reuse_only_not_whole_stage')


def _regular(path):
    # Junctions/reparse points and symlinks could escape the declared asset tree.
    for ancestor in [path, *path.parents]:
        attributes = getattr(ancestor.lstat(), 'st_file_attributes', 0)
        if (ancestor.is_symlink() or
                attributes & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise StorageGateError('Symlink/junction assets cannot be reused: ' + str(path))
    if not path.is_file():
        raise StorageGateError('Expected a sealed regular file: ' + str(path))


def _relative_asset(name):
    p = PurePosixPath(name)
    if (p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name
            or not (name == 'source-visible.json' or
                    (len(p.parts) > 1 and p.parts[0] == 'requests'))
            or p.name in _NEVER_REUSE):
        raise StorageGateError('Not an allowed sealed asset: ' + name)
    return p


def _asset_inventory(parent):
    manifest_path = parent / 'manifest.json'
    _regular(manifest_path)
    manifest = json.loads(manifest_path.read_text('utf-8'))
    rows = manifest.get('files')
    if not isinstance(rows, dict) or 'source-visible.json' not in rows:
        raise StorageGateError('Parent manifest must seal source-visible.json and request files')
    names = ['source-visible.json'] + sorted(k for k in rows if k.startswith('requests/'))
    # Refuse unsealed files rather than silently omitting a request receipt.
    actual = {p.relative_to(parent).as_posix() for p in (parent / 'requests').rglob('*') if p.is_file()}
    if actual != {n for n in names if n.startswith('requests/')}:
        raise StorageGateError('Request tree and sealed manifest differ')
    inventory = []
    for name in names:
        _relative_asset(name)
        source = parent.joinpath(*PurePosixPath(name).parts)
        _regular(source)
        expected = rows[name]
        size = source.stat().st_size
        digest = sha256_file(source)
        if expected.get('bytes') != size or expected.get('sha256') != digest:
            raise StorageGateError('Sealed parent asset differs: ' + name)
        inventory.append(dict(path=name, bytes=size, sha256=digest))
    return inventory, sha256_file(manifest_path)


def reuse_sealed_assets(parent, destination, *, max_copy_bytes=0,
                        min_free_bytes=64 * 1024 * 1024,
                        prefer_hardlinks=True):
    """Reuse only verified source-visible/requests; return a persisted audit.

    A failed hard link may use an explicit bounded copy allowance, never an
    implicit unlimited fallback.  Existing destination files are never opened
    for writing.  The caller still owns independent ledger backup/copy and all
    fresh run/report/manifest files.
    """
    parent = filesystem_path(parent)
    destination = filesystem_path(destination)
    if destination == parent or destination.is_relative_to(parent) or parent.is_relative_to(destination):
        raise StorageGateError('Parent and child storage trees must be disjoint')
    inventory, manifest_sha256 = _asset_inventory(parent)
    destination.mkdir(parents=True, exist_ok=True)
    audit_path = destination / AUDIT_NAME
    if audit_path.exists() or (destination / 'source-visible.json').exists() or (destination / 'requests').exists():
        raise StorageGateError('Continuation assets/audit already exist')
    gate = storage_preflight(logical_bytes=sum(r['bytes'] for r in inventory), files=len(inventory),
        free_bytes=shutil.disk_usage(destination).free, max_copy_bytes=max_copy_bytes,
        min_free_bytes=min_free_bytes, prefer_hardlinks=prefer_hardlinks)
    if gate['state'] != 'ready':
        raise StorageGateError('Storage preflight blocked: ' + ','.join(gate['reasons']))
    stage = destination / ('.reuse-stage-' + uuid4().hex)
    stage.mkdir()
    published = []
    copied = 0
    result = []
    try:
        for row in inventory:
            relative = PurePosixPath(row['path'])
            source = parent.joinpath(*relative.parts)
            target = stage.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            failure = None
            if prefer_hardlinks:
                try:
                    os.link(source, target)
                    mode = 'hardlink'
                except OSError as error:
                    failure = dict(type=type(error).__name__, errno=error.errno,
                                   winerror=getattr(error, 'winerror', None), message=str(error))
            if not prefer_hardlinks or failure is not None:
                if copied + row['bytes'] > max_copy_bytes:
                    raise StorageGateError('Hardlink unavailable; explicit fallback-copy budget exhausted: ' + row['path'])
                if shutil.disk_usage(destination).free < min_free_bytes + row['bytes'] + 4096:
                    raise StorageGateError('Fallback copy would cross minimum free-space reserve')
                # copyfile with exclusive destination creation; never overwrite.
                with source.open('rb') as reader, target.open('xb') as writer:
                    shutil.copyfileobj(reader, writer, 1024 * 1024)
                copied += row['bytes']
                mode = 'copy'
            source_stat, target_stat = source.stat(), target.stat()
            same = os.path.samestat(source_stat, target_stat)
            if sha256_file(target) != row['sha256'] or sha256_file(source) != row['sha256']:
                raise StorageGateError('Asset changed during reuse: ' + row['path'])
            if (mode == 'hardlink') != same:
                raise StorageGateError('Storage identity does not match recorded reuse mode')
            result.append(dict(row, mode=mode, hardlink_error=failure,
                               same_file=same, source_links=source_stat.st_nlink,
                               target_links=target_stat.st_nlink))
        if sha256_file(parent / 'manifest.json') != manifest_sha256:
            raise StorageGateError('Parent manifest changed during reuse')
        audit = dict(schema_version=VERSION, parent=str(parent),
            parent_manifest_sha256=manifest_sha256, immutable_paths=[r['path'] for r in result],
            files=result, preflight=gate, logical_reused_bytes=sum(r['bytes'] for r in result),
            new_content_bytes=copied, hardlink_bytes=sum(r['bytes'] for r in result if r['mode']=='hardlink'),
            immutability='application_write_guard_required; no_old_inode_attribute_changes',
            mutable_ledger='always_independent_copy_or_sqlite_backup')
        (stage / AUDIT_NAME).write_text(json.dumps(audit, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        for name in ('source-visible.json', 'requests', AUDIT_NAME):
            source = stage / name
            if source.exists():
                target = destination / name
                if target.exists():
                    raise StorageGateError('Destination appeared during asset publication')
                source.rename(target)
                published.append(target)
        return audit
    except BaseException:
        # Only paths created by this call can be removed; old snapshots are untouched.
        for path in reversed(published):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        raise
    finally:
        shutil.rmtree(stage)


def assert_writable(path, *, segment_root):
    """Reject writes to inherited assets, aliases and storage audit itself."""
    root = filesystem_path(segment_root)
    target = filesystem_path(path)
    if not target.is_relative_to(root):
        raise StorageGateError('Write target lies outside the current segment')
    if target == root:
        raise StorageGateError('The current segment root cannot be overwritten')
    relative = target.relative_to(root).as_posix()
    if relative == AUDIT_NAME:
        raise StorageGateError('Storage audit is immutable')
    audit_path = root / AUDIT_NAME
    if audit_path.exists():
        audit = json.loads(audit_path.read_text('utf-8'))
        protected = set(audit['immutable_paths'])
        if relative in protected or any(name.startswith(relative + '/') for name in protected):
            raise StorageGateError('Write to inherited immutable asset rejected: ' + relative)
    if target.exists() and (target.is_symlink() or (target.is_file() and target.stat().st_nlink > 1)):
        raise StorageGateError('Write to linked/aliased asset rejected: ' + relative)
    return target


def write_new_text(path, value, *, segment_root, encoding='utf-8'):
    target = assert_writable(path, segment_root=segment_root)
    with target.open('x', encoding=encoding) as writer:
        writer.write(value)


def copy_mutable_ledger(source, destination, *, min_free_bytes=64 * 1024 * 1024):
    """Byte copy only a closed/checkpointed ledger, never a hard link.

    For a live SQLite connection the caller must use SQLite's backup API
    instead.  A detected WAL/journal sidecar refuses this byte-copy route.
    """
    _nonnegative(min_free_bytes, 'min_free_bytes')
    source, destination = filesystem_path(source), filesystem_path(destination)
    if source.name != 'ledger.sqlite' or destination.name != 'ledger.sqlite':
        raise StorageGateError('This copy boundary only accepts ledger.sqlite')
    _regular(source)
    if any(Path(str(source)+suffix).exists() for suffix in ('-wal', '-journal')):
        raise StorageGateError('Ledger sidecar present; use SQLite backup')
    if destination.exists():
        raise StorageGateError('Ledger destination already exists')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(destination.parent).free < source.stat().st_size + min_free_bytes:
        raise StorageGateError('Insufficient free space for independent ledger copy')
    with source.open('rb') as reader, destination.open('xb') as writer:
        shutil.copyfileobj(reader, writer, 1024 * 1024)
    if os.path.samefile(source, destination) or sha256_file(source) != sha256_file(destination):
        destination.unlink()
        raise StorageGateError('Ledger copy is not independent and byte-identical')
    return dict(mode='independent_copy', bytes=destination.stat().st_size,
                sha256=sha256_file(destination), same_file=False)
