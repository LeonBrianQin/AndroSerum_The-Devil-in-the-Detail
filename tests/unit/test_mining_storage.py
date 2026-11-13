import json
import os
from pathlib import Path

import pytest

from androserum.facts.identity import sha256_file
from androserum.mining_storage import (StorageGateError, assert_writable,
    copy_mutable_ledger, reuse_sealed_assets, storage_preflight, write_new_text)


def sealed(tmp_path):
    root = tmp_path / 'parent'
    (root / 'requests/000').mkdir(parents=True)
    (root / 'source-visible.json').write_text('{"visible": true}', encoding='utf-8')
    (root / 'requests/000/request.json').write_text('{"request": 1}', encoding='utf-8')
    (root / 'ledger.sqlite').write_bytes(b'closed-ledger-fixture')
    (root / 'run.json').write_text('{}', encoding='utf-8')
    rows = {p.relative_to(root).as_posix(): {'sha256': sha256_file(p), 'bytes': p.stat().st_size}
            for p in root.rglob('*') if p.is_file()}
    (root / 'manifest.json').write_text(json.dumps({'files': rows}), encoding='utf-8')
    return root


def test_real_hardlink_guard_and_independent_ledger(tmp_path):
    parent = sealed(tmp_path)
    before = {p: (sha256_file(p), p.stat().st_mode, p.stat().st_mtime_ns)
              for p in parent.rglob('*') if p.is_file()}
    child = tmp_path / 'child'
    audit = reuse_sealed_assets(parent, child, min_free_bytes=0)
    assert audit['new_content_bytes'] == 0
    assert all(row['mode'] == 'hardlink' and row['target_links'] >= 2 for row in audit['files'])
    assert not (child / 'ledger.sqlite').exists()
    for relative in audit['immutable_paths']:
        assert os.path.samefile(parent / relative, child / relative)
        with pytest.raises(StorageGateError, match='immutable'):
            write_new_text(child / relative, 'replacement', segment_root=child)
    with pytest.raises(StorageGateError):
        assert_writable(child / 'requests', segment_root=child)
    copied = copy_mutable_ledger(parent / 'ledger.sqlite', child / 'ledger.sqlite', min_free_bytes=0)
    assert copied['same_file'] is False
    (child / 'ledger.sqlite').write_bytes(b'new-ledger')
    assert (parent / 'ledger.sqlite').read_bytes() == b'closed-ledger-fixture'
    write_new_text(child / 'report.json', '{}', segment_root=child)
    assert not (child / 'run.json').exists()
    assert not (child / 'manifest.json').exists()
    for path, marker in before.items():
        assert (sha256_file(path), path.stat().st_mode, path.stat().st_mtime_ns) == marker


def test_link_failure_bounded_explicit_copy_and_guard(tmp_path, monkeypatch):
    parent = sealed(tmp_path)
    def unavailable(*args, **kwargs):
        raise OSError(18, 'cross-device link')
    monkeypatch.setattr(os, 'link', unavailable)
    with pytest.raises(StorageGateError, match='budget exhausted'):
        reuse_sealed_assets(parent, tmp_path / 'blocked', min_free_bytes=0)
    assert not list((tmp_path / 'blocked').glob('.reuse-stage-*'))
    child = tmp_path / 'copied'
    audit = reuse_sealed_assets(parent, child, max_copy_bytes=1000, min_free_bytes=0)
    assert all(row['mode'] == 'copy' and row['hardlink_error']['errno'] == 18 for row in audit['files'])
    assert audit['new_content_bytes'] == audit['logical_reused_bytes']
    assert not os.path.samefile(parent / 'source-visible.json', child / 'source-visible.json')
    with pytest.raises(StorageGateError, match='immutable'):
        write_new_text(child / 'source-visible.json', '{}', segment_root=child)


def test_resource_gate_is_finite_and_precedes_copy(tmp_path):
    parent = sealed(tmp_path)
    child = tmp_path / 'blocked'
    with pytest.raises(StorageGateError, match='preflight blocked'):
        reuse_sealed_assets(parent, child, prefer_hardlinks=False, max_copy_bytes=1, min_free_bytes=0)
    assert list(child.iterdir()) == []
    gate = storage_preflight(logical_bytes=100, files=2, free_bytes=100,
                             max_copy_bytes=100, min_free_bytes=0)
    assert gate['state'] == 'blocked'
    assert gate['required_free_bytes'] == 100 + 8192


def test_seal_mismatch_and_unsealed_requests_rejected(tmp_path):
    parent = sealed(tmp_path)
    (parent / 'requests/000/unsealed.txt').write_text('new')
    with pytest.raises(StorageGateError, match='tree and sealed manifest differ'):
        reuse_sealed_assets(parent, tmp_path / 'child')
    (parent / 'requests/000/unsealed.txt').unlink()
    (parent / 'source-visible.json').write_text('changed')
    with pytest.raises(StorageGateError, match='differs'):
        reuse_sealed_assets(parent, tmp_path / 'child')


def test_ledger_never_linked_and_existing_assets_never_overwritten(tmp_path):
    parent = sealed(tmp_path)
    child = tmp_path / 'child'
    reuse_sealed_assets(parent, child, min_free_bytes=0)
    with pytest.raises(StorageGateError, match='already exist'):
        reuse_sealed_assets(parent, child, min_free_bytes=0)
    with pytest.raises(StorageGateError, match='only accepts ledger'):
        copy_mutable_ledger(parent / 'source-visible.json', child / 'ledger.sqlite')
    (parent / 'ledger.sqlite-wal').write_bytes(b'live')
    with pytest.raises(StorageGateError, match='backup'):
        copy_mutable_ledger(parent / 'ledger.sqlite', child / 'ledger.sqlite')
    with pytest.raises(StorageGateError, match='disjoint'):
        reuse_sealed_assets(parent, parent / 'bad')


def test_alias_write_and_audit_write_rejected(tmp_path):
    parent = sealed(tmp_path)
    child = tmp_path / 'child'
    reuse_sealed_assets(parent, child, min_free_bytes=0)
    os.link(child / 'source-visible.json', child / 'alias.json')
    with pytest.raises(StorageGateError, match='aliased'):
        assert_writable(child / 'alias.json', segment_root=child)
    with pytest.raises(StorageGateError, match='audit'):
        assert_writable(child / 'storage-reuse.json', segment_root=child)
    with pytest.raises(StorageGateError, match='outside'):
        assert_writable(parent / 'source-visible.json', segment_root=child)
