"""Checked inert storage identities; payloads here are harmless fixture text."""
import hashlib
import json
import zipfile
from pathlib import Path
import pytest

from androserum.facts.identity import sha256_file
from androserum.facts.store import EvidenceFile, read_evidence_file, copy_evidence_storage


def descriptor(root, data=b'harmless inert evidence fixture'):
    source = root / 'original.apk'
    with zipfile.ZipFile(source, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('classes.dex', data)
    container_sha = sha256_file(source)
    container = root / 'evidence/source-apk' / (container_sha + '.apk')
    container.parent.mkdir(parents=True); source.rename(container)
    content_sha = hashlib.sha256(data).hexdigest()
    item = EvidenceFile(archive_entry='classes.dex', sha256=content_sha, bytes=len(data),
                        path=f'evidence/apk-entry-v1/{content_sha}.json')
    path = root / item.path; path.parent.mkdir(parents=True)
    value = {'schema_version': 'apk-entry-evidence.v1', 'container_path': f'evidence/source-apk/{container_sha}.apk',
             'container_sha256': container_sha, 'archive_entries': ['classes.dex'],
             'content_sha256': content_sha, 'content_bytes': len(data)}
    path.write_text(json.dumps(value), 'utf-8')
    return item, value, container


def test_apk_reference_reconstructs_in_memory_and_copy_preserves_container(tmp_path):
    source = tmp_path / 'source'; source.mkdir()
    item, value, container = descriptor(source)
    assert read_evidence_file(source, item) == b'harmless inert evidence fixture'
    destination = tmp_path / 'copy'
    copy_evidence_storage(source, destination, item)
    assert read_evidence_file(destination, item) == read_evidence_file(source, item)
    assert not (destination / 'classes.dex').exists()
    assert not (destination / 'evidence' / item.sha256).exists()
    assert (destination / value['container_path']).read_bytes() == container.read_bytes()


def test_wrong_container_and_escaping_descriptor_are_rejected(tmp_path):
    item, value, container = descriptor(tmp_path)
    value['container_path'] = '../outside.apk'
    (tmp_path / item.path).write_text(json.dumps(value), 'utf-8')
    with pytest.raises(ValueError, match='identity'):
        read_evidence_file(tmp_path, item)
    value['container_path'] = f"evidence/source-apk/{value['container_sha256']}.apk"
    (tmp_path / item.path).write_text(json.dumps(value), 'utf-8')
    container.write_bytes(b'changed container')
    with pytest.raises(ValueError, match='checksum'):
        read_evidence_file(tmp_path, item)


def test_original_raw_default_remains_supported(tmp_path):
    data = b'ordinary analysis JSON evidence'
    digest = hashlib.sha256(data).hexdigest()
    item = EvidenceFile(archive_entry='analysis/test.json', sha256=digest, bytes=len(data), path='evidence/' + digest)
    (tmp_path / 'evidence').mkdir(); (tmp_path / item.path).write_bytes(data)
    assert read_evidence_file(tmp_path, item) == data
    (tmp_path / item.path).write_bytes(data + b' changed')
    with pytest.raises(ValueError, match='checksum'):
        read_evidence_file(tmp_path, item)
