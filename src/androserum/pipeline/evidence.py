"""Inert evidence storage for static APK analysis; no native code is executed.

Original APK containers and checked JSON descriptors preserve the archive
entry, SHA-256 and original byte length used by fact-store.v1. A previous
base64 attempt was also quarantined and is retained only as failed evidence.
"""
import hashlib
from pathlib import Path
import shutil
from uuid import uuid4
import zipfile

from androserum.facts.extractor import ExtractionResult
from androserum.facts.identity import archive_path, filesystem_path, sha256_file
from androserum.facts.io import dump_facts, load_facts, loads_facts
from androserum.facts.store import EvidenceFile, read_evidence_file
from androserum.encoding.runner import read, write


def write_encoded_extraction(result: ExtractionResult, output_root: str | Path, *, input_apk=None) -> Path:
    """Write original-APK references; never materialize an extracted DEX.

    The function name is retained for the initial integration. The production
    codec is apk-entry-v1, not base64: base64 was also quarantined by Defender.
    JSON analysis/rule artifacts retain their existing ordinary byte storage.
    """
    loads_facts(result.facts.model_dump_json())
    for digest, data in result.blobs.items():
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Evidence content does not match its SHA-256 identity')
    if any(digest not in result.blobs for digest in result.entry_digests.values()):
        raise ValueError('Evidence manifest refers to an absent blob')
    for entry in result.entry_digests:
        archive_path(entry)
    dex_entries = [entry for entry in result.entry_digests if entry.lower().endswith('.dex')]
    descriptors = {}
    apk = filesystem_path(input_apk) if input_apk is not None else None
    if dex_entries:
        if apk is None or sha256_file(apk) != result.facts.run.apk_sha256:
            raise ValueError('Original matching APK container is required for inert DEX evidence')
        with zipfile.ZipFile(apk) as archive:
            names = archive.namelist()
            for entry in dex_entries:
                digest = result.entry_digests[entry]
                if names.count(entry) != 1 or archive.read(entry) != result.blobs[digest]:
                    raise ValueError('Original APK cannot supply exact DEX evidence: ' + entry)
                descriptors.setdefault(digest, []).append(entry)
    if any(data.startswith(b'dex\n') and digest not in descriptors for digest, data in result.blobs.items()):
        raise ValueError('DEX blob has no checked original APK entry; refusing a raw write')
    base = filesystem_path(output_root)
    final = base / result.facts.run.apk_sha256 / result.facts.run.run_id.replace(':', '_')
    final.relative_to(base)
    if final.exists():
        raise FileExistsError('Accepted run already exists: ' + str(final))
    staging = final.with_name('.building_encoded_' + uuid4().hex)
    staging.mkdir(parents=True, exist_ok=False)
    evidence = staging / 'evidence'; evidence.mkdir()
    if descriptors:
        container = evidence / 'source-apk' / (result.facts.run.apk_sha256 + '.apk')
        container.parent.mkdir()
        shutil.copyfile(apk, container)
    for digest, data in sorted(result.blobs.items()):
        if digest in descriptors:
            target = evidence / 'apk-entry-v1' / (digest + '.json')
            target.parent.mkdir(exist_ok=True)
            write(target, {'schema_version': 'apk-entry-evidence.v1',
                  'container_path': 'evidence/source-apk/' + result.facts.run.apk_sha256 + '.apk',
                  'container_sha256': result.facts.run.apk_sha256,
                  'archive_entries': sorted(descriptors[digest]), 'content_sha256': digest, 'content_bytes': len(data)})
        else:
            (evidence / digest).write_bytes(data)
    files = [{'archive_entry': entry, 'sha256': digest,
              'path': f'evidence/apk-entry-v1/{digest}.json' if digest in descriptors else f'evidence/{digest}',
              'bytes': len(result.blobs[digest])} for entry, digest in sorted(result.entry_digests.items())]
    dump_facts(result.facts, staging / 'facts.json')
    write(staging / 'summary.json', result.summary)
    write(staging / 'run.json', result.facts.run.model_dump(mode='json'))
    write(staging / 'manifest.json', {'schema_version': 'fact-evidence.v1', 'run_ref': result.facts.run.run_id,
          'files': files, 'facts_sha256': sha256_file(staging / 'facts.json')})
    write(staging / 'evidence-storage.json', {'schema_version': 'inert-evidence-storage.v1',
          'codec': 'original-apk-entry-v1; raw non-code analysis artifacts', 'original_identity_unchanged': True,
          'raw_code_files_written': False, 'decoding': 'checked read-only bytes in memory',
          'apk_execution': False, 'security_settings_changed': False})
    staging.rename(final)
    return final


def recover_failed_extraction(failed_bundle_dir, input_apk, output):
    """Repackage existing facts and recover only missing original ZIP entries.

    No static analysis is rerun and no quarantined file is restored. Remaining
    evidence is verified as-is. Missing analysis artifacts cannot be invented
    from the APK and cause a clear failure.
    """
    failed = filesystem_path(failed_bundle_dir)
    apk = filesystem_path(input_apk)
    manifest = read(failed / 'manifest.json')
    facts = load_facts(failed / 'facts.json')
    if (manifest.get('schema_version') != 'fact-evidence.v1' or manifest['run_ref'] != facts.run.run_id or
            sha256_file(failed / 'facts.json') != manifest['facts_sha256']):
        raise ValueError('Failed source fact package identity differs')
    if sha256_file(apk) != facts.run.apk_sha256:
        raise ValueError('Recovery APK does not match the existing fact run')
    files = [EvidenceFile.model_validate(item) for item in manifest['files']]
    if len({item.archive_entry for item in files}) != len(files):
        raise ValueError('Duplicate original evidence entries')
    blobs, entries, restored = {}, {}, []
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        for item in files:
            path = filesystem_path(failed / item.path)
            if not path.is_relative_to(failed):
                raise ValueError('Evidence path escapes source package')
            if path.exists():
                data = read_evidence_file(failed, item)
            else:
                if names.count(item.archive_entry) != 1:
                    raise ValueError('Missing evidence is not one unambiguous original APK entry: ' + item.archive_entry)
                metadata = archive.getinfo(item.archive_entry)
                if metadata.file_size != item.bytes:
                    raise ValueError('Recovery ZIP entry length differs: ' + item.archive_entry)
                data = archive.read(item.archive_entry)
                if len(data) != item.bytes or hashlib.sha256(data).hexdigest() != item.sha256:
                    raise ValueError('Recovery ZIP entry identity differs: ' + item.archive_entry)
                restored.append({'archive_entry': item.archive_entry, 'sha256': item.sha256, 'bytes': item.bytes,
                                 'source': 'original APK ZIP, read into memory only'})
            if item.sha256 in blobs and blobs[item.sha256] != data:
                raise ValueError('Conflicting shared content identity')
            blobs[item.sha256] = data
            entries[item.archive_entry] = item.sha256
    result = ExtractionResult(facts=facts, summary=read(failed / 'summary.json'), blobs=blobs, entry_digests=entries)
    destination = write_encoded_extraction(result, output, input_apk=apk)
    write(destination / 'recovery.json', {'schema_version': 'existing-facts-evidence-recovery.v1',
          'source_failed_package': str(failed), 'source_manifest_sha256': sha256_file(failed / 'manifest.json'),
          'input_apk_sha256': facts.run.apk_sha256, 'facts_sha256_before': manifest['facts_sha256'],
          'facts_sha256_after': sha256_file(destination / 'facts.json'), 'recovered_missing_entries': restored,
          'original_failed_package_preserved': True, 'static_analysis_rerun': False,
          'quarantined_files_restored': False, 'apk_execution': False, 'security_settings_changed': False})
    return destination
