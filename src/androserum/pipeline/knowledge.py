"""Portable storage for explicit new history freezes, plus legacy read support."""
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
from uuid import uuid4
import json
import shutil
import sqlite3

from androserum.encoding.models import EncodingConfig
from androserum.encoding.runner import read, write
from androserum.facts.identity import canonical_json, filesystem_path, fingerprint, sha256_file
from androserum.knowledge.store import SCHEMA, apk_identity, readonly, safe_asset
from .approval import inventory, verify_files, load_frozen
from .encoding import verify_encoding

VERSION = 'reviewed-behavior-knowledge.v1'


def create_snapshot(encoding_run, output, *, model_dir, background=None):
    """Explicit history admission; passing a query encoding is an error."""
    run = filesystem_path(encoding_run)
    verify_encoding(run, model_dir)
    policy, entries = load_frozen(run / 'audit/freeze')
    if policy['role'] != 'history':
        raise ValueError('Query freeze cannot enter history; issue a separately reviewed history freeze')
    rows = read(run / 'rows.json')
    identities = {entry['source_apk_sha256']: apk_identity(entry) for entry in entries}
    background = background or {}
    if set(background) - set(identities):
        raise ValueError('Background refers to an unknown APK')
    output = filesystem_path(output); output.mkdir(parents=True, exist_ok=True)
    token = uuid4().hex
    building, final = output / ('.building_' + token), output / ('knowledge_' + token)
    building.mkdir()
    shutil.copytree(run, building / 'encoding')
    write(building / 'apk-identities.json', {'identities': identities, 'source_background': background})
    write(building / 'provenance.json', {'schema_version': VERSION, 'source_encoding_run': str(run),
          'source_encoding_manifest_sha256': sha256_file(run / 'manifest.json'),
          'source_freeze_id': read(run / 'audit/freeze/manifest.json')['freeze_id'],
          'frozen_qualified_refs': policy['qualified_refs'], 'excluded_candidate_count': policy['excluded_count'],
          'retrieval_quality_validated': False, 'source_labels_inherited_by_bcs': False,
          'query_roles': {'visible_evidence': 'actually displayed accepted source packets only',
                          'ledger_and_backlinks': 'audit only; do not grant model visibility'}})
    with closing(sqlite3.connect(building / 'knowledge.sqlite')) as db:
        db.executescript(SCHEMA)
        db.execute('INSERT INTO metadata VALUES (?,?)', ('store_version', canonical_json(VERSION)))
        for sha, identity in identities.items():
            db.execute('INSERT INTO apks VALUES (?,?,?)', (sha, canonical_json(identity), canonical_json(background.get(sha, {}))))
        for entry, row in zip(entries, rows):
            ref, bc = entry['qualified_ref'], entry['bc']
            db.execute('INSERT INTO bcs VALUES (?,?,?,?,?,?,?)',
                       (ref, bc['bc_id'], entry['source_case'], entry['ledger_revision'], row['bc_vector_row'],
                        'encoding/' + row['directory'], canonical_json(bc)))
            db.execute('INSERT INTO apk_bc_edges VALUES (?,?,?)', (entry['source_apk_sha256'], ref, 'origin'))
            for key, action in entry['actions'].items():
                db.execute('INSERT INTO actions VALUES (?,?,?)', (ref, key, canonical_json(action)))
            for relation in bc['relations']:
                db.execute('INSERT INTO action_relations VALUES (?,?,?)', (ref, relation['link_id'], canonical_json(relation)))
            for handle, evidence in entry['model_visible_evidence']['registry'].items():
                db.execute('INSERT INTO visible_evidence VALUES (?,?,?,?,?)',
                           (ref, handle, evidence['category'], evidence.get('record_ref'), canonical_json(evidence)))
            ledger = building / 'ledgers' / (row['directory'] + '.sqlite')
            ledger.parent.mkdir(exist_ok=True)
            shutil.copyfile(filesystem_path(entry['source_mining_run']) / 'ledger.sqlite', ledger)
        db.commit()
    # sqlite3.Connection.__exit__ commits but deliberately does not close.
    # Windows requires all handles closed before publishing the directory.
    files = inventory(building)
    write(building / 'manifest.json', {'schema_version': 'reviewed-behavior-knowledge-snapshot.v1',
          'store_version': VERSION, 'state': 'published', 'created_utc': datetime.now(timezone.utc).isoformat(),
          'snapshot_id': fingerprint(files), 'apk_count': len(identities), 'bc_count': len(entries),
          'origin_edge_count': len(entries), 'retrieval_quality_validated': False, 'files': files})
    verify_snapshot(building)
    try:
        building.rename(final)
    except OSError as error:
        write(building / 'failure.json', {'state': 'failed_not_published', 'error': str(error)})
        raise
    return final


def verify_snapshot(directory):
    import numpy as np
    directory = filesystem_path(directory)
    raw = read(directory / 'manifest.json')
    if raw.get('store_version') != VERSION:
        from androserum.knowledge.store import verify_snapshot as legacy_verify
        return legacy_verify(directory)
    manifest = verify_files(directory)
    if manifest['snapshot_id'] != fingerprint(manifest['files']) or manifest['state'] != 'published':
        raise ValueError('Generic history identity differs')
    run = directory / 'encoding'; verify_files(run)
    provenance = read(directory / 'provenance.json')
    policy, entries = load_frozen(run / 'audit/freeze', verify_sources=False)
    if policy['role'] != 'history' or policy['qualified_refs'] != provenance['frozen_qualified_refs']:
        raise ValueError('History contains unapproved query instances')
    if sha256_file(run / 'manifest.json') != provenance['source_encoding_manifest_sha256']:
        raise ValueError('Source encoding manifest differs')
    if read(run / 'audit/approved-pool.json')['entries'] != entries:
        raise ValueError('Stored native entries differ from frozen review')
    vectors = np.load(run / 'bc_vectors.npy', allow_pickle=False)
    rows = read(run / 'rows.json')
    if (vectors.shape != (len(entries), 768) or vectors.dtype != np.float32 or not np.isfinite(vectors).all() or
            [r['qualified_ref'] for r in rows] != policy['qualified_refs'] or manifest['bc_count'] != len(entries)):
        raise ValueError('Generic history vector identities differ')
    counts = {}
    with readonly(directory / 'knowledge.sqlite') as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchall():
            raise ValueError('Generic history database integrity failure')
        for table in ['apks', 'bcs', 'apk_bc_edges', 'actions', 'action_relations', 'visible_evidence']:
            counts[table] = db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
        identities = read(directory / 'apk-identities.json')
        found_apks = {a: (json.loads(b), json.loads(c)) for a, b, c in db.execute('SELECT * FROM apks')}
        expected_apks = {sha: (identity, identities['source_background'].get(sha, {}))
                         for sha, identity in identities['identities'].items()}
        if found_apks != expected_apks or set(found_apks) != {e['source_apk_sha256'] for e in entries}:
            raise ValueError('History APK identity/background differs')
        if counts['bcs'] != len(entries) or counts['apk_bc_edges'] != len(entries):
            raise ValueError('Generic history origin inventory differs')
        for i, (entry, row) in enumerate(zip(entries, rows)):
            ref, bc = entry['qualified_ref'], entry['bc']
            found = db.execute('SELECT * FROM bcs WHERE qualified_ref=?', (ref,)).fetchone()
            expected = (ref, bc['bc_id'], entry['source_case'], entry['ledger_revision'], i,
                        'encoding/' + row['directory'], canonical_json(bc))
            if found != expected:
                raise ValueError('Stored native BC differs')
            if db.execute('SELECT * FROM apk_bc_edges WHERE qualified_ref=?', (ref,)).fetchone() != (entry['source_apk_sha256'], ref, 'origin'):
                raise ValueError('Wrong APK--BC origin')
            for table, column, expected_records in [
                ('actions', 'action_id', entry['actions']),
                ('action_relations', 'link_id', {r['link_id']: r for r in bc['relations']}),
                ('visible_evidence', 'handle', entry['model_visible_evidence']['registry'])]:
                found_records = {k: json.loads(v) for k, v in db.execute(
                    'SELECT ' + column + ',payload_json FROM ' + table + ' WHERE qualified_ref=?', (ref,))}
                if found_records != expected_records:
                    raise ValueError('Stored ' + table + ' differs from approved model visibility')
            source = read(run / row['directory'] / 'audit/source.json')
            ledger = directory / 'ledgers' / (row['directory'] + '.sqlite')
            if sha256_file(ledger) != source['ledger_file_sha256']:
                raise ValueError('Copied source ledger differs')
            with readonly(ledger) as ldb:
                version = ldb.execute('SELECT payload,sha256 FROM versions WHERE revision=?', (entry['ledger_revision'],)).fetchone()
            if version is None or fingerprint(json.loads(version[0])) != version[1] or version[1] != source['ledger_state_sha256']:
                raise ValueError('Frozen source revision is not recoverable')
    if any(p.name == 'facts.sqlite' for p in directory.rglob('*')):
        raise ValueError('Full fact database must remain outside behavior history')
    return {'schema_version': 'reviewed-knowledge-verification.v1', 'status': 'passed',
            'snapshot_id': manifest['snapshot_id'], 'counts': counts, 'retrieval_quality_validated': False,
            'all_visible_evidence_exact': True, 'source_ledgers_recoverable': True,
            'external_original_sources_required_for_local_queries': False}


def query_snapshot(directory, kind, *, qualified_ref=None, apk_sha256=None, key=None, limit=100):
    directory = filesystem_path(directory)
    if read(directory / 'manifest.json').get('store_version') != VERSION:
        from androserum.knowledge.store import query_snapshot as legacy_query
        return legacy_query(directory, kind, qualified_ref=qualified_ref, apk_sha256=apk_sha256, key=key, limit=limit)
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError('Query limit must be 1..1000')
    verification = verify_snapshot(directory)
    with readonly(directory / 'knowledge.sqlite') as db:
        if kind == 'bc':
            rows = db.execute('SELECT b.qualified_ref,b.payload_json,b.vector_row,b.asset_directory,e.apk_sha256 '
                              'FROM bcs b JOIN apk_bc_edges e USING(qualified_ref) ORDER BY b.qualified_ref')
            records = [{'qualified_ref': ref, 'bc': json.loads(payload), 'vector_row': row, 'asset_directory': asset,
                        'source_apk_sha256': sha, 'source_labels_inherited': False}
                       for ref, payload, row, asset, sha in rows
                       if (qualified_ref is None or ref == qualified_ref) and (apk_sha256 is None or sha == apk_sha256)]
        elif kind == 'apk':
            records = [{'apk_sha256': sha, 'identity': json.loads(identity), 'source_background': json.loads(background)}
                       for sha, identity, background in db.execute('SELECT * FROM apks ORDER BY apk_sha256')
                       if apk_sha256 is None or sha == apk_sha256]
        elif kind in {'action', 'relation', 'evidence'}:
            if not qualified_ref:
                raise ValueError('Scoped lookup requires a BC identity')
            table, column = {'action': ('actions', 'action_id'), 'relation': ('action_relations', 'link_id'),
                             'evidence': ('visible_evidence', 'handle')}[kind]
            records = [{'key': k, 'record': json.loads(v), 'visibility_role': 'actually_displayed' if kind == 'evidence' else 'approved_native'}
                       for k, v in db.execute('SELECT ' + column + ',payload_json FROM ' + table + ' WHERE qualified_ref=? ORDER BY ' + column,
                                              (qualified_ref,)) if key is None or k == key]
        elif kind == 'audit':
            if not qualified_ref:
                raise ValueError('Audit lookup requires a BC identity')
            row = db.execute('SELECT asset_directory FROM bcs WHERE qualified_ref=?', (qualified_ref,)).fetchone()
            records = [] if not row else [{'source': read(safe_asset(directory, row[0]) / 'audit/source.json'),
                                         'role': 'archive_only_not_automatically_model_visible',
                                         'local_ledger': 'ledgers/' + Path(row[0]).name + '.sqlite'}]
        else:
            raise ValueError('Unsupported exact query kind')
    return {'schema_version': 'reviewed-knowledge-query.v1', 'snapshot_id': verification['snapshot_id'],
            'kind': kind, 'total_matches': len(records), 'records': records[:limit], 'truncated': len(records) > limit,
            'missing': not records, 'lookup_type': 'exact', 'missing_describes_index_only': True,
            'retrieval_quality_validated': False}


def load_history(snapshot):
    import numpy as np
    snapshot = filesystem_path(snapshot)
    verified = verify_snapshot(snapshot)
    entries = read(snapshot / 'encoding/audit/approved-pool.json')['entries']
    vectors = np.load(snapshot / 'encoding/bc_vectors.npy', allow_pickle=False)
    rows = [{'instance_ref': e['qualified_ref'], 'apk_sha256': e['source_apk_sha256'],
             'ledger_ref': e['source_mining_run']} for e in entries]
    return rows, vectors, verified
