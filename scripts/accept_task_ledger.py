"""Read-only integrity review and public-API replay of one bounded task ledger."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
from androserum.facts.identity import canonical_json, fingerprint, filesystem_path
from androserum.facts.io import strict_json_syntax
from androserum.tasking import TaskLedger, TaskConfig
from androserum.pipeline.tasking import GeneralTaskLedger


def _query_match(reference, packet, catalog):
    bid = reference['query_bc_id']
    side = packet['current_bcs'][bid]
    fields = ['instance_ref', 'bc', 'actions', 'registry', 'condition_semantics', 'purpose_claims', 'source_limits', 'limitations']
    version = reference.get('matching_request_schema_version',
                            'behavior-match-request.v2' if reference['proposal']['schema_version'] == 'behavior-match-proposal.v2'
                            else 'behavior-match-request.v1')
    return {'schema_version': version, 'request_id': reference['proposal']['request_id'],
            'pair_sha256': reference['pair_sha256'],
            'sides': {'query': {k: deepcopy(side[k]) for k in fields}, 'reference': deepcopy(reference['reference'])},
            'source_audit': {'query': deepcopy(catalog['bcs'][bid]['origin']), 'reference': {}},
            'rules': {'history_labels_included': False}}


def accept_ledger(ledger_path):
    path = filesystem_path(ledger_path)
    if not path.is_file():
        raise ValueError('Actual task ledger does not exist')
    # SQLite read-only connection prevents changing the reviewed source artifact.
    # The public caller can pass filesystem_path's Windows extended spelling;
    # SQLite URI parsing requires the ordinary drive/UNC authority spelling.
    uri_path = str(ledger_path)
    if uri_path.startswith('\\\\?\\UNC\\'):
        uri_path = '\\\\' + uri_path[8:]
    elif uri_path.startswith('\\\\?\\'):
        uri_path = uri_path[4:]
    plain = Path(uri_path).resolve()
    db = sqlite3.connect(plain.as_uri() + '?mode=ro', uri=True)
    db.execute('PRAGMA query_only=ON')
    checks = {}
    try:
        checks['sqlite_integrity'] = db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        metadata = {}
        for key, payload, digest in db.execute('SELECT key,payload,sha256 FROM metadata'):
            value = json.loads(payload)
            if fingerprint(value) != digest:
                raise ValueError('Metadata digest mismatch')
            metadata[key] = value
        checks['source_metadata_hashes'] = True
        versions, events = [], []
        for table, index, target in [('revisions', 'revision', versions), ('audit', 'sequence', events)]:
            expected, parent = 0, None
            for num, payload, digest, ancestor in db.execute(f'SELECT {index},payload,sha256,parent_sha256 FROM {table} ORDER BY {index}'):
                value = json.loads(payload)
                if num != expected or fingerprint(value) != digest or ancestor != parent:
                    raise ValueError('Revision/audit chain mismatch')
                target.append(value)
                expected, parent = expected+1, digest
            checks[table+'_hash_chain'] = True
        packets = {}
        for rid, payload, digest in db.execute('SELECT request_id,payload,sha256 FROM packets'):
            value = json.loads(payload)
            if fingerprint(value) != digest or value['request_id'] != rid:
                raise ValueError('Visible packet digest mismatch')
            packets[rid] = value
        checks['visible_packet_hashes'] = True
    finally:
        db.close()
    steps = []
    contract = metadata.get('proposal_contract')
    if contract is None:
        ledger_class = TaskLedger
    elif contract.get('schema_version') == 'apk-task-ledger-protocol.v2':
        ledger_class = GeneralTaskLedger
    else:
        raise ValueError('Unknown task protocol; independent replay cannot silently use v1')
    with tempfile.TemporaryDirectory(prefix='androserum-task-replay-') as task_dir:
        with ledger_class(Path(task_dir)/'replay.sqlite', metadata['identity'], config=TaskConfig.model_validate(metadata['config']), source_catalog=metadata['catalog']) as replay:
            if replay._protocol_contract() != contract:
                raise ValueError('Recorded task protocol/schema differs from independent replay')
            if replay.state() != versions[0]:
                raise ValueError('Initial source/config state differs on public replay')
            for number, event in enumerate(events):
                previous_state = replay.state()
                if fingerprint(replay.state()) != event['before_sha256']:
                    raise ValueError('Audit source revision differs before replay step')
                if event['kind'] == 'retrieval':
                    replay.fulfill_queries(event['results'])
                    valid = True
                elif event['kind'] == 'empty_finalization':
                    if ledger_class is not GeneralTaskLedger:
                        raise ValueError('Empty finalization requires explicit generalized v2 protocol')
                    source = event['result']
                    restored = replay.finalize_empty(source['reason'], source_limits=source['source_limits'],
                                                     coverage=source['upstream_coverage'])
                    if restored != source or event.get('model_generation_used') is not False:
                        raise ValueError('Empty finalization output differs or incorrectly claims model generation')
                    valid = True
                elif event['kind'] == 'proposal':
                    original = packets[event['request_id']]
                    legal = [{'match_ref': key, 'request': _query_match(value, original, metadata['catalog']),
                              'proposal': value['proposal']} for key, value in original['legal_references'].items()]
                    packet = replay.prepare_packet(list(original['current_bcs']), legal_matches=legal, phase=original['phase'])
                    raw = event['raw']
                    try:
                        strict_json_syntax(raw)
                        p = json.loads(raw)
                    except ValueError:
                        pass  # Malformed source responses are replayed without repair.
                    else:
                        if isinstance(p, dict) and p.get('request_id') == original['request_id']:
                            p['request_id'] = packet['request_id']
                            raw = canonical_json(p)
                    result = replay.update(raw, packet)
                    valid = result['valid']
                    if valid != event['check']['valid']:
                        raise ValueError('Original/replayed acceptance differs')
                    if not valid and replay.state() != previous_state:
                        raise ValueError('Rejected public replay replaced the prior accepted revision')
                else:
                    raise ValueError('Unknown task audit event')
                if fingerprint(replay.state()) != event['after_sha256']:
                    raise ValueError('Original/replayed accepted state differs')
                if event['kind'] == 'proposal' and not valid and event['before_sha256'] != event['after_sha256']:
                    raise ValueError('A rejected original update changed state')
                steps.append({'index': number, 'kind': event['kind'], 'accepted': valid, 'state_equal': True})
            if replay.state() != versions[-1]:
                raise ValueError('Final task state differs after public replay')
            replay_verification = replay.verify()
            checks['public_api_replay'] = True
            checks['final_state_equal'] = True
    state = versions[-1]
    checks['source_limits_retained'] = set(state.get('source_limits', {})) == set(state['seen_bc_ids'])
    checks['absence_not_benign'] = state['absence_proves_benign'] is False
    checks['checker_semantic_limit_explicit'] = state.get('natural_language_correctness_certified') is False
    result = {'schema_version': 'task-ledger-independent-acceptance.v1', 'valid': all(checks.values()),
              'checks': checks, 'source_catalog_sha256': fingerprint(metadata['catalog']),
              'final_state_sha256': fingerprint(state), 'replay': replay_verification, 'steps': steps,
              'accepted_findings': len(state['findings']), 'open_issues': sum(v['status']=='open' for v in state['issues'].values()),
              'final_synthesis_present': state['synthesis'] is not None,
              'checker_limit': 'Protocol/source integrity and deterministic replay; natural-language correctness needs separate evaluation'}
    if contract is not None:
        empty = state.get('empty_result')
        if empty is not None and (metadata['catalog']['bcs'] or state['findings'] or state['synthesis'] is not None
                                  or empty.get('status') != 'evidence_insufficient'
                                  or empty.get('absence_proves_benign') is not False):
            raise ValueError('Invalid zero-BC outcome or fabricated behavior finding')
        result.update(schema_version='task-ledger-independent-acceptance.v2', proposal_contract=contract,
                      final_empty_outcome_present=empty is not None,
                      final_outcome='evidence_insufficient' if empty is not None else
                                    'completed' if state['synthesis'] is not None else 'incomplete')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger', required=True)
    parser.add_argument('--output')
    args = parser.parse_args()
    result = accept_ledger(args.ledger)
    if args.output:
        output = filesystem_path(args.output)
        if output.exists():
            raise ValueError('Acceptance output is immutable; choose a new file')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result['valid']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
