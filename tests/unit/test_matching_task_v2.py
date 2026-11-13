"""A legitimate v2 internal reference must survive native task transactions."""
from copy import deepcopy
import json
from pathlib import Path
import runpy

import pytest

from androserum.facts.identity import canonical_json, fingerprint
from androserum.pipeline.tasking import GeneralTaskLedger, TaskConfig


HELPERS = runpy.run_path(str(Path(__file__).with_name('test_matching_internal_paths.py')))
pytestmark = pytest.mark.skipif(not HELPERS['ACTUAL_PAIR'].exists(), reason='Actual retained pair needed for the native protocol control')


def material():
    request, proposal = HELPERS['retained_real_control']()
    query = {**deepcopy(request['sides']['query']), 'origin': deepcopy(request['source_audit']['query'])}
    run = next(e['record']['run_ref'] for e in query['registry'].values() if e['category'] == 'fact')
    identity = {'apk_sha256': query['origin']['apk_sha256'], 'source_run_ref': run}
    return request, proposal, query, identity


def task_proposal(packet, match):
    bid = match['request']['sides']['query']['bc']['bc_id']; side = packet['current_bcs'][bid]
    proposal = match['proposal']; selected = [a for m in proposal['action_mappings'] for a in m['query_actions']]
    paths = [m['query'] for m in proposal['relation_mappings']]
    link_ids = [link for p in paths for link in p.get('link_ids', [])]
    proof = {h for a in selected for h in side['actions'][a]['operation_refs']}
    proof.update(h for p in paths for h in p['support_path'])
    conditions = {h for a in selected for h in side['actions'][a]['condition_refs']}
    conditions.update(h for p in paths for h in p['condition_refs'])
    finding = {'finding_id': 'phone_prefix', 'description': 'Possible local phone-service lookup and cast; later guarded identifier acquisition is outside this selected scope.',
               'scopes': [{'bc_id': bid, 'action_ids': selected, 'link_ids': link_ids}],
               'evidence_refs': sorted(proof), 'condition_refs': sorted(conditions),
               'reference_uses': [{'match_ref': match['match_ref'],
                                   'action_mapping_ids': [m['mapping_id'] for m in proposal['action_mappings']],
                                   'relation_mapping_ids': [m['mapping_id'] for m in proposal['relation_mappings']],
                                   'condition_mapping_ids': [m['mapping_id'] for m in proposal['condition_mappings']],
                                   'scope_description': 'Only the supported service/cast prefix with each actual internal/BC path.',
                                   'limitations': ['Reference scope excludes the identifier read, return and historical terminal use.']}],
               'limitations': ['Static partial evidence; unknown runtime objects and success; not a verdict.'],
               'execution_claim': 'possible_only'}
    return {'schema_version': 'apk-task-proposal.v2', 'request_id': packet['request_id'], 'base_revision': packet['base_revision'],
            'upsert_findings': [finding], 'delete_finding_ids': [], 'issue_updates': [], 'fact_queries': [],
            'synthesis': None, 'rationale': 'Constructed protocol integration control, not a new model result.'}


def test_real_internal_reference_rejects_omitted_path_then_commits_and_replays(tmp_path):
    request, proposal, query, identity = material(); bid = query['bc']['bc_id']
    match = {'match_ref': 'real-typed-prefix', 'request': request, 'proposal': proposal}
    path = tmp_path/'task.sqlite'
    with GeneralTaskLedger(path, identity, config=TaskConfig(), source_catalog={'bcs': {bid: query}, 'supplemental': {}}) as book:
        packet = book.prepare_packet([bid], legal_matches=[match]); p = task_proposal(packet, match)
        internal = next(m['query'] for m in proposal['relation_mappings'] if m['query']['path_kind'] == 'action_internal')
        bad = deepcopy(p); bad['upsert_findings'][0]['evidence_refs'].remove(internal['support_path'][0])
        before = fingerprint(book.state()); rejected = book.update(canonical_json(bad), packet)
        assert not rejected['valid'] and 'finding_support' in {e['code'] for e in rejected['errors']}
        assert fingerprint(book.state()) == before
        assert book.update(canonical_json(p), packet)['valid']
        assert book.state()['legal_references']['real-typed-prefix']['matching_request_schema_version'] == 'behavior-match-request.v2'
    api = runpy.run_path(str(Path(__file__).resolve().parents[2]/'scripts/accept_task_ledger.py'))
    reviewed = api['accept_ledger'](path)
    assert reviewed['valid'] and reviewed['accepted_findings'] == 1
    assert reviewed['checks']['public_api_replay'] and reviewed['checks']['final_state_equal']


def test_v2_reference_cannot_use_historical_records_as_current_evidence(tmp_path):
    request, proposal, query, identity = material(); bid = query['bc']['bc_id']
    match = {'match_ref': 'real-typed-prefix', 'request': request, 'proposal': proposal}
    with GeneralTaskLedger(tmp_path/'task.sqlite', identity, source_catalog={'bcs': {bid: query}, 'supplemental': {}}) as book:
        packet = book.prepare_packet([bid], legal_matches=[match]); p = task_proposal(packet, match)
        foreign = proposal['relation_mappings'][0]['reference']['support_path'][0]
        assert foreign not in packet['evidence']
        p['upsert_findings'][0]['evidence_refs'].append(foreign)
        before = fingerprint(book.state()); result = book.update(canonical_json(p), packet)
        assert not result['valid'] and 'current_evidence' in {e['code'] for e in result['errors']}
        assert fingerprint(book.state()) == before


def test_v2_wrong_path_metadata_is_not_a_legal_reference(tmp_path):
    request, proposal, query, identity = material(); bid = query['bc']['bc_id']
    proposal['relation_mappings'][1]['query']['context_refs'] = ['context:not_this_call']
    with GeneralTaskLedger(tmp_path/'task.sqlite', identity, source_catalog={'bcs': {bid: query}, 'supplemental': {}}) as book:
        with pytest.raises(ValueError, match='program-accepted'):
            book.prepare_packet([bid], legal_matches=[{'match_ref': 'bad', 'request': request, 'proposal': proposal}])
        assert book.state()['revision'] == 0


def test_internal_path_model_condition_is_required_even_without_bc_link(tmp_path):
    request, proposal = HELPERS['typed_control'](reverse_granularity=True)
    query = {**deepcopy(request['sides']['query']), 'origin': deepcopy(request['source_audit']['query'])}
    bid = query['bc']['bc_id']; match = {'match_ref': 'typed-condition', 'request': request, 'proposal': proposal}
    identity = {'apk_sha256': 'a'*64, 'source_run_ref': 'run:protocol_only'}
    with GeneralTaskLedger(tmp_path/'task.sqlite', identity, config=TaskConfig(allow_synthetic_protocol=True),
                           source_catalog={'bcs': {bid: query}, 'supplemental': {}}) as book:
        packet = book.prepare_packet([bid], legal_matches=[match]); p = task_proposal(packet, match)
        assert p['upsert_findings'][0]['scopes'][0]['link_ids'] == []
        assert p['upsert_findings'][0]['condition_refs']
        bad = deepcopy(p); bad['upsert_findings'][0]['condition_refs'] = []
        result = book.update(canonical_json(bad), packet)
        assert not result['valid'] and 'condition_scope' in {e['code'] for e in result['errors']}
        bad = deepcopy(p); bad['upsert_findings'][0]['reference_uses'][0]['condition_mapping_ids'] = []
        result = book.update(canonical_json(bad), packet)
        assert not result['valid'] and 'reference_condition_scope' in {e['code'] for e in result['errors']}
        assert book.update(canonical_json(p), packet)['valid']
