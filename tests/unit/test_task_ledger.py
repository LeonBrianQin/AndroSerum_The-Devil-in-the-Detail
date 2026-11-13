"""Task ledger protocol controls; these do not measure model interpretation quality."""
from copy import deepcopy
import json
from pathlib import Path
import runpy
import pytest
from androserum.facts.identity import canonical_json, fingerprint
from androserum.matching.fixtures import toy_side, support_response, negative_response
from androserum.matching.views import make_request
from androserum.tasking import TaskConfig, TaskLedger, proposal_schema, TASK_PROMPT


def catalog():
    sides = {}
    for key in ['first', 'second']:
        side = toy_side('task_' + key)
        side['bc']['bc_id'] = key
        sides[key] = side
    return {'bcs': sides, 'supplemental': {'fact:extra': {'handle': 'fact:extra', 'category': 'fact',
            'record': {'run_ref': 'run:current', 'record_id': 'fact:extra', 'value': 'Current source retrieved only later'}}}}


def ledger(tmp_path, **config):
    return TaskLedger(tmp_path / 'task.sqlite', {'apk_sha256': 'a'*64, 'source_run_ref': 'run:current'},
                      config=TaskConfig(allow_synthetic_protocol=True, **config), source_catalog=catalog())


def finding(packet, bid='first', key='finding1'):
    side = packet['current_bcs'][bid]
    return {'finding_id': key, 'description': 'A bounded possible controlled value transfer.',
            'scopes': [{'bc_id': bid, 'action_ids': list(side['actions']),
                        'link_ids': [x['link_id'] for x in side['bc']['relations']]}],
            'evidence_refs': [op for a in side['actions'].values() for op in a['operation_refs']] +
                             [r for x in side['bc']['relations'] for r in x['support_path']],
            'condition_refs': [c for x in side['bc']['relations'] for c in x['condition_refs']],
            'reference_uses': [], 'limitations': ['Synthetic possible static relation; execution unknown.'],
            'execution_claim': 'possible_only'}


def proposal(packet, findings=()):
    return {'schema_version': 'apk-task-proposal.v1', 'request_id': packet['request_id'],
            'base_revision': packet['base_revision'], 'upsert_findings': list(findings),
            'delete_finding_ids': [], 'issue_updates': [], 'fact_queries': [], 'synthesis': None,
            'rationale': 'Bounded deterministic protocol update, not a real model result.'}


def submit(book, packet, p): return book.update(canonical_json(p), packet)


def open_issue():
    return {'issue_id': 'missing', 'description': 'A current source detail is not yet displayed.',
            'bc_ids': ['first'], 'finding_ids': [], 'evidence_refs': [], 'status': 'open', 'resolution': None}


def synthesize(book):
    packet = book.prepare_packet(phase='synthesis')
    p = proposal(packet)
    state = book.state()
    p['synthesis'] = {'summary': 'Two independent possible mechanisms coexist; no connecting path is established.',
                      'finding_ids': list(state['findings']), 'bc_ids': ['first', 'second'],
                      'cross_bc_links': [], 'unresolved_issue_ids': [k for k, v in state['issues'].items() if v['status'] == 'open'],
                      'limitations': ['No proved cross-BC connection; partial static coverage.'],
                      'execution_claim': 'possible_only', 'absence_proves_benign': False}
    return packet, p


def test_independent_schema_and_prompt():
    assert proposal_schema()['properties']['schema_version']['const'] == 'apk-task-proposal.v1'
    assert 'unknown' in TASK_PROMPT and 'not a malware/benign verdict' in TASK_PROMPT


def test_transaction_commit_resume_hash_chain_and_catalog_binding(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first'])
        assert submit(book, packet, proposal(packet, [finding(packet)]))['valid']
        assert book.state()['source_limits']['first']['source_limits'] == packet['current_bcs']['first']['source_limits']
        assert book.state()['natural_language_correctness_certified'] is False
        before = book.report()
    with TaskLedger(tmp_path/'task.sqlite') as resumed:
        assert resumed.state() == before['state']
        assert resumed.verify() == {'valid': True, 'revisions': 2, 'audits': 1}
    altered = catalog(); altered['bcs']['first']['bc']['description'] = 'Changed source'
    with pytest.raises(ValueError, match='Frozen source'):
        TaskLedger(tmp_path/'task.sqlite', source_catalog=altered)


@pytest.mark.parametrize('mutation,code', [
    ('foreign_evidence', 'current_evidence'), ('omit_path', 'finding_support'),
    ('omit_condition', 'condition_scope'), ('fake_bc', 'bc_visibility'),
    ('historical_ref', 'reference_authority'), ('stale_revision', 'request_identity'),
    ('unknown_scope_action', 'scope_ref')])
def test_rejections_preserve_state(tmp_path, mutation, code):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); f = finding(packet); p = proposal(packet, [f])
        if mutation == 'foreign_evidence': f['evidence_refs'].append('historical:only')
        elif mutation == 'omit_path': f['evidence_refs'].pop()
        elif mutation == 'omit_condition': f['condition_refs'] = []
        elif mutation == 'fake_bc': f['scopes'][0]['bc_id'] = 'foreign'
        elif mutation == 'historical_ref': f['reference_uses'] = [{'match_ref': 'unaccepted', 'action_mapping_ids': ['x'], 'relation_mapping_ids': [], 'condition_mapping_ids': [], 'scope_description': 'Not authorized', 'limitations': ['None authorized']}]
        elif mutation == 'stale_revision': p['base_revision'] += 1
        else: f['scopes'][0]['action_ids'].append('imagined')
        old = fingerprint(book.state()); result = submit(book, packet, p)
        assert not result['valid'] and code in {e['code'] for e in result['errors']}
        assert fingerprint(book.state()) == old
        assert book.report()['audits'][-1]['rejected_update_preserved_state']


def test_repair_same_packet_then_replay_stale(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); p = proposal(packet, [finding(packet)])
        bad = deepcopy(p); bad['upsert_findings'][0]['condition_refs'] = []
        assert not submit(book, packet, bad)['valid']
        assert submit(book, packet, p)['valid']
        assert not submit(book, packet, p)['valid']
        assert book.state()['revision'] == 1 and len(book.report()['audits']) == 3


def test_packet_mutation_rejected(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); p = proposal(packet, [finding(packet)])
        packet['current_bcs']['first']['bc']['description'] = 'Tamper'
        assert submit(book, packet, p)['errors'][0]['code'] == 'packet_integrity'


def test_explicit_query_later_visibility_and_resolved_issue(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); p = proposal(packet, [finding(packet)])
        p['issue_updates'] = [open_issue()]
        p['fact_queries'] = [{'query_id': 'query1', 'requested_refs': ['fact:extra'], 'purpose': 'Verify current source detail', 'issue_ids': ['missing']}]
        assert 'fact:extra' not in packet['evidence']
        assert submit(book, packet, p)['valid']
        premature = book.prepare_packet(['first']); p2 = proposal(premature, [finding(premature)])
        p2['upsert_findings'][0]['evidence_refs'].append('fact:extra')
        assert not submit(book, premature, p2)['valid']
        assert book.fulfill_queries({'query1': ['fact:extra']})['queries']['query1']['status'] == 'fulfilled'
        packet2 = book.prepare_packet(['first']); assert 'fact:extra' in packet2['evidence']
        p2 = proposal(packet2); issue = open_issue()
        issue.update(status='resolved', resolution='Retrieved current record supports only the requested local detail.', evidence_refs=['fact:extra'])
        p2['issue_updates'] = [issue]
        assert submit(book, packet2, p2)['valid']
        assert book.state()['issues']['missing']['status'] == 'resolved'


def test_query_unavailable_remains_issue_and_cannot_replace_catalog(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); p = proposal(packet)
        p['issue_updates'] = [open_issue()]
        p['fact_queries'] = [{'query_id': 'q', 'requested_refs': ['fact:extra'], 'purpose': 'Bounded supplement', 'issue_ids': ['missing']}]
        assert submit(book, packet, p)['valid']
        with pytest.raises(ValueError, match='nonrequested'):
            book.fulfill_queries({'q': ['fact:foreign']})
        book.fulfill_queries({'q': []})
        assert book.state()['issues']['missing']['status'] == 'open'
        assert book.state()['queries']['q']['status'] == 'unavailable'
        assert 'fact:extra' not in book.prepare_packet()['evidence']


def test_query_budget_and_foreign_query_rejected(tmp_path):
    with ledger(tmp_path, max_fact_queries=0) as book:
        packet = book.prepare_packet(); p = proposal(packet); p['issue_updates'] = [open_issue()]
        p['fact_queries'] = [{'query_id': 'q', 'requested_refs': ['fact:extra'], 'purpose': 'Budget control', 'issue_ids': ['missing']}]
        assert 'query_budget' in {x['code'] for x in submit(book, packet, p)['errors']}
    with ledger(tmp_path/'foreign') as book:
        packet = book.prepare_packet(); p = proposal(packet); p['issue_updates'] = [open_issue()]
        p['fact_queries'] = [{'query_id': 'q', 'requested_refs': ['fact:foreign'], 'purpose': 'Unauthorized', 'issue_ids': ['missing']}]
        assert 'query_authority' in {x['code'] for x in submit(book, packet, p)['errors']}


def test_attempt_budget_persists_on_resume(tmp_path):
    with ledger(tmp_path, max_attempts=1) as book:
        packet = book.prepare_packet(['first']); assert submit(book, packet, proposal(packet))['valid']
    with TaskLedger(tmp_path/'task.sqlite') as book:
        packet = book.prepare_packet(['first'])
        assert packet['budget']['attempts_remaining'] == 0
        assert submit(book, packet, proposal(packet))['errors'][0]['code'] == 'attempt_budget'


def test_rollback_keeps_both_audit_and_state_atomic(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(); p = proposal(packet, [finding(packet)])
        def crash(): raise RuntimeError('transaction failure injection')
        with pytest.raises(RuntimeError, match='injection'):
            book.update(canonical_json(p), packet, before_commit=crash)
        assert book.state()['revision'] == 0 and not book.report()['audits']
        assert submit(book, packet, p)['valid']


def test_same_apk_two_independent_bcs_can_finalize_with_open_issue(tmp_path):
    with ledger(tmp_path) as book:
        first = book.prepare_packet(['first']); p = proposal(first, [finding(first)])
        p['issue_updates'] = [open_issue()]; assert submit(book, first, p)['valid']
        second = book.prepare_packet(['second']); assert set(second['current_bcs']) == {'first', 'second'}
        assert submit(book, second, proposal(second, [finding(second, 'second', 'finding2')]))['valid']
        packet, p = synthesize(book); assert book.finalize(canonical_json(p), packet)['valid']
        assert book.state()['synthesis']['cross_bc_links'] == []
        assert book.state()['synthesis']['unresolved_issue_ids'] == ['missing']


def test_false_cross_bc_join_is_rejected(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(); assert submit(book, packet, proposal(packet, [finding(packet), finding(packet, 'second', 'finding2')]))['valid']
        packet, p = synthesize(book); side = packet['current_bcs']['first']; link = side['bc']['relations'][0]
        rel = side['registry'][link['support_path'][0]]
        p['synthesis']['cross_bc_links'] = [{'link_id': 'imagined_cross_join', 'from_bc': 'first', 'from_action': 'left',
            'to_bc': 'second', 'to_action': 'right', 'support_path': link['support_path'],
            'source_endpoint': rel['source_endpoint_ref'], 'target_endpoint': rel['target_endpoint_ref'],
            'binding_refs': [], 'context_refs': [rel['context_ref']], 'condition_refs': rel['condition_refs'],
            'relation_kind': 'data_transfer', 'evidence_strength': 'recorded_dependency_path', 'claims_complete_fine_path': False,
            'explanation': 'Unjustified shared-entry inference must be rejected.'}]
        result = book.finalize(canonical_json(p), packet)
        assert not result['valid'] and 'cross_bc_path' in {x['code'] for x in result['errors']}


@pytest.mark.parametrize('mutation', ['hide_issue', 'one_bc', 'omit_finding', 'empty_synthesis'])
def test_synthesis_closure(tmp_path, mutation):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(); p = proposal(packet, [finding(packet), finding(packet, 'second', 'finding2')])
        p['issue_updates'] = [open_issue()]; assert submit(book, packet, p)['valid']
        packet, p = synthesize(book)
        if mutation == 'hide_issue': p['synthesis']['unresolved_issue_ids'] = []
        elif mutation == 'one_bc': p['synthesis']['bc_ids'] = ['first']
        elif mutation == 'omit_finding': p['synthesis']['finding_ids'].pop()
        else: p['synthesis'] = None
        assert not book.finalize(canonical_json(p), packet)['valid']


def test_finding_delete_requires_issue_reference_closure(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); p = proposal(packet, [finding(packet)])
        issue = open_issue(); issue['finding_ids'] = ['finding1']; p['issue_updates'] = [issue]
        assert submit(book, packet, p)['valid']
        packet = book.prepare_packet(['first']); p = proposal(packet); p['delete_finding_ids'] = ['finding1']
        assert 'dangling_issue' in {x['code'] for x in submit(book, packet, p)['errors']}
        issue['finding_ids'] = []; p['issue_updates'] = [issue]
        assert submit(book, packet, p)['valid']


def test_legal_reference_scope_and_negative_match_exclusion(tmp_path):
    with ledger(tmp_path) as book:
        query = catalog()['bcs']['first']; reference = toy_side('historical')
        request = make_request(query, reference); accepted = support_response(request)
        legal = {'match_ref': 'match:accepted', 'request': request, 'proposal': accepted}
        packet = book.prepare_packet(['first'], legal_matches=[legal]); f = finding(packet)
        f['reference_uses'] = [{'match_ref': 'match:accepted', 'action_mapping_ids': [m['mapping_id'] for m in accepted['action_mappings']],
            'relation_mapping_ids': [m['mapping_id'] for m in accepted['relation_mappings']],
            'condition_mapping_ids': [m['mapping_id'] for m in accepted['condition_mappings']],
            'scope_description': 'Only selected checked controlled transfer correspondence.', 'limitations': ['Historical fixture is background only.']}]
        assert submit(book, packet, proposal(packet, [f]))['valid']
        packet = book.prepare_packet(['first']); f = finding(packet); f['reference_uses'] = deepcopy(book.state()['findings']['finding1']['reference_uses'])
        f['reference_uses'][0]['condition_mapping_ids'] = []
        assert 'reference_condition_scope' in {x['code'] for x in submit(book, packet, proposal(packet, [f]))['errors']}
        gap = make_request(query, toy_side('gap_reference', gap=True))
        with pytest.raises(ValueError, match='support match'):
            book.prepare_packet(['first'], legal_matches=[{'match_ref': 'negative', 'request': gap, 'proposal': negative_response(gap, 'evidence')}])
    accept = runpy.run_path(str(Path(__file__).resolve().parents[2]/'scripts/accept_task_ledger.py'))['accept_ledger']
    assert accept(tmp_path/'task.sqlite')['valid']


def test_source_mismatch_synthetic_opt_in_and_digest_tamper(tmp_path):
    with pytest.raises(ValueError, match='Synthetic'):
        TaskLedger(tmp_path/'no_opt.sqlite', {'apk_sha256': 'a'*64, 'source_run_ref': 'run:current'}, source_catalog=catalog())
    wrong = catalog(); wrong['supplemental']['fact:extra']['record']['run_ref'] = 'run:foreign'
    with pytest.raises(ValueError, match='current-run'):
        TaskLedger(tmp_path/'foreign.sqlite', {'apk_sha256': 'a'*64, 'source_run_ref': 'run:current'},
                   config=TaskConfig(allow_synthetic_protocol=True), source_catalog=wrong)
    with ledger(tmp_path/'valid') as book:
        book.db.execute("UPDATE revisions SET payload='{}' WHERE revision=0")
        with pytest.raises(ValueError, match='hash chain'):
            book.verify()


def test_foreign_apk_support_match_and_reassigned_query_rejected(tmp_path):
    with ledger(tmp_path) as book:
        query = catalog()['bcs']['first']; reference = toy_side('historical')
        request = make_request(query, reference); p = support_response(request)
        request['source_audit']['query'].update(evidence_kind='actual_static_program_evidence', apk_sha256='b'*64)
        with pytest.raises(ValueError, match='different APK'):
            book.prepare_packet(['first'], legal_matches=[{'match_ref': 'foreign', 'request': request, 'proposal': p}])
        query = toy_side('altered_query'); query['bc']['bc_id'] = 'first'
        request = make_request(query, reference); p = support_response(request)
        with pytest.raises(ValueError, match='differs from current'):
            book.prepare_packet(['first'], legal_matches=[{'match_ref': 'altered', 'request': request, 'proposal': p}])


def test_legal_reference_cannot_escape_finding_action_scope(tmp_path):
    with ledger(tmp_path) as book:
        request = make_request(catalog()['bcs']['first'], toy_side('historical'))
        p = support_response(request)
        packet = book.prepare_packet(['first'], legal_matches=[{'match_ref': 'support', 'request': request, 'proposal': p}])
        f = finding(packet); f['scopes'][0].update(action_ids=['left'], link_ids=[])
        f['evidence_refs'] = packet['current_bcs']['first']['actions']['left']['operation_refs']; f['condition_refs'] = []
        f['reference_uses'] = [{'match_ref': 'support', 'action_mapping_ids': ['actions0', 'actions1'],
            'relation_mapping_ids': [], 'condition_mapping_ids': [], 'scope_description': 'Illegitimate expansion into unmapped current action.', 'limitations': ['Bounds remain narrow.']}]
        result = submit(book, packet, proposal(packet, [f]))
        assert not result['valid'] and 'reference_scope' in {e['code'] for e in result['errors']}


def test_actual_recorded_cross_bc_summary_retained_without_upgrade(tmp_path):
    side = toy_side('shared_protocol_path', summary=True)
    first, second = deepcopy(side), deepcopy(side)
    first['bc'].update(bc_id='first', action_ids=['left'], relations=[])
    first['actions'] = {'left': first['actions']['left']}
    second['bc'].update(bc_id='second', action_ids=['right'], relations=[])
    second['actions'] = {'right': second['actions']['right']}
    source = {'bcs': {'first': first, 'second': second}, 'supplemental': {}}
    with TaskLedger(tmp_path/'task.sqlite', {'apk_sha256': 'a'*64, 'source_run_ref': 'run:current'},
                    config=TaskConfig(allow_synthetic_protocol=True), source_catalog=source) as book:
        packet = book.prepare_packet(); assert submit(book, packet, proposal(packet, [finding(packet), finding(packet, 'second', 'finding2')]))['valid']
        packet, p = synthesize(book); edge = side['bc']['relations'][0]; rel = side['registry'][edge['support_path'][0]]
        p['synthesis']['cross_bc_links'] = [{'link_id': 'recorded_summary', 'from_bc': 'first', 'from_action': 'left',
            'to_bc': 'second', 'to_action': 'right', 'support_path': edge['support_path'],
            'source_endpoint': rel['source_endpoint_ref'], 'target_endpoint': rel['target_endpoint_ref'],
            'binding_refs': [], 'context_refs': [rel['context_ref']], 'condition_refs': rel['condition_refs'],
            'relation_kind': 'information_flow', 'evidence_strength': 'information_flow_summary', 'claims_complete_fine_path': True,
            'explanation': 'A current recorded coarse relationship connects the two action endpoints.'}]
        assert not book.finalize(canonical_json(p), packet)['valid']
        p['synthesis']['cross_bc_links'][0]['claims_complete_fine_path'] = False
        assert book.finalize(canonical_json(p), packet)['valid']


def test_public_independent_replay_with_query_repair_and_synthesis(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); p = proposal(packet, [finding(packet)])
        p['issue_updates'] = [open_issue()]
        p['fact_queries'] = [{'query_id': 'q', 'requested_refs': ['fact:extra'], 'purpose': 'Bounded current source lookup', 'issue_ids': ['missing']}]
        wrong = deepcopy(p); wrong['upsert_findings'][0]['evidence_refs'].append('fact:extra')
        assert not submit(book, packet, wrong)['valid']
        assert submit(book, packet, p)['valid']; book.fulfill_queries({'q': ['fact:extra']})
        packet = book.prepare_packet(['second']); p = proposal(packet, [finding(packet, 'second', 'finding2')])
        issue = open_issue(); issue.update(status='resolved', resolution='Only a local current-source detail was clarified.', evidence_refs=['fact:extra'])
        p['issue_updates'] = [issue]; assert submit(book, packet, p)['valid']
        packet, p = synthesize(book); assert book.finalize(canonical_json(p), packet)['valid']
    accept = runpy.run_path(str(Path(__file__).resolve().parents[2]/'scripts/accept_task_ledger.py'))['accept_ledger']
    report = accept(tmp_path/'task.sqlite')
    assert report['valid'] and report['accepted_findings'] == 2 and report['final_synthesis_present']
    assert len(report['steps']) == 5 and report['steps'][0]['accepted'] is False


def test_independent_replay_preserves_duplicate_key_syntax_rejection(tmp_path):
    with ledger(tmp_path) as book:
        packet = book.prepare_packet(['first']); p = proposal(packet, [finding(packet)])
        duplicate = canonical_json(p)[:-1]+',"rationale":"duplicate must remain rejected"}'
        assert not book.update(duplicate, packet)['valid']
        assert submit(book, packet, p)['valid']
    accept = runpy.run_path(str(Path(__file__).resolve().parents[2]/'scripts/accept_task_ledger.py'))['accept_ledger']
    assert accept(tmp_path/'task.sqlite')['valid']
