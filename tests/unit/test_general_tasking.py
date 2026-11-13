"""General task cardinality is source-bound; v1 contracts stay unchanged."""
from copy import deepcopy
from pathlib import Path
import runpy

import pytest

from androserum.facts.identity import canonical_json, fingerprint
from androserum.matching.fixtures import toy_side
from androserum.pipeline.tasking import GeneralTaskLedger, PROMPT, proposal_schema
from androserum.tasking import TaskConfig, TaskLedger, proposal_schema as v1_schema


IDENTITY = {'apk_sha256': 'a' * 64, 'source_run_ref': 'run:current'}


def catalog(count=1):
    sides = {}
    for index in range(count):
        key = 'bc_' + str(index)
        side = toy_side('general_' + str(index)); side['bc']['bc_id'] = key
        sides[key] = side
    return {'bcs': sides, 'supplemental': {}}


def proposal(packet, *, final=False):
    findings = []
    for bid, side in packet['current_bcs'].items():
        findings.append({'finding_id': 'finding_' + bid, 'description': 'One supported possible local transfer.',
                         'scopes': [{'bc_id': bid, 'action_ids': list(side['actions']),
                                     'link_ids': [r['link_id'] for r in side['bc']['relations']]}],
                         'evidence_refs': list(dict.fromkeys([op for a in side['actions'].values() for op in a['operation_refs']] +
                                         [r for link in side['bc']['relations'] for r in link['support_path']])),
                         'condition_refs': list(dict.fromkeys([c for a in side['actions'].values() for c in a['condition_refs']] +
                                          [c for link in side['bc']['relations'] for c in link['condition_refs']])),
                         'reference_uses': [], 'limitations': ['Partial static evidence; runtime execution unknown.'],
                         'execution_claim': 'possible_only'})
    return {'schema_version': 'apk-task-proposal.v2', 'request_id': packet['request_id'],
            'base_revision': packet['base_revision'], 'upsert_findings': findings,
            'delete_finding_ids': [], 'issue_updates': [], 'fact_queries': [],
            'synthesis': {'summary': 'Only the supported independent mechanisms are reported.',
                          'finding_ids': [f['finding_id'] for f in findings], 'bc_ids': list(packet['current_bcs']),
                          'cross_bc_links': [], 'unresolved_issue_ids': [],
                          'limitations': ['Static partial analysis does not establish actual execution.'],
                          'execution_claim': 'possible_only', 'absence_proves_benign': False} if final else None,
            'rationale': 'Deterministic protocol check, not a real model result.'}


def book(path, count=1):
    return GeneralTaskLedger(path, IDENTITY, config=TaskConfig(allow_synthetic_protocol=True),
                             source_catalog=catalog(count))


def test_v1_schema_stays_two_bc_and_v2_is_explicit():
    assert v1_schema()['$defs']['Synthesis']['properties']['bc_ids']['minItems'] == 2
    assert proposal_schema()['$defs']['GeneralSynthesis']['properties']['bc_ids']['minItems'] == 1
    assert v1_schema()['properties']['schema_version']['const'] == 'apk-task-proposal.v1'
    assert proposal_schema()['properties']['schema_version']['const'] == 'apk-task-proposal.v2'
    assert 'at least two current BCs' not in PROMPT


@pytest.mark.parametrize('count', [1, 2, 3])
def test_general_catalog_and_final_cardinality(tmp_path, count):
    path = tmp_path / 'task.sqlite'
    with book(path, count) as ledger:
        packet = ledger.prepare_packet(phase='synthesis')
        assert packet['schema_version'] == 'apk-task-request.v2'
        assert ledger.finalize(canonical_json(proposal(packet, final=True)), packet)['valid']
        assert ledger.report()['outcome']['status'] == 'completed'
        retained = ledger.report()
    with GeneralTaskLedger(path) as resumed:
        assert resumed.report() == retained
        assert resumed.verify()['valid']


def test_single_bc_foreign_ref_rejected_then_real_scope_accepted(tmp_path):
    with book(tmp_path / 'task.sqlite') as ledger:
        packet = ledger.prepare_packet(phase='synthesis'); p = proposal(packet, final=True)
        bad = deepcopy(p); bad['upsert_findings'][0]['evidence_refs'].append('foreign:historical_only')
        before = fingerprint(ledger.state())
        assert not ledger.finalize(canonical_json(bad), packet)['valid']
        assert fingerprint(ledger.state()) == before
        assert ledger.finalize(canonical_json(p), packet)['valid']
        assert ledger.report()['audits'][0]['rejected_update_preserved_state']


def test_empty_approved_catalog_is_explicit_idempotent_no_model_terminal(tmp_path):
    path = tmp_path / 'empty.sqlite'
    kwargs = {'source_limits': ['BU extraction was truncated'], 'coverage': {'bu_count': 2, 'approved_bc_count': 0}}
    with book(path, 0) as ledger:
        with pytest.raises(ValueError, match='finalize_empty'):
            ledger.prepare_packet()
        result = ledger.finalize_empty('No candidate passed the frozen review criteria.', **kwargs)
        assert result['status'] == 'evidence_insufficient' and result['findings'] == []
        assert result['absence_proves_benign'] is False
        assert result['llm_calls_for_empty_finalization'] == 0
        before = ledger.report()
        assert ledger.finalize_empty('No candidate passed the frozen review criteria.', **kwargs) == result
        assert ledger.report() == before
        with pytest.raises(ValueError, match='cannot change'):
            ledger.finalize_empty('Changed result')
        assert ledger.report() == before
    with GeneralTaskLedger(path) as resumed:
        assert resumed.report()['outcome'] == result
        assert resumed.verify() == {'valid': True, 'revisions': 2, 'audits': 1}


def test_v1_and_v2_ledgers_cannot_mix_protocols_on_resume(tmp_path):
    path = tmp_path / 'v2.sqlite'
    with book(path): pass
    with pytest.raises(ValueError, match='protocol differs'):
        TaskLedger(path)
    v1 = tmp_path / 'v1.sqlite'
    with TaskLedger(v1, IDENTITY, config=TaskConfig(allow_synthetic_protocol=True), source_catalog=catalog(2)):
        pass
    with pytest.raises(ValueError, match='protocol differs'):
        GeneralTaskLedger(v1)


def test_nonempty_catalog_cannot_use_insufficient_terminal_as_shortcut(tmp_path):
    with book(tmp_path / 'task.sqlite') as ledger:
        with pytest.raises(ValueError, match='Nonempty'):
            ledger.finalize_empty('Do not bypass real analysis')
        assert ledger.state()['revision'] == 0


def test_v1_still_rejects_empty_catalog(tmp_path):
    with pytest.raises(ValueError, match='requires bcs'):
        TaskLedger(tmp_path / 'v1empty.sqlite', IDENTITY, source_catalog=catalog(0))


@pytest.mark.parametrize('count', [0, 1, 2])
def test_independent_replay_selects_v2_and_handles_empty_one_many(tmp_path, count):
    path = tmp_path / 'review.sqlite'
    with book(path, count) as ledger:
        if count:
            packet = ledger.prepare_packet(phase='synthesis')
            assert ledger.finalize(canonical_json(proposal(packet, final=True)), packet)['valid']
        else:
            ledger.finalize_empty('All extracted candidates remained unapproved.', source_limits=['Partial extraction'],
                                  coverage={'approved_bc_count': 0})
    api = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'scripts/accept_task_ledger.py'))
    accepted = api['accept_ledger'](path)
    assert accepted['valid'] and accepted['schema_version'] == 'task-ledger-independent-acceptance.v2'
    assert accepted['final_empty_outcome_present'] == (count == 0)
    assert accepted['final_outcome'] == ('evidence_insufficient' if count == 0 else 'completed')
    assert accepted['checks']['public_api_replay'] and accepted['checks']['final_state_equal']
