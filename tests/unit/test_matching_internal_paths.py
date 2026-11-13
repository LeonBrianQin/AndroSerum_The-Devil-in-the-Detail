"""Explicit v2 action granularity; v1 failures are not silently reinterpreted."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from androserum.facts.identity import canonical_json, fingerprint
from androserum.matching.checker import check_match, path_metadata, path_metadata_v2
from androserum.matching.fixtures import toy_side
from androserum.matching.models import MatchProposal, MatchProposalV2
from androserum.matching.views import make_request_v2


ACTUAL_PAIR = Path('artifacts/acceptance/e2e/20261027_224007_938289/samples/imei-hash/analysis/matching/bc-0-rank-0')


def typed_control(*, summary=False, reverse_granularity=False):
    query = toy_side('v2_query', summary=summary)
    reference = toy_side('v2_reference', summary=summary)
    joined = deepcopy(reference['actions']['left'])
    joined.update(action_id='joined', operation_refs=[op for a in reference['actions'].values() for op in a['operation_refs']],
                  support_relation_refs=reference['bc']['relations'][0]['support_path'],
                  outputs=deepcopy(reference['actions']['right']['outputs']))
    reference['actions'] = {'joined': joined}
    reference['bc']['action_ids'] = ['joined']; reference['bc']['relations'] = []
    reference['purpose_claims'] = {'joined': 'audit'}
    q, kind, strength = path_metadata(query, ['flow0']); q['path_kind'] = 'bc_links'
    refs = joined['support_relation_refs']; edge = reference['registry'][refs[0]]
    r = {'path_kind': 'action_internal', 'action_id': 'joined', 'support_path': refs,
         'source_endpoint': edge['source_endpoint_ref'], 'target_endpoint': edge['target_endpoint_ref'],
         'binding_refs': [], 'context_refs': [edge['context_ref']], 'condition_refs': edge['condition_refs']}
    if reverse_granularity: query, reference, q, r = reference, query, r, q
    request = make_request_v2(query, reference)
    proposal = {'schema_version': 'behavior-match-proposal.v2', 'request_id': request['request_id'],
                'pair_sha256': request['pair_sha256'], 'decision': '\u652f\u6301\u5339\u914d', 'scope': 'full',
                'action_mappings': [{'mapping_id': 'function', 'query_actions': list(query['actions']),
                                     'reference_actions': list(reference['actions']),
                                     'object_and_io_correspondence': 'The selected native value roles correspond.',
                                     'functional_basis': 'Deterministic granularity control, not a model prediction.',
                                     'limitations': ['Natural-language meaning requires independent review.']}],
                'relation_mappings': [{'mapping_id': 'path', 'from_mapping': 'function', 'to_mapping': 'function',
                                       'query': q, 'reference': r, 'direction': 'aligned',
                                       'endpoint_correspondence': [{'query_role': role, 'query_endpoint': q[role+'_endpoint'],
                                                                    'reference_endpoint': r[role+'_endpoint']} for role in ['source','target']],
                                       'binding_basis': 'Each side retains its own native object/call context.',
                                       'relation_kind': kind, 'evidence_strength': strength,
                                       'claims_complete_fine_path': False,
                                       'explanation': 'Actual supplied paths support the selected granularity.'}],
                'condition_mappings': [{'mapping_id': 'guard', 'query_condition': q['condition_refs'][0],
                                        'reference_condition': r['condition_refs'][0], 'comparison': 'equivalent',
                                        'affected_mappings': ['path'], 'explanation': 'Same fixed normalized synthetic guard.'}],
                'differences': [], 'unmapped': {'query_actions': [], 'reference_actions': [], 'query_links': [], 'reference_links': []},
                'limitations': ['Static recorded dependencies only; actual execution and success are unknown.'],
                'unresolved': [], 'rationale': 'Prewritten explicit-v2 protocol control only.',
                'execution_claim': 'possible_only', 'unconditional_execution_claimed': False}
    return request, proposal


def retained_real_control():
    request = json.loads((ACTUAL_PAIR/'request.json').read_text('utf-8'))
    old = json.loads((ACTUAL_PAIR/'attempt-1/raw-model-output.json').read_text('utf-8'))
    request = deepcopy(request); request['schema_version'] = 'behavior-match-request.v2'
    request['request_id'] = 'match-request:retained-real-internal-path-v2-control'
    request['rules']['native_path_protocol'] = 'typed_bc_links_or_action_internal.v2'
    proposal = deepcopy(old); proposal['schema_version'] = 'behavior-match-proposal.v2'
    proposal['request_id'] = request['request_id']
    for relation in proposal['relation_mappings']:
        for which in ['query','reference']:
            selected = relation[which]; side = request['sides'][which]
            if all(x in {r['link_id'] for r in side['bc']['relations']} for x in selected['link_ids']):
                selected['path_kind'] = 'bc_links'
            else:
                owners = {side['registry'][selected[k]]['owner_operation_ref'] for k in ['source_endpoint','target_endpoint']}
                candidates = [aid for aid,a in side['actions'].items()
                              if owners <= set(a['operation_refs']) and set(selected['support_path']) <= set(a['support_relation_refs'])]
                if len(candidates) != 1: raise ValueError('Real control does not have one supported internal action')
                selected.pop('link_ids'); selected.update(path_kind='action_internal', action_id=candidates[0])
    proposal['rationale'] = 'Constructed v2 control from the retained rejected real proposal; not a new real-model output.'
    return request, proposal


def checked(request, proposal): return check_match(canonical_json(proposal), request)


@pytest.mark.parametrize('reverse', [False, True])
def test_two_actions_and_one_composite_match_in_both_directions(reverse):
    request, proposal = typed_control(reverse_granularity=reverse)
    result = checked(request, proposal)
    assert result['valid'], result['errors']
    assert result['accepted']['decision'] == '\u652f\u6301\u5339\u914d'


def test_summary_remains_summary_in_internal_action_path():
    request, proposal = typed_control(summary=True)
    assert checked(request, proposal)['valid']
    proposal['relation_mappings'][0]['claims_complete_fine_path'] = True
    result = checked(request, proposal)
    assert not result['valid'] and 'summary_upgrade' in {e['code'] for e in result['errors']}


@pytest.mark.parametrize('mutation', ['mixed', 'unknown_kind', 'wrong_action', 'nonmember', 'repeated', 'wrong_endpoint',
                                    'wrong_context', 'wrong_binding', 'condition_omitted', 'mapping_condition_omitted',
                                    'direction', 'type', 'unmapped', 'internal_scope'])
def test_internal_path_false_connections_rejected(mutation):
    request, proposal = typed_control(); relation = proposal['relation_mappings'][0]; path = relation['reference']
    if mutation == 'mixed': path['link_ids'] = ['flow0']
    elif mutation == 'unknown_kind': path['path_kind'] = 'inferred_path'
    elif mutation == 'wrong_action': path['action_id'] = 'absent'
    elif mutation == 'nonmember': path['support_path'] = ['rel_000000000000']
    elif mutation == 'repeated': path['support_path'] *= 2
    elif mutation == 'wrong_endpoint': path['source_endpoint'], path['target_endpoint'] = path['target_endpoint'], path['source_endpoint']
    elif mutation == 'wrong_context': path['context_refs'] = ['synthetic:other_frame']
    elif mutation == 'wrong_binding': path['binding_refs'] = ['bind_000000000000']
    elif mutation == 'condition_omitted': path['condition_refs'] = []
    elif mutation == 'mapping_condition_omitted': proposal['condition_mappings'] = []
    elif mutation == 'direction': relation['direction'] = 'reversed'
    elif mutation == 'type': relation['relation_kind'] = 'control_constraint'
    elif mutation == 'unmapped': proposal['unmapped']['query_links'] = ['flow0']
    else:
        proposal['action_mappings'][0]['reference_actions'] = ['absent']
    assert not checked(request, proposal)['valid']


@pytest.mark.parametrize('mutation', ['owner', 'disconnected', 'control_role', 'unknown_condition'])
def test_recorded_path_ownership_connectivity_role_and_unknown_are_not_guessed(mutation):
    request, proposal = typed_control(); side = request['sides']['reference']; selected = proposal['relation_mappings'][0]['reference']
    if mutation == 'owner': side['actions']['joined']['operation_refs'].pop()
    elif mutation == 'disconnected':
        original = selected['support_path'][0]; other = 'rel_0123456789ab'
        side['registry'][other] = deepcopy(side['registry'][original]); side['registry'][other]['handle'] = other
        # Same recorded direction repeated as a distinct edge does not connect.
        side['actions']['joined']['support_relation_refs'].append(other); selected['support_path'].append(other)
    elif mutation == 'control_role': side['registry'][selected['support_path'][0]]['kind'] = 'control_dependency'
    else: side['condition_semantics'][selected['condition_refs'][0]]['predicate_key'] = None
    request['pair_sha256'] = fingerprint(request['sides']); proposal['pair_sha256'] = request['pair_sha256']
    assert not checked(request, proposal)['valid']


def test_v1_never_silently_accepts_the_new_typed_path_schema():
    request, proposal = typed_control()
    request['schema_version'] = 'behavior-match-request.v1'
    assert not checked(request, proposal)['valid']
    proposal['schema_version'] = 'behavior-match-proposal.v1'
    assert not checked(request, proposal)['valid']
    assert MatchProposal.model_json_schema()['properties']['schema_version']['const'] == 'behavior-match-proposal.v1'
    assert MatchProposalV2.model_json_schema()['properties']['schema_version']['const'] == 'behavior-match-proposal.v2'


@pytest.mark.skipif(not ACTUAL_PAIR.exists(), reason='Retained local actual APK pair is an acceptance artifact')
def test_retained_real_rejection_has_explicitly_supported_v2_counterpart():
    old_request = json.loads((ACTUAL_PAIR/'request.json').read_text('utf-8'))
    for index in [0,1]:
        raw = (ACTUAL_PAIR/f'attempt-{index}/raw-model-output.json').read_text('utf-8')
        original = json.loads((ACTUAL_PAIR/f'check-{index}.json').read_text('utf-8'))['check']
        assert check_match(raw, old_request) == original
        assert not original['valid']
    request, proposal = retained_real_control(); result = checked(request, proposal)
    assert result['valid'], result['errors']
    assert result['accepted']['scope'] == 'partial'
