from copy import deepcopy
import pytest

from androserum.pipeline.approval import freeze_reviewed, shown_for_bc
from androserum.pipeline.encoding import ReviewedProjector


REVIEW = {'reviewer': 'test reviewer', 'method': 'explicit review', 'rationale': 'bounded evidence-supported scope'}


def test_new_list_requires_explicit_review(tmp_path):
    with pytest.raises(ValueError, match='Reviewer, method and rationale'):
        freeze_reviewed([], [], {'reviewer': 'test'}, tmp_path)


def test_query_history_roles_are_explicit(tmp_path):
    with pytest.raises(ValueError, match='role'):
        freeze_reviewed([], [], REVIEW, tmp_path, role='silently_promote_query')


def test_approval_does_not_hide_duplicate_or_excluded_identity(tmp_path):
    entry = {'qualified_ref': 'reviewed:one'}
    with pytest.raises(ValueError, match='Duplicate'):
        freeze_reviewed([entry, entry], [], REVIEW, tmp_path)
    with pytest.raises(ValueError, match='disjoint'):
        freeze_reviewed([entry], [{'qualified_ref': 'reviewed:one', 'reason': 'excluded'}], REVIEW, tmp_path)


def test_fixed_response_annotation_is_not_real_model_mining(tmp_path):
    bc = {'action_ids': ['a'], 'evidence_request_id': 'r1'}
    report = {'accepted_state': {'actions': {'a': {'evidence_request_id': 'r1'}}},
              'attempts': [{'request_id': 'r1', 'status': 'accepted', 'provider': {'real_model': False}}]}
    with pytest.raises(ValueError, match='real-model'):
        shown_for_bc(tmp_path, report, bc)


def projector(text, *, slot='value', truth=True):
    p = object.__new__(ReviewedProjector)
    p.conditions = {}; p.range_conditions = {}; p.loop_conditions = set()
    p.registry = {'cond_test': {'category': 'condition', 'record_ref': 'condition:one', 'branch_ref': 'analysis:branch',
                               'expected_value': {'status': 'known', 'value': truth}, 'scope': 'local_operation_only',
                               'source_collection_by_bu': {'bu:one': 'complete'}}}
    p.facts = {'condition:one': {'value_endpoint': {'slot_kind': slot}, 'provenance': {'rule_ref': 'rule:control'}},
               'analysis:branch': {'text': text}}
    p.audit = {'conditions': {}}
    return p


def test_generic_predicate_preserves_direction_truth_and_unknown_meaning():
    p = projector('if $i0 > 0 goto label27')
    assert p.condition('cond_test') == 'Condition1'
    value = p.conditions['cond_test']
    assert value['predicate_shape']['operator'] == 'greater than'
    assert value['predicate_shape']['right'] == {'role': 'constant', 'value': 0}
    assert value['required_truth']['value'] is True
    assert not value['runtime_established']
    assert value['predicate_meaning'].startswith('unknown')
    q = projector('if $i99 > 0 goto label3000')
    q.condition('cond_test')
    assert q.conditions == p.conditions
    reverse = projector('if $i0 < 0 goto label27')
    reverse.condition('cond_test')
    assert reverse.conditions != p.conditions


def test_boolean_normalization_does_not_reinterpret_branch_truth():
    p = projector('if $z0 == 0 goto label27', slot='local', truth=False)
    p.condition('cond_test')
    value = p.conditions['cond_test']
    assert value['required_truth']['value'] is False
    assert value['predicate_shape'] == 'recorded boolean value must have the required truth'
    assert 'original_condition' in p.audit['conditions']['Condition1']
