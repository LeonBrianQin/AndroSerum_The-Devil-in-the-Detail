"""Finite budgets must fit actual work, retain final reserves and freeze scope."""
from copy import deepcopy
import pytest

from androserum.pipeline.workload_planning import (
    InputPolicy, dispatch_readiness, downstream_budgets, encoding_readiness,
    final_review_budget, freeze_stage, mining_budget, scope_readiness,
    supported_limits_readiness,
    verify_stage,
)


def test_aes_all_discovered_scope_cannot_be_relabelled_materialized():
    value = scope_readiness(discovered_contexts=558, materialized_contexts=64,
                            blocks=926, unpackable_atoms=36)
    assert value['state'] == 'pending' and not value['dispatch_authorized']
    assert value['unmaterialized_contexts'] == 494
    assert set(value['reasons']) == {'discovered_contexts_not_materialized',
                                    'evidence_not_losslessly_packable'}
    assert scope_readiness(discovered_contexts=558, materialized_contexts=558,
                           blocks=120)['state'] == 'ready'


def test_invalid_scope_is_blocked_and_empty_scope_is_explicit():
    assert scope_readiness(discovered_contexts=1, materialized_contexts=2,
                           blocks=1)['state'] == 'blocked'
    assert scope_readiness(discovered_contexts=0, materialized_contexts=0,
                           blocks=0)['state'] == 'ready'
    with pytest.raises(ValueError): mining_budget(True)


def test_budget_covers_all_blocks_repairs_and_later_supplement_reviews():
    policy = InputPolicy(max_wire_chars=100, max_response_chars=20, segment_calls=1)
    b = mining_budget(14, repairs_per_block=1, supplement_review_rounds=4, policy=policy)
    assert b['max_calls'] == 32 and b['max_input_chars'] == 3200
    assert b['base_calls'] == b['repair_calls'] == 14
    assert b['segments']['count_upper_bound'] == 32
    assert not b['post_BU_final_review_included']


def test_unknown_BC_count_cannot_authorize_and_exact_freeze_retains_parent():
    upper = downstream_budgets(bc_upper_bound=128, top_k=2)
    assert upper['matching']['max_calls'] == 512
    with pytest.raises(ValueError, match='Unknown-output'):
        freeze_stage(upper['tasks'], input_manifest_sha256='a'*64, scope_sha256='b'*64)
    exact = downstream_budgets(8)
    assert exact['tasks']['initial_plus_synthesis_minimum_calls'] == 9
    assert exact['tasks']['max_calls'] == 18
    assert exact['tasks']['reservations']['synthesis_calls'] == 2
    with pytest.raises(ValueError):
        freeze_stage(exact['tasks'], input_manifest_sha256='a'*64, scope_sha256='b'*64)
    stage = freeze_stage(exact['tasks'], input_manifest_sha256='a'*64,
                         scope_sha256='b'*64, parent_stage_sha256='c'*64,
                         observed_output_manifest_sha256='d'*64)
    assert stage['dispatch_authorized'] and stage['parent_stage_sha256'] == 'c'*64
    assert verify_stage(stage)
    changed = deepcopy(exact['tasks']); changed['max_calls'] += 1
    with pytest.raises(ValueError, match='contradict'):
        freeze_stage(changed, input_manifest_sha256='a'*64, scope_sha256='b'*64,
            parent_stage_sha256='c'*64, observed_output_manifest_sha256='d'*64)
    later = downstream_budgets(9)['tasks']
    assert freeze_stage(later, input_manifest_sha256='a'*64, scope_sha256='b'*64,
        parent_stage_sha256='c'*64, observed_output_manifest_sha256='e'*64)['stage_sha256'] != stage['stage_sha256']


def test_final_frontier_is_frozen_separately_and_budget_never_claims_issue_resolution():
    assert final_review_budget()['state'] == 'pending'
    assert not final_review_budget(issue_upper_bound=20)['dispatch_authorized']
    b = final_review_budget(7)
    assert b['max_calls'] == 21 and b['query_plus_later_review_reserve'] == 14
    with pytest.raises(ValueError): final_review_budget(21, issue_upper_bound=20)


def test_synthesis_reserve_cannot_be_spent_by_incremental_call():
    b = downstream_budgets(8, policy=InputPolicy(max_wire_chars=100))['tasks']
    frozen = freeze_stage(b, input_manifest_sha256='a'*64, scope_sha256='b'*64,
        parent_stage_sha256='c'*64, observed_output_manifest_sha256='d'*64)
    assert dispatch_readiness(b, spent_calls=16, spent_input_chars=1600,
                               next_wire_chars=50, protected_calls=2, frozen_stage=frozen)['state'] == 'pending'
    assert dispatch_readiness(b, spent_calls=16, spent_input_chars=1600,
                               next_wire_chars=50, protected_calls=0, frozen_stage=frozen)['state'] == 'ready'
    assert dispatch_readiness(b, spent_calls=0, spent_input_chars=0,
                               next_wire_chars=101, frozen_stage=frozen)['state'] == 'blocked'
    assert dispatch_readiness(b, spent_calls=0, spent_input_chars=0,
                               next_wire_chars=50)['reason'] == 'stage_contract_not_frozen'


def test_frozen_contract_is_detached_and_mutation_fails_verification():
    b = mining_budget(2)
    frozen = freeze_stage(b, input_manifest_sha256='a'*64, scope_sha256='b'*64)
    b['max_calls'] = 99
    assert frozen['budget']['max_calls'] == 4
    frozen['budget']['max_calls'] = 98
    with pytest.raises(ValueError): verify_stage(frozen)


def test_zero_BCs_terminate_without_inventing_a_model_report():
    b = downstream_budgets(0)
    assert b['matching']['max_calls'] == b['tasks']['max_calls'] == 0


def test_v2_history_and_retained_pointer_need_exact_frozen_profile():
    cfg = {'serializer_version': 'bc-semantics.v2', 'revision': 'fixed', 'pooling': 'mean'}
    assert encoding_readiness(frozen_query=cfg, history=cfg)['state'] == 'ready'
    old = {**cfg, 'serializer_version': 'bc-semantics.v1'}
    assert encoding_readiness(frozen_query=cfg, history=old)['state'] == 'blocked'
    assert encoding_readiness(frozen_query=cfg, history=cfg,
                              retained_query=old)['state'] == 'blocked'
    assert encoding_readiness(frozen_query=None, history=cfg)['state'] == 'pending'


def test_runtime_contract_limit_is_not_silently_clamped():
    b = mining_budget(926, supplement_review_rounds=16)
    check = supported_limits_readiness(b, max_calls=10000,
        max_input_chars=1000000000, max_reported_input_tokens=1000000000)
    assert check['state'] == 'blocked'
    assert check['exceeded_fields'] == ['reported_input_token_stop']
    assert not check['silent_clamping_allowed']
