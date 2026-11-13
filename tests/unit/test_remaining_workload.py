"""Observed frontiers and cumulative-budget regression, without model calls."""
from copy import deepcopy

import pytest

from androserum.pipeline.remaining_workload import plan_remaining_workload


def scope(max_calls, spent_calls):
    return {'max_calls':max_calls,'spent_calls':spent_calls,
        'max_input_chars':6000000,'spent_input_chars':1000000,
        'max_reported_input_tokens':2000000,'spent_reported_input_tokens':1624883}


def observed():
    bcs=['bc:'+str(i) for i in range(7)]
    return dict(source_identity={'apk_sha256':'a'*64,'snapshot':'b'*64},
        pending_review_ids=['issue:'+str(i) for i in range(10)], frozen_bc_ids=bcs,
        pending_candidates_by_bc={bc:['reference:'+str(i) for i in range(3)] for bc in bcs},
        pending_task_bc_ids=list(bcs), synthesis_status='not_started',
        budget_scopes={'batch':scope(240,24),'pilot':scope(48,24),'apk':scope(64,24)},
        extra_call_pools={'matching_repairs':1,'task_repairs':1},
        projected_input={'input_chars':100000,'reported_input_tokens':50000},
        frontier_frozen=True)


def test_observed_seven_bc_frontier_cannot_fit_remaining_pilot_budget():
    args=observed();unchanged=deepcopy(args);plan=plan_remaining_workload(**args)
    assert args==unchanged
    assert plan['minimum_initial_calls']==39
    assert plan['declared_total_calls']==42
    assert plan['all_proposals_repaired_upper_estimate']==78
    assert plan['budget_scopes']['pilot']['remaining']['calls']==24
    assert plan['budget_scopes']['pilot']['minimum_initial_call_shortfall']==15
    assert plan['budget_scopes']['pilot']['shortfall']['calls']==18
    assert plan['budget_scopes']['apk']['shortfall']['calls']==2
    assert not plan['can_dispatch'] and not plan['can_dispatch_by_calls']
    assert plan['final_synthesis_reservation']=={'calls':2,'initial':1,'repair':1,'borrowable':False}


def test_actual_candidate_counts_are_used_instead_of_bc_times_top_k():
    args=observed();bcs=args['frozen_bc_ids']
    args['pending_candidates_by_bc']={bcs[0]:['reference:a'],bcs[1]:['reference:b','reference:c']}
    args['pending_review_ids']=[]
    plan=plan_remaining_workload(**args)
    assert plan['stages']['matching']['initial_calls']==3
    assert plan['minimum_initial_calls']==11
    assert plan['can_dispatch']


def test_final_reserve_cannot_be_borrowed_to_start_last_incremental_call():
    args=observed();args['pending_review_ids']=[];args['pending_candidates_by_bc']={}
    args['extra_call_pools']={};args['budget_scopes']={'apk':scope(32,24)}
    plan=plan_remaining_workload(**args)
    assert plan['minimum_initial_calls']==8 and plan['declared_total_calls']==9
    assert not plan['can_dispatch_by_calls']
    assert plan['stages']['task_updates']['other_stages_reserved_calls']==2
    assert plan['stages']['task_updates']['usable_after_reserving_other_stages']==6
    assert plan['stages']['task_updates']['shortfall']==1


def test_resumed_final_repair_keeps_previous_initial_spend():
    args=observed();args.update(pending_review_ids=[],pending_candidates_by_bc={},pending_task_bc_ids=[],
        extra_call_pools={},synthesis_status='needs_repair',budget_scopes={'apk':scope(64,63)})
    plan=plan_remaining_workload(**args)
    assert plan['minimum_initial_calls']==0 and plan['minimum_calls_to_finish']==1
    assert plan['declared_total_calls']==1 and plan['can_dispatch']
    assert plan['final_synthesis_reservation']['initial']==0
    assert plan['final_synthesis_reservation']['repair']==1


def test_new_bc_or_candidate_identity_requires_new_plan_even_if_count_equal():
    args=observed();first=plan_remaining_workload(**args)
    args['pending_candidates_by_bc'][args['frozen_bc_ids'][0]][0]='reference:replacement'
    second=plan_remaining_workload(**args,previous_plan=first)
    assert second['plan_version']==2 and second['parent_plan_id']==first['plan_id']
    assert second['plan_id']!=first['plan_id']
    assert 'pending_candidates_by_bc' in second['changed_observation_fields']
    args['frozen_bc_ids'].append('bc:new');args['pending_task_bc_ids'].append('bc:new')
    args['pending_candidates_by_bc']['bc:new']=['reference:one']
    third=plan_remaining_workload(**args,previous_plan=second)
    assert third['plan_version']==3 and third['minimum_initial_calls']==41
    assert third['budget_scopes']['pilot']['remaining']['calls']==24


@pytest.mark.parametrize('change', ['limit','spend','scope_removal','stage_limit','stage_spend'])
def test_continuation_rejects_silent_budget_expansion_or_spend_reset(change):
    args=observed();args['stage_call_budgets']={'mining_review':{'max_calls':20,'spent_calls':3}}
    first=plan_remaining_workload(**args)
    if change=='limit':args['budget_scopes']['pilot']['max_calls']=100
    if change=='spend':args['budget_scopes']['apk']['spent_calls']=0
    if change=='scope_removal':del args['budget_scopes']['pilot']
    if change=='stage_limit':args['stage_call_budgets']['mining_review']['max_calls']=100
    if change=='stage_spend':args['stage_call_budgets']['mining_review']['spent_calls']=0
    with pytest.raises(ValueError):plan_remaining_workload(**args,previous_plan=first)


def test_same_plan_recomputes_gate_and_does_not_trust_derived_status():
    args=observed();first=plan_remaining_workload(**args);first['can_dispatch']=True
    second=plan_remaining_workload(**args,previous_plan=first)
    assert second['plan_id']==first['plan_id'] and second['plan_version']==1
    assert not second['can_dispatch']


def test_unknown_then_late_token_receipt_cannot_reset_known_spend_floor():
    args=observed();first=plan_remaining_workload(**args)
    args['budget_scopes']['pilot']['spent_reported_input_tokens']=None
    unknown=plan_remaining_workload(**args,previous_plan=first)
    assert not unknown['can_dispatch']
    assert unknown['budget_scopes']['pilot']['known_cumulative_spend_floor']['reported_input_tokens']==1624883
    args['budget_scopes']['pilot']['spent_reported_input_tokens']=1000
    with pytest.raises(ValueError,match='late receipt'):plan_remaining_workload(**args,previous_plan=unknown)
    args['budget_scopes']['pilot']['spent_reported_input_tokens']=1700000
    reconciled=plan_remaining_workload(**args,previous_plan=unknown)
    assert reconciled['budget_scopes']['pilot']['known_cumulative_spend_floor']['reported_input_tokens']==1700000


def test_stage_limit_and_missing_usage_remain_independent_blockers():
    args=observed();args['budget_scopes']={'batch':scope(240,24)}
    args['stage_call_budgets']={'mining_review':{'max_calls':6,'spent_calls':1}}
    args['budget_scopes']['batch']['spent_reported_input_tokens']=None
    plan=plan_remaining_workload(**args)
    assert 'mining_review:frozen_stage_call_budget_shortfall' in plan['blocking_reasons']
    assert 'batch:unreconciled_input_usage' in plan['blocking_reasons']
    assert plan['stages']['mining_review']['frozen_stage_remaining']==5
    assert not plan['can_dispatch']


def test_unfrozen_frontier_and_unmeasured_input_cannot_authorize_dispatch():
    args=observed();args['budget_scopes']={'batch':scope(240,24)}
    args.update(frontier_frozen=False,projected_input=None)
    plan=plan_remaining_workload(**args)
    assert plan['can_dispatch_by_calls'] and not plan['can_dispatch']
    assert set(plan['blocking_reasons'])=={'observed_frontier_not_frozen','remaining_input_workload_unmeasured'}


def test_invalid_pool_and_foreign_bc_are_rejected():
    args=observed();args['extra_call_pools']['matching_repairs']=22
    with pytest.raises(ValueError,match='one repair'):plan_remaining_workload(**args)
    args=observed();args['pending_task_bc_ids'].append('bc:foreign')
    with pytest.raises(ValueError,match='outside'):plan_remaining_workload(**args)


def test_empty_scope_deterministic_completion_requires_no_fabricated_calls():
    args=observed();args.update(pending_review_ids=[],frozen_bc_ids=[],pending_candidates_by_bc={},
        pending_task_bc_ids=[],synthesis_status='not_required',extra_call_pools={},projected_input=None)
    plan=plan_remaining_workload(**args)
    assert plan['declared_total_calls']==0 and plan['minimum_calls_to_finish']==0 and plan['can_dispatch']
