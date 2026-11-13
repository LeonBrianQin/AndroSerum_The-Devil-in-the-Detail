"""Pure workload/budget calculations; no inference, extraction or budget mutation.

Budgets for unknown model output are estimates only. A downstream/final-review
stage is dispatchable only after its actual input list is frozen separately.
The caller persists the returned contract before starting that stage.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass
import re

from androserum.facts.identity import fingerprint


VERSION = 'workload-stage-planning.v1'


def _count(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(name + ' must be a nonnegative integer')
    return value


def _positive(value, name):
    if _count(value, name) == 0:
        raise ValueError(name + ' must be positive')
    return value


def _digest(value, name):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError(name + ' requires an exact SHA-256')
    return value


@dataclass(frozen=True)
class InputPolicy:
    """Hard wire bounds and an explicit conservative reported-token stop.

    Four tokens per wire character covers a UTF-8 byte-level upper estimate.
    Hidden provider overhead is represented separately, not silently treated
    as measured usage. Runtime still stops before the next dispatch when the
    reported-token stop is reached; one in-flight call may cross that stop.
    """
    max_wire_chars: int = 400000
    max_response_chars: int = 60000
    token_bound_per_wire_char: int = 4
    provider_overhead_tokens_per_call: int = 8192
    segment_calls: int = 1

    def __post_init__(self):
        for name in ('max_wire_chars', 'max_response_chars',
                     'token_bound_per_wire_char', 'segment_calls'):
            _positive(getattr(self, name), name)
        _count(self.provider_overhead_tokens_per_call, 'provider_overhead_tokens_per_call')


def scope_readiness(*, discovered_contexts, materialized_contexts, blocks,
                    unpackable_atoms=0, pending_roots=0, failed_contexts=0):
    """All discovered contexts stay in the denominator; no subset fallback."""
    counts = dict(discovered_contexts=discovered_contexts,
                  materialized_contexts=materialized_contexts, blocks=blocks,
                  unpackable_atoms=unpackable_atoms, pending_roots=pending_roots,
                  failed_contexts=failed_contexts)
    for name, value in counts.items():
        _count(value, name)
    if materialized_contexts > discovered_contexts:
        return {'state': 'blocked', 'reasons': ['materialization_exceeds_discovered_scope'],
                'counts': counts, 'dispatch_authorized': False}
    pending = []
    if materialized_contexts < discovered_contexts:
        pending.append('discovered_contexts_not_materialized')
    if unpackable_atoms:
        pending.append('evidence_not_losslessly_packable')
    if pending_roots:
        pending.append('root_context_discovery_incomplete')
    if failed_contexts:
        pending.append('context_failures_require_explicit_resolution')
    if discovered_contexts and not blocks:
        pending.append('nonempty_context_scope_has_no_measured_blocks')
    return {'state': 'pending' if pending else 'ready', 'reasons': pending,
            'counts': counts,
            'unmaterialized_contexts': discovered_contexts - materialized_contexts,
            'dispatch_authorized': not pending,
            'scope_policy': 'all_discovered_contexts_no_silent_subset'}


def encoding_readiness(*, frozen_query, history, retained_query=None,
                       required_serializer='bc-semantics.v2'):
    """No v2/v1 vector mixing and no pointer bypass of the frozen profile."""
    if frozen_query is None or history is None:
        return {'state': 'pending', 'reasons': ['explicit_query_and_history_profiles_required'],
                'dispatch_authorized': False}
    reasons = []
    if frozen_query.get('serializer_version') != required_serializer:
        reasons.append('query_serializer_differs_from_declared_new_stage')
    if frozen_query != history:
        reasons.append('query_history_encoding_profiles_differ')
    if retained_query is not None and retained_query != frozen_query:
        reasons.append('retained_pointer_differs_from_frozen_query_profile')
    return {'state': 'blocked' if reasons else 'ready', 'reasons': reasons,
            'dispatch_authorized': not reasons}


def _budget(stage, units, *, base=0, repairs=0, query_reviews=0,
            synthesis=0, policy=None, exact=True, unresolved_output=None):
    policy = policy or InputPolicy()
    components = dict(base_calls=base, repair_calls=repairs,
                      query_review_calls=query_reviews, synthesis_calls=synthesis)
    for name, value in components.items():
        _count(value, name)
    calls = sum(components.values())
    wire = calls * policy.max_wire_chars
    return {'schema_version': VERSION, 'stage': stage, 'work_items': units,
            **components, 'max_calls': calls, 'max_input_chars': wire,
            'max_response_chars_total': calls * policy.max_response_chars,
            'reported_input_token_stop': wire * policy.token_bound_per_wire_char
                + calls * policy.provider_overhead_tokens_per_call,
            'input_policy': asdict(policy),
            'segments': {'max_new_calls': policy.segment_calls,
                         'count_upper_bound': (calls + policy.segment_calls - 1)
                            // policy.segment_calls,
                         'persistent_spend_across_segments': True},
            'reservations': {'synthesis_calls': synthesis,
                             'synthesis_input_chars': synthesis * policy.max_wire_chars,
                             'cannot_be_borrowed_by_incremental_work': True},
            'exact_workload': exact,
            'unknown_output': unresolved_output,
            'dispatch_authorized': False,
            'requires_frozen_stage_contract': True,
            'token_stop_scope': 'conservative estimate with explicit overhead; actual reported usage audited; stop before next call',
            'monetary_cost': None}


def mining_budget(blocks, *, repairs_per_block=1, supplement_review_rounds=0,
                  policy=None):
    """One initial request per measured block, independent repair reserve."""
    _count(blocks, 'blocks'); _count(repairs_per_block, 'repairs_per_block')
    _count(supplement_review_rounds, 'supplement_review_rounds')
    result = _budget('mining', blocks, base=blocks,
                     repairs=blocks * repairs_per_block,
                     query_reviews=supplement_review_rounds, policy=policy)
    result['ordinary_first_pass_minimum_calls'] = blocks
    result['post_BU_final_review_included'] = False
    return result


def final_review_budget(issues=None, *, issue_upper_bound=None,
                        attempts_per_issue=3, policy=None):
    """Actual issue frontier is frozen after ordinary BU work completes."""
    _positive(attempts_per_issue, 'attempts_per_issue')
    if issues is None:
        if issue_upper_bound is None:
            return {'schema_version': VERSION, 'stage': 'mining_final_review',
                    'state': 'pending', 'reason': 'model_issue_frontier_not_frozen',
                    'dispatch_authorized': False, 'max_calls': None}
        count = _count(issue_upper_bound, 'issue_upper_bound')
    else:
        count = _count(issues, 'issues')
        if issue_upper_bound is not None and count > _count(issue_upper_bound, 'issue_upper_bound'):
            raise ValueError('Actual issue frontier exceeds the declared upper estimate; freeze a new stage before dispatch')
    result = _budget('mining_final_review', count, base=count,
                     query_reviews=count * (attempts_per_issue - 1), policy=policy,
                     exact=issues is not None,
                     unresolved_output=None if issues is not None else 'issue_frontier')
    result['per_issue_attempt_cap'] = attempts_per_issue
    result['query_plus_later_review_reserve'] = min(2, attempts_per_issue) * count
    return result


def downstream_budgets(bcs=None, *, bc_upper_bound=None, history_candidates=3,
                       top_k=1, matching_repairs=1, runnable_tasks=1,
                       task_repairs=1, extra_query_reviews_per_task=0, policy=None):
    """Per-BC task staging; never assume unimplemented task batching.

    A count based on bc_upper_bound is only a conservative planning estimate.
    It cannot authorize inference. Recompute with the exact final BC freeze.
    """
    for name, value in dict(history_candidates=history_candidates, top_k=top_k,
            matching_repairs=matching_repairs, runnable_tasks=runnable_tasks,
            task_repairs=task_repairs,
            extra_query_reviews_per_task=extra_query_reviews_per_task).items():
        _count(value, name)
    if bcs is None:
        if bc_upper_bound is None:
            return {'state': 'pending', 'reason': 'final_BC_list_not_frozen',
                    'dispatch_authorized': False, 'matching': None, 'tasks': None}
        count = _count(bc_upper_bound, 'bc_upper_bound')
    else:
        count = _count(bcs, 'bcs')
        if bc_upper_bound is not None and count > _count(bc_upper_bound, 'bc_upper_bound'):
            raise ValueError('Actual BCs exceed the declared upper estimate; freeze a new downstream stage')
    exact = bcs is not None
    pairs = count * min(top_k, history_candidates)
    matching = _budget('matching', pairs, base=pairs,
                       repairs=pairs * matching_repairs, policy=policy,
                       exact=exact, unresolved_output=None if exact else 'final_BC_list')
    # Empty BC input has a deterministic insufficient-evidence outcome and
    # needs no synthesized behavior or generative conclusion.
    initial = count * runnable_tasks
    final = runnable_tasks * (1 + task_repairs) if count else 0
    task = _budget('tasks', initial, base=initial,
                   repairs=initial * task_repairs, synthesis=final,
                   query_reviews=runnable_tasks * extra_query_reviews_per_task if count else 0,
                   policy=policy, exact=exact,
                   unresolved_output=None if exact else 'final_BC_list')
    task['per_BC_staging'] = True
    task['runnable_tasks'] = runnable_tasks
    task['initial_plus_synthesis_minimum_calls'] = (count + 1) * runnable_tasks if count else 0
    return {'state': 'ready_to_freeze' if exact else 'pending',
            'dispatch_authorized': False, 'matching': matching, 'tasks': task,
            'BC_count': count, 'count_is_conservative_upper_bound': not exact}


def freeze_stage(budget, *, input_manifest_sha256, scope_sha256,
                 parent_stage_sha256=None, observed_output_manifest_sha256=None):
    """Pure immutable child contract; caller writes it to a NEW stage path.

    This creates no amendment to an active stage. Final review/matching/tasks
    additionally require the actual model-output frontier or BC freeze hash.
    """
    if not budget.get('exact_workload') or budget.get('unknown_output') is not None:
        raise ValueError('Unknown-output estimates cannot authorize dispatch')
    if (budget.get('schema_version') != VERSION or type(budget['exact_workload']) is not bool
            or budget.get('stage') not in {'mining', 'mining_final_review', 'matching', 'tasks'}):
        raise ValueError('Unsupported stage budget contract')
    expected = _budget(budget['stage'], _count(budget['work_items'], 'work_items'),
        base=budget['base_calls'], repairs=budget['repair_calls'],
        query_reviews=budget['query_review_calls'], synthesis=budget['synthesis_calls'],
        policy=InputPolicy(**budget['input_policy']), exact=True,
        unresolved_output=budget.get('unknown_output'))
    if any(budget.get(key) != value for key, value in expected.items()):
        raise ValueError('Stage budget totals or reservations contradict their components')
    if budget['base_calls'] != budget['work_items']:
        raise ValueError('Initial-call denominator differs from measured stage work')
    _digest(input_manifest_sha256, 'input_manifest_sha256')
    _digest(scope_sha256, 'scope_sha256')
    if parent_stage_sha256 is not None:
        _digest(parent_stage_sha256, 'parent_stage_sha256')
    if budget['stage'] != 'mining':
        _digest(observed_output_manifest_sha256, 'observed_output_manifest_sha256')
        if parent_stage_sha256 is None:
            raise ValueError('A follow-up stage must retain its completed parent stage')
    body = {'schema_version': 'frozen-workload-stage.v1', 'budget': deepcopy(budget),
            'input_manifest_sha256': input_manifest_sha256, 'scope_sha256': scope_sha256,
            'parent_stage_sha256': parent_stage_sha256,
            'observed_output_manifest_sha256': observed_output_manifest_sha256,
            'budget_change_policy': 'new_child_stage_only_before_its_first_dispatch',
            'dispatch_authorized': True}
    return {**body, 'stage_sha256': fingerprint(body)}


def verify_stage(contract):
    expected = freeze_stage(contract['budget'],
        input_manifest_sha256=contract['input_manifest_sha256'],
        scope_sha256=contract['scope_sha256'],
        parent_stage_sha256=contract.get('parent_stage_sha256'),
        observed_output_manifest_sha256=contract.get('observed_output_manifest_sha256'))
    if contract != expected:
        raise ValueError('Frozen stage identity, budget or parent binding changed')
    return True


def supported_limits_readiness(budget, *, max_calls, max_input_chars,
                               max_reported_input_tokens):
    """Fail explicitly when integration limits cannot represent the plan."""
    limits = dict(max_calls=max_calls, max_input_chars=max_input_chars,
                  reported_input_token_stop=max_reported_input_tokens)
    for name, value in limits.items():
        _count(value, name)
    exceeded = [name for name, limit in limits.items() if budget[name] > limit]
    return {'state': 'blocked' if exceeded else 'ready',
            'reason': 'computed_stage_exceeds_supported_runtime_limits' if exceeded else 'within_supported_limits',
            'exceeded_fields': exceeded, 'limits': limits,
            'silent_clamping_allowed': False}


def dispatch_readiness(budget, *, spent_calls, spent_input_chars, next_wire_chars,
                       protected_calls=0, frozen_stage=None):
    """Three outcomes; never clamp or enlarge a frozen finite allowance."""
    for name, value in dict(spent_calls=spent_calls,
            spent_input_chars=spent_input_chars, next_wire_chars=next_wire_chars,
            protected_calls=protected_calls).items():
        _count(value, name)
    if not budget.get('exact_workload'):
        return {'state': 'pending', 'reason': 'actual_stage_workload_not_frozen'}
    if frozen_stage is None:
        return {'state': 'pending', 'reason': 'stage_contract_not_frozen'}
    verify_stage(frozen_stage)
    if frozen_stage['budget'] != budget:
        return {'state': 'blocked', 'reason': 'active_stage_budget_differs_from_frozen_contract'}
    maximum = budget['input_policy']['max_wire_chars']
    if next_wire_chars > maximum:
        return {'state': 'blocked', 'reason': 'single_packet_exceeds_frozen_wire_limit'}
    remaining_calls = budget['max_calls'] - spent_calls
    remaining_chars = budget['max_input_chars'] - spent_input_chars
    if remaining_calls < 0 or remaining_chars < 0:
        return {'state': 'blocked', 'reason': 'recorded_spend_exceeds_frozen_contract'}
    if remaining_calls <= protected_calls or remaining_chars < next_wire_chars + protected_calls * maximum:
        return {'state': 'pending', 'reason': 'frozen_budget_or_reserved_final_work',
                'remaining_calls': remaining_calls, 'remaining_input_chars': remaining_chars}
    return {'state': 'ready', 'reason': 'fits_frozen_allowance',
            'remaining_calls': remaining_calls, 'remaining_input_chars': remaining_chars}


__all__ = ['InputPolicy', 'scope_readiness', 'encoding_readiness',
           'mining_budget', 'final_review_budget', 'downstream_budgets',
           'freeze_stage', 'verify_stage', 'dispatch_readiness', 'supported_limits_readiness']
