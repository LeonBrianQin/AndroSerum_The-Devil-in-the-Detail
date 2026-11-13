"""Plan an observed remaining frontier against unchanged cumulative budgets.

This module never dispatches, reserves, changes a ledger, or assigns labels.
The caller persists the returned version before executing it and still applies
the native request-size and transactional runtime budget checks to every call.
"""
from copy import deepcopy

from androserum.facts.identity import fingerprint


VERSION = 'remaining-observed-workload.v1'
STAGES = ('mining_review', 'matching', 'task_updates', 'synthesis')
POOLS = ('review_repairs', 'review_followups', 'matching_repairs',
         'task_repairs', 'task_followups')
DIMENSIONS = ('calls', 'input_chars', 'reported_input_tokens')


def _count(value, name, *, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not int or value < 0:
        raise ValueError(name + ' must be a nonnegative integer')
    return value


def _ids(values, name):
    if not isinstance(values, (list, tuple)):
        raise ValueError(name + ' must be an ordered list')
    result = list(values)
    if any(not isinstance(v, str) or not v.strip() for v in result) or len(result) != len(set(result)):
        raise ValueError(name + ' contains an empty or duplicate identity')
    return result


def _scopes(value):
    if not isinstance(value, dict) or not value:
        raise ValueError('Explicit cumulative budget scopes are required')
    expected = {prefix + dimension for dimension in DIMENSIONS for prefix in ('max_', 'spent_')}
    result = {}
    for name, row in value.items():
        if not isinstance(name, str) or not name.strip() or set(row) != expected:
            raise ValueError('Every scope needs all cumulative limits and spend fields')
        result[name] = {key: _count(n, name + '.' + key,
                                   nullable=key == 'spent_reported_input_tokens')
                        for key, n in row.items()}
    return result


def plan_remaining_workload(*, source_identity, pending_review_ids, frozen_bc_ids,
                            pending_candidates_by_bc, pending_task_bc_ids,
                            synthesis_status, budget_scopes, extra_call_pools=None,
                            stage_call_budgets=None, projected_input=None,
                            frontier_frozen=False, previous_plan=None,
                            pending_repair_items=None):
    """Return a new immutable *proposal* for the complete remaining workload.

    ``budget_scopes`` may include batch, pilot, and APK; each has ``max_calls``,
    ``spent_calls``, ``max_input_chars``, ``spent_input_chars``,
    ``max_reported_input_tokens`` and ``spent_reported_input_tokens``. A missing
    token receipt is represented by None and blocks any new dispatch.

    Shared repair pools are totals across a stage, not an entitlement to retry
    every item. Each proposal can be repaired at most once. Followup pools are
    explicitly bounded *additional model submissions*, not free fact queries.
    The final synthesis has its own nonborrowable initial+one-repair reserve.

    Input projections must cover all declared calls, including extra pools and
    final reserve. Without such a projection this is a calls-only precheck and
    cannot authorize dispatch. ``frontier_frozen=False`` is useful before final
    review changes the BC list; its numbers are an estimate, never a freeze.
    """
    if not isinstance(source_identity, dict) or not source_identity:
        raise ValueError('Bind this plan to the current source identity')
    if type(frontier_frozen) is not bool:
        raise ValueError('frontier_frozen must be explicit boolean')
    reviews = _ids(pending_review_ids, 'pending_review_ids')
    bcs = _ids(frozen_bc_ids, 'frozen_bc_ids')
    tasks = _ids(pending_task_bc_ids, 'pending_task_bc_ids')
    if not set(tasks) <= set(bcs):
        raise ValueError('Pending task BC is outside the observed BC frontier')
    if not isinstance(pending_candidates_by_bc, dict) or not set(pending_candidates_by_bc) <= set(bcs):
        raise ValueError('Pending matches must belong to the observed BC frontier')
    candidates = {bc: _ids(ids, 'candidates for ' + bc) for bc, ids in pending_candidates_by_bc.items()}
    pairs = [(bc, candidate) for bc in bcs for candidate in candidates.get(bc, [])]
    repairs = {stage: [] for stage in STAGES if stage != 'synthesis'}
    if pending_repair_items is not None:
        if not isinstance(pending_repair_items, dict) or not set(pending_repair_items) <= set(repairs):
            raise ValueError('Unknown pending repair stage')
        repairs.update({stage:_ids(ids, stage + ' pending repairs') for stage,ids in pending_repair_items.items()})
    if not set(repairs['task_updates']) <= set(bcs) or set(repairs['task_updates']) & set(tasks):
        raise ValueError('A task repair must be a current BC whose initial call is already spent')
    if set(repairs['mining_review']) & set(reviews):
        raise ValueError('A review cannot need both an initial call and its repair')
    if synthesis_status not in {'not_started', 'needs_repair', 'complete', 'not_required'}:
        raise ValueError('Unknown synthesis status')
    if synthesis_status == 'not_required' and bcs:
        raise ValueError('A nonempty BC scope cannot silently skip synthesis')
    if synthesis_status in {'complete', 'needs_repair'} and (tasks or repairs['task_updates']):
        raise ValueError('Finish the pending BC task updates before final synthesis')
    if synthesis_status in {'not_started', 'needs_repair'} and not bcs:
        raise ValueError('Empty BC scope has a deterministic outcome, not invented synthesis work')

    pools = dict.fromkeys(POOLS, 0)
    if extra_call_pools is not None:
        if not isinstance(extra_call_pools, dict) or not set(extra_call_pools) <= set(POOLS):
            raise ValueError('Unknown additional-call pool')
        pools.update(extra_call_pools)
    for key, value in pools.items():
        _count(value, key)
    for count, followups, repair_count, label in (
            (len(reviews), pools['review_followups'], pools['review_repairs'], 'review'),
            (len(pairs), 0, pools['matching_repairs'], 'matching'),
            (len(tasks), pools['task_followups'], pools['task_repairs'], 'task')):
        if not count and (followups or repair_count):
            raise ValueError('No remaining ' + label + ' work can consume an extra pool')
        if repair_count > count + followups:
            raise ValueError('Repair pool exceeds one repair per ' + label + ' proposal')
    scopes = _scopes(budget_scopes)
    spent_floors = {name:{dimension:row['spent_' + dimension] or 0 for dimension in DIMENSIONS}
                    for name, row in scopes.items()}
    stage_limits = deepcopy(stage_call_budgets or {})
    if not isinstance(stage_limits, dict) or not set(stage_limits) <= set(STAGES):
        raise ValueError('Unknown stage budget')
    for name, row in stage_limits.items():
        if set(row) != {'max_calls', 'spent_calls'}:
            raise ValueError('Stage limits must preserve cumulative calls and spend')
        for key, n in row.items():
            _count(n, name + '.' + key)
    inputs = deepcopy(projected_input)
    if inputs is not None:
        if set(inputs) != {'input_chars', 'reported_input_tokens'}:
            raise ValueError('Projection needs both remaining input dimensions')
        for key, n in inputs.items():
            _count(n, 'projected_' + key)

    observation = {'source_identity': deepcopy(source_identity), 'pending_review_ids': reviews,
        'frozen_bc_ids': bcs, 'pending_candidates_by_bc': candidates,
        'pending_task_bc_ids': tasks, 'synthesis_status': synthesis_status,
        'budget_scopes': scopes, 'extra_call_pools': pools,
        'stage_call_budgets': stage_limits, 'projected_input': inputs,
        'pending_repair_items': repairs,
        'frontier_frozen': frontier_frozen, 'max_repairs_per_proposal': 1}
    version = 1; parent = None; changed = []
    if previous_plan is not None:
        previous_contract = previous_plan['contract']
        if (previous_contract.get('schema_version') != VERSION or
                fingerprint(previous_contract) != previous_plan['plan_id']):
            raise ValueError('Previous plan integrity failed')
        old = previous_contract['observation']
        if old['source_identity'] != observation['source_identity']:
            raise ValueError('Cannot continue another source plan')
        for key in ('budget_scopes', 'stage_call_budgets'):
            if set(old[key]) != set(observation[key]):
                raise ValueError('Continuation cannot add or remove frozen budget scopes')
            for name, before in old[key].items():
                after = observation[key][name]
                for field, value in before.items():
                    if field.startswith('max_') and after[field] != value:
                        raise ValueError('Continuation cannot alter a frozen budget limit')
                    if field.startswith('spent_') and value is not None and after[field] is not None and after[field] < value:
                        raise ValueError('Continuation cannot reset cumulative spend')
        for name, floor in previous_contract['spent_floors'].items():
            for dimension, value in floor.items():
                current = scopes[name]['spent_' + dimension]
                if current is not None and current < value:
                    raise ValueError('A late receipt cannot reset the last known cumulative spend')
                spent_floors[name][dimension] = max(value, spent_floors[name][dimension])
        if old == observation:
            # Recompute derived gates instead of trusting a caller-modified
            # previous report whose input contract still has a valid hash.
            version = previous_contract['plan_version']
            parent = previous_contract['parent_plan_id']
        else:
            changed = [key for key in observation if old.get(key) != observation[key]]
            version = previous_contract['plan_version'] + 1
            parent = previous_plan['plan_id']

    initial = {'mining_review': len(reviews), 'matching': len(pairs), 'task_updates': len(tasks),
               'synthesis': int(synthesis_status == 'not_started')}
    additional = {'mining_review': pools['review_repairs'] + pools['review_followups'] + len(repairs['mining_review']),
                  'matching': pools['matching_repairs'] + len(repairs['matching']),
                  'task_updates': pools['task_repairs'] + pools['task_followups'] + len(repairs['task_updates']),
                  'synthesis': int(synthesis_status in {'not_started', 'needs_repair'})}
    # The required retry is the only remaining call when a final initial call
    # already failed. Its original spend is still present in every scope.
    minimum_finish = sum(initial.values()) + sum(map(len, repairs.values())) + int(synthesis_status == 'needs_repair')
    declared = {stage: initial[stage] + additional[stage] for stage in STAGES}
    required = sum(declared.values())
    if required and inputs is not None and any(value == 0 for value in inputs.values()):
        raise ValueError('Nonempty model work cannot have a zero input projection')
    worst = {'mining_review': 2 * (len(reviews) + pools['review_followups']) + len(repairs['mining_review']),
             'matching': 2 * len(pairs) + len(repairs['matching']),
             'task_updates': 2 * (len(tasks) + pools['task_followups']) + len(repairs['task_updates']),
             'synthesis': declared['synthesis']}
    reasons = []
    if not frontier_frozen:
        reasons.append('observed_frontier_not_frozen')
    if inputs is None and required:
        reasons.append('remaining_input_workload_unmeasured')
    scope_rows = {}
    for name, scope in scopes.items():
        remaining = {d: None if scope['spent_' + d] is None else scope['max_' + d] - scope['spent_' + d]
                     for d in DIMENSIONS}
        demand = {'calls': required, **(inputs or {})}
        gaps = {d: None if remaining[d] is None or d not in demand else max(0, demand[d] - remaining[d])
                for d in DIMENSIONS}
        if remaining['reported_input_tokens'] is None:
            reasons.append(name + ':unreconciled_input_usage')
        for dimension, gap in gaps.items():
            if gap is not None and gap:
                reasons.append(name + ':' + dimension + '_budget_shortfall')
        scope_rows[name] = {'limits_and_spend': deepcopy(scope), 'remaining': remaining,
                           'known_cumulative_spend_floor': spent_floors[name],
                           'declared_demand': demand, 'shortfall': gaps,
                           'minimum_initial_call_shortfall': max(0, sum(initial.values()) - remaining['calls']),
                           'minimum_finish_call_shortfall': max(0, minimum_finish - remaining['calls'])}
    effective_calls = min(row['remaining']['calls'] for row in scope_rows.values())
    stage_rows = {}
    for stage in STAGES:
        limit = stage_limits.get(stage)
        own_remaining = None if limit is None else limit['max_calls'] - limit['spent_calls']
        other_reserved = required - declared[stage]
        usable = max(0, effective_calls - other_reserved)
        if own_remaining is not None:
            usable = min(usable, max(0, own_remaining))
        shortfall = max(0, declared[stage] - usable)
        if own_remaining is not None and declared[stage] > own_remaining:
            reasons.append(stage + ':frozen_stage_call_budget_shortfall')
        stage_rows[stage] = {'initial_calls': initial[stage], 'declared_additional_pool': additional[stage],
            'pending_required_repairs': len(repairs.get(stage, [])),
            'declared_calls': declared[stage], 'all_proposals_repaired_upper_estimate': worst[stage],
            'frozen_stage_remaining': own_remaining, 'other_stages_reserved_calls': other_reserved,
            'usable_after_reserving_other_stages': usable, 'shortfall': shortfall}

    contract = {'schema_version': VERSION, 'plan_version': version, 'parent_plan_id': parent,
                'observation': observation, 'spent_floors': spent_floors}
    return {'schema_version': VERSION, 'contract': contract, 'plan_id': fingerprint(contract),
        'plan_version': version, 'parent_plan_id': parent, 'changed_observation_fields': changed,
        'new_plan_version_required': bool(changed), 'minimum_initial_calls': sum(initial.values()),
        'minimum_calls_to_finish': minimum_finish, 'declared_extra_pools': pools,
        'declared_total_calls': required, 'all_proposals_repaired_upper_estimate': sum(worst.values()),
        'stages': stage_rows, 'budget_scopes': scope_rows,
        'final_synthesis_reservation': {'calls': declared['synthesis'],
            'initial': initial['synthesis'], 'repair': additional['synthesis'], 'borrowable': False},
        'can_dispatch_by_calls': not any(row['shortfall']['calls'] for row in scope_rows.values())
            and not any('frozen_stage_call_budget_shortfall' in reason for reason in reasons),
        'can_dispatch': not reasons, 'blocking_reasons': reasons,
        'native_per_call_checks_still_required': True, 'budget_mutated': False,
        'upper_estimate_is_not_authorization': True, 'monetary_cost_estimate': None}
