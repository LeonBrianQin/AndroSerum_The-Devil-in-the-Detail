"""APK-parametric reviewed BC -> BERT -> references -> audited task report.

This module consumes an explicit new query freeze. It never admits that query
to history, manufactures mining annotations, or executes the input APK.
"""
from __future__ import annotations

from copy import deepcopy
from collections import deque, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from androserum.encoding.models import EncodingConfig
from androserum.facts.identity import canonical_json, fingerprint, filesystem_path, sha256_file
from androserum.facts.store import FactView
from androserum.inference.compact import COMPACT_INSTRUCTIONS, expand_compact
from androserum.inference.matching import MATCH_PROMPT, match_protocol
from androserum.inference.provider import strict_schema, write
from androserum.matching.checker import check_match
from androserum.matching.models import MatchConfig, MatchProposal
from androserum.matching.retrieval import recall
from androserum.matching.views import native_check, view_from_entry, make_request, make_request_v2, make_request_v3
from androserum.matching.decisions import is_supported
from androserum.mining.checker import proposal_handles
from androserum.mining.evidence import handle as evidence_handle
from .approval import load_frozen
from .encoding import encode_frozen, verify_encoding
from .knowledge import load_history
from .provider import PipelineProvider
from .tasking import GeneralTaskLedger, TaskConfig, PROMPT, proposal_schema, MATCHING_V2_REFERENCE_INSTRUCTIONS


def read(path):
    return json.loads(filesystem_path(path).read_text('utf-8'))


def _query_encoder_config(config, encoded=None):
    expected=EncodingConfig.model_validate(config.get('query_encoding_config',{}))
    if encoded is not None and read(filesystem_path(encoded)/'config.json')!=expected.model_dump(mode='json'):
        raise ValueError('Retained query encoding differs from the round-frozen encoding configuration')
    return expected


def _frozen(path, value):
    path = filesystem_path(path)
    if path.exists():
        if read(path) != value: raise ValueError('Frozen analysis material differs: ' + str(path))
    else: write(path, value)
    return value


def coordinate_visible(sides):
    """Unify only actually displayed monotonic detail and BU membership.

    Handles are never imported from an archive. Each native side retains its
    original handle set; an already visible fact can gain fields shown for that
    same fact in another approved current BC. Semantic collisions are rejected.
    """
    sides = deepcopy(sides); union = {}; audit = []
    for bid, side in sides.items():
        for handle, value in side['registry'].items():
            if handle not in union:
                union[handle] = deepcopy(value); continue
            old = union[handle]
            if old == value: continue
            if old.get('category') != value.get('category'):
                raise ValueError('Cross-BC visible evidence category collision')
            a, b = deepcopy(old), deepcopy(value)
            membership = sorted(set(a.pop('bu_ids', [])) | set(b.pop('bu_ids', [])))
            sources_a = a.pop('source_collection_by_bu', None)
            sources_b = b.pop('source_collection_by_bu', None)
            if sources_a is not None or sources_b is not None:
                sources_a, sources_b = sources_a or {}, sources_b or {}
                if any(sources_a[k] != sources_b[k] for k in set(sources_a) & set(sources_b)):
                    raise ValueError('Conflicting condition source collection states')
            if a.get('category') == 'fact':
                if a.get('record_sha256') != b.get('record_sha256'):
                    raise ValueError('Conflicting underlying visible fact hashes')
                ra, rb = a['record'], b['record']
                if any(ra[k] != rb[k] for k in set(ra) & set(rb)):
                    raise ValueError('Conflicting displayed fact fields')
                if not (set(ra) <= set(rb) or set(rb) <= set(ra)):
                    raise ValueError('Non-monotonic displayed fact detail')
                richer = value if set(ra) <= set(rb) else old
                for key in ['record', 'shown_fields', 'detail_fields_available', 'supplement_query_id']:
                    a.pop(key, None); b.pop(key, None)
                if a != b: raise ValueError('Conflicting visible fact identity metadata')
                merged = deepcopy(richer)
            else:
                if a != b: raise ValueError('Conflicting semantic evidence; new review required')
                merged = deepcopy(old)
            if membership: merged['bu_ids'] = membership
            if sources_a is not None or sources_b is not None:
                merged['source_collection_by_bu'] = {**(sources_a or {}), **(sources_b or {})}
            audit.append({'handle': handle, 'bc_id': bid, 'before_sha256': fingerprint(old),
                          'other_displayed_sha256': fingerprint(value), 'after_sha256': fingerprint(merged),
                          'policy': 'Same immutable fact; only displayed monotonic fields/BU membership/source collection metadata',
                          'archive_evidence_added': False})
            union[handle] = merged
    for side in sides.values():
        side['registry'] = {h: deepcopy(union[h]) for h in side['registry']}
        native_check({'bc': side['bc'], 'actions': side['actions'],
                      'model_visible_evidence': {'registry': side['registry']}})
    return sides, audit


def scope_side(side):
    """Project the necessary native evidence closure once, without summarizing.

    Start with every handle cited by the bare BC and its selected actions. Use
    the EvidenceCatalog closure fields, retain endpoint owners, and distinguish
    binding records' raw condition IDs from model-facing handles. Raw provenance
    references remain audit metadata; they do not authorize archive expansion.
    """
    native_check({'bc': side['bc'], 'actions': side['actions'],
                  'model_visible_evidence': {'registry': side['registry']}})
    registry = side['registry']; reasons = defaultdict(list); queue = deque()
    def require(handle, reason):
        if handle not in registry:
            raise ValueError('Scoped BC evidence closure is missing a visible record: ' + str(handle))
        if reason not in reasons[handle]: reasons[handle].append(reason)
        queue.append(handle)
    for handle in sorted(proposal_handles(side['bc'])):
        require(handle, {'kind': 'bc_citation'})
    for aid, action in side['actions'].items():
        for handle in sorted(proposal_handles(action)):
            require(handle, {'kind': 'selected_action_citation', 'action_id': aid})
    kept = set()
    while queue:
        handle = queue.popleft()
        if handle in kept: continue
        kept.add(handle); entry = registry[handle]
        for key in ['endpoint_refs', 'binding_refs', 'condition_refs']:
            for ref in entry.get(key, []):
                reason = {'kind': 'evidence_closure', 'from_handle': handle, 'field': key}
                if ref in registry:
                    require(ref, reason)
                elif key == 'condition_refs' and entry['category'] == 'binding' and ref.startswith('condition:'):
                    # These are original ConditionRecord identities, not model
                    # handles. Keep their visible fact and existing condition
                    # views; do not infer a new guard or change its context.
                    require(evidence_handle('fact', ref), {**reason, 'role': 'raw_binding_condition_fact'})
                    views = [h for h,e in registry.items() if e['category'] == 'condition' and e.get('record_ref') == ref]
                    if not views: raise ValueError('Raw binding condition lacks an actually displayed condition view')
                    for view in views: require(view, {**reason, 'role': 'raw_binding_condition_view'})
                else:
                    require(ref, reason)
        for key in ['source_endpoint_ref', 'target_endpoint_ref', 'owner_operation_ref']:
            if entry.get(key):
                require(entry[key], {'kind': 'evidence_closure', 'from_handle': handle, 'field': key})
        for ref in entry.get('fact_refs', []):
            require(evidence_handle('fact', ref), {'kind': 'evidence_closure', 'from_handle': handle, 'field': 'fact_refs',
                                                  'raw_record_ref': ref})
    result = deepcopy(side)
    result['registry'] = {h: deepcopy(registry[h]) for h in sorted(kept)}
    result['condition_semantics'] = {h: deepcopy(v) for h,v in side['condition_semantics'].items() if h in kept}
    checked = native_check({'bc': result['bc'], 'actions': result['actions'],
                            'model_visible_evidence': {'registry': result['registry']}})
    result['native_check'] = checked
    assert result['bc'] == side['bc'] and result['actions'] == side['actions']
    assert all(result['registry'][h] == registry[h] for h in result['registry'])
    audit = {'schema_version': 'native-bc-evidence-scope.v1', 'instance_ref': side['instance_ref'],
             'full_side_sha256': fingerprint(side), 'scoped_side_sha256': fingerprint(result),
             'full_registry_sha256': fingerprint(registry), 'scoped_registry_sha256': fingerprint(result['registry']),
             'full_handles': sorted(registry), 'scoped_handles': sorted(kept),
             'omitted_handles': sorted(set(registry)-kept), 'inclusion_reasons': dict(reasons),
             'full_handle_count': len(registry), 'scoped_handle_count': len(kept),
             'selected_actions_relations_conditions_limits_unchanged': True,
             'retained_evidence_values_unchanged': True, 'native_check': checked,
             'archive_records_added': False, 'original_approved_entry_modified': False,
             'closure_policy': 'One deterministic EvidenceCatalog closure plus endpoint owners and explicitly mapped raw binding conditions; no graph-neighbor or consumer expansion'}
    return result, audit


def _retained_call(directory, packet, schema, instructions):
    """Replay transport only; failures remain charged and cannot be reissued."""
    directory = filesystem_path(directory)
    if not directory.exists(): return None
    receipt_path = directory / 'receipt.json'
    if not receipt_path.exists():
        return {'raw': '', 'receipt': None, 'error': 'Interrupted reserved call retained; no repeat invocation'}
    receipt = read(receipt_path)
    if receipt.get('status') != 'completed':
        return {'raw': '', 'receipt': receipt, 'error': receipt.get('error', 'Prior failed model invocation retained')}
    text = (directory / 'input.txt').read_text('utf-8')
    if not text.startswith('REQUEST_JSON\n'):
        raise ValueError('Retained transport request has an unknown format')
    if expand_compact(json.loads(text[len('REQUEST_JSON\n'):])) != packet:
        raise ValueError('Retained transport materialization differs from original authorized packet')
    augmented = instructions + '\n' + COMPACT_INSTRUCTIONS
    if ((directory / 'instructions.txt').read_text('utf-8') != augmented
            or read(directory / 'proposal.schema.json') != strict_schema(schema)
            or receipt.get('input_sha256') != hashlib.sha256(text.encode()).hexdigest()
            or receipt.get('instruction_sha256') != hashlib.sha256(augmented.encode()).hexdigest()
            or receipt.get('tool_event_count') != 0 or receipt.get('cli_exit_code') != 0):
        raise ValueError('Retained inference receipt/instructions/schema/tool audit differs')
    raw = (directory / 'raw-model-output.json').read_text('utf-8')
    if receipt.get('output_sha256') != hashlib.sha256(raw.encode()).hexdigest():
        raise ValueError('Retained real-model output differs from receipt')
    return {'raw': raw, 'receipt': receipt, 'error': None}


def _call(provider, packet, schema, instructions, directory, *, phase, call_id):
    retained = _retained_call(directory, packet, schema, instructions)
    if retained is not None: return retained
    try:
        raw, receipt = provider.invoke(packet, schema, instructions, directory, phase=phase, call_id=call_id)
        return {'raw': raw, 'receipt': receipt, 'error': None}
    except Exception as error:
        path = filesystem_path(directory) / 'receipt.json'
        return {'raw': '', 'receipt': read(path) if path.exists() else None, 'error': str(error)}


def _sample_calls(provider, phase):
    prefix = provider.sample_id + ':'
    return [row for row in provider.budget.report()['calls']
            if row['phase'] == phase and row['call_id'].startswith(prefix)]


def _cost_summary(calls):
    return {'real_calls_by_phase': {phase: sum(c['phase']==phase for c in calls) for phase in ['mining','matching','task']},
            'input_tokens': sum(((c.get('receipt') or {}).get('usage') or {}).get('input_tokens',0) for c in calls),
            'output_tokens': sum(((c.get('receipt') or {}).get('usage') or {}).get('output_tokens',0) for c in calls),
            'cached_input_tokens': sum(((c.get('receipt') or {}).get('usage') or {}).get('cached_input_tokens',0) for c in calls),
            'application_context_chars': sum((c.get('receipt') or {}).get('application_context_chars',0) for c in calls),
            'failed_or_timeout_calls': sum(c['status']!='completed' for c in calls),
            'missing_usage_call_count': sum(not isinstance((c.get('receipt') or {}).get('usage'), dict)
                or 'input_tokens' not in ((c.get('receipt') or {}).get('usage') or {})
                or 'output_tokens' not in ((c.get('receipt') or {}).get('usage') or {}) for c in calls),
            'tokens_scope': 'reported_usage_only', 'currency_cost': None, 'monetary_cost': None,
            'monetary_cost_reason': 'tariff not configured',
            'reason': 'Only reported gateway usage is summed; unreported failed-call cost remains unknown.'}


def _persisted_sample_calls(root, sample):
    path = filesystem_path(root / 'real-call-budget.sqlite')
    if not path.exists(): return []
    ordinary = str(path).removeprefix('\\\\?\\')
    with sqlite3.connect(Path(ordinary).as_uri() + '?mode=ro', uri=True) as db:
        return [{'call_id': a, 'phase': b, 'status': c, 'receipt': json.loads(d) if d else None}
                for a,b,c,d in db.execute('SELECT call_id,phase,status,receipt FROM calls') if a.startswith(sample + ':')]


def _supplement_catalog(prepared, sides):
    visible = {h for side in sides.values() for h in side['registry']}
    entries = {}
    with FactView(prepared['snapshot']) as view:
        bundle = view.export_bundle()
        candidates = [e for e in bundle.elements if e.kind in {'configuration', 'resource'}]
        candidates.sort(key=lambda e: (0 if getattr(e, 'configuration_kind', None) == 'permission' else
                                       1 if e.kind == 'configuration' else 2, e.id))
        for record in candidates:
            handle = 'fact_' + fingerprint(record.id)[:12]
            if handle in visible: continue
            raw = record.model_dump(mode='json')
            entries[handle] = {'handle': handle, 'category': 'fact', 'record_ref': record.id,
                               'record_sha256': fingerprint(raw), 'record': raw,
                               'shown_fields': list(raw), 'detail_fields_available': [],
                               'fact_refs': [record.id], 'bu_ids': []}
            if len(entries) >= 4: break
    return entries


def _retrieve_pending(ledger, prepared, output):
    pending = {k: q for k, q in ledger.state()['queries'].items() if q['status'] == 'pending'}
    if not pending: return
    results = {}; evidence = {}
    with FactView(prepared['snapshot']) as view:
        for query_id, query in pending.items():
            handles = query['requested_refs']
            refs = [ledger.catalog['supplemental'][h]['record_ref'] for h in handles]
            response = view.get_records(refs, limit=32)
            actual = {e.id: e.model_dump(mode='json') for e in response.records}
            accepted = [h for h in handles if actual.get(ledger.catalog['supplemental'][h]['record_ref'])
                        == ledger.catalog['supplemental'][h]['record']]
            results[query_id] = accepted
            evidence[query_id] = {'factview_response': response.to_dict(), 'requested_handles': handles,
                                  'fulfilled_handles': accepted, 'verified_against_frozen_current_catalog': True}
    # Append immutable retrieval evidence before the atomic visibility grant.
    target = output / ('retrieval-revision-' + str(ledger.state()['revision']) + '.json')
    _frozen(target, evidence)
    ledger.fulfill_queries(results)


def _task_envelope(packet, phase, feedback, upstream_status=None):
    work = ('Accumulate the newly supplied current BC as evidence-supported findings. Preserve old findings unless explicit '
            'current evidence warrants revision. Keep unknown/partial/truncated limits. A useful advertised configuration '
            'or resource query may be requested for an open issue; do not assume its unseen content. Use fulfilled '
            'supplementary facts if relevant. No final synthesis yet.' if phase == 'incremental' else
            'Finalize the accepted findings across the current approved BCs. Integrate actually fulfilled supplementary '
            'facts and checked reference scopes. Preserve all open issues, limited coverage and independent mechanisms. '
            'Do not invent cooperation, a second BC, execution, malware or benignness. Request no new fact query.')
    envelope = {'task_request': packet, 'work_item': work}
    if any(reference['proposal']['schema_version'] == 'behavior-match-proposal.v2'
           for reference in packet['legal_references'].values()):
        envelope['work_item'] += '\n' + MATCHING_V2_REFERENCE_INSTRUCTIONS
    if upstream_status is not None:
        envelope['upstream_analysis_status'] = deepcopy(upstream_status)
        envelope['work_item'] += (' The separate upstream_analysis_status describes actual analysis capability limits only. '
                                  'Retain material failures and unknown coverage in the report. It is not behavior evidence, '
                                  'does not authorize a finding or reference, and cannot prove behavior existence or absence.')
    if feedback: envelope['repair_feedback'] = feedback
    return envelope


def _task_stage(ledger, provider, directory, ids, legal, *, phase, max_attempts, limit, upstream_status=None):
    directory.mkdir(parents=True, exist_ok=True)
    packet_path = directory / 'packet.json'
    if packet_path.exists(): packet = read(packet_path)
    else:
        packet = ledger.prepare_packet(ids, legal_matches=legal, phase=phase)
        write(packet_path, packet)
    registered = ledger.db.execute('SELECT sha256 FROM packets WHERE request_id=?', (packet['request_id'],)).fetchone()
    if not registered or registered[0] != fingerprint(packet): raise ValueError('Task stage packet differs from native registration')
    if (directory / 'result.json').exists():
        stage = read(directory / 'result.json')
        rows = [json.loads(p) for p, in ledger.db.execute('SELECT payload FROM audit ORDER BY sequence')
                if json.loads(p).get('kind') == 'proposal' and json.loads(p).get('request_id') == packet['request_id']]
        if (len(rows) != len(stage['attempts']) or stage.get('request_id') != packet['request_id']
                or stage.get('phase') != phase or stage.get('current_bc_ids') != ids):
            raise ValueError('Completed task stage differs from native audit')
        feedback = None
        for index, (event, row) in enumerate(zip(rows, stage['attempts'])):
            if row['index'] != index or any(row[k] != event['check'][k] for k in ['valid', 'errors']):
                raise ValueError('Task stage acceptance/errors differ from the native proposal audit')
            if read(directory / ('check-' + str(index) + '.json')) != row:
                raise ValueError('Task stage check sidecar differs from the retained stage result')
            if getattr(provider, 'is_real', False):
                call = _retained_call(directory / ('attempt-' + str(index)),
                                     _task_envelope(packet, phase, feedback, upstream_status), proposal_schema(), PROMPT)
                if (call['raw'] if call else '') != event['raw']:
                    raise ValueError('Task real-model output differs from the committed native proposal')
            feedback = {'previous_raw': event['raw'], 'program_check_errors': event['check']['errors']}
        if stage['accepted'] != bool(rows and rows[-1]['check']['valid']):
            raise ValueError('Retained task stage final status differs from its native checks')
        return stage
    attempts = []; feedback = None
    events = [json.loads(p) for p, in ledger.db.execute('SELECT payload FROM audit ORDER BY sequence')
              if json.loads(p).get('kind') == 'proposal' and json.loads(p).get('request_id') == packet['request_id']]
    for index in range(max_attempts):
        if index < len(events):
            event = events[index]; checked = event['check']; raw = event['raw']
            transport = None; error = None
            if getattr(provider, 'is_real', False):
                call = _retained_call(directory / ('attempt-' + str(index)),
                                     _task_envelope(packet, phase, feedback, upstream_status), proposal_schema(), PROMPT)
                if (call['raw'] if call else '') != raw:
                    raise ValueError('Interrupted-stage real response differs from the native committed proposal')
        else:
            if len(_sample_calls(provider, 'task')) >= limit:
                break
            envelope = _task_envelope(packet, phase, feedback, upstream_status)
            call = _call(provider, envelope, proposal_schema(), PROMPT, directory / ('attempt-' + str(index)),
                         phase='task', call_id=directory.name + ':' + str(index))
            raw, transport, error = call['raw'], call['receipt'], call['error']
            checked = ledger.finalize(raw, packet) if phase == 'synthesis' else ledger.update(raw, packet)
        row = {'index': index, 'valid': checked['valid'], 'errors': checked['errors'],
               'transport': transport, 'transport_error': error,
               'rejected_update_preserved_state': checked['valid'] or checked.get('accepted') is None}
        check_path = directory / ('check-' + str(index) + '.json')
        if check_path.exists():
            retained = read(check_path)
            if any(retained.get(k) != row[k] for k in ['index', 'valid', 'errors', 'rejected_update_preserved_state']):
                raise ValueError('Task check sidecar contradicts native committed audit')
            row = retained
        attempts.append(row); _frozen(check_path, row)
        if checked['valid']: break
        feedback = {'previous_raw': raw, 'program_check_errors': checked['errors']}
    stage = {'phase': phase, 'request_id': packet['request_id'], 'current_bc_ids': ids, 'attempts': attempts,
             'accepted': bool(attempts and attempts[-1]['valid']), 'unprocessed': not attempts,
             'reason': None if attempts and attempts[-1]['valid'] else 'No accepted update within the declared per-sample/round budget'}
    write(directory / 'result.json', stage)
    return stage


def _defined_config(config):
    from .tasks import DefinedTaskConfig
    return DefinedTaskConfig.model_validate(config['defined_task_config'])


def _defined_tasks(root,sample,prepared,output,identity,catalog,legal,provider,config,scope,segment_call_limit=None):
    from .tasks import run_task,load_task_definition
    runs=[];start_calls=len(_sample_calls(provider,'task'))
    with FactView(prepared['snapshot']) as view:
        for value in config['task_definitions']:
            definition=load_task_definition(value)
            directory=output/'defined-tasks'/fingerprint(value)[:20]
            remaining=max(0,config['per_sample_task_call_limit']-len(_sample_calls(provider,'task')))
            if segment_call_limit is not None:
                remaining=min(remaining,max(0,segment_call_limit-(len(_sample_calls(provider,'task'))-start_calls)))
            result=run_task(definition,identity,catalog,directory,provider,fact_view=view,legal_matches=legal,
                config=_defined_config(config),max_new_calls=remaining,scope_status=scope)
            runs.append({'task_id':definition.task_id,'kind':definition.kind,'directory':str(directory),'result':result})
    return runs


def _verify_defined_retained(report,config,catalog):
    from .tasks import DefinitionTaskLedger,load_task_definition
    definitions={d['task_id']:d for d in config['task_definitions']}
    ids=[r['task_id'] for r in report['task_runs']]
    if len(ids)!=len(set(ids)) or set(ids)!=set(definitions):
        raise ValueError('Retained task report must contain every frozen task exactly once')
    for row in report['task_runs']:
        definition=load_task_definition(definitions[row['task_id']])
        if row['kind']!=definition.kind or row['result']['identity']!=report['identity']:
            raise ValueError('Retained task definition/source identity changed')
        if row['result']['status']=='blocked':
            if not definition.blocked_reasons():raise ValueError('Configured task cannot be relabeled blocked')
            if read(filesystem_path(row['directory'])/'blocked.json')!=row['result']:
                raise ValueError('Blocked task record changed')
            continue
        scope=report['upstream_scope_status']
        with DefinitionTaskLedger(filesystem_path(row['directory'])/'task-ledger.sqlite',definition,
                config=_defined_config(config),source_catalog=catalog,scope_status=scope) as ledger:
            ledger.verify()
            actual=ledger.report()
            for key in ('state','task_definition','task_result','outcome','identity'):
                if row['result'].get(key)!=actual.get(key):
                    raise ValueError('Retained typed task result differs from actual accepted ledger: '+key)
            state=actual['state']
            expected_status='evidence_insufficient' if state.get('empty_result') is not None else 'completed' if state['synthesis'] is not None else 'partial'
            if row['result']['status']!=expected_status:raise ValueError('Typed task completion status contradicts the actual ledger')


def _work_scope(prepared,sample_dir):
    pointer=sample_dir/'complete-plan/progress.json'
    plan=read(pointer) if pointer.exists() else None
    summary=None
    if plan:
        pending=[{k:r[k] for k in ('item_id','kind','state','reason')} for r in plan['items'] if r['state'] not in {'completed','superseded'}]
        summary={k:deepcopy(plan[k]) for k in ('plan_id','counts','by_kind','remaining_budget','audit_head','apk_all_discovered_work_completed')}
        summary.update(pending_items=pending[:64],pending_item_total=len(pending),pending_list_truncated=len(pending)>64,
            full_audit_path=str(pointer),citation_authority_added=False)
    return {'candidate_plan':summary,
        'selection':{k:prepared.get(k) for k in ('physical_sapi_calls','available_sapi_roots','selected_roots','unprocessed_roots','bu_count')},
        'role':'analysis_capability_and_work_coverage_metadata_not_behavior_evidence'}


def _sync_downstream_plan(sample_dir,entries,**kwargs):
    directory=sample_dir/'complete-plan'
    if not (directory/'plan.json').exists():return None
    from .workplan import CandidatePlan
    with CandidatePlan(directory) as plan:
        plan.sync_downstream(entries,**kwargs)
        result=plan.report();write(directory/'progress.json',result)
        return {k:result[k] for k in ('plan_id','counts','by_kind','remaining_budget','audit_head','apk_all_discovered_work_completed')}


def _authorize_workload_downstream(root, sample, config, freeze, entries, history):
    workload=config.get('workload_budget')
    if workload is None:return None
    from .tasks import load_task_definition
    runnable=sum(not load_task_definition(d).blocked_reasons() for d in config.get('task_definitions',[]))
    if not config.get('task_definitions'):runnable=1
    count=len(entries)
    stages={'matching':2*count*config['top_k'],
            'task_incremental':2*count*runnable,
            'task_synthesis':2*runnable if count else 0}
    master=workload['per_sample_call_caps']
    if (stages['matching']>master['matching'] or
            stages['task_incremental']+stages['task_synthesis']>master['task'] or
            stages['task_incremental']>master['task']-workload['task_synthesis_reserved_calls'] or
            stages['task_synthesis']>workload['task_synthesis_reserved_calls']):
        return {'status':'budget_pending_resume','reason':'actual_BC_workload_exceeds_frozen_downstream_reserve',
            'required_stage_calls':stages,'frozen_phase_caps':master,'model_dispatches':0,
            'final_task_report':False}
    path=root/'stage-authorizations'/(sample+'.downstream.json')
    body={'schema_version':'workload-stage-authorization.v1','budget_id':workload['budget_id'],
        'sample_id':sample,'channel':'downstream','stage_call_caps':stages,
        'actual_bc_ids':[e['bc']['bc_id'] for e in entries],'runnable_task_count':runnable,
        'query_serializer_version':config['query_encoding_config']['serializer_version'],
        'frozen_inputs':[{'path':str(filesystem_path(freeze)/'manifest.json'),
            'sha256':sha256_file(filesystem_path(freeze)/'manifest.json')},
            {'path':str(filesystem_path(history)/'manifest.json'),
             'sha256':sha256_file(filesystem_path(history)/'manifest.json')}]}
    value={**body,'authorization_sha256':fingerprint(body)}
    if path.exists():
        if read(path)!=value:
            raise ValueError('Actual downstream work or source manifest changed after stage authorization')
        return None
    write(path,value)
    return None


def analyze_apk(root, sample, freeze, history, *, model_dir=None, lock_path='configs/bert-artifacts.lock.json',resume=False,task_segment_call_limit=None):
    import numpy as np
    from .runner import sample_path
    started = time.monotonic(); root = filesystem_path(root); sample_dir = sample_path(root, sample)
    if task_segment_call_limit is not None and (type(task_segment_call_limit) is not int or task_segment_call_limit<0):
        raise ValueError('Task segment limit must be a nonnegative stop within the frozen total budget')
    parent_report_sha256=None
    config = read(root / 'experiment-config.json'); prepared = read(sample_dir / 'prepared.json')
    retained_encoding=sample_dir/'analysis/encoding-pointer.json'
    if retained_encoding.exists():_query_encoder_config(config,read(retained_encoding)['encoding_run'])
    matching_protocol_name = config.get('matching_protocol', 'v1')
    matching_model, matching_prompt = match_protocol({'schema_version': 'behavior-match-request.' + matching_protocol_name})
    if config.get('task_prompt_sha256') != fingerprint(PROMPT) or config.get('matching_prompt_sha256') != fingerprint(matching_prompt):
        raise ValueError('Matching/task prompts differ from the frozen round configuration')
    expected_sample = next((s for s in config['samples'] if s['sample_id'] == sample), None)
    if not expected_sample or expected_sample['apk_sha256'] != prepared['apk_sha256']:
        raise ValueError('Sample is absent from the frozen round or prepared APK differs')
    if sha256_file(prepared['input_apk']) != prepared['apk_sha256']:
        raise ValueError('Prepared APK bytes differ from their frozen actual SHA-256')
    policy, entries = load_frozen(freeze)
    if policy['role'] != 'query': raise ValueError('APK analysis requires an explicit query freeze')
    if not entries:
        review = read(filesystem_path(freeze) / 'review.json')
        if (review.get('apk_sha256') != prepared['apk_sha256']
                or review.get('source_run_ref') != prepared['source_run_ref']):
            raise ValueError('An empty query freeze must explicitly identify apk_sha256 and source_run_ref in its review')
    if any(e['source_apk_sha256'] != prepared['apk_sha256'] or
           read(filesystem_path(e['source_snapshot']) / 'manifest.json')['snapshot_id'] != read(filesystem_path(prepared['snapshot']) / 'manifest.json')['snapshot_id']
           for e in entries):
        raise ValueError('Frozen BC source APK/fact snapshot differs from this prepared sample')
    pending=_authorize_workload_downstream(root,sample,config,freeze,entries,history)
    if pending is not None:return pending
    output = sample_dir / 'analysis'; output.mkdir(parents=True, exist_ok=True)
    selected_flow = deepcopy(prepared.get('fact_summary', {}).get('selected_flow'))
    upstream_status = {'coverage': deepcopy(prepared.get('fact_coverage', {})), 'selected_flow': selected_flow,
                       'role': 'analysis_capability_limits_only', 'permitted_as_behavior_evidence': False}
    if config.get('task_definitions'):upstream_status.update(_work_scope(prepared,sample_dir))
    engineering = {'upstream_analysis_results': {'selected_flow': selected_flow},
                   'upstream_failures': ([{'stage': 'selected_flow', **selected_flow}]
                                         if selected_flow and selected_flow.get('state') in {'failed', 'unavailable', 'timeout'} else []),
                   'limitation': 'Zero reported flows after analysis failure is not evidence that information flow is absent.'}
    upstream_file=output/'upstream-analysis-status.json'
    if config.get('task_definitions') and upstream_file.exists():
        retained_scope=read(upstream_file)
        if any(retained_scope.get(k)!=upstream_status.get(k) for k in ('coverage','selected_flow','selection')):
            raise ValueError('Frozen upstream analysis source changed')
        upstream_status=retained_scope
    _frozen(upstream_file, upstream_status)
    identity = {'apk_sha256': prepared['apk_sha256'], 'source_run_ref': prepared['source_run_ref']}
    pinned = {'sample_id': sample, 'identity': identity, 'query_freeze': str(filesystem_path(freeze)),
              'query_freeze_id': read(filesystem_path(freeze) / 'manifest.json')['freeze_id'],
              'history': str(filesystem_path(history)), 'history_manifest_sha256': sha256_file(filesystem_path(history) / 'manifest.json'),
              'config_sha256': fingerprint(config), 'top_k': config.get('top_k', 2),
              'matching_call_limit': (config['per_sample_matching_call_limit'] if config.get('workload_budget') else
                                      min(8, config['per_sample_matching_call_limit'])),
              'task_call_limit': (config['per_sample_task_call_limit'] if config.get('workload_budget') else
                                  min(6, config['per_sample_task_call_limit']))}
    if 'matching_protocol' in config:
        pinned['matching_protocol'] = matching_protocol_name
    _frozen(output / 'analysis-inputs.json', pinned)
    sides = {}
    for e in entries:
        side = view_from_entry(e, material_kind='real_apk_query', ledger_ref=e['source_mining_run'])
        bid = side['bc']['bc_id']
        if bid in sides: raise ValueError('Duplicate native BC ID in current APK query freeze')
        sides[bid] = side
    sides, coordination = coordinate_visible(sides)
    scopes = {}
    for bid, side in list(sides.items()):
        sides[bid], scopes[bid] = scope_side(side)
    _frozen(output / 'query-evidence-scopes.json', scopes)
    _frozen(output / 'visibility-coordination.json', {'changes': coordination, 'archive_evidence_added': False})
    _frozen(output / 'task-source-catalog.json', {'bcs': sides, 'supplemental': {} if config.get('task_definitions') else _supplement_catalog(prepared, sides)})
    catalog = read(output / 'task-source-catalog.json')
    if (output / 'final-report.json').exists():
        retained = read(output / 'final-report.json')
        if config.get('task_definitions'):
            if retained.get('identity')!=identity:raise ValueError('Retained task report belongs to another APK/run')
            if retained.get('program_qualified_bc_count')!=len(entries) or retained.get('history_updated') is not False:
                raise ValueError('Retained task source coverage/history policy changed')
            _verify_defined_retained(retained,config,catalog)
            pending=any(t['result']['status']=='partial' for t in retained['task_runs'])
            if not resume or not pending:return retained
            parent_report_sha256=sha256_file(output/'final-report.json')
            archive=output/'report-history'/(parent_report_sha256+'.json')
            if not archive.exists():write(archive,retained)
        else:
            with GeneralTaskLedger(output / 'task/task-ledger.sqlite') as ledger:
                ledger.verify(); state = ledger.state()
                if retained.get('identity') != identity:
                    raise ValueError('Retained final report belongs to a different APK/run')
                if entries and (retained.get('findings') != state['findings'] or retained.get('synthesis') != state['synthesis']):
                    raise ValueError('Retained final report differs from the native accepted task ledger')
                if not entries and retained.get('outcome') != state.get('empty_result'):
                    raise ValueError('Retained insufficient-evidence report differs from the native terminal state')
            return retained
    if not entries and not config.get('task_definitions'):
        with GeneralTaskLedger(output / 'task/task-ledger.sqlite', identity, source_catalog=catalog) as ledger:
            outcome = ledger.finalize_empty('No extracted candidate was approved in this frozen query list.',
                         source_limits=['Current fact/BU coverage remains limited.'],
                         coverage={'prepared': prepared.get('fact_coverage'), 'excluded_candidates': policy['excluded_count']})
            report = {'schema_version': 'apk-pipeline-final-report.v1', 'sample_id': sample, 'identity': identity,
                      'status': 'evidence_insufficient', 'approved_bc_count': 0, 'outcome': outcome,
                      'recall': [], 'matches': [], 'task_stages': [], 'ledger': ledger.report(),
                      'engineering': engineering,
                      'cost': _cost_summary(_persisted_sample_calls(root, sample)),
                      'elapsed_seconds': time.monotonic()-started, 'history_updated': False, 'benign_verdict': None}
        write(output / 'final-report.json', report); return report
    if not entries and config.get('task_definitions'):
        provider=PipelineProvider(root,sample,config)
        try:
            tasks=_defined_tasks(root,sample,prepared,output,identity,catalog,[],provider,config,upstream_status,task_segment_call_limit)
            report={'schema_version':'apk-defined-tasks-final-report.v1','sample_id':sample,'identity':identity,
                'status':'evidence_insufficient','program_qualified_bc_count':0,'task_runs':tasks,
                'recall':[],'matches':[],'upstream_scope_status':upstream_status,
                'cost':_cost_summary(_persisted_sample_calls(root,sample)),
                'history_updated':False,'semantic_review_required':False,'absence_proves_benign':False}
            write(output/'final-report.json',report);return report
        finally:provider.close()
    encoding_pointer = output / 'encoding-pointer.json'
    encoder_config = _query_encoder_config(config)
    if encoding_pointer.exists(): encoded = filesystem_path(read(encoding_pointer)['encoding_run'])
    else:
        model_dir = model_dir or Path('.models/bert-base-uncased') / encoder_config.revision
        encoded = encode_frozen(freeze, model_dir, lock_path, output / 'encodings', encoder_config)
        write(encoding_pointer, {'encoding_run': str(encoded), 'model_dir': str(filesystem_path(model_dir)),
                                 'lock_path': str(filesystem_path(lock_path))})
    _query_encoder_config(config,encoded)
    pointer = read(encoding_pointer); verify_encoding(encoded, pointer['model_dir'])
    history_rows, history_vectors, history_verified = load_history(history)
    history_entries = read(filesystem_path(history) / 'encoding/audit/approved-pool.json')['entries']
    history_by_ref = {e['qualified_ref']: e for e in history_entries}
    # Incompatible BERT models/pooling cannot be silently mixed for cosine recall.
    if read(encoded / 'config.json') != read(filesystem_path(history) / 'encoding/config.json'):
        raise ValueError('Query/history encoder configuration differs from the frozen BERT baseline')
    vectors = np.load(encoded / 'bc_vectors.npy', allow_pickle=False)
    provider = PipelineProvider(root, sample, config); recalls = []; matches = []; legal = []; scoped_history = {}
    try:
        for index, entry in enumerate(entries):
            bid = entry['bc']['bc_id']; side = sides[bid]
            returned = recall(side['instance_ref'], side['origin'], vectors[index], history_rows, history_vectors,
                              k=pinned['top_k'], exclude_related=True)
            _frozen(output / 'recall' / ('bc-' + str(index) + '.json'), returned); recalls.append(returned)
            accepted_candidates = []
            for rank, candidate in enumerate(returned['ranked_candidates']):
                pair_dir = output / 'matching' / ('bc-' + str(index) + '-rank-' + str(rank))
                request_path = pair_dir / 'request.json'
                if request_path.exists(): request = read(request_path)
                else:
                    reference_entry = history_by_ref[candidate['instance_ref']]
                    if candidate['instance_ref'] not in scoped_history:
                        full_reference = view_from_entry(reference_entry, material_kind='frozen_history', ledger_ref=reference_entry['source_mining_run'])
                        reference, audit = scope_side(full_reference)
                        name = fingerprint(candidate['instance_ref'])[:24]
                        _frozen(output / 'history-evidence-scopes' / (name + '.audit.json'), audit)
                        _frozen(output / 'history-evidence-scopes' / (name + '.side.json'), reference)
                        scoped_history[candidate['instance_ref']] = reference
                    reference = scoped_history[candidate['instance_ref']]
                    request = ({'v1':make_request,'v2':make_request_v2,'v3':make_request_v3}[matching_protocol_name])(side, reference, MatchConfig())
                    write(request_path, request)
                if request.get('schema_version') != 'behavior-match-request.' + matching_protocol_name:
                    raise ValueError('Retained matching request protocol differs from the explicitly frozen round')
                if request['sides']['query']['registry'] != side['registry'] or request['sides']['query']['bc'] != side['bc']:
                    raise ValueError('Retained match query differs from coordinated current task evidence')
                attempts = []; accepted = None; feedback = None
                for attempt in range(2):
                    check_path = pair_dir / ('check-' + str(attempt) + '.json')
                    packet = {k: v for k, v in request.items() if k != 'source_audit'}
                    if feedback: packet['repair_feedback'] = feedback
                    call_dir = pair_dir / ('attempt-' + str(attempt))
                    if not check_path.exists() and not call_dir.exists() and len(_sample_calls(provider, 'matching')) >= pinned['matching_call_limit']:
                        break
                    if check_path.exists():
                        row = read(check_path)
                        retained_call = _retained_call(call_dir, packet, matching_model.model_json_schema(), matching_prompt)
                        raw = retained_call['raw'] if retained_call else ''
                        checked = check_match(raw, request)
                        if row.get('check') != checked or row.get('attempt') != attempt:
                            raise ValueError('Retained match check differs from the original real response')
                    else:
                        call = _call(provider, packet, matching_model.model_json_schema(), matching_prompt, call_dir,
                                     phase='matching', call_id=pair_dir.name + ':' + str(attempt))
                        raw = call['raw']; checked = check_match(raw, request)
                        row = {'attempt': attempt, 'check': checked, 'transport_error': call['error'],
                               'rejected_update_preserved_state': checked['valid'] or accepted is None}
                    _frozen(check_path, row); attempts.append(row)
                    if checked['valid']: accepted = checked['accepted']; break
                    feedback = {'previous_raw': raw, 'program_check_errors': checked['errors']}
                result = {'bc_id': bid, 'reference_ref': candidate['instance_ref'], 'cosine': candidate['cosine'],
                          'attempts': attempts, 'accepted': accepted, 'request_file': str(request_path),
                          'status': 'accepted' if accepted else 'rejected' if attempts else 'unprocessed',
                          'unprocessed_reason': 'Per-sample/round budget or failure retained' if not accepted else None}
                write(pair_dir / 'result.json', result); matches.append(result)
                if accepted and is_supported(accepted['decision']):
                    accepted_candidates.append((candidate['cosine'], candidate['instance_ref'], request, accepted))
            accepted_candidates.sort(key=lambda r: (-r[0], r[1]))
            if accepted_candidates:
                _, ref, request, proposal = accepted_candidates[0]
                legal.append({'match_ref': 'pipeline-match:' + fingerprint([side['instance_ref'], ref])[:20],
                              'request': request, 'proposal': proposal})
        if config.get('task_definitions'):
            _sync_downstream_plan(sample_dir,entries,encoding=encoded,recalls=recalls,matches=matches)
            scope_file=output/'typed-task-scope.json'
            scope=read(scope_file) if scope_file.exists() else {**upstream_status,**_work_scope(prepared,sample_dir)}
            _frozen(scope_file,scope)
            tasks=_defined_tasks(root,sample,prepared,output,identity,catalog,legal,provider,config,scope,task_segment_call_limit)
            final_plan=_sync_downstream_plan(sample_dir,entries,encoding=encoded,recalls=recalls,matches=matches,task_runs=tasks)
            calls=[c for c in provider.budget.report()['calls'] if c['call_id'].startswith(sample+':')]
            report={'schema_version':'apk-defined-tasks-final-report.v1','sample_id':sample,'identity':identity,
                'status':'completed' if all(t['result']['status']=='completed' for t in tasks) else 'partial_or_definition_blocked',
                'program_qualified_bc_count':len(entries),'task_runs':tasks,'freeze':pinned,
                'encoding_run':str(encoded),'history_verification':history_verified,
                'recall':recalls,'matches':matches,'selected_legal_reference_count':len(legal),
                'upstream_scope_status':scope,'cost':_cost_summary(calls),'elapsed_seconds':time.monotonic()-started,
                'complete_candidate_plan_final':final_plan,
                'semantic_review_required':False,'natural_language_correctness_certified':False,
                'history_updated':False,'bert_changed':False,'absence_proves_benign':False,
                'engineering':engineering}
            if parent_report_sha256:report['parent_report_sha256']=parent_report_sha256
            write(output/'final-report.json',report);return report
        task_config = TaskConfig(max_attempts=pinned['task_call_limit'], max_fact_queries=2,
                                 max_response_chars=config['max_response_chars'], max_packet_chars=5_000_000)
        stages = []
        with GeneralTaskLedger(output / 'task/task-ledger.sqlite', identity, config=task_config, source_catalog=catalog) as ledger:
            bids = list(sides)
            for index, bid in enumerate(bids):
                remaining = pinned['task_call_limit'] - len(_sample_calls(provider, 'task'))
                # Reserve a bounded synthesis and at least one attempt for later BCs.
                attempts = max(0, min(2, remaining - 2 - (len(bids)-index-1)))
                stage_dir = output / 'task' / ('incremental-' + str(index))
                if attempts == 0 and not (stage_dir / 'packet.json').exists():
                    stages.append({'phase': 'incremental', 'current_bc_ids': [bid], 'accepted': False,
                                   'unprocessed': True, 'reason': 'Reserved synthesis/per-sample task call budget'}); continue
                available = set(ledger.state()['seen_bc_ids']) | {bid}
                relevant = [m for m in legal if m['request']['sides']['query']['bc']['bc_id'] in available]
                stage = _task_stage(ledger, provider, stage_dir, [bid], relevant,
                                    phase='incremental', max_attempts=max(2, attempts) if (stage_dir/'packet.json').exists() else attempts,
                                    limit=pinned['task_call_limit'], upstream_status=upstream_status)
                stages.append(stage); _retrieve_pending(ledger, prepared, output / 'task')
            remaining = pinned['task_call_limit'] - len(_sample_calls(provider, 'task'))
            final_dir = output / 'task/final'
            if remaining or (final_dir / 'packet.json').exists():
                final = _task_stage(ledger, provider, final_dir, bids, legal, phase='synthesis',
                                    max_attempts=2, limit=pinned['task_call_limit'], upstream_status=upstream_status)
                stages.append(final)
            write(output / 'task/task-report.json', ledger.report())
            write(output / 'task/task-verification.json', ledger.verify())
            state = ledger.state(); calls = [c for c in provider.budget.report()['calls'] if c['call_id'].startswith(sample + ':')]
            costs = _cost_summary(calls)
            model_seconds = {}
            for phase in ['mining', 'matching', 'task']:
                durations = []
                for call in calls:
                    receipt = call.get('receipt') or {}
                    if call['phase'] == phase and receipt.get('started_utc') and receipt.get('finished_utc'):
                        durations.append((datetime.fromisoformat(receipt['finished_utc'])-
                                          datetime.fromisoformat(receipt['started_utc'])).total_seconds())
                model_seconds[phase] = sum(durations)
            report = {'schema_version': 'apk-pipeline-final-report.v1', 'sample_id': sample, 'identity': identity,
                      'status': 'completed' if state['synthesis'] is not None else 'partial_no_accepted_synthesis',
                      'approved_bc_count': len(entries), 'excluded_candidates': policy['excluded_count'],
                      'freeze': pinned, 'encoding_run': str(encoded), 'history_verification': history_verified,
                      'recall': recalls, 'matches': matches, 'selected_legal_reference_count': len(legal),
                      'task_stages': stages, 'findings': state['findings'], 'synthesis': state['synthesis'],
                      'issues': state['issues'], 'source_limits': state['source_limits'], 'cost': costs,
                      'engineering': engineering,
                      'processed_bc_ids': state['seen_bc_ids'], 'unprocessed_bc_ids': sorted(set(bids)-set(state['seen_bc_ids'])),
                      'bc_ids_with_findings': sorted({s['bc_id'] for f in state['findings'].values() for s in f['scopes']}),
                      'approved_bc_ids_without_findings': sorted(set(bids)-{s['bc_id'] for f in state['findings'].values() for s in f['scopes']}),
                      'prepared_coverage': prepared.get('fact_coverage'), 'elapsed_seconds': time.monotonic()-started,
                      'timing': {'preparation_elapsed_seconds': prepared.get('elapsed_seconds'),
                                 'downstream_wall_seconds': time.monotonic()-started,
                                 'sum_model_invocation_seconds_by_phase': model_seconds,
                                 'sum_invocation_seconds_is_not_total_wall_time': True},
                      'history_updated': False, 'bert_changed': False, 'benign_verdict': None,
                      'natural_language_correctness_certified': False,
                      'limits': ['A completed program-checked pipeline does not certify natural-language explanations.',
                                 'Coverage refers to this selected BU/reviewed BC scope, not all behavior in the APK.',
                                 'No supporting historical reference does not establish benignness or behavior absence.']}
            write(output / 'final-report.json', report)
            return report
    finally:
        provider.close()


__all__ = ['analyze_apk', 'coordinate_visible', 'scope_side']
