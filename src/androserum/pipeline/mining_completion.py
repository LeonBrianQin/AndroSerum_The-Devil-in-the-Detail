"""Automatic, bounded post-BU query/review scheduling over the native ledger.

No mining schema, prompt, checker or query rule is replaced. One fixed final
frontier is derived from model open issues after all ORIGINAL blocks terminate;
each issue gets at most one native consolidation amendment. Later new/changed
issues remain explicit pending candidates rather than recursively spawning work.
"""
from copy import deepcopy
import json
from pathlib import Path

from androserum.facts.identity import filesystem_path, fingerprint, sha256_file
from androserum.inference.provider import write


VERSION = 'automatic-mining-completion.v1'
TERMINAL = {'accepted', 'rejected', 'blocked'}
MAX_SOURCE_BLOCKS = 4
MAX_REVIEW_ATTEMPTS = 3
LEGACY_UNSTARTED_HELPER = '2c1c914b64ed0704851663bc533e477d640cc1bce38b7dcd59844d3e191d6e66'
LOADED_ORCHESTRATION_SHA = sha256_file(__file__)


def _read(path):
    return json.loads(filesystem_path(path).read_text('utf-8'))


def _issue_key(plan_id, issue):
    body = {k: v for k, v in issue.items() if k not in {'evidence_request_id', 'status'}}
    return 'mining_finalization:' + fingerprint([VERSION, plan_id, body])[:24]


def _open(report):
    return {key: issue for key, issue in report['accepted_state'].get('unresolved', {}).items() if issue.get('status') == 'open'}


def _selection(report, issue):
    state = report['accepted_state']; subjects = issue.get('subject_ids', [])
    actions = set(); unknown = []
    for key in subjects:
        if key in state['actions']: actions.add(key)
        elif key in state['bcs']: actions.update(state['bcs'][key]['action_ids'])
        else: unknown.append(key)
    refs = set(issue.get('evidence_refs', [])); by_action = {}
    for key in actions:
        value = state['actions'][key]
        bound = set(value.get('evidence_handles', [])) | set(value.get('support_fact_refs', []))
        refs.update(bound); by_action[key] = bound
    accepted = [r for r in report.get('chunk_progress', [])
                if not r.get('work_amendment') and r['state'] == 'accepted' and r['chunk'].get('handles')]
    related = [r for r in accepted if set(r['chunk']['handles']) & refs]
    overview = not subjects and not related
    if overview: related = accepted[:1]
    related.sort(key=lambda r: (-len(set(r['chunk']['handles']) & refs), r['chunk_id']))
    chosen = related[:MAX_SOURCE_BLOCKS]
    shown = {h for row in chosen for h in row['chunk']['handles']}
    missing = sorted(key for key in by_action if not set(state['actions'][key].get('operation_refs', [])) <= shown)
    omitted_support = {key: sorted(required - shown) for key, required in by_action.items() if required - shown}
    return {'target_chunk_ids': [r['chunk_id'] for r in chosen], 'action_ids': sorted(actions),
            'subject_ids': subjects, 'unknown_subject_ids': unknown,
            'subject_actions_without_selected_direct_support': missing,
            'subject_support_not_explicit_in_selected_chunks': omitted_support,
            'not_selected_related_chunk_ids': [r['chunk_id'] for r in related[MAX_SOURCE_BLOCKS:]],
            'accepted_original_block_count': len(accepted), 'max_source_blocks': MAX_SOURCE_BLOCKS,
            'finite_overview_without_subjects': overview,
            'scope_partial': bool(missing or omitted_support or unknown or len(related) > MAX_SOURCE_BLOCKS),
            'archive_evidence_added': False, 'all_apk_handles_combined': False}


def _trace(run, report, amendment_id, issue):
    """Distinguish planning, returned facts, later presentation and actual use."""
    rows = [r for r in report.get('chunk_progress', []) if r.get('work_amendment', {}).get('amendment_id') == amendment_id]
    ids = {rid for row in rows for rid in row.get('request_ids', [])}
    attempts = [a for a in report.get('attempts', []) if a['request_id'] in ids]
    requests = []; proposed = []
    for record in report.get('requests', []):
        if record['request_id'] not in ids: continue
        directory = filesystem_path(run) / record['directory']
        packet = _read(directory / 'request.json')
        accepted = next((a['status'] == 'accepted' for a in attempts if a['request_id'] == record['request_id']), False)
        proposal = _read(directory / 'proposal.json') if (directory / 'proposal.json').exists() else {}
        context = packet.get('ledger_context', {})
        visible_subjects = set(context.get('actions', {})) | set(context.get('bcs', {}))
        requests.append({'request_id': record['request_id'], 'accepted': accepted,
                         'fact_query_results': packet.get('fact_query_results', []),
                         'target_issue_editable': issue['issue_id'] in context.get('unresolved', {}),
                         'missing_target_subject_ids': sorted(set(issue.get('subject_ids', [])) - visible_subjects),
                         'ledger_context_deferred': packet.get('ledger_context_deferred', []),
                         'request_file': str(directory / 'request.json'), 'request_sha256': sha256_file(directory / 'request.json')})
        proposed.extend({'request_id': record['request_id'], 'proposal_accepted': accepted, 'query': query}
                        for query in proposal.get('fact_queries', []))
    service = report.get('current_fact_queries', {})
    events = [e for e in report.get('query_typed_admissions', []) if e['request_id'] in ids]
    actual_ids = {e['receipt_id'] for e in events}
    receipts = [q for q in service.get('queries', []) if q['receipt_id'] in actual_ids]
    unfulfilled = [q for q in proposed if q['proposal_accepted'] and not any(
        e['request_id'] == q['request_id'] and any(r['receipt_id'] == e['receipt_id'] and r['query'] == q['query'] for r in receipts)
        for e in events)]
    unseen = []
    position = {r['request_id']: i for i, r in enumerate(report.get('requests', []))}
    for receipt in receipts:
        origins = [position[e['request_id']] for e in events if e['receipt_id'] == receipt['receipt_id']]
        after = max(origins) if origins else len(position)
        presented = any(r['accepted'] and r['target_issue_editable'] and not r['missing_target_subject_ids']
            and position[r['request_id']] > after
            and any(x.get('receipt_id') == receipt['receipt_id'] for x in r['fact_query_results']) for r in requests)
        if not presented: unseen.append(receipt['receipt_id'])
    accepted_requests = [r for r in requests if r['accepted']]
    final_editable = bool(accepted_requests and accepted_requests[-1]['target_issue_editable']
                          and not accepted_requests[-1]['missing_target_subject_ids'])
    receipt_ids = {q['receipt_id'] for q in receipts}
    return {'review_rows': [{k: v for k, v in r.items() if k != 'chunk'} for r in rows],
            'attempts': attempts, 'requests': requests, 'model_query_requests': proposed,
            'actual_receipts': [{k: v for k, v in q.items() if k != 'records'} |
                                {'returned_record_refs': [r['id'] for r in q['records']]} for q in receipts],
            'actual_uses': [u for u in service.get('uses', []) if u['receipt_id'] in receipt_ids],
            'unfulfilled_accepted_model_queries': unfulfilled,
            'target_issue_editable_in_accepted_review': final_editable,
            'receipt_review_requires_same_later_accepted_editable_request': True,
            'returned_without_later_accepted_review': unseen,
            'actual_records_in_source_report': str(filesystem_path(run) / 'report.json')}


def migrate_unstarted_completion(directory, *, expected_binding=None):
    """Metadata-only upgrade of this EXACT legacy, never-started final gate.

    Invoke after an active phase finishes. The old state bytes and migration
    receipt are retained. No model ledger, budget, candidate plan or facts are
    modified, and any historical final-work creation fails closed.
    """
    root = filesystem_path(directory); state_file = root / 'state.json'
    raw = state_file.read_bytes(); state = json.loads(raw)
    source_plan = _read(root.parent / 'complete-plan/plan.json')['plan']
    if source_plan['plan_id'] != fingerprint([source_plan['source'], source_plan['items']]):
        raise ValueError('Completion migration original plan content identity differs')
    expected = {'schema_version': VERSION, 'plan_id': source_plan['plan_id'],
        'source': source_plan['source'], 'orchestration_sha256': LOADED_ORCHESTRATION_SHA,
        'max_source_blocks_per_issue': MAX_SOURCE_BLOCKS, 'max_attempts_per_issue': MAX_REVIEW_ATTEMPTS,
        'mining_rules_changed': False, 'frozen_task_rules_changed': False}
    if expected_binding is not None and expected_binding != expected:
        raise ValueError('Completion migration target differs from the actual unchanged source plan')
    if state['binding'] == expected:
        return {'status': 'already_current', 'state_file': str(state_file), 'state_sha256': sha256_file(state_file), 'model_ledgers_modified': False}
    legacy = {**expected, 'orchestration_sha256': LEGACY_UNSTARTED_HELPER}
    if state['binding'] != legacy or state.get('frontier') is not None or state.get('last_run') is not None:
        raise ValueError('Only the exact legacy helper with an unfrozen, undispatched final frontier may migrate')
    for item in state.get('items', {}).values():
        if item.get('state') not in {'pending', 'superseded'} or any(item.get(k) for k in ('trace', 'last_run', 'last_parent_run')):
            raise ValueError('Prior finalization activity cannot use metadata-only migration')
    native = []
    for info_file in sorted((root.parent / 'mining').glob('mining_*/run.json')):
        info = _read(info_file)
        amendments = list(info.get('work_amendments', []))
        if info.get('new_work_amendment'): amendments.append(info['new_work_amendment'])
        if any(a.get('amendment_id', '').startswith('auto-final:') for a in amendments):
            raise ValueError('Native final work already exists; legacy unstarted migration refused')
        native.append({'path': str(info_file), 'sha256': sha256_file(info_file)})
    before_sha = sha256_file(state_file)
    archive = root / 'compatibility' / (before_sha + '.state.json')
    receipt_file = root / 'compatibility' / (before_sha + '.migration.json')
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists() and archive.read_bytes() != raw: raise ValueError('Legacy state archive differs')
    if not archive.exists(): archive.write_bytes(raw)
    state['binding'] = expected
    state.setdefault('orchestration_migrations', []).append({'old_helper_sha256': LEGACY_UNSTARTED_HELPER,
        'new_helper_sha256': LOADED_ORCHESTRATION_SHA, 'old_state_sha256': before_sha,
        'receipt_file': str(receipt_file), 'scope': 'Exact unstarted final gate; no accepted model update or trace result reinterpreted'})
    temporary = root / 'state.json.migration.tmp'; write(temporary, state)
    receipt = {'schema_version': 'completion-unstarted-migration.v1', 'status': 'migrated',
        'old_helper_sha256': LEGACY_UNSTARTED_HELPER, 'new_helper_sha256': LOADED_ORCHESTRATION_SHA,
        'before_state_sha256': before_sha, 'after_state_sha256': sha256_file(temporary),
        'old_state_archive': str(archive), 'source_plan_id': source_plan['plan_id'],
        'native_run_files_checked': native, 'frontier_was_unfrozen': True,
        'native_final_work_count': 0, 'model_ledgers_modified': False, 'budgets_modified': False,
        'candidate_plan_modified': False, 'new_model_calls': 0, 'new_solver_runs': 0}
    if receipt_file.exists() and _read(receipt_file) != receipt:
        raise ValueError('Retained completion migration receipt differs')
    if not receipt_file.exists(): write(receipt_file, receipt)
    if state_file.read_bytes() != raw: raise ValueError('Completion state changed during metadata migration')
    temporary.replace(state_file)
    return receipt


class Completion:
    def __init__(self, directory, progress):
        self.root = filesystem_path(directory); self.progress = progress
        self.file = self.root / 'state.json'
        binding = {'schema_version': VERSION, 'plan_id': progress.plan['plan_id'],
                   'source': progress.plan['source'], 'orchestration_sha256': LOADED_ORCHESTRATION_SHA,
                   'max_source_blocks_per_issue': MAX_SOURCE_BLOCKS, 'max_attempts_per_issue': MAX_REVIEW_ATTEMPTS,
                   'mining_rules_changed': False, 'frozen_task_rules_changed': False}
        if self.file.exists():
            self.state = _read(self.file)
            if self.state['binding'] != binding and self.state['binding'].get('orchestration_sha256') == LEGACY_UNSTARTED_HELPER:
                migrate_unstarted_completion(self.root, expected_binding=binding)
                self.state = _read(self.file)
            if self.state['binding'] != binding: raise ValueError('Completion source/rules changed; retain this run and use an explicit new version')
        else: self.state = {'binding': binding, 'items': {}, 'frontier': None, 'events': [], 'last_run': None}

    def save(self, reason):
        previous = fingerprint(self.state)
        self.state['events'].append({'previous_state_sha256': previous, 'reason': reason,
                                     'item_states': {k: v['state'] for k, v in self.state['items'].items()}})
        self.root.mkdir(parents=True, exist_ok=True)
        temp = self.root / 'state.json.tmp'; write(temp, self.state); temp.replace(self.file)

    def register(self, key, value):
        self.state['items'][key] = value
        self.progress.record_mining_finalization(key, value, value['state'], value['reason'])

    def candidates(self, report):
        current = {}; frontier = self.state['frontier']
        for issue in _open(report).values():
            key = _issue_key(self.progress.plan['plan_id'], issue); current[key] = issue
            if key not in self.state['items']:
                self.register(key, {'issue': deepcopy(issue), 'state': 'pending',
                    'reason': 'Await original blocks and bounded final review' if frontier is None or key in frontier else 'New or changed issue outside the fixed one-pass final frontier',
                    'amendment_id': 'auto-final:' + key.split(':', 1)[1], 'scope': _selection(report, issue)})
            elif frontier is None and self.state['items'][key]['state'] in {'pending', 'superseded'}:
                old = self.state['items'][key]
                self.register(key, {**old, 'state': 'pending', 'scope': _selection(report, issue),
                    'reason': 'Model reopened the same unstarted issue before final frontier' if old['state'] == 'superseded' else old['reason']})
        if frontier is None:
            for key, item in list(self.state['items'].items()):
                if key not in current and item['state'] == 'pending':
                    self.register(key, {**item, 'state': 'superseded', 'reason': 'Model resolved, removed or revised issue before final frontier'})
        return current

    def gate(self, state, reason):
        key = 'mining_finalization:' + fingerprint([VERSION, self.progress.plan['plan_id'], 'gate'])[:24]
        self.progress.record_mining_finalization(key, {'role': 'automatic_final_frontier_gate',
            'frontier': self.state['frontier'], 'state_file': str(self.file),
            'source_orchestration_sha256': self.state['binding']['orchestration_sha256']}, state, reason)


def finalize_mining(catalog, view, output, provider, config, progress, run, report, *, remaining_segment_calls=None, checkpoint=None):
    """Return the native last segment/report plus explicit orchestration status.

Callers must use the same cumulative PlannedProvider as ordinary mining. No
fresh call budget, config amendment, manual approval or caller work amendment
is required or permitted to activate this automatic stage.
"""
    from androserum.mining.runner import run_mining
    completion = Completion(progress.root.parent / 'mining-completion', progress)
    current = completion.candidates(report)
    original = [r for r in report.get('chunk_progress', []) if not r.get('work_amendment')]
    ready = bool(original) and all(r['state'] in TERMINAL for r in original) and not report.get('coverage', {}).get('unscheduled')
    if not ready:
        completion.gate('pending', 'Original BU blocks remain unprocessed/nonterminal or evidence is unscheduled')
        completion.save('Original-work gate remains pending; no final-review dispatch')
        return run, report, {'status': 'pending_original_blocks', 'state_file': str(completion.file), 'new_final_review_calls': 0}
    if completion.state['frontier'] is None:
        completion.state['frontier'] = sorted(current)
        completion.save('Freeze model-open issue frontier after all original blocks terminated')
    started_calls = report['budgets']['model_calls']; remaining = remaining_segment_calls
    for key in completion.state['frontier']:
        item = completion.state['items'][key]
        if item['state'] in {'completed', 'superseded', 'failed', 'truncated'}: continue
        if key not in current:
            completion.register(key, {**item, 'state': 'completed', 'reason': 'Model issue resolved or revised by an earlier accepted final update', 'outcome': 'skip_no_longer_open'})
            continue
        scope = item['scope']; amendment_id = item['amendment_id']
        if not scope['target_chunk_ids']:
            completion.register(key, {**item, 'state': 'completed', 'reason': 'No accepted original visible block supports this issue; no archive expansion', 'outcome': 'skip_no_accepted_visible_support'})
            continue
        # A crash after creation leaves the native segment retained. Adopt a
        # published segment, or block rather than redispatch an unfinished one.
        existing = [r for r in report['chunk_progress'] if r.get('work_amendment', {}).get('amendment_id') == amendment_id]
        if not existing:
            retained = []
            for info_file in filesystem_path(output).glob('mining_*/run.json'):
                info = _read(info_file)
                if (info.get('new_work_amendment') or {}).get('amendment_id') == amendment_id:
                    retained.append(info_file.parent)
            if retained:
                if len(retained) != 1 or not (retained[0] / 'manifest.json').exists():
                    completion.register(key, {**item, 'state': 'pending', 'reason': 'Interrupted native final segment retained; explicit reconciliation required before redispatch'})
                    continue
                from androserum.mining.verification import verify_package
                verify_package(retained[0], catalog, view)
                run = retained[0]; report = _read(run / 'report.json'); progress.sync_mining(run, report)
                existing = [r for r in report['chunk_progress'] if r.get('work_amendment', {}).get('amendment_id') == amendment_id]
        if existing and all(r['state'] in TERMINAL for r in existing):
            trace = _trace(run, report, amendment_id, item['issue']); row = existing[-1]
            state = 'failed' if row['state'] == 'rejected' else 'truncated' if row['state'] == 'blocked' or trace['returned_without_later_accepted_review'] or trace['unfulfilled_accepted_model_queries'] or not trace['target_issue_editable_in_accepted_review'] else 'completed'
            outcome = ('rejected' if state == 'failed' else 'truncated_or_query_return_not_reviewed' if state == 'truncated' else
                       'queried_and_reviewed' if trace['actual_receipts'] else 'reviewed_no_query')
            completion.register(key, {**item, 'state': state, 'reason': outcome, 'outcome': outcome, 'trace': trace,
                                     'last_run': str(run), 'model_issue_still_open': item['issue']['issue_id'] in _open(report)})
            continue
        available = min(config.max_model_calls - report['budgets']['model_calls'], progress.remaining()['max_model_calls'])
        if remaining is not None: available = min(available, remaining)
        needed = 1 if existing else 2
        query_room = (report['budgets'].get('supplement_rounds', 0) < config.max_supplement_rounds and
                      report['budgets'].get('supplement_records', 0) < config.max_supplement_records)
        if available < needed or (not existing and not query_room):
            completion.register(key, {**item, 'state': 'pending', 'reason': 'Frozen segment/cumulative/query budget insufficient for query and later review',
                                     'available_model_calls': max(0, available), 'minimum_start_calls': needed})
            continue
        allowance = min(available, MAX_REVIEW_ATTEMPTS)
        amendment = None if existing else {'amendment_id': amendment_id, 'kind': 'consolidation',
            'reason': 'Automatic post-BU review of model open issue ' + item['issue']['issue_id'],
            'instruction': ('Review only this recorded model issue and supplied accepted support: ' + json.dumps(item['issue'], ensure_ascii=False) +
                '. Selected support scope and omitted blocks: ' + json.dumps(scope, ensure_ascii=False) +
                '. Request necessary current-APK facts with the existing fact_queries contract; unknown until actual returns are supplied. '
                'Use a later proposal to resolve or constrain the issue. Preserve unproven links and partial coverage. '
                'This is one bounded final review, not evidence of execution or full APK behavior.'),
            'target_chunk_ids': scope['target_chunk_ids'], 'max_attempts': allowance}
        completion.register(key, {**item, 'state': 'running', 'reason': 'Persist automatic bounded review before native dispatch', 'last_parent_run': str(run)})
        completion.save('Reserve finalization work identity before entering native mining continuation')
        before = report['budgets']['model_calls']
        # Persist each dispatch before continuing. Native resume rebuilds
        # returned evidence from the exact stored receipts; no in-memory-only
        # grant is used, and every query/review keeps its immutable segment.
        left = allowance
        while left > 0:
            at = report['budgets']['model_calls']
            run, report = run_mining(catalog, view, output, provider, config, resume_from=run,
                                    call_limit=1, work_amendment=amendment)
            amendment = None
            progress.sync_mining(run, report)
            step = report['budgets']['model_calls'] - at
            completion.state['last_run'] = str(run)
            completion.save('Retain one native dispatch/receipt segment before any final-review continuation')
            if checkpoint: checkpoint(run, report, {'status': 'native_final_review_segment_retained',
                                                   'state_file': str(completion.file), 'work_item_id': key})
            left -= step
            review = [r for r in report['chunk_progress'] if r.get('work_amendment', {}).get('amendment_id') == amendment_id]
            if not step or not review or all(r['state'] in TERMINAL for r in review): break
        used = report['budgets']['model_calls'] - before
        if remaining is not None: remaining -= used
        trace = _trace(run, report, amendment_id, item['issue']); review_rows = trace['review_rows']
        terminal = review_rows and all(r['state'] in TERMINAL for r in review_rows)
        last = review_rows[-1] if review_rows else {}
        state = ('failed' if terminal and last['state'] == 'rejected' else 'truncated' if terminal and
                 (last['state'] == 'blocked' or trace['returned_without_later_accepted_review'] or trace['unfulfilled_accepted_model_queries'] or not trace['target_issue_editable_in_accepted_review']) else 'completed' if terminal else 'pending')
        outcome = ('queried_review_pending' if trace['returned_without_later_accepted_review'] else 'queried_and_reviewed' if trace['actual_receipts']
                   else 'reviewed_no_query' if state == 'completed' else state)
        completion.register(key, {**item, 'state': state, 'reason': outcome if terminal else report.get('stop_reason') or outcome,
                                 'outcome': outcome, 'trace': trace, 'last_run': str(run),
                                 'model_issue_still_open': item['issue']['issue_id'] in _open(report)})
        completion.state['last_run'] = str(run); completion.save('Retain native query/return/review outcome without rewriting accepted model content')
        current = completion.candidates(report)
    open_work = [v for v in completion.state['items'].values() if v['state'] not in {'completed', 'superseded'}]
    completion.gate('pending' if open_work else 'completed',
                    'Bounded final review has pending/rejected/truncated or newly changed issues' if open_work else
                    'Bounded final frontier processed; remaining model uncertainty is preserved' if completion.state['frontier'] else 'Skip: no model-open unresolved items')
    completion.save('Publish complete finalization candidate inventory and gate')
    return run, report, {'status': 'partial' if open_work else 'bounded_final_review_complete',
                        'state_file': str(completion.file), 'frontier': completion.state['frontier'],
                        'item_states': {k: v['state'] for k, v in completion.state['items'].items()},
                        'new_final_review_calls': report['budgets']['model_calls'] - started_calls,
                        'orchestration_sha256': completion.state['binding']['orchestration_sha256']}
