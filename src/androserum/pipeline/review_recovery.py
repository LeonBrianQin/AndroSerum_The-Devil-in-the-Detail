"""Bounded recovery of an existing post-BU frontier using the native ledger.

This module never resubmits accepted original blocks, rewrites a proposal, or
changes a budget. The caller supplies an explicitly frozen cumulative config
and the ordinary PipelineProvider/PlannedProvider transaction boundary.
"""
from copy import deepcopy
import json
from pathlib import Path

from androserum.facts.identity import filesystem_path,fingerprint,sha256_file
from androserum.facts.query_reuse import POLICY
from androserum.inference.provider import write
from .mining_completion import _trace,_selection

VERSION='post-bu-review-recovery.v1'
RULE_SHA=sha256_file(__file__)


def read(path):return json.loads(filesystem_path(path).read_text('utf-8'))


def review_trace(run,report,amendment_id,issue):
    """Require the *current accepted* issue closure in the later review.

An accepted merge/deletion may legitimately revise subject IDs. They are read
from each stored request's checked ledger state, never invented as aliases.
The denied-query receipt is still required in a later accepted editable input.
"""
    trace=_trace(run,report,amendment_id,issue)
    for row in trace['requests']:
        packet=read(row['request_file']);context=packet.get('ledger_context',{})
        current=context.get('unresolved',{}).get(issue['issue_id'])
        visible=set(context.get('actions',{}))|set(context.get('bcs',{}))
        subjects=current.get('subject_ids',[]) if current else issue.get('subject_ids',[])
        row.update(target_issue_editable=current is not None,
            missing_target_subject_ids=sorted(set(subjects)-visible),
            reviewed_subject_ids=subjects,subject_basis='actual accepted ledger issue in this request')
    positions={r['request_id']:i for i,r in enumerate(report['requests'])}
    events=report.get('query_typed_admissions',[])
    ids={r['request_id'] for r in trace['requests']}
    unseen=[]
    for receipt in trace['actual_receipts']:
        origins=[positions[e['request_id']] for e in events if e['receipt_id']==receipt['receipt_id'] and e['request_id'] in ids]
        after=max(origins) if origins else len(positions)
        if not any(r['accepted'] and r['target_issue_editable'] and not r['missing_target_subject_ids']
                and positions[r['request_id']]>after
                and any(q.get('receipt_id')==receipt['receipt_id'] for q in r['fact_query_results']) for r in trace['requests']):
            unseen.append(receipt['receipt_id'])
    accepted=[r for r in trace['requests'] if r['accepted']]
    trace['target_issue_editable_in_accepted_review']=bool(accepted and accepted[-1]['target_issue_editable'] and not accepted[-1]['missing_target_subject_ids'])
    trace['returned_without_later_accepted_review']=unseen
    trace['budget_denial_is_not_behavior_absence']=True
    return trace


def review_outcome(trace):
    rows=trace['review_rows']
    if not rows:return 'pending','not_submitted'
    if any(r['state']=='rejected' for r in rows):return 'failed','program_rejected'
    if any(r['state']=='blocked' for r in rows):return 'blocked','request_not_assemblable'
    if any(r['state']!='accepted' for r in rows):return 'pending','review_or_query_followup_pending'
    if (trace['unfulfilled_accepted_model_queries'] or trace['returned_without_later_accepted_review']
            or not trace['target_issue_editable_in_accepted_review']):
        return 'pending','receipt_or_target_closure_not_reviewed'
    limited=any(r['state'] in {'budget_exhausted','failed'} or r.get('truncated') for r in trace['actual_receipts'])
    return 'completed',('reviewed_with_query_limits' if limited else
                        'queried_and_reviewed' if trace['actual_receipts'] else 'reviewed_no_query')


def initialize_recovery(directory,source_run,source_completion,config,*,reason):
    """Bind a new control state to immutable predecessor bytes and spend."""
    if not str(reason).strip():raise ValueError('Explicit recovery grounds required')
    directory=filesystem_path(directory);source_run=filesystem_path(source_run)
    source_completion=filesystem_path(source_completion);report=read(source_run/'report.json');old=read(source_completion)
    original=[r for r in report['chunk_progress'] if not r.get('work_amendment')]
    if not original or any(r['state']!='accepted' for r in original) or report['coverage'].get('unscheduled'):
        raise ValueError('Finish all original blocks before review recovery')
    if old.get('frontier') is None:raise ValueError('Recovery requires the actual frozen final frontier')
    body={'schema_version':VERSION,'source_run':str(source_run),'source_manifest_sha256':sha256_file(source_run/'manifest.json'),
        'source_completion':str(source_completion),'source_completion_sha256':sha256_file(source_completion),
        'source_identity':report['identity'],'source_accepted_state_sha256':fingerprint(report['accepted_state']),
        'original_block_ids':[r['chunk_id'] for r in original],'source_model_calls':report['budgets']['model_calls'],
        'config_sha256':fingerprint(config.model_dump(mode='json')),'query_delivery_policy':POLICY,
        'rule_sha256':RULE_SHA,'reason':reason}
    binding={**body,'binding_id':fingerprint(body)};path=directory/'state.json'
    if path.exists():
        state=read(path)
        if state['binding']!=binding:raise ValueError('Recovery source/config/rule changed; use a new bound segment')
        return state
    directory.mkdir(parents=True,exist_ok=True)
    items={}
    for key in old['frontier']:
        item=old['items'][key];trace=_trace(source_run,report,item['amendment_id'],item['issue'])
        prior_done=(item['state']=='completed' and review_outcome(trace)[0]=='completed')
        items[key]={'source_item':deepcopy(item),'issue_id':item['issue']['issue_id'],
            'state':'completed' if prior_done else 'pending','outcome':'retained_verified_review' if prior_done else 'pending_recovery',
            'amendment_id':item['amendment_id'] if prior_done else 'auto-final:recovery:'+fingerprint([binding['binding_id'],key])[:24],
            'trace':trace if prior_done else None,'amendment':None,'source_trace':trace}
    state={'binding':binding,'frontier':list(old['frontier']),'items':items,'last_run':str(source_run),'events':[],
        'new_model_calls':0,'accepted_state_modified_by_program':False}
    write(directory/'source-completion.json',old);write(path,state)
    return state


def continue_reviews(catalog,view,output,provider,config,directory,*,call_limit=None,progress=None,checkpoint=None):
    """Every new dispatch uses run_mining; denied queries still get a review."""
    from androserum.mining.runner import run_mining
    from androserum.mining.verification import verify_package
    directory=filesystem_path(directory);path=directory/'state.json';state=read(path);binding=state['binding']
    if binding['rule_sha256']!=RULE_SHA or binding['config_sha256']!=fingerprint(config.model_dump(mode='json')):
        raise ValueError('Recovery config or implementation changed')
    if sha256_file(binding['source_completion'])!=binding['source_completion_sha256'] or sha256_file(filesystem_path(binding['source_run'])/'manifest.json')!=binding['source_manifest_sha256']:
        raise ValueError('Recovery predecessor changed')
    run=filesystem_path(state['last_run']);verify_package(run,catalog,view);report=read(run/'report.json')
    start=report['budgets']['model_calls'];remaining=call_limit
    def save(reason):
        state['events'].append({'reason':reason,'run':str(run),'cumulative_calls':report['budgets']['model_calls'],
            'states':{k:v['state'] for k,v in state['items'].items()}})
        state['last_run']=str(run);state['new_model_calls']=report['budgets']['model_calls']-binding['source_model_calls']
        write(path,state)
    for key in state['frontier']:
        item=state['items'][key]
        if item['state'] in {'completed','failed','blocked'}:continue
        issue=report['accepted_state']['unresolved'].get(item['issue_id'])
        if issue is None:
            item.update(state='blocked',outcome='target_issue_absent_no_implicit_success');save('Missing accepted review target');continue
        existing=[r for r in report['chunk_progress'] if r.get('work_amendment',{}).get('amendment_id')==item['amendment_id']]
        # An interrupted publication is never silently redispatched.
        if not existing:
            retained=[p.parent for p in filesystem_path(output).glob('mining_*/run.json')
                if (read(p).get('new_work_amendment') or {}).get('amendment_id')==item['amendment_id']]
            if retained:
                raise ValueError('Unreconciled retained review segment; no redispatch')
        allowance=config.max_model_calls-report['budgets']['model_calls']
        if remaining is not None:allowance=min(allowance,remaining)
        if allowance<(1 if existing else 2):
            item.update(outcome='pending_call_budget',available_calls=max(0,allowance));save('Keep pending review within frozen cumulative slots');break
        if item['amendment'] is None:
            scope=_selection(report,issue)
            if not scope['target_chunk_ids']:
                item.update(state='blocked',outcome='no_supported_original_context');save('No invented context for issue');continue
            item['issue']=deepcopy(issue);item['scope']=scope
            item['amendment']={'amendment_id':item['amendment_id'],'kind':'consolidation',
                'reason':'Bounded recovery of the retained final-review issue '+issue['issue_id'],
                'instruction':'Review this existing issue and its complete editable closure: '+json.dumps(issue,ensure_ascii=False)+
                    '. Preserve unresolved facts and scope limits. A denied or exhausted query is not evidence of absence. '
                    'Review the actual query status in a later update; you may retain evidence insufficiency. '
                    'Only the supplied current-APK records and exact prior receipt grants are evidence.',
                'target_chunk_ids':scope['target_chunk_ids'],'required_ledger_ids':[issue['issue_id']],
                'max_attempts':3,'max_program_repairs':1}
            save('Bind targeted recovery work before dispatch')
        left=min(allowance,3-(existing[-1].get('amendment_attempts_used',0) if existing else 0))
        if not left:
            item.update(state='blocked',outcome='bounded_review_attempts_exhausted');save('No repeated repair beyond the declared review');continue
        amendment=None if existing else item['amendment']
        while left>0:
            before=report['budgets']['model_calls']
            run,report=run_mining(catalog,view,output,provider,config,resume_from=run,call_limit=1,
                budget_amendment_reason=binding['reason'],provider_rebind_reason=binding['reason'],
                work_amendment=amendment,query_delivery_policy=POLICY)
            amendment=None
            if progress:progress.sync_mining(run,report)
            used=report['budgets']['model_calls']-before;left-=used
            if remaining is not None:remaining-=used
            trace=review_trace(run,report,item['amendment_id'],item['issue'])
            status,outcome=review_outcome(trace)
            item.update(state=status,outcome=outcome,trace=trace,last_run=str(run))
            save('Retain actual native dispatch, receipt and accepted update')
            if checkpoint:checkpoint(run,report,state)
            if status in {'completed','failed','blocked'} or not used:break
        if not used:break
    gate=recovery_gate(directory)
    return run,report,{**gate,'new_final_review_calls':report['budgets']['model_calls']-start,'state_file':str(path)}


def recovery_gate(directory):
    state=read(filesystem_path(directory)/'state.json');run=filesystem_path(state['last_run']);report=read(run/'report.json')
    reasons=[];rows=[]
    for key in state['frontier']:
        item=state['items'][key];issue=item.get('issue') or item['source_item']['issue']
        trace=review_trace(run,report,item['amendment_id'],issue);status,outcome=review_outcome(trace)
        done=item['state']=='completed' and status=='completed'
        if not done:reasons.append(key+':'+outcome)
        rows.append({'item_id':key,'state':item['state'],'outcome':item['outcome'],'required_review_complete':done,
            'query_outcomes':[{'receipt_id':r['receipt_id'],'state':r['state'],'truncated':r.get('truncated',False)} for r in trace['actual_receipts']]})
    original=[r for r in report['chunk_progress'] if not r.get('work_amendment')]
    if [r['chunk_id'] for r in original]!=state['binding']['original_block_ids'] or any(r['state']!='accepted' for r in original):
        reasons.append('original_plan_changed_or_not_accepted')
    if report['budgets']['model_calls']<state['binding']['source_model_calls']:reasons.append('historical_spend_reset')
    return {'schema_version':'post-bu-recovery-gate.v1','ready':not reasons,'frozen_procedure_scope_complete':not reasons,
        'reasons':reasons,'required_frontier_reviews':rows,'original_blocks_accepted':len(original),
        'cumulative_model_calls':report['budgets']['model_calls'],'source_calls_retained':state['binding']['source_model_calls'],
        'residual_unknowns':list(report['accepted_state']['unresolved'].values()),'unknowns_must_be_zero':False,
        'report_sha256':sha256_file(run/'report.json')}
