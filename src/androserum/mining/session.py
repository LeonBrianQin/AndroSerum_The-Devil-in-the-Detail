"""Immutable continuation segments over one logical ledger and fixed work plan."""
from copy import deepcopy
from collections import Counter
from pathlib import Path
from uuid import uuid4
import hashlib,json,shutil,sqlite3

from androserum.facts.identity import filesystem_path,fingerprint,sha256_file,canonical_json
from androserum.mining.assembly import make_packet
from androserum.mining.checker import check_proposal,proposal_handles
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.ledger import Ledger
from androserum.mining.models import MiningConfig

TERMINAL={'accepted','rejected','blocked'}
AMENDABLE_BUDGETS={'max_model_calls','max_ledger_context_chars','max_request_chars',
                  'max_supplement_records','max_query_return_chars','max_supplement_rounds'}


def apply_work_amendment(rows,amendment):
    """An explicit, bounded new task; never reset original retry counters."""
    required_fields={'amendment_id','kind','reason','instruction','target_chunk_ids','max_attempts'}
    if not required_fields<=set(amendment) or set(amendment)-required_fields-{'required_ledger_ids','max_program_repairs'}:
        raise ValueError('Invalid work amendment fields')
    if 'required_ledger_ids' in amendment and (not isinstance(amendment['required_ledger_ids'],list) or
            any(not isinstance(v,str) or not v for v in amendment['required_ledger_ids'])):
        raise ValueError('Review ledger subjects must be explicit identifiers')
    if 'max_program_repairs' in amendment and amendment['max_program_repairs']!=1:
        raise ValueError('Explicit review policy permits at most one repair per proposal')
    if amendment['kind'] not in {'closure_repair','closure_followup','consolidation'} or not all(isinstance(amendment[k],str) and amendment[k].strip() for k in ['amendment_id','reason','instruction']):
        raise ValueError('Work amendment requires kind, identity and grounds')
    if type(amendment['max_attempts']) is not int or not 1<=amendment['max_attempts']<=3:
        raise ValueError('Work amendment is bounded to 1..3 attempts per target')
    targets=amendment['target_chunk_ids']
    if not targets or len(targets)!=len(set(targets)):raise ValueError('Work targets must be unique and nonempty')
    selected=[r for r in rows if r['chunk_id'] in targets]
    if len(selected)!=len(targets):raise ValueError('Unknown work amendment target')
    if amendment['kind']!='closure_followup' and any(r.get('work_amendment') for r in selected):raise ValueError('Cannot repeatedly reopen amended work')
    if amendment['kind']=='closure_followup':
        if any(r['state']!='rejected' or r.get('work_amendment',{}).get('kind')!='closure_repair' for r in selected):
            raise ValueError('Follow-up requires exhausted explicit closure repair')
        if any(r.get('followup_target_ref') in targets for r in rows):raise ValueError('Each failed closure target permits only one explicit follow-up')
        for source in selected:
            rows.append({'chunk_id':'review_'+fingerprint([amendment,source['chunk_id']])[:16],
                'chunk':deepcopy(source['chunk']),'state':'unprocessed','attempt_ids':[],'request_ids':[],
                'repairs_used':0,'extra_handles':[],'repair':None,'reason':None,'shown_handles':[],
                'accepted_handles':[],'cited_handles':[],'work_amendment':deepcopy(amendment),
                'amendment_attempts_used':0,'followup_target_ref':source['chunk_id']})
        return
    if amendment['kind']=='closure_repair':
        if any(r['state']!='rejected' for r in selected):raise ValueError('Closure repair requires terminal rejected chunks')
        for row in selected:
            row['prior_terminal_state']={'state':row['state'],'reason':deepcopy(row['reason']),'attempt_ids':list(row['attempt_ids'])}
            row.update(state='unprocessed',repair=None,reason=None,work_amendment=deepcopy(amendment),amendment_attempts_used=0)
    else:
        if any(r['state']!='accepted' for r in selected):raise ValueError('Consolidation requires accepted source chunks')
        chunk={'bu_ids':sorted({b for r in selected for b in r['chunk']['bu_ids']}),
            'handles':sorted({h for r in selected for h in r['chunk']['handles']})}
        rows.append({'chunk_id':'review_'+fingerprint(amendment)[:16],'chunk':chunk,'state':'unprocessed','attempt_ids':[],
            'request_ids':[],'repairs_used':0,'extra_handles':[],'repair':None,'reason':None,
            'shown_handles':[],'accepted_handles':[],'cited_handles':[],
            'work_amendment':deepcopy(amendment),'amendment_attempts_used':0})


def save(path,value):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')


def work_plan(catalog,config):
    chunks,pending=catalog.chunks(config)
    rows=[{'chunk_id':'chunk_'+fingerprint(c)[:16],'chunk':c,'state':'unprocessed','attempt_ids':[],
        'request_ids':[],'repairs_used':0,'extra_handles':[],'repair':None,'reason':None,
        'shown_handles':[],'accepted_handles':[],'cited_handles':[]} for c in chunks]
    return rows,pending


def coverage(catalog,rows,pending):
    from androserum.mining_packing import clone_catalog
    catalog=clone_catalog(catalog)
    by_bu={}
    for bu in catalog.units:
        relevant=[r for r in rows if bu in r['chunk']['bu_ids']]
        candidates={h for h,e in catalog.entries.items() if bu in e['bu_ids'] and not e.get('supplement_query_id')}
        planned={h for r in relevant for h in catalog.render(r['chunk']['handles'],{bu})}
        shown={h for r in relevant for h in r['shown_handles']} & candidates
        accepted={h for r in relevant for h in r['accepted_handles']} & candidates
        cited={h for r in relevant for h in r['cited_handles']} & candidates
        by_bu[bu]={'chunks':len(relevant),'states':dict(Counter(r['state'] for r in relevant)),
            'candidate_handles':len(candidates),'planned_handles':len(planned),'shown_handles':len(shown),
            'accepted_handles':len(accepted),'unshown_handles':sorted(candidates-shown),
            'accepted_handles_meaning':'Visible in accepted requests, not necessarily semantically used',
            'explicitly_cited_handles':len(cited),'explicitly_cited_operations':len([h for h in cited if catalog.entries[h]['category']=='operation']),
            'candidate_operations':sum(catalog.entries[h]['category']=='operation' for h in candidates),
            'unaccepted_handles':sorted(candidates-accepted),'all_chunks_terminal':all(r['state'] in TERMINAL for r in relevant),
            'all_chunks_accepted':all(r['state']=='accepted' for r in relevant),
            'semantic_completeness_claimed':False}
    return {'by_bu':by_bu,'states':dict(Counter(r['state'] for r in rows)),
        'unscheduled':pending,'all_planned_chunks_terminal':all(r['state'] in TERMINAL for r in rows),
        'all_selected_evidence_submitted':not pending and all(not b['unshown_handles'] for b in by_bu.values()),
        'full_behavior_coverage_claimed':False}


def support_additions(before,after,packet):
    events=[];seen={h for a in before['actions'].values() for h in a['evidence_handles']}
    for key,action in after['actions'].items():
        old=before['actions'].get(key)
        if not old:continue
        added_bu=set(action['source_bu_refs'])-set(old['source_bu_refs'])
        fresh=set(action['evidence_handles'])-seen
        # A different incoming/outgoing dependency is required. Merely showing
        # the identical operation from a second BU does not satisfy this gate.
        fresh_relations=[h for h in fresh if packet['evidence'].get(h,{}).get('category')=='relation']
        if added_bu and fresh_relations:
            events.append({'action_id':key,'new_bu_refs':sorted(added_bu),'new_relation_handles':sorted(fresh_relations),
                'before_revision':before['revision'],'after_revision':after['revision'],
                'request_id':packet['request_id'],'nonempty_model_update':True})
    return events


def run_session(catalog,view,output,provider,config=None,*,resume_from=None,call_limit=None,budget_amendment_reason=None,recheck_rejected=False,work_amendment=None,query_delivery_policy=None,provider_rebind_reason=None):
    from androserum.mining.runner import reference_frontier
    config=config or MiningConfig()
    packed=hasattr(catalog,'bundle_size');assets_reused=False
    def publish(path,value):
        if packed:
            from androserum.mining_storage import assert_writable
            assert_writable(path,segment_root=root)
        save(path,value)
    if len(catalog.units)>config.max_bu:raise ValueError('Selected BU count exceeds mining budget')
    if call_limit is not None and call_limit<0:raise ValueError('Segment call limit must be nonnegative')
    # Rebuild an un-enriched catalog, including when a caller reuses an object.
    scope_limits={b:deepcopy(s['analysis_scope_limits']) for b,s in catalog.statuses.items() if 'analysis_scope_limits' in s}
    from androserum.mining_packing import clone_catalog
    catalog=clone_catalog(catalog)
    # Retain only verified provider-scope metadata through the clean rebuild.
    # Supplements and actual visible evidence still come solely from units.
    for b,limits in scope_limits.items():catalog.statuses[b]['analysis_scope_limits']=limits
    rows,pending=work_plan(catalog,config);initial_plan=[r['chunk'] for r in rows]
    root=filesystem_path(output)/('mining_'+uuid4().hex)
    if resume_from and root.is_relative_to(filesystem_path(resume_from)):raise ValueError('Continuation must be outside its immutable parent')
    root.mkdir(parents=True,exist_ok=False)
    requests=[];queries=[];additions=[];typed_admissions=[];calls=0;supplement_rounds=0;supplement_records=0;parent=None;amendments=[];provider_change=None
    if work_amendment and not resume_from:raise ValueError('Work amendment requires immutable continuation')
    identity={'mining_run_ref':'mining-run:'+root.name.removeprefix('mining_'),'source':catalog.identity,
        'selected_bu_ids':list(catalog.units),'mining_version':'behavior-mining.v2'}
    if resume_from:
        from androserum.mining.verification import verify_mining
        previous=filesystem_path(resume_from)
        # Source BU identity is already checked by the caller; replay from the
        # exact catalog rather than trusting a mutable report summary.
        from androserum.mining.verification import verify_package
        verify_package(previous,catalog,view)
        # Verification reconstructs all historical query visibility in its
        # catalog. Restore from the exact clean source before replaying those
        # receipts chronologically; later support must not alter an earlier
        # needs_support decision. Every original comparison remains strict.
        catalog=clone_catalog(catalog)
        for b,limits in scope_limits.items():catalog.statuses[b]['analysis_scope_limits']=limits
        info=json.loads((previous/'run.json').read_text('utf-8'));old=json.loads((previous/'report.json').read_text('utf-8'))
        inherited_policy=info.get('query_delivery_policy')
        if query_delivery_policy is None:query_delivery_policy=inherited_policy
        if inherited_policy and query_delivery_policy!=inherited_policy:raise ValueError('Cannot replace a pinned query delivery policy')
        if query_delivery_policy!=inherited_policy and not budget_amendment_reason:
            raise ValueError('Query policy upgrade requires an explicit immutable continuation reason')
        if info['identity']['mining_version']!='behavior-mining.v2':raise ValueError('Only matching v2 sessions support continuation')
        new_config=config.model_dump(mode='json');previous_config=info['config']
        amendment=None
        if previous_config!=new_config:
            changed={k for k in set(previous_config)|set(new_config) if previous_config.get(k)!=new_config.get(k)}
            if not changed<=AMENDABLE_BUDGETS or any(new_config[k]<previous_config[k] for k in changed) or not budget_amendment_reason:
                raise ValueError('Cannot change fixed configuration or plan on continuation')
            amendment={'reason':budget_amendment_reason,'old_max_calls':previous_config['max_model_calls'],
                'new_max_calls':new_config['max_model_calls'],'calls_already_used':len(old['attempts']),
                'changes':{k:{'old':previous_config[k],'new':new_config[k]} for k in sorted(changed)}}
        if info['plan']!=initial_plan:raise ValueError('Cannot change fixed configuration or plan on continuation')
        if info['provider']!=provider.description:
            different={k for k in set(info['provider'])|set(provider.description) if info['provider'].get(k)!=provider.description.get(k)}
            if different!={'round_config_sha256'} or not provider_rebind_reason:
                raise ValueError('Continuation provider identity differs')
            provider_change={'reason':provider_rebind_reason,'old':fingerprint(info['provider']),
                'new':fingerprint(provider.description),'only_budget_round_binding_changed':True}
        identity=info['identity'];rows=deepcopy(old['chunk_progress']);requests=deepcopy(old['requests']);queries=deepcopy(old['queries'])
        typed_admissions=deepcopy(old.get('query_typed_admissions',[]))
        amendments=deepcopy(info.get('work_amendments',[]))
        if work_amendment:
            if any(a['amendment_id']==work_amendment['amendment_id'] for a in amendments):raise ValueError('Work amendment identity already consumed')
            apply_work_amendment(rows,work_amendment);amendments.append(deepcopy(work_amendment))
            # Repair the actual historical refusal rather than asking a model
            # to rediscover it from a broad ledger. Provider failures have no
            # proposal; find the last structural refusal for that target.
            for row in rows:
                if row.get('work_amendment')!=work_amendment or work_amendment['kind']=='consolidation':continue
                target=row.get('followup_target_ref',row['chunk_id'])
                prior=[a for a in old['attempts'] if a['chunk_id']==target and a['status']=='rejected' and a['files'].get('proposal') and
                    any(e['code']!='provider' for e in a['check']['errors'])]
                if prior:
                    last=prior[-1];raw=(previous/last['files']['proposal']).read_text('utf-8')
                    row['repair']={'errors':last['check']['errors'],'previous_proposal':raw[:config.max_response_chars],
                        'historical_request_id':last['request_id'],'rebase_required':True}
        if recheck_rejected:
            if not budget_amendment_reason:raise ValueError('Policy recheck requires an explicit reason')
            for row in rows:
                if row['state']=='rejected' and row.get('policy_rechecks_used',0)<1:
                    row.update(state='unprocessed',repair=None,reason=None,policy_rechecks_used=1)
        additions=deepcopy(old['support_additions']);calls=len(old['attempts'])
        supplement_rounds=old['budgets']['supplement_rounds'];supplement_records=old['budgets']['supplement_records']
        if packed:
            from androserum.mining_storage import reuse_sealed_assets
            reuse_sealed_assets(previous,root,max_copy_bytes=0)
            assets_reused=True
        elif (previous/'requests').exists():shutil.copytree(previous/'requests',root/'requests')
        with Ledger(previous/'ledger.sqlite',readonly=True) as prior:
            target=sqlite3.connect(root/'ledger.sqlite');prior.db.backup(target);target.close()
        for q in queries:
            if q['state']=='admitted_for_next_request' and not (typed_admissions and q.get('query_receipt_id')):
                record=view.get_records([q['record_ref']],limit=1).records[0].model_dump(mode='json')
                if fingerprint(record)!=q['record_sha256']:raise ValueError('Continuation supplement differs')
                catalog.supplement(record,q['query_id'],q['source_bu_refs'])
        if typed_admissions:
            from androserum.facts.query_evidence import adapt_query_evidence
            receipts={q['receipt_id']:q for q in old['current_fact_queries']['queries']}
            for event in typed_admissions:
                from androserum.facts.query_reuse import records_for
                actual=adapt_query_evidence(catalog,view,records_for(receipts[event['receipt_id']],old['current_fact_queries']),event['source_bu_refs'],query_id=event['query_id'])
                # Raw facts above are already reconstructed. Typed membership
                # and mapping decisions must still match the original receipt.
                if actual['decisions']!=event['admission']['decisions'] or actual['required_record_refs']!=event['admission']['required_record_refs']:
                    raise ValueError('Continuation typed query evidence mapping differs')
        parent={'manifest_sha256':sha256_file(previous/'manifest.json'),'prior_revision':old['accepted_state']['revision'],
            'prior_attempts':len(old['attempts']),'segment_ref':info['segment_ref'],
            'ledger_sha256':sha256_file(previous/'ledger.sqlite'),'prior_attempt_hashes':[fingerprint(a) for a in old['attempts']]}
        shutil.copyfile(previous/'manifest.json',root/'parent-manifest.json')
        shutil.copyfile(previous/'report.json',root/'parent-report.json')
    segment_start=calls
    current_queries = getattr(config, 'fact_query_protocol', None) == 'current_facts.v1'
    query_service = None
    if current_queries:
        from androserum.facts.queries import FactQuerySession, FactQueryBudget
        if resume_from and (previous/'fact-query-audit.sqlite').exists():
            shutil.copyfile(previous/'fact-query-audit.sqlite', root/'fact-query-audit.sqlite')
        query_budget=FactQueryBudget(max_queries=config.max_supplement_rounds*config.max_queries_per_proposal,
            max_records=config.max_supplement_records,max_return_chars=config.max_query_return_chars)
        if query_delivery_policy:
            from androserum.facts.query_reuse import ReusableFactQuerySession,POLICY
            if query_delivery_policy!=POLICY:raise ValueError('Unknown query delivery policy')
            query_service=ReusableFactQuerySession(root/'fact-query-audit.sqlite',view,query_budget,
                amendment_reason=budget_amendment_reason)
        else:query_service=FactQuerySession(root/'fact-query-audit.sqlite',view,query_budget)
    info={'identity':identity,'segment_ref':'segment:'+uuid4().hex,'parent':parent,'config':config.model_dump(mode='json'),
        'budget_amendment':amendment if resume_from else None,'policy_recheck_reason':budget_amendment_reason if recheck_rejected else None,
        'work_amendments':amendments,'new_work_amendment':work_amendment,
        'provider':provider.description,'plan':initial_plan,'plan_sha256':fingerprint(initial_plan),'segment_call_limit':call_limit,
        'source_visible_sha256':{b:fingerprint(u['model_visible']) for b,u in catalog.units.items()}}
    if provider_change:info['provider_continuation']=provider_change
    if current_queries:
        external={'queries.py':Path(__file__).parents[1]/'facts/queries.py',
            'query_evidence.py':Path(__file__).parents[1]/'facts/query_evidence.py',
            'bu.py':Path(__file__).parents[1]/'facts/bu.py'}
        info['query_evidence_protocol']='typed_context.v1'
        if query_delivery_policy:
            info['query_delivery_policy']=query_delivery_policy
            info['query_evidence_protocol']='typed_context.v2'
            external['query_reuse.py']=Path(__file__).parents[1]/'facts/query_reuse.py'
        info['query_rule_sha256']={name:sha256_file(path) for name,path in external.items()}
        (root/'query-rules').mkdir(exist_ok=True)
        for name,path in external.items():shutil.copyfile(path,root/'query-rules'/name)
    if packed:
        from androserum import mining_packing,mining_storage
        auxiliary={'mining_packing.py':Path(mining_packing.__file__),'mining_storage.py':Path(mining_storage.__file__)}
        if catalog.identity.get('packing_profile')=='lossless-scoped-compact.v3':
            from androserum import mining_catalog,mining_packing_v3
            auxiliary.update({'mining_catalog.py':Path(mining_catalog.__file__),
                              'mining_packing_v3.py':Path(mining_packing_v3.__file__)})
        info['packing_auxiliary_sha256']={name:sha256_file(file) for name,file in auxiliary.items()}
        (root/'packing-rules').mkdir(exist_ok=True)
        for name,file in auxiliary.items():shutil.copyfile(file,root/'packing-rules'/name)
    publish(root/'run.json',info)
    for p in Path(__file__).parent.iterdir():
        if p.suffix in {'.py','.txt'}:
            (root/'rules').mkdir(exist_ok=True);shutil.copyfile(p,root/'rules'/p.name)
    if not assets_reused:
        publish(root/'source-visible.json',{'identity':catalog.identity,'units':{b:{'model_visible':u['model_visible'],
            'extraction_status':u['extraction_status']} for b,u in catalog.units.items()}})
    stop_reason=None
    with Ledger(root/'ledger.sqlite',identity) as ledger:
        for p in pending:ledger.system_issue('chunk_budget',p)
        for row in rows:
            if row['state'] in TERMINAL:continue
            while row['state'] not in TERMINAL:
                if calls>=config.max_model_calls:stop_reason='global_model_call_budget';break
                if call_limit is not None and calls-segment_start>=call_limit:stop_reason='segment_call_limit';break
                before=ledger.state();request_id='request:'+uuid4().hex
                directory=root/'requests'/f'{calls:03d}'
                directory.mkdir(parents=True,exist_ok=False)
                try:
                    packet=make_packet(catalog,row['chunk'],before,config,request_id,
                        extra_handles=row['extra_handles'],repair=row['repair'],
                        required_ledger_ids=row.get('work_amendment',{}).get('required_ledger_ids',()))
                except ValueError as error:
                    row.update(state='blocked',reason=str(error));ledger.system_issue('context_budget',{'chunk_id':row['chunk_id'],'reason':str(error)});break
                packet['work_context']={'chunk_id':row['chunk_id'],'chunk_bu_refs':row['chunk']['bu_ids'],
                    'total_chunks':len(rows),'meaningful_support_required_for_new_dependencies':True}
                if row.get('pending_query_results'):
                    packet['fact_query_results']=deepcopy(row['pending_query_results'])
                    from androserum.mining.evidence import size
                    if (catalog.bundle_size(packet) if hasattr(catalog,'bundle_size') else size(packet))>config.max_request_chars:
                        row.update(state='blocked',reason='Returned query status/evidence exceeds request budget')
                        ledger.system_issue('query_context_budget',{'chunk_id':row['chunk_id'],'actual_results_preserved':True})
                        directory.rmdir();break
                if row.get('work_amendment'):
                    packet['work_context']['review_task']=row['work_amendment']
                if hasattr(catalog,'bundle_size') and catalog.bundle_size(packet)>config.max_request_chars:
                    row.update(state='blocked',reason='Complete lossless packed request exceeds context budget')
                    ledger.system_issue('packed_context_budget',{'chunk_id':row['chunk_id'],'complete_bundle_preserved':True})
                    directory.rmdir();break
                if hasattr(provider, 'preflight'):
                    reason=provider.preflight(packet,config)
                    if reason:
                        stop_reason=reason
                        stops=root/'budget-stops';stops.mkdir(exist_ok=True)
                        publish(stops/(request_id.replace(':','_')+'.json'),{'reason':reason,'request':packet,
                            'budget_consumed':False,'work_remains_pending':True})
                        directory.rmdir()
                        break
                publish(directory/'request.json',packet)
                request={'request_id':request_id,'directory':directory.relative_to(root).as_posix(),
                    'request_sha256':fingerprint(packet),'base_revision':before['revision'],'chunk_id':row['chunk_id']}
                requests.append(request);row['request_ids'].append(request_id)
                row['shown_handles']=sorted(set(row['shown_handles'])|set(packet['evidence']))
                calls+=1;attempt_id='attempt:'+uuid4().hex;raw=''
                if row.get('work_amendment'):row['amendment_attempts_used']+=1
                try:
                    raw,meta=provider.generate(packet,directory,config)
                    if packed:
                        from androserum.mining_storage import write_new_text
                        write_new_text(directory/'proposal.json',raw,segment_root=root)
                    else:(directory/'proposal.json').write_text(raw,encoding='utf-8')
                    checked,candidate=check_proposal(raw,packet,before,config)
                except (ValueError,OSError) as error:
                    checked={'valid':False,'errors':[{'code':'provider','message':str(error),'subject':None}]};candidate=None
                    meta={'real_model':bool(provider.is_real),'failure':str(error)}
                publish(directory/'provider.json',meta);publish(directory/'check.json',checked)
                attempt={'attempt_id':attempt_id,'request_id':request_id,'chunk_id':row['chunk_id'],
                    'status':'accepted' if checked['valid'] else 'rejected','base_revision':before['revision'],
                    'after_revision':before['revision']+1 if checked['valid'] else before['revision'],
                    'request_sha256':fingerprint(packet),'response_sha256':hashlib.sha256(raw.encode('utf-8')).hexdigest(),
                    'check':checked,'provider':meta,'files':{'request':str((directory/'request.json').relative_to(root)),
                    'proposal':str((directory/'proposal.json').relative_to(root)) if raw else None}}
                if checked['valid']:
                    ledger.commit(before['revision'],candidate,attempt=attempt)
                    additions.extend(support_additions(before,candidate,packet))
                    row['accepted_handles']=sorted(set(row['accepted_handles'])|set(packet['evidence']))
                    row['cited_handles']=sorted(set(row['cited_handles'])|proposal_handles(json.loads(raw)))
                    if query_service:
                        cited = proposal_handles(json.loads(raw))
                        query_report=query_service.report()
                        from androserum.facts.query_reuse import records_for
                        for receipt in query_report['queries']:
                            used = [r['id'] for r in records_for(receipt,query_report) if any(
                                h in cited and e.get('record_ref') == r['id']
                                for h,e in packet['evidence'].items())]
                            if used:query_service.record_use(receipt['receipt_id'],request_id,used)
                else:ledger.audit(attempt)
                row['attempt_ids'].append(attempt_id)
                if not checked['valid']:
                    repair_allowed=not (row.get('work_amendment',{}).get('max_program_repairs')==1 and row.get('repair'))
                    if row.get('work_amendment') and repair_allowed and row['amendment_attempts_used']<row['work_amendment']['max_attempts']:
                        row.update(state='pending_repair',repair={'errors':checked['errors'],'previous_proposal':raw[:config.max_response_chars]});continue
                    if not row.get('work_amendment') and row['repairs_used']<config.max_repairs_per_chunk:
                        row.update(state='pending_repair',repair={'errors':checked['errors'],'previous_proposal':raw[:config.max_response_chars]})
                        row['repairs_used']+=1;continue
                    row.update(state='rejected',reason=checked['errors'])
                    ledger.system_issue('proposal_not_accepted',{'chunk_id':row['chunk_id'],'errors':checked['errors']});break
                row.update(state='accepted',repair=None,reason=None)
                proposal=json.loads(raw)
                if not proposal['fact_queries']:break
                if supplement_rounds>=config.max_supplement_rounds:
                    ledger.system_issue('supplement_round_budget',proposal['fact_queries']);break
                supplement_rounds+=1;frontier=reference_frontier(packet);extra=[]
                query_batch = proposal['fact_queries']
                if query_service:
                    query_batch = []
                    row['pending_query_results']=[]
                    for selector in proposal['fact_queries']:
                        try:receipt = query_service.execute(selector)
                        except (ValueError,OSError) as error:
                            ledger.system_issue('current_fact_query_rejected',{'query':selector,'reason':str(error)})
                            row['pending_query_results'].append({'query_id':selector['query_id'],'state':'rejected',
                                'reason':str(error),'returned_record_refs':[],'no_match_does_not_prove_absence':True})
                            continue
                        row['pending_query_results'].append({k:deepcopy(v) for k,v in receipt.items()
                            if k not in {'records','source','query'}} | {'query_id':selector['query_id'],
                                'returned_record_refs':[r['id'] for r in receipt['records']],
                                'record_role':'Actually returned fact support only; no inferred new path or execution'})
                        from androserum.facts.query_reuse import records_for
                        returned_records=records_for(receipt,query_service.report())
                        query_batch.append({'query_id':selector['query_id'], 'reason':selector['reason'],
                            'record_refs':[r['id'] for r in returned_records],
                            'reused_record_refs':[r['record_ref'] for r in receipt.get('reused_records',[])],
                            'receipt_id':receipt['receipt_id']})
                        from androserum.facts.query_evidence import adapt_query_evidence
                        admission=adapt_query_evidence(catalog,view,returned_records,packet['manifest']['source_bu_refs'],
                            query_id=receipt['query']['query_id'])
                        extra.extend(admission['added_handles'])
                        from androserum.mining.evidence import handle
                        extra.extend(handle('fact',ref) for decision in admission['decisions']
                            if decision['state']=='admitted_typed' for ref in decision.get('support_record_refs',[]))
                        event={'request_id':request_id,'query_id':receipt['query']['query_id'],
                            'receipt_id':receipt['receipt_id'],'source_bu_refs':packet['manifest']['source_bu_refs'],'admission':admission}
                        typed_admissions.append(event)
                        row['pending_query_results'].append({'query_id':event['query_id'],'typed_admission':admission})
                        if receipt['state'] not in {'completed', 'ran_no_matching_fact'} or receipt['truncated']:
                            ledger.system_issue('current_fact_query_result',receipt)
                for query in query_batch:
                    for ref in query['record_refs']:
                        item={'query_id':query['query_id'],'record_ref':ref,'request_id':request_id,
                            'source_bu_refs':packet['manifest']['source_bu_refs'],'reason':query['reason']}
                        if query.get('receipt_id'):item['query_receipt_id']=query['receipt_id']
                        if not current_queries and ref not in frontier:item.update(state='unsupported',reason='Record not explicitly referenced by shown evidence')
                        elif supplement_records>=config.max_supplement_records and ref not in query.get('reused_record_refs',[]):item.update(state='budget_exhausted')
                        else:
                            if ref not in query.get('reused_record_refs',[]):supplement_records+=1
                            else:item['reused_without_new_record_charge']=True
                            try:
                                found=view.get_records([ref],limit=1)
                                if found.missing_refs:item.update(state='unknown')
                                else:
                                    record=found.records[0].model_dump(mode='json')
                                    if query_delivery_policy:record=json.loads(canonical_json(record))
                                    old_entry=next((e for e in packet['evidence'].values() if e.get('record_ref')==ref and e['category']=='fact'),None)
                                    added=[k for k in record if not old_entry or k not in old_entry['shown_fields']]
                                    h=catalog.supplement(record,query['query_id'],packet['manifest']['source_bu_refs'])
                                    if added:extra.append(h)
                                    item.update(state='admitted_for_next_request' if added else 'no_new_information',
                                        evidence_handle=h,record_sha256=fingerprint(record),added_fields=added)
                            except (ValueError,OSError) as error:item.update(state='failed',reason=str(error))
                        queries.append(item)
                        if item['state']!='admitted_for_next_request':ledger.system_issue('supplement_unresolved',item)
                if not extra and not (current_queries and row.get('pending_query_results')):break
                if row.get('work_amendment') and row['amendment_attempts_used']>=row['work_amendment']['max_attempts']:
                    ledger.system_issue('work_amendment_budget',{'chunk_id':row['chunk_id'],'admitted_but_not_presented':extra});break
                row.update(state='pending_supplement',extra_handles=sorted(set(row['extra_handles'])|set(extra)))
            if stop_reason:break
        if stop_reason=='global_model_call_budget':
            ledger.system_issue('model_call_budget',{'remaining_chunks':[r['chunk'] for r in rows if r['state'] not in TERMINAL]})
        report=ledger.report();validation=ledger.verify()
        version_hashes=[list(r) for r in ledger.db.execute('SELECT revision,sha256 FROM versions ORDER BY revision')]
    progress=coverage(catalog,rows,pending)
    report.update(schema_version='behavior-mining-report.v2',identity=identity,provider=provider.description,
        segment_ref=info['segment_ref'],parent=parent,chunk_progress=rows,coverage=progress,support_additions=additions,
        budgets={'model_calls':calls,'segment_model_calls':calls-segment_start,'chunks_planned':len(rows),
            'chunks_pending':len(pending)+sum(r['state'] not in TERMINAL for r in rows),'supplement_rounds':supplement_rounds,
            'supplement_records':supplement_records,'config':config.model_dump(mode='json')},
        stop_reason=stop_reason,ledger_verification=validation,requests=requests,queries=queries,
        real_model_attempts=sum(bool(x['provider'].get('real_model')) for x in report['attempts']),
        real_model_accepted=sum(x['status']=='accepted' and bool(x['provider'].get('real_model')) for x in report['attempts']),
        semantic_validation_scope='Program checks and coverage of shown evidence; human semantic review is separate')
    report['version_sha256']=version_hashes
    if query_service:
        report['current_fact_queries']=query_service.report()
        report['query_typed_admissions']=typed_admissions
        query_service.close()
    publish(root/'report.json',report)
    files={p.relative_to(root).as_posix():{'sha256':sha256_file(p),'bytes':p.stat().st_size} for p in root.rglob('*') if p.is_file()}
    publish(root/'manifest.json',{'schema_version':'behavior-mining-manifest.v1','identity':identity,'files':files})
    return root,report
