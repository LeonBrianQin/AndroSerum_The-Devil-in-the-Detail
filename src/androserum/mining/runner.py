"""Budgeted proposal/check/transaction loop with explicitly admitted supplements."""
from pathlib import Path
from uuid import uuid4
import json
import hashlib
import shutil

from androserum.facts.identity import canonical_json,fingerprint,filesystem_path,sha256_file
from androserum.facts.bu import verify_units
from androserum.mining.assembly import make_packet
from androserum.mining.checker import check_proposal
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.ledger import Ledger
from androserum.mining.models import MiningConfig


def load_catalog(package, view, bu_ids, *, packing_profile=None):
    package=filesystem_path(package)
    verify_units(package,view)
    collection=json.loads((package/'collection.json').read_text('utf-8'))
    from androserum.mining_catalog import catalog_for
    catalog=catalog_for(collection,bu_ids,packing_profile=packing_profile)
    configuration=view.export_bundle().run.configuration.options.get('selected_flow',{})
    if configuration.get('schema_version') in {'selected-method-flow-config.v2','selected-summary-flow-config.v3'}:
        scope={'schema_version':'selected-method-flow-scope-metadata.v1',
            'role':'analysis_capability_metadata_not_behavior_evidence',
            'applies_to':'selected FlowDroid provider only; direct and other static facts retain their own scopes',
            'provider_configuration_version':configuration['schema_version'],
            'entry_scope':configuration['entry_scope'],'entry_methods':list(configuration['entry_methods']),
            'sources':list(configuration['sources']),'sinks':list(configuration['sinks']),
            'android_reachability_established':False,'runtime_execution_established':False,
            'mechanical_sources_are_automatically_privacy_sources':False,
            'source_interpretation':'Configured mechanical taint origins; these settings do not classify privacy sensitivity or behavior purpose.',
            'citation_policy':'Configuration scope only; no evidence handles or citation grants are added.'}
        for status in catalog.statuses.values():status['analysis_scope_limits']=[scope]
        if configuration.get('schema_version')=='selected-summary-flow-config.v3':
            scope.update(taint_wrapper=configuration['taint_wrapper'],summary_resource_id=configuration['summary_resource_id'],
                native_summary_ap_role='Abstract receiver/parameter/return/state effects; not concrete byte ranges or a complete call frame',
                fine_grained_path_established_by_summary=False)
    return catalog


def reference_frontier(packet):
    refs=set()
    keys={'support_refs','source_refs','element_ref','method_ref','class_ref','dex_ref','branch_ref','context_ref','binding_refs','condition_refs','reference_ref','resource_ref'}
    def scan(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key in keys:
                    for ref in item if isinstance(item,list) else [item]:
                        if isinstance(ref,str) and ':' in ref:refs.add(ref)
                if key not in {'text','value','description'}:scan(item)
        elif isinstance(value,list):
            for item in value:scan(item)
    for e in packet['evidence'].values():
        if e['category']=='fact':
            scan(e['record'])
            if e.get('detail_fields_available'):refs.add(e['record_ref'])
    return refs


def run_mining_v1(catalog,view,output,provider,config=None):
    config=MiningConfig.model_validate((config or MiningConfig()).model_dump())
    if len(catalog.units)>config.max_bu:raise ValueError('Selected BU count exceeds mining budget')
    root=filesystem_path(output)/('mining_'+uuid4().hex);root.mkdir(parents=True,exist_ok=False)
    identity={'mining_run_ref':'mining-run:'+root.name.removeprefix('mining_'),'source':catalog.identity,
        'selected_bu_ids':list(catalog.units),'mining_version':'behavior-mining.v1'}
    chunks,pending=catalog.chunks(config)
    source={'identity':identity,'config':config.model_dump(mode='json'),'provider':provider.description,
        'source_visible_sha256':{b:fingerprint(u['model_visible']) for b,u in catalog.units.items()}}
    def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    save(root/'run.json',source)
    for path in Path(__file__).parent.iterdir():
        if path.suffix in {'.py','.txt'}:
            dest=root/'rules'/path.name;dest.parent.mkdir(exist_ok=True);shutil.copyfile(path,dest)
    # Audit source contains only selected model_visible plus the scope status.
    save(root/'source-visible.json',{'identity':catalog.identity,'units':{b:{'model_visible':u['model_visible'],
        'extraction_status':u['extraction_status']} for b,u in catalog.units.items()}})
    calls=0;supplement_rounds=0;supplement_records=0;requests=[];query_log=[]
    with Ledger(root/'ledger.sqlite',identity) as ledger:
        for p in pending:ledger.system_issue('chunk_budget',p)
        for chunk_index,chunk in enumerate(chunks):
            extra=[];repair=None;repairs=0
            while True:
                if calls>=config.max_model_calls:
                    ledger.system_issue('model_call_budget',{'chunk_index':chunk_index,'remaining_chunks':len(chunks)-chunk_index});break
                state=ledger.state();request_id='request:'+uuid4().hex
                directory=root/'requests'/f'{calls:03d}';directory.mkdir(parents=True,exist_ok=False)
                try:
                    packet=make_packet(catalog,chunk,state,config,request_id,extra_handles=extra,repair=repair)
                except ValueError as error:
                    ledger.system_issue('context_budget',{'chunk_index':chunk_index,'reason':str(error)});break
                save(directory/'request.json',packet);requests.append({'request_id':request_id,'directory':directory.relative_to(root).as_posix(),
                    'request_sha256':fingerprint(packet),'base_revision':state['revision']})
                attempt_id='attempt:'+uuid4().hex;calls+=1
                try:
                    raw,model_meta=provider.generate(packet,directory,config)
                    (directory/'proposal.json').write_text(raw,encoding='utf-8')
                    save(directory/'provider.json',model_meta)
                    checked,candidate=check_proposal(raw,packet,state,config)
                except (ValueError,OSError) as error:
                    checked={'valid':False,'errors':[{'code':'provider','message':str(error),'subject':None}]};candidate=None;raw=''
                    model_meta={'real_model':bool(provider.is_real),'failure':str(error)}
                    save(directory/'provider.json',model_meta)
                save(directory/'check.json',checked)
                accepted=False
                attempt={'attempt_id':attempt_id,'request_id':request_id,'status':'accepted' if checked['valid'] else 'rejected',
                    'base_revision':state['revision'],'after_revision':state['revision']+1 if checked['valid'] else state['revision'],
                    'request_sha256':fingerprint(packet),'response_sha256':hashlib.sha256(raw.encode('utf-8')).hexdigest(),
                    'check':checked,'provider':model_meta,
                    'files':{'request':str((directory/'request.json').relative_to(root)),'proposal':str((directory/'proposal.json').relative_to(root)) if raw else None}}
                if checked['valid']:
                    try:ledger.commit(state['revision'],candidate,attempt=attempt);accepted=True
                    except (ValueError,OSError) as error:
                        checked={'valid':False,'errors':[{'code':'commit','message':str(error),'subject':None}]}
                        save(directory/'check.json',checked)
                if not accepted:
                    attempt.update(status='rejected',after_revision=ledger.state()['revision'],check=checked)
                    ledger.audit(attempt)
                if not accepted:
                    if repairs<config.max_repairs_per_chunk:
                        repairs+=1;repair={'errors':checked['errors'],'previous_proposal':raw[:config.max_response_chars]};continue
                    ledger.system_issue('proposal_not_accepted',{'request_id':request_id,'errors':checked['errors'],'chunk_index':chunk_index});break
                proposal=json.loads(raw)
                if not proposal['fact_queries']:break
                if supplement_rounds>=config.max_supplement_rounds:
                    ledger.system_issue('supplement_round_budget',proposal['fact_queries']);break
                supplement_rounds+=1;frontier=reference_frontier(packet);extra_added=[]
                for query in proposal['fact_queries']:
                    for ref in query['record_refs']:
                        item={'query_id':query['query_id'],'record_ref':ref,'request_id':request_id,
                              'source_bu_refs':packet['manifest']['source_bu_refs']}
                        if ref not in frontier:item.update(state='unsupported',reason='Record was not explicitly referenced by currently shown evidence')
                        elif supplement_records>=config.max_supplement_records:item.update(state='budget_exhausted',reason='Record lookup budget exhausted')
                        else:
                            supplement_records+=1
                            try:
                                found=view.get_records([ref],limit=1)
                                if found.missing_refs:item.update(state='unknown',reason='Referenced record absent in current APK facts')
                                else:
                                    record=found.records[0].model_dump(mode='json')
                                    h=catalog.supplement(record,query['query_id'],packet['manifest']['source_bu_refs'])
                                    extra_added.append(h);item.update(state='admitted_for_next_request',evidence_handle=h,record_sha256=fingerprint(record))
                            except (ValueError,OSError) as error:item.update(state='failed',reason=str(error))
                        query_log.append(item)
                        if item['state']!='admitted_for_next_request':ledger.system_issue('supplement_unresolved',item)
                save(root/'supplement-queries.json',query_log)
                if not extra_added:break
                extra.extend(extra_added);repair=None
            if calls>=config.max_model_calls:
                if chunk_index+1<len(chunks):
                    ledger.system_issue('model_call_budget',{'remaining_chunks':chunks[chunk_index+1:],
                        'reason':'Chunks were not presented because the global model-call budget was exhausted'})
                break
        validation=ledger.verify();report=ledger.report()
    report.update(schema_version='behavior-mining-report.v1',identity=identity,provider=provider.description,
        budgets={'model_calls':calls,'chunks_planned':len(chunks),'chunks_pending':len(pending),'supplement_rounds':supplement_rounds,
                 'supplement_records':supplement_records,'config':config.model_dump(mode='json')},
        ledger_verification=validation,requests=requests,queries=query_log,
        real_model_attempts=sum(bool(x['provider'].get('real_model')) for x in report['attempts']),
        real_model_accepted=sum(x['status']=='accepted' and bool(x['provider'].get('real_model')) for x in report['attempts']),
        semantic_validation_scope='Structured evidence checks; natural-language meaning and full behavior coverage are not guaranteed')
    save(root/'report.json',report)
    files={p.relative_to(root).as_posix():{'sha256':sha256_file(p),'bytes':p.stat().st_size} for p in root.rglob('*') if p.is_file()}
    save(root/'manifest.json',{'schema_version':'behavior-mining-manifest.v1','identity':identity,'files':files})
    return root,report


def run_mining(catalog,view,output,provider,config=None,*,resume_from=None,call_limit=None,budget_amendment_reason=None,recheck_rejected=False,work_amendment=None,query_delivery_policy=None,provider_rebind_reason=None):
    from androserum.mining.session import run_session
    return run_session(catalog,view,output,provider,config,resume_from=resume_from,call_limit=call_limit,
        budget_amendment_reason=budget_amendment_reason,recheck_rejected=recheck_rejected,work_amendment=work_amendment,
        query_delivery_policy=query_delivery_policy,provider_rebind_reason=provider_rebind_reason)
