"""One frozen bounded real matching + independent APK task-ledger experiment."""
import argparse
import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

from androserum.inference.provider import RealProvider, CallBudget, write
from androserum.inference.matching import MATCH_PROMPT, run_pair
from androserum.mining.providers import settings
from androserum.facts.identity import fingerprint,sha256_file
from androserum.tasking import TaskLedger,TaskConfig,proposal_schema,TASK_PROMPT
from androserum.matching.models import MatchProposal


def read(p):return json.loads(Path(p).read_text('utf-8'))


def verify_inputs(root,config):
    """Validate content identities on every resume, separate from model evaluation."""
    material=root/'match-materials-final';manifest=read(material/'manifest.json')
    for row in manifest['cases']:
        path=material/row['request_file']
        if sha256_file(path)!=row['request_sha256']:raise ValueError('Frozen match request was changed')
        request=read(path)
        if fingerprint(request['sides'])!=row['pair_sha256'] or request['pair_sha256']!=row['pair_sha256']:
            raise ValueError('Frozen pair side digest differs')
    files=[root/'experiment-config.json',material/'manifest.json',material/'oracle.json',
           root/'task-fixture-final/compact/source-catalog.json',*sorted((root/'rules').rglob('*'))]
    files=[p for p in files if p.is_file()]
    inventory={'files':{str(p.relative_to(root)).replace('\\','/'):sha256_file(p) for p in files},
               'schemas':{'matching':fingerprint(MatchProposal.model_json_schema()),'task':fingerprint(proposal_schema())}}
    path=root/'material-integrity.json'
    if path.exists() and read(path)!=inventory:raise ValueError('Frozen inputs/rule copies/schema integrity changed')
    if not path.exists():write(path,inventory)
    if config['budgets']!={'matching':16,'task':8} or config['total_real_calls_max']!=24:
        raise ValueError('Undeclared real call budget')
    return inventory


TASK_WORK = {
 'first': 'Review the first current BC and add its evidence-supported finding. Preserve its partial/unknown limits. Open a narrowly scoped question about current configuration relevant to interpreting these API operations, and use at most one advertised fact query to investigate it. Do not assume what the unseen record contains. No synthesis yet.',
 'second': 'Review the newly added second BC and preserve/update the first finding using actual visible evidence. Inspect the retrieved supplementary fact if present, cite it in the relevant finding and explain its limited relevance; resolve only the part of the configuration issue it really answers. Keep runtime success and missing event/path evidence unresolved. Do not claim a connection between independent BCs merely because both belong to this APK. No synthesis yet.',
 'final': 'Produce the final evidence-supported report across the two current BCs and all accepted findings. Integrate the actual supplementary evidence, legal reference scopes and every open issue. Two independent mechanisms may be reported together without any cross_bc_links. Do not claim malware or benignness. Do not make new fact queries at final synthesis.'
}


def freeze(root):
    p=root/'experiment-config.json'
    if p.exists():
        config=read(p)
        if config['match_prompt_sha256']!=fingerprint(MATCH_PROMPT) or config['task_prompt_sha256']!=fingerprint(TASK_PROMPT):
            raise ValueError('Frozen prompts changed; create a separately declared experiment')
        if config['task_work']!=TASK_WORK:raise ValueError('Frozen task work changed')
        return config
    options=settings()
    config={'schema_version':'live-match-task-experiment.v1','model_options':options,
        'budgets':{'matching':16,'task':8},'max_pair_attempts':2,'task_attempts':[3,3,2],
        'timeout_seconds':300,'max_request_chars':1000000,'max_response_chars':120000,
        'schema_mode':'structured','schema_fallback':'none; failed transport counts and retained',
        'match_prompt_sha256':fingerprint(MATCH_PROMPT),'task_prompt_sha256':fingerprint(TASK_PROMPT),
        'task_work':TASK_WORK,'task':'evidence_supported_behavior_report',
        'no_encoder_changes':True,'no_history_pool_expansion':True,'total_real_calls_max':24,
        'monetary_or_token_hard_cap':False,'concurrency_matching':2,
        'knowledge_snapshot_id':'d4783632928cc01e91d37026c19ea092e88e91ab4089909aa32b149cf5ed7a49'}
    write(p,config);(root/'frozen-match-prompt.txt').write_text(MATCH_PROMPT,encoding='utf-8')
    (root/'frozen-task-prompt.txt').write_text(TASK_PROMPT,encoding='utf-8')
    for folder in ['inference','tasking','matching']:
        for source in (Path('src/androserum')/folder).glob('*'):
            if source.is_file():
                target=root/'rules'/folder/source.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes())
    return config


def match_all(root,config):
    manifest=read(root/'match-materials-final/manifest.json')
    cases=manifest['cases']
    def one(case,seed=None):
        request=read(root/'match-materials-final'/case['request_file'])
        b=CallBudget(root/'real-call-budget.sqlite',config['budgets'])
        try:return run_pair(request,root/'matching'/case['case_id'],RealProvider(config['model_options']),b,
                            pair_id=case['case_id'],max_attempts=2,seed=seed)
        finally:b.close()
    results=[]
    with ThreadPoolExecutor(max_workers=2) as pool:
        for case,result in zip(cases[:7],pool.map(one,cases[:7])):
            results.append({'case_id':case['case_id'],'report':result});print('MATCH',case['case_id'],result['status'],flush=True)
    seed=deepcopy(results[0]['report']['accepted'])
    request8=read(root/'match-materials-final'/cases[7]['request_file'])
    if seed is None:seed={'schema_version':'deliberately_invalid_program_seed'}
    else:
        seed['request_id']=request8['request_id'];seed['pair_sha256']=request8['pair_sha256']
        if seed['relation_mappings']:seed['relation_mappings'][0]['query']['context_refs']=['deliberately_injected_wrong_context']
        else:seed['request_id']='deliberately_wrong_request'
    result=one(cases[7],seed=seed)
    results.append({'case_id':cases[7]['case_id'],'report':result});print('MATCH',cases[7]['case_id'],result['status'],flush=True)
    write(root/'matching-results.json',{'cases':results,'synthetic_quality_is_not_apk_generalization':True})
    return results


def structural_index(packet):
    return {bid:{'action_operations':{aid:a['operation_refs'] for aid,a in side['actions'].items()},
             'links':[{'link_id':link['link_id'],'from_action':link['from_action'],'to_action':link['to_action'],
                       'support_path':link['support_path'],'condition_refs':link['condition_refs']} for link in side['bc']['relations']],
             'action_conditions':{aid:a['condition_refs'] for aid,a in side['actions'].items()}}
            for bid,side in packet['current_bcs'].items()}


def task_packet_integrity(ledger, packet):
    """A saved request must be the exact request authorized by this native ledger."""
    ledger.verify()
    row=ledger.db.execute('SELECT sha256 FROM packets WHERE request_id=?',(packet.get('request_id'),)).fetchone()
    if not row or row[0]!=fingerprint(packet):
        raise ValueError('Saved task packet differs from its native ledger registration')


def task_audit_checks(ledger, packet):
    task_packet_integrity(ledger,packet)
    rows=[]
    for sequence,payload,digest in ledger.db.execute('SELECT sequence,payload,sha256 FROM audit ORDER BY sequence'):
        event=json.loads(payload)
        if event.get('kind')!='proposal' or event.get('request_id')!=packet['request_id']:continue
        revision=ledger.db.execute('SELECT revision FROM revisions WHERE sha256=?',(event['after_sha256'],)).fetchone()
        if not revision:raise ValueError('Task audit does not identify an accepted native revision')
        rows.append({'sequence':sequence,'sha256':digest,'event':event,'revision':revision[0]})
    return rows


def restore_task_check(ledger, packet, index, check_path, call_dir, call_id, *, transport_error=None, recovered=True):
    """Recover committed attempts before touching a retained provider response again."""
    rows=task_audit_checks(ledger,packet)
    existing=read(check_path) if Path(check_path).exists() else None
    if index>=len(rows):
        if existing is not None:raise ValueError('Task check file has no corresponding committed native audit')
        return None
    native=rows[index];event=native['event'];checked=event['check']
    expected={'valid':checked['valid'],'errors':checked['errors'],'revision':native['revision'],'call_id':call_id}
    receipt_path=Path(call_dir)/'receipt.json'
    if receipt_path.exists():
        receipt=read(receipt_path)
        if receipt.get('call_id')!=call_id:raise ValueError('Task receipt belongs to another invocation')
        if receipt.get('status')=='completed':
            raw_path=Path(call_dir)/'raw-model-output.json'
            if not raw_path.exists() or raw_path.read_text('utf-8')!=event['raw']:
                raise ValueError('Retained real task output differs from the committed native audit')
        elif transport_error is None:transport_error=receipt.get('error','Retained unsuccessful real invocation')
    if existing is not None:
        if any(existing.get(key)!=value for key,value in expected.items()):
            raise ValueError('Task check file contradicts its committed native audit/revision')
        if 'audit_sequence' in existing and existing['audit_sequence']!=native['sequence']:
            raise ValueError('Task check audit sequence mismatch')
        if 'audit_sha256' in existing and existing['audit_sha256']!=native['sha256']:
            raise ValueError('Task check audit digest mismatch')
        return existing
    restored={**expected,'transport_error':transport_error,'audit_sequence':native['sequence'],
              'audit_sha256':native['sha256'],'recovered_from_native_audit':recovered}
    write(check_path,restored)
    return restored


def task_stage_revision(ledger, packet):
    rows=task_audit_checks(ledger,packet)
    if not rows:raise ValueError('Task stage has no committed attempts')
    final_sequence=rows[-1]['sequence'];final_revision=rows[-1]['revision']
    # A first-stage retrieval may commit immediately after its last proposal.
    for sequence,payload in ledger.db.execute('SELECT sequence,payload FROM audit WHERE sequence>? ORDER BY sequence',(final_sequence,)):
        event=json.loads(payload)
        if event.get('kind')!='retrieval':break
        revision=ledger.db.execute('SELECT revision FROM revisions WHERE sha256=?',(event['after_sha256'],)).fetchone()
        if not revision:raise ValueError('Task retrieval audit revision is missing')
        final_revision=revision[0]
    return final_revision


def validate_task_stage_result(ledger, packet, stage, task_dir):
    """Completed stage sidecars must agree with committed proposals and retrievals."""
    name=stage['phase'];rows=task_audit_checks(ledger,packet)
    if not rows or len(stage['attempts'])!=len(rows):
        raise ValueError('Task stage attempt list differs from its native audit history')
    for index,entry in enumerate(stage['attempts']):
        checked=restore_task_check(ledger,packet,index,Path(task_dir)/(name+'-check-'+str(index)+'.json'),
                                   Path(task_dir)/(name+'-attempt-'+str(index)),'task:'+name+':'+str(index))
        if any(entry.get(k)!=checked.get(k) for k in ['valid','errors','revision','call_id']):
            raise ValueError('Task stage result contradicts its audited check file')
    final_revision=task_stage_revision(ledger,packet)
    if stage['revision']!=final_revision:
        raise ValueError('Task stage revision differs from its native proposal/retrieval boundary')
    return stage


def task_run(root,config,results):
    catalog=read(root/'task-fixture-final/compact/source-catalog.json')
    fixture=read(root/'task-fixture-final/supplement-candidate.json')
    sides=list(catalog['bcs'].values());first,second=[s['bc']['bc_id'] for s in sides]
    record=next(iter(catalog['supplemental'].values()))['record']
    identity={'apk_sha256':sides[0]['origin']['apk_sha256'],'source_run_ref':record['run_ref']}
    legal=[]
    manifest=read(root/'match-materials-final/manifest.json')
    for case,row in zip(manifest['cases'][:2],results[:2]):
        proposal=row['report']['accepted']
        if proposal and proposal['decision']=='\u652f\u6301\u5339\u914d':
            legal.append({'match_ref':'live:'+case['case_id'],'request':read(root/'match-materials-final'/case['request_file']),'proposal':proposal})
    ledger_path=root/'task/task-ledger.sqlite';ledger_path.parent.mkdir(exist_ok=True)
    ledger=TaskLedger(ledger_path,identity,config=TaskConfig(max_attempts=8,max_fact_queries=2),source_catalog=catalog)
    budget=CallBudget(root/'real-call-budget.sqlite',config['budgets']);provider=RealProvider(config['model_options'])
    outcomes=[]
    try:
        for phase_name,ids,nattempts in [('first',[first],3),('second',[second],3),('final',[first,second],2)]:
            done=root/'task'/(phase_name+'-result.json')
            if done.exists():
                packet_path=root/'task'/(phase_name+'-packet.json')
                if not packet_path.exists():raise ValueError('Completed task stage has no retained request packet')
                outcomes.append(validate_task_stage_result(ledger,read(packet_path),read(done),root/'task'));continue
            stage_matches=[m for m in legal if m['request']['sides']['query']['bc']['bc_id'] in set(ledger.state()['seen_bc_ids'])|set(ids)]
            packet_path=root/'task'/(phase_name+'-packet.json')
            if packet_path.exists():packet=read(packet_path)
            else:
                packet=ledger.prepare_packet(ids,legal_matches=stage_matches,phase='synthesis' if phase_name=='final' else 'incremental')
                write(packet_path,packet)
            feedback=None;tries=[]
            for i in range(nattempts):
                check_path=root/'task'/(phase_name+'-check-'+str(i)+'.json')
                call_dir=root/'task'/(phase_name+'-attempt-'+str(i))
                recovered=restore_task_check(ledger,packet,i,check_path,call_dir,'task:'+phase_name+':'+str(i))
                if recovered is not None:
                    row=recovered;tries.append(row)
                    if row['valid']:break
                    native=task_audit_checks(ledger,packet)[i]['event']
                    feedback={'previous_raw':native['raw'],'program_check_errors':row['errors']};continue
                envelope={'task_request':packet,'structural_index':structural_index(packet),'work_item':TASK_WORK[phase_name]}
                if feedback:envelope['repair_feedback']=feedback
                raw='';transport_error=None
                try:
                    if call_dir.exists():
                        receipt=read(call_dir/'receipt.json')
                        if receipt['status']!='completed':raise ValueError('Prior failed call retained on resume')
                        raw=(call_dir/'raw-model-output.json').read_text('utf-8')
                    else:
                        raw,_=provider.generate(envelope,proposal_schema(),TASK_PROMPT,call_dir,budget=budget,
                            phase='task',call_id='task:'+phase_name+':'+str(i))
                except Exception as error:transport_error=str(error)
                result=ledger.finalize(raw,packet) if phase_name=='final' else ledger.update(raw,packet)
                row=restore_task_check(ledger,packet,i,check_path,call_dir,'task:'+phase_name+':'+str(i),
                                       transport_error=transport_error,recovered=False)
                if row is None:raise ValueError('Committed task update has no native audit')
                tries.append(row);print('TASK',phase_name,i,result['valid'],result['errors'],flush=True)
                if result['valid']:break
                feedback={'previous_raw':raw,'program_check_errors':result['errors']}
            if phase_name=='first':
                retrievals={qid:q['requested_refs'] for qid,q in ledger.state()['queries'].items() if q['status']=='pending'}
                if retrievals:
                    ledger.fulfill_queries(retrievals)
                    write(root/'task/actual-retrieval.json',{'results':retrievals,
                        'records':{h:catalog['supplemental'][h] for hs in retrievals.values() for h in hs},
                        'source':'actual FactView replay verified against frozen current-run record',
                        'fixture_supplement_audit':fixture})
            row={'phase':phase_name,'attempts':tries,'revision':task_stage_revision(ledger,packet)}
            validate_task_stage_result(ledger,packet,row,root/'task')
            write(done,row);outcomes.append(row)
        write(root/'task/task-report.json',ledger.report());write(root/'task/task-verification.json',ledger.verify())
        write(root/'task/task-stage-results.json',outcomes)
    finally:ledger.close();budget.close()
    return outcomes


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);parser.add_argument('--phase',choices=['freeze','matching','task','all'],default='all');args=parser.parse_args()
    root=Path(args.root).resolve();config=freeze(root)
    verify_inputs(root,config)
    if args.phase=='freeze':print('Frozen configuration',root/'experiment-config.json');return
    if args.phase in {'matching','all'}:results=match_all(root,config)
    else:results=read(root/'matching-results.json')['cases']
    if args.phase in {'task','all'}:task_run(root,config,results)
    budget=CallBudget(root/'real-call-budget.sqlite',config['budgets']);write(root/'real-call-report.json',budget.report());budget.close()


if __name__=='__main__':main()
