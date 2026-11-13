"""Task protocols and actual fact-query transactions, never task-effect scores."""
from copy import deepcopy
from pathlib import Path

import pytest

from androserum.facts.identity import canonical_json, fingerprint, sha256_file
from androserum.facts.io import load_facts
from androserum.facts.queries import FactQueryBudget, FactQuerySession
from androserum.facts.store import FactView, create_snapshot
from androserum.matching.fixtures import toy_side
from androserum.pipeline.tasks import (
    DefinedTaskConfig, DefinitionTaskLedger, TaskDefinition,
    default_threat_intelligence_definition, run_task, task_prompt, task_proposal_schema,
)
from androserum.tasking.models import TaskConfig


IDENTITY={'apk_sha256':'a'*64,'source_run_ref':'run:current'}


def config(**kwargs):
    return DefinedTaskConfig(ledger=TaskConfig(allow_synthetic_protocol=True,max_attempts=20),**kwargs)


def definition(kind='threat_intelligence',mode='single'):
    value={'task_id':'protocol-'+kind,'version':'1','kind':kind,'requirements':'Explicit synthetic protocol controls only; not evaluation truth.',
           'evaluation_role':'protocol_only'}
    if kind=='malware_detection':
        value['detection_rules']=[{'rule_id':'synthetic_positive','decision':'malware',
            'requirements':'Synthetic positive-control rule: cite the explicitly shown possible transfer; not a real malware standard.'}]
    if kind=='malware_classification':
        value['taxonomy']={'taxonomy_id':'synthetic-only','version':'1','mode':mode,
            'labels':[{'label_id':'synthetic_a','description':'Protocol class A, no real family truth.'},
                      {'label_id':'synthetic_b','description':'Protocol class B, no real family truth.'}]}
    return TaskDefinition.model_validate(value)


def catalog(count=1):
    bcs={}
    for index in range(count):
        side=toy_side('defined_'+str(index));side['bc']['bc_id']='bc'+str(index);bcs['bc'+str(index)]=side
    return {'bcs':bcs,'supplemental':{}}


def proposal(packet, *, final=False):
    findings=[]
    for bid,side in packet['current_bcs'].items():
        findings.append({'finding_id':'f_'+bid,'description':'Possible independent static transfer in the visible scope.',
            'scopes':[{'bc_id':bid,'action_ids':list(side['actions']),'link_ids':[x['link_id'] for x in side['bc']['relations']]}],
            'evidence_refs':list(dict.fromkeys([o for a in side['actions'].values() for o in a['operation_refs']]+
                [r for link in side['bc']['relations'] for r in link['support_path']])),
            'condition_refs':list(dict.fromkeys([c for a in side['actions'].values() for c in a['condition_refs']]+
                [c for link in side['bc']['relations'] for c in link['condition_refs']])),
            'reference_uses':[],'limitations':['Partial static evidence; execution and purpose unknown.'],'execution_claim':'possible_only'})
    state=packet['ledger_context'];current={**state['findings'],**{f['finding_id']:f for f in findings}}
    result={'kind':packet['task_definition']['kind'],'status':'supported','summary':'Supported only within the explicit current scope.',
        'finding_ids':list(current),'current_evidence_refs':list(dict.fromkeys(h for f in current.values() for h in f['evidence_refs'])),
        'condition_refs':list(dict.fromkeys(h for f in current.values() for h in f['condition_refs'])),
        'unresolved_issue_ids':[k for k,v in state['issues'].items() if v['status']=='open'],
        'limitations':['Protocol-only interpretation; no semantic accuracy or runtime claim.'],
        'execution_claim':'possible_only','absence_proves_benign':False}
    if result['kind']=='malware_detection':result.update(decision='malware',rule_ids=['synthetic_positive'])
    elif result['kind']=='malware_classification':result.update(labels=[{'label_id':'synthetic_a',
        'finding_ids':list(current),'current_evidence_refs':result['current_evidence_refs'],
        'rationale':'Synthetic protocol label definition only.','limitations':['Not real classification truth.']}])
    else:result['possible_purposes']=[]
    synthesis={'summary':'Independent mechanisms are kept separate without a connecting path.',
        'finding_ids':list(current),'bc_ids':list(packet['current_bcs']),'cross_bc_links':[],
        'unresolved_issue_ids':result['unresolved_issue_ids'],'limitations':['Partial evidence; no runtime connection inferred.'],
        'execution_claim':'possible_only','absence_proves_benign':False} if final else None
    return {'schema_version':'apk-defined-task-proposal.v2','request_id':packet['request_id'],'base_revision':packet['base_revision'],
        'upsert_findings':findings,'delete_finding_ids':[],'issue_updates':[],'fact_queries':[],'current_fact_queries':[],
        'task_result':result if final else None,'synthesis':synthesis,'rationale':'Deterministic protocol response; not a real model output.'}


class Provider:
    is_real=False
    def __init__(self,mutate=None):self.calls=[];self.mutate=mutate
    def invoke(self,envelope,schema,instructions,directory,*,phase,call_id):
        self.calls.append(call_id)
        p=proposal(envelope['task_request'],final=envelope['task_request']['phase']=='synthesis')
        if self.mutate:self.mutate(p,envelope)
        return canonical_json(p),{'status':'completed','real_model':False,'usage':None,'protocol_fixture':True}


def test_missing_definitions_block_without_provider_calls_or_invented_taxonomy(tmp_path):
    provider=Provider()
    for kind in ['malware_detection','malware_classification']:
        d=TaskDefinition(task_id=kind,version='1',kind=kind,requirements='Configured task required.')
        result=run_task(d,IDENTITY,catalog(),tmp_path/kind,provider,config=config())
        assert result['status']=='blocked' and result['task_result'] is None and result['new_model_calls']==0
        assert not (tmp_path/kind/'task-ledger.sqlite').exists()
    assert not provider.calls
    assert default_threat_intelligence_definition().blocked_reasons()==[]


def test_three_task_schemas_prompts_and_definition_resume_are_independent(tmp_path):
    definitions=[definition(k) for k in ['malware_detection','malware_classification','threat_intelligence']]
    assert len({fingerprint(task_proposal_schema(d)) for d in definitions})==3
    assert len({fingerprint(task_prompt(d)) for d in definitions})==3
    with DefinitionTaskLedger(tmp_path/'task.sqlite',definitions[0],IDENTITY,source_catalog=catalog(),config=config()):pass
    with pytest.raises(ValueError,match='protocol differs'):
        DefinitionTaskLedger(tmp_path/'task.sqlite',definitions[1],IDENTITY,source_catalog=catalog(),config=config())


@pytest.mark.parametrize('kind',['malware_detection','malware_classification','threat_intelligence'])
def test_each_task_accepts_current_support_and_rejects_foreign_evidence_atomically(tmp_path,kind):
    with DefinitionTaskLedger(tmp_path/(kind+'.sqlite'),definition(kind),IDENTITY,source_catalog=catalog(),config=config()) as ledger:
        packet=ledger.prepare_packet(phase='synthesis');good=proposal(packet,final=True);bad=deepcopy(good)
        bad['task_result']['current_evidence_refs'].append('history_only_handle')
        old=fingerprint(ledger.state());checked=ledger.finalize(canonical_json(bad),packet)
        assert not checked['valid'] and fingerprint(ledger.state())==old
        assert ledger.finalize(canonical_json(good),packet)['valid']
        assert ledger.state()['task']==kind and ledger.state()['task_result']['kind']==kind
        assert ledger.report()['evaluation_status']=='protocol_only_not_task_quality'


def test_unknown_taxonomy_single_multi_and_detection_rule_mismatches_are_rejected(tmp_path):
    for mode in ['single','multi']:
        with DefinitionTaskLedger(tmp_path/(mode+'.sqlite'),definition('malware_classification',mode),IDENTITY,
                source_catalog=catalog(),config=config()) as ledger:
            packet=ledger.prepare_packet(phase='synthesis');p=proposal(packet,final=True)
            second=deepcopy(p['task_result']['labels'][0]);second['label_id']='synthetic_b';p['task_result']['labels'].append(second)
            check=ledger.finalize(canonical_json(p),packet)
            assert check['valid']==(mode=='multi')
            if mode=='single':
                p['task_result']['labels']=[second];second['label_id']='invented_family'
                assert not ledger.finalize(canonical_json(p),packet)['valid']
    with DefinitionTaskLedger(tmp_path/'detect.sqlite',definition('malware_detection'),IDENTITY,source_catalog=catalog(),config=config()) as ledger:
        packet=ledger.prepare_packet(phase='synthesis');p=proposal(packet,final=True)
        p['task_result']['decision']='benign'
        assert not ledger.finalize(canonical_json(p),packet)['valid']


def test_continuous_driver_resume_has_no_duplicate_calls_and_one_final_synthesis(tmp_path):
    provider=Provider();d=definition();out=tmp_path/'run';cfg=config()
    first=run_task(d,IDENTITY,catalog(2),out,provider,config=cfg,max_new_calls=1)
    assert first['status']=='partial' and first['new_provider_invocations']==1 and first['state']['synthesis'] is None
    second=run_task(d,IDENTITY,catalog(2),out,provider,config=cfg,max_new_calls=2)
    assert second['status']=='completed' and second['new_provider_invocations']==2 and second['new_model_calls']==0
    assert len(provider.calls)==3 and len(set(provider.calls))==3
    state=deepcopy(second['state']);audits=deepcopy(second['audits'])
    replay=run_task(d,IDENTITY,catalog(2),out,provider,config=cfg,max_new_calls=0)
    assert replay['new_model_calls']==0 and len(provider.calls)==3
    assert replay['state']==state and replay['audits']==audits
    assert sum('synthesis' in x for x in provider.calls)==1


def test_rejected_response_repairs_and_failure_does_not_replace_old_state(tmp_path):
    def reject_first(p,envelope):
        if envelope['repair_feedback'] is None:p['upsert_findings'][0]['evidence_refs'].append('unseen')
    provider=Provider(reject_first)
    result=run_task(definition(),IDENTITY,catalog(),tmp_path/'repair',provider,config=config())
    assert result['status']=='completed'
    assert result['audits'][0]['rejected_update_preserved_state']
    assert len(provider.calls)==4


def test_actual_method_query_is_later_visible_source_bound_and_recorded_used(tmp_path):
    facts=load_facts(Path(__file__).parents[1]/'fixtures/contracts/valid.json')
    snapshot=create_snapshot(facts,tmp_path/'store');before=sha256_file(snapshot/'facts.sqlite')
    identity={'apk_sha256':facts.run.apk_sha256,'source_run_ref':facts.run.run_id};cfg=config()
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'queries.sqlite',view,cfg.queries) as service, \
            DefinitionTaskLedger(tmp_path/'task.sqlite',definition(),identity,source_catalog=catalog(),config=cfg) as ledger:
        packet=ledger.prepare_packet();p=proposal(packet)
        p['issue_updates']=[{'issue_id':'method_detail','description':'Method boundary is not yet displayed.',
            'bc_ids':['bc0'],'finding_ids':['f_bc0'],'evidence_refs':[],'status':'open','resolution':None}]
        p['current_fact_queries']=[{'query_id':'method_detail_query','query_type':'method',
            'apk_sha256':identity['apk_sha256'],'run_ref':identity['source_run_ref'],
            'subject_ref':'method:run','reason':'Check this actual current method declaration.', 'issue_ids':['method_detail']}]
        assert ledger.update(canonical_json(p),packet)['valid']
        assert not ledger.state()['current_query_grants']
        receipt=ledger.fulfill_current_queries(service)[0]
        assert receipt['records'][0]['id']=='method:run'
        final=ledger.prepare_packet(phase='synthesis');p=proposal(final,final=True)
        handle=next(iter(ledger.state()['current_query_grants']))
        assert handle not in packet['evidence'] and handle in final['evidence']
        assert final['evidence'][handle]['category']=='fact'
        assert 'not_automatically' in final['evidence'][handle]['role']
        p['upsert_findings'][0]['evidence_refs'].append(handle)
        p['issue_updates']=[{'issue_id':'method_detail','description':'Actual current declaration is now displayed.',
            'bc_ids':['bc0'],'finding_ids':['f_bc0'],'evidence_refs':[handle],'status':'resolved','resolution':'Actual returned method declaration examined.'}]
        p['synthesis']['unresolved_issue_ids']=[];p['task_result']['unresolved_issue_ids']=[]
        p['task_result']['current_evidence_refs'].append(handle)
        checked=ledger.finalize(canonical_json(p),final)
        assert checked['valid'],checked
        ledger.record_query_uses(service,final,checked['accepted'])
        assert service.report()['uses'][0]['record_refs']==['method:run']
        assert ledger.verify()['valid']
    assert sha256_file(snapshot/'facts.sqlite')==before


def test_query_identity_and_final_queries_reject_without_grant(tmp_path):
    with DefinitionTaskLedger(tmp_path/'ledger.sqlite',definition(),IDENTITY,source_catalog=catalog(),config=config()) as ledger:
        packet=ledger.prepare_packet();p=proposal(packet)
        p['issue_updates']=[{'issue_id':'open','description':'Missing current fact.', 'bc_ids':['bc0'],'finding_ids':[],
            'evidence_refs':[],'status':'open','resolution':None}]
        p['current_fact_queries']=[{'query_id':'foreign','query_type':'method','apk_sha256':'f'*64,
            'run_ref':'run:other','subject_ref':'method:run','reason':'Foreign','issue_ids':['open']}]
        old=fingerprint(ledger.state())
        assert not ledger.update(canonical_json(p),packet)['valid'] and fingerprint(ledger.state())==old
        assert not ledger.state()['current_query_grants']


def test_empty_current_catalog_yields_insufficient_for_each_configured_task(tmp_path):
    provider=Provider()
    for kind in ['malware_detection','malware_classification','threat_intelligence']:
        result=run_task(definition(kind),IDENTITY,catalog(0),tmp_path/kind,provider,config=config())
        assert result['status']=='evidence_insufficient'
        assert result['task_result']['kind']==kind and result['task_result']['absence_proves_benign'] is False
    assert not provider.calls


def test_frozen_total_call_budget_is_not_reset_by_resume(tmp_path):
    provider=Provider();cfg=config(max_model_calls=1);out=tmp_path/'bounded'
    first=run_task(definition(),IDENTITY,catalog(),out,provider,config=cfg)
    assert first['status']=='partial' and first['new_provider_invocations']==1
    second=run_task(definition(),IDENTITY,catalog(),out,provider,config=cfg)
    assert second['status']=='partial' and second['new_provider_invocations']==0
    assert second['state']==first['state'] and len(provider.calls)==1
    assert second['stages'][-1]['reason']=='frozen_total_task_call_budget'


def test_driver_performs_actual_query_then_single_synthesis_and_use_audit(tmp_path):
    facts=load_facts(Path(__file__).parents[1]/'fixtures/contracts/valid.json')
    snapshot=create_snapshot(facts,tmp_path/'store')
    identity={'apk_sha256':facts.run.apk_sha256,'source_run_ref':facts.run.run_id}
    def add_query_or_use(p,envelope):
        packet=envelope['task_request']
        issue={'issue_id':'method_detail','description':'Current method declaration required.',
            'bc_ids':['bc0'],'finding_ids':['f_bc0'],'evidence_refs':[],'status':'open','resolution':None}
        if packet['phase']=='incremental':
            p['issue_updates']=[issue]
            p['current_fact_queries']=[{'query_id':'method_detail_query','query_type':'method',
                'apk_sha256':identity['apk_sha256'],'run_ref':identity['source_run_ref'],'subject_ref':'method:run',
                'reason':'Check exact current declaration.','issue_ids':['method_detail']}]
        else:
            handle=next(k for k in packet['evidence'] if k.startswith('qfact_'))
            p['upsert_findings'][0]['evidence_refs'].append(handle)
            issue.update(status='resolved',resolution='Actual returned method declaration examined.',evidence_refs=[handle])
            p['issue_updates']=[issue]
            p['task_result']['current_evidence_refs'].append(handle)
            p['task_result']['unresolved_issue_ids']=[];p['synthesis']['unresolved_issue_ids']=[]
    with FactView(snapshot) as view:
        result=run_task(definition(),identity,catalog(),tmp_path/'run',Provider(add_query_or_use),fact_view=view,config=config())
    assert result['status']=='completed' and result['new_model_calls']==0
    assert result['query_service']['budget_used']['queries']==1
    assert result['query_service']['uses'][0]['record_refs']==['method:run']
    assert len(result['actual_current_fact_receipts'])==1


def test_receipt_admission_rollback_replays_actual_query_without_spending_again(tmp_path,monkeypatch):
    facts=load_facts(Path(__file__).parents[1]/'fixtures/contracts/valid.json')
    snapshot=create_snapshot(facts,tmp_path/'store');identity={'apk_sha256':facts.run.apk_sha256,'source_run_ref':facts.run.run_id}
    cfg=config(queries=FactQueryBudget(max_queries=1,max_records=2))
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'queries.sqlite',view,cfg.queries) as service, \
            DefinitionTaskLedger(tmp_path/'task.sqlite',definition(),identity,source_catalog=catalog(),config=cfg) as ledger:
        packet=ledger.prepare_packet();p=proposal(packet)
        p['issue_updates']=[{'issue_id':'needed','description':'Need exact method.','bc_ids':['bc0'],
            'finding_ids':[],'evidence_refs':[],'status':'open','resolution':None}]
        p['current_fact_queries']=[{'query_id':'check_method','query_type':'method','apk_sha256':identity['apk_sha256'],
            'run_ref':identity['source_run_ref'],'subject_ref':'method:run','reason':'Read current method.','issue_ids':['needed']}]
        assert ledger.update(canonical_json(p),packet)['valid']
        old=fingerprint(ledger.state());insert=ledger._insert_state
        def interrupted(*args):raise RuntimeError('simulated interruption after actual return, before task grant commit')
        monkeypatch.setattr(ledger,'_insert_state',interrupted)
        with pytest.raises(RuntimeError):ledger.fulfill_current_queries(service)
        assert fingerprint(ledger.state())==old and not ledger.state()['current_query_grants']
        assert service.report()['budget_used']['queries']==1
        monkeypatch.setattr(ledger,'_insert_state',insert)
        assert ledger.fulfill_current_queries(service)[0]['records'][0]['id']=='method:run'
        assert service.report()['budget_used']['queries']==1 and ledger.state()['current_query_grants']


def test_global_scope_is_frozen_visible_and_cannot_authorize_a_finding(tmp_path):
    scope={'pending_roots':['unprocessed-method'],'backend_failures':[{'provider':'flow','state':'failed'}],
           'coverage':{'events':'partial'},'metadata_only_handle':'scope-is-not-evidence'}
    with DefinitionTaskLedger(tmp_path/'task.sqlite',definition(),IDENTITY,source_catalog=catalog(),config=config(),scope_status=scope) as ledger:
        packet=ledger.prepare_packet(phase='synthesis')
        assert packet['analysis_scope_metadata']['status']==scope
        assert not packet['analysis_scope_metadata']['citation_authority_added']
        p=proposal(packet,final=True);p['upsert_findings'][0]['evidence_refs'].append('scope-is-not-evidence')
        old=fingerprint(ledger.state())
        assert not ledger.finalize(canonical_json(p),packet)['valid']
        assert fingerprint(ledger.state())==old
    with pytest.raises(ValueError,match='protocol differs'):
        DefinitionTaskLedger(tmp_path/'task.sqlite',definition(),IDENTITY,source_catalog=catalog(),config=config(),scope_status={})
    result=run_task(definition('malware_detection'),IDENTITY,catalog(0),tmp_path/'empty',Provider(),config=config(),scope_status=scope)
    assert result['task_result']['decision']=='evidence_insufficient'
    assert result['analysis_scope_metadata']['status']==scope and result['outcome']['upstream_coverage']==scope


def test_provider_preflight_stop_keeps_pending_stage_without_dispatch_or_attempt(tmp_path):
    class Preflight(Provider):
        stop='aggregate compact input budget reached'
        def preflight_invocation(self,*args,**kwargs):return self.stop
    provider=Preflight();out=tmp_path/'preflight';d=definition();cfg=config()
    first=run_task(d,IDENTITY,catalog(),out,provider,config=cfg)
    assert first['status']=='partial' and first['new_provider_invocations']==0
    assert not first['model_dispatches'] and not first['audits'] and not provider.calls
    assert first['stages'][0]['stop_source']=='provider_preflight'
    provider.stop=None
    resumed=run_task(d,IDENTITY,catalog(),out,provider,config=cfg)
    assert resumed['status']=='completed' and resumed['new_provider_invocations']==2
    assert len(provider.calls)==2
