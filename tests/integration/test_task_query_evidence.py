"""Actual compiled task-query paths; all behavior proposals are protocol controls."""
from copy import deepcopy
import json
from pathlib import Path
import runpy

import pytest

from androserum.facts.bu import _Graph
from androserum.facts.identity import canonical_json, fingerprint
from androserum.facts.queries import FactQueryBudget, FactQuerySession
from androserum.facts.store import FactView
from androserum.matching.checker import path_metadata
from androserum.mining.evidence import EvidenceCatalog
from androserum.pipeline.tasks import DefinitionTaskLedger, DefinedTaskConfig
from androserum.tasking.models import TaskConfig


ROOT=Path(__file__).resolve().parents[2]
GRAPH=runpy.run_path(str(ROOT/'tests/integration/test_query_evidence.py'))
TASK=runpy.run_path(str(ROOT/'tests/unit/test_defined_tasks.py'))
actual=GRAPH['actual']


def task_catalog(view,collection,unit,start,goal,anchor,target):
    evidence=EvidenceCatalog({**collection,'units':[unit]},[unit['bu_id']])
    full=evidence.render(evidence.entries,set(evidence.units))
    op=lambda ref:next(h for h,e in full.items() if e['category']=='operation' and e['record_ref']==ref)
    ep=lambda point:next(h for h,e in full.items() if e['category']=='endpoint' and e['endpoint']==point.model_dump(mode='json'))
    a,b=op(anchor.node_ref),op(target.node_ref);source,sink=ep(start),ep(goal)
    keep=set(evidence.closure([a,b]));registry={h:deepcopy(full[h]) for h in keep}
    # The selected operations are already visible, but their connection and
    # consumer guard were not exposed in the controlled initial BC scope.
    condition_refs={e['record_ref'] for e in registry.values() if e['category']=='condition'}
    branch_refs={e['branch_ref'] for e in registry.values() if e['category']=='condition'}
    registry={h:e for h,e in registry.items() if e['category']!='condition' and
        not(e['category']=='fact' and e['record_ref'] in condition_refs|branch_refs)}
    for e in registry.values():
        if e['category']=='operation':e['condition_refs']=[]
    unknown={'availability':'unknown','description':'Not established.','endpoint_refs':[]}
    def action(aid,operation,inputs,outputs):
        return {'action_id':aid,'function':'Protocol-local operation from the actual compiled projection.',
            'operation_refs':[operation],'objects':deepcopy(unknown),'inputs':inputs,'outputs':outputs,
            'condition_status':'unknown','condition_refs':[],'effect_refs':[],'support_relation_refs':[],
            'support_fact_refs':[],'limitation_notes':['Controlled initial visibility crop; not a new real model result.']}
    actions=[action('read',a,deepcopy(unknown),{'availability':'supported','description':'Recorded return value.','endpoint_refs':[source]}),
             action('pass',b,{'availability':'supported','description':'Recorded use argument.','endpoint_refs':[sink]},deepcopy(unknown))]
    sides={}
    for act in actions:
        bid='bc_'+act['action_id']
        sides[bid]={'schema_version':'match-side.v1','instance_ref':'protocol:'+bid,
            'origin':{'evidence_kind':'synthetic_protocol','apk_sha256':view.manifest.apk_sha256,
                'query_context_basis':deepcopy(evidence.identity)},
            'bc':{'bc_id':bid,'description':'Protocol action scope over actual compiled evidence.','action_ids':[act['action_id']],
                'relations':[],'boundary':{'inputs':deepcopy(unknown),'outputs':deepcopy(unknown),'potential_effects':'Unknown.','condition_refs':[]},
                'limitation_notes':['No cross-BC path is initially visible.'],'execution_claim':'possible_only'},
            'actions':{act['action_id']:act},'registry':deepcopy(registry),'condition_semantics':{},'purpose_claims':{},
            'source_limits':[{'state':'partial','reason':'Controlled evidence crop.'}],'limitations':['No execution claim.']}
    return {'bcs':sides,'supplemental':{}},source,sink


def book(view,catalog,path):
    cfg=DefinedTaskConfig(ledger=TaskConfig(allow_synthetic_protocol=True,max_attempts=64),
        queries=FactQueryBudget(max_queries=128,max_records=4096,max_return_chars=3000000))
    return DefinitionTaskLedger(path,TASK['definition'](),
        {'apk_sha256':view.manifest.apk_sha256,'source_run_ref':view.run_ref},config=cfg,source_catalog=catalog)


def update_proposal(packet,*,final=False):
    p=TASK['proposal'](packet,final=final)
    for finding in p['upsert_findings']:
        ops={o for s in finding['scopes'] for aid in s['action_ids'] for o in packet['current_bcs'][s['bc_id']]['actions'][aid]['operation_refs']}
        finding['supplemental_condition_refs']=sorted({c for op in ops if op in packet['ledger_context']['current_query_grants']
            for c in packet['evidence'][op].get('condition_refs',[])}-set(finding['condition_refs']))
    if final:
        p['task_result']['condition_refs']=sorted({c for f in p['upsert_findings'] for c in
            [*f['condition_refs'],*f['supplemental_condition_refs']]})
    return p


def replenish(ledger,service,seeds):
    pending=list(seeds);index=0;receipts=[]
    for round_index in range(8):
        packet=ledger.prepare_packet();p=update_proposal(packet)
        p['issue_updates']=[{'issue_id':'missing_connection','description':'Need actual typed connection and local constraints.',
            'bc_ids':list(packet['current_bcs']),'finding_ids':[],'evidence_refs':[],'status':'open','resolution':None}]
        p['current_fact_queries']=[]
        for ref in pending:
            p['current_fact_queries'].append({'query_id':'task_query_'+str(index),'query_type':'record',
                'apk_sha256':ledger.identity['apk_sha256'],'run_ref':ledger.identity['source_run_ref'],'subject_ref':ref,
                'limit':64,'include_support':True,'reason':'Obtain the missing actual typed proof.','issue_ids':['missing_connection']})
            index+=1
        check=ledger.update(canonical_json(p),packet);assert check['valid'],check
        receipts.extend(ledger.fulfill_current_queries(service))
        pending=sorted({ref for row in ledger.state()['typed_query_admissions'] for ref in row['required_record_refs']
            if not any(e['category']=='fact' and e.get('record_ref')==ref and not e.get('detail_fields_available')
                for e in ledger.state()['current_query_grants'].values())})
        if not pending:return receipts
    raise AssertionError('Known finite task query support failed to converge')


def final_proposal(ledger,path,source,target):
    packet=ledger.prepare_packet(phase='synthesis');p=update_proposal(packet,final=True)
    refs=[next(h for h,e in packet['evidence'].items() if e['category']=='relation' and e['record_ref']==raw) for raw in path]
    profile,kind,strength=path_metadata({'registry':packet['evidence'],'bc':{'relations':[{'link_id':'new','support_path':refs}]}},['new'])
    assert profile['source_endpoint']==source and profile['target_endpoint']==target
    cross={'link_id':'queried_connection','from_bc':'bc_read','from_action':'read','to_bc':'bc_pass','to_action':'pass',
        **{k:v for k,v in profile.items() if k!='link_ids'},'relation_kind':kind,'evidence_strength':strength,
        'claims_complete_fine_path':False,'explanation':'Newly queried recorded path; conditions, frame and binding remain scoped.'}
    p['synthesis']['cross_bc_links']=[cross]
    for finding in p['upsert_findings']:finding['evidence_refs']=list(dict.fromkeys([*finding['evidence_refs'],*refs]))
    p['issue_updates']=[{'issue_id':'missing_connection','description':'The requested typed relation is now displayed.',
        'bc_ids':['bc_read','bc_pass'],'finding_ids':[],'evidence_refs':refs,'status':'resolved',
        'resolution':'Actual queried proof was admitted without changing the original BC/actions.'}]
    p['synthesis']['unresolved_issue_ids']=[];p['task_result']['unresolved_issue_ids']=[]
    p['task_result']['current_evidence_refs']=list(dict.fromkeys([*p['task_result']['current_evidence_refs'],*refs]))
    return packet,p,cross


def test_task_actual_query_enables_cross_BC_path_and_new_local_condition(actual):
    snapshot,collection,out=actual;unit=GRAPH['unit_for'](collection,'guarded')
    with FactView(snapshot) as view:
        graph,anchor,target,path,start,goal=GRAPH['guarded_path'](view,unit)
        catalog,source,sink=task_catalog(view,collection,unit,start,goal,anchor,target)
        before=fingerprint(catalog)
        with book(view,catalog,out/'task-query-positive.sqlite') as ledger,FactQuerySession(out/'task-query-positive-queries.sqlite',view,ledger.run_config.queries) as service:
            assert not any(e['category']=='relation' and e['record_ref'] in path for s in catalog['bcs'].values() for e in s['registry'].values())
            receipts=replenish(ledger,service,[target.node_ref,*path])
            packet,p,cross=final_proposal(ledger,path,source,sink)
            guarded=next(i for i,f in enumerate(p['upsert_findings']) if f['scopes'][0]['bc_id']=='bc_pass')
            assert p['upsert_findings'][guarded]['supplemental_condition_refs']
            bad=deepcopy(p);bad['upsert_findings'][guarded]['supplemental_condition_refs']=[]
            assert not ledger.finalize(canonical_json(bad),packet)['valid']
            bad=deepcopy(p);bad['synthesis']['cross_bc_links'][0]['condition_refs']=([] if cross['condition_refs'] else
                p['upsert_findings'][guarded]['supplemental_condition_refs'])
            assert not ledger.finalize(canonical_json(bad),packet)['valid']
            bad=deepcopy(p);bad['synthesis']['cross_bc_links'][0]['context_refs']=['context:another_call']
            assert not ledger.finalize(canonical_json(bad),packet)['valid']
            checked=ledger.finalize(canonical_json(p),packet);assert checked['valid'],checked
            ledger.record_query_uses(service,packet,checked['accepted'])
            used={r for row in service.report()['uses'] for r in row['record_refs']}
            assert set(path)<=used and service.report()['uses']
            assert fingerprint(catalog)==before
            out.joinpath('task-query-positive.json').write_text(json.dumps({'receipts':receipts,'typed_admissions':ledger.state()['typed_query_admissions'],
                'proposal':p,'check':checked,'query_audit':service.report(),'source_catalog_unchanged':True,'actual_LLM_calls':0},indent=2)+'\n',encoding='utf-8')


def test_task_typed_storage_binding_and_other_object_rejection(actual):
    snapshot,collection,out=actual;unit=GRAPH['unit_for'](collection,'storage')
    with FactView(snapshot) as view:
        graph,anchor,target,path,start,goal=GRAPH['guarded_path'](view,unit)
        catalog,source,sink=task_catalog(view,collection,unit,start,goal,anchor,target)
        with book(view,catalog,out/'task-query-object.sqlite') as ledger,FactQuerySession(out/'task-query-object-queries.sqlite',view,ledger.run_config.queries) as service:
            replenish(ledger,service,[target.node_ref,*path]);packet,p,cross=final_proposal(ledger,path,source,sink)
            assert cross['binding_refs']
            bad=deepcopy(p);bad['synthesis']['cross_bc_links'][0]['binding_refs']=[]
            assert not ledger.finalize(canonical_json(bad),packet)['valid']
            forbidden={m.node_ref for m in graph.nodes.values() if graph.report.projection.method.units[m.index].invoke and
                '->unrelated(' in graph.report.projection.method.units[m.index].invoke.signature}
            assert not any(e['category']=='operation' and e['record_ref'] in forbidden for e in ledger.state()['current_query_grants'].values())
            assert ledger.finalize(canonical_json(p),packet)['valid']


def test_task_query_keeps_concrete_other_caller_out(actual):
    snapshot,collection,out=actual
    with FactView(snapshot) as view:
        facts=view.export_bundle();root=next(m.id for m in facts.elements if m.kind=='method' and m.is_definition and '->twice(' in m.signature)
        calls=sorted([c for c in view.read_call_flow().calls if c.caller_ref==root and '->helper(' in c.declared_signature],key=lambda c:c.unit)
        unit=next(u for u in collection['units'] if u['anchor']['root_method_ref']==root and u['anchor']['call_path'] and
            u['anchor']['call_path'][0]['callsite_ref']==calls[0].callsite_ref)
        graph,anchor,target,path,start,goal=GRAPH['guarded_path'](view,unit)
        catalog,source,sink=task_catalog(view,collection,unit,start,goal,anchor,target)
        with book(view,catalog,out/'task-query-caller.sqlite') as ledger,FactQuerySession(out/'task-query-caller-queries.sqlite',view,ledger.run_config.queries) as service:
            replenish(ledger,service,[target.node_ref,*path]);packet,p,cross=final_proposal(ledger,path,source,sink)
            other_frames={f.context_ref for f in graph.frames.values() if f.call_path and f.call_path[0].callsite_ref==calls[1].callsite_ref}
            forbidden={m.node_ref for m in graph.nodes.values() if m.frame_ref in other_frames}
            assert forbidden and not any(e['category']=='operation' and e['record_ref'] in forbidden for e in ledger.state()['current_query_grants'].values())
            bad=deepcopy(p);bad['synthesis']['cross_bc_links'][0]['context_refs'].extend(other_frames)
            assert not ledger.finalize(canonical_json(bad),packet)['valid']
            assert ledger.finalize(canonical_json(p),packet)['valid']


def test_actual_FlowDroid_summary_can_support_coarse_cross_BC_only(tmp_path):
    # Reuse the independently executed fixed FlowDroid snapshot; no new taint
    # execution or model call is needed to test the task evidence role.
    prepared=json.loads((ROOT/'artifacts/acceptance/bounded-repair/20261028_075147_975745/inference-round/samples/imei-hash/prepared.json').read_text('utf-8'))
    collection=json.loads(Path(prepared['bu_package']+'/collection.json').read_text('utf-8'))
    with FactView(prepared['snapshot']) as view:
        facts=view.export_bundle()
        root=next(m.id for m in facts.elements if m.kind=='method' and m.is_definition and '->md5(' in m.signature)
        unit=next(u for u in collection['units'] if u['anchor']['root_method_ref']==root)
        graph=_Graph(view,facts,root)
        item=next(e for e in graph.edges.values() if e['record'].relation_kind=='information_flow')
        start,goal=item['source'],item['target'];anchor,target=graph.meta(start),graph.meta(goal)
        catalog,source,sink=task_catalog(view,collection,unit,start,goal,anchor,target)
        with book(view,catalog,tmp_path/'summary-task.sqlite') as ledger,FactQuerySession(tmp_path/'summary-queries.sqlite',view,ledger.run_config.queries) as service:
            path=[item['record'].id];replenish(ledger,service,[target.node_ref,*path])
            packet,p,cross=final_proposal(ledger,path,source,sink)
            assert (cross['relation_kind'],cross['evidence_strength'])==('information_flow','information_flow_summary')
            bad=deepcopy(p);bad['synthesis']['cross_bc_links'][0]['claims_complete_fine_path']=True
            assert not ledger.finalize(canonical_json(bad),packet)['valid']
            bad=deepcopy(p);bad['synthesis']['cross_bc_links'][0].update(relation_kind='data_transfer',evidence_strength='recorded_dependency_path')
            assert not ledger.finalize(canonical_json(bad),packet)['valid']
            checked=ledger.finalize(canonical_json(p),packet);assert checked['valid'],checked
            ledger.record_query_uses(service,packet,checked['accepted'])
            assert any(item['record'].id in use['record_refs'] for use in service.report()['uses'])
            (tmp_path/'task-query-summary.json').write_text(json.dumps({'proposal':p,'check':checked,'typed_admissions':ledger.state()['typed_query_admissions'],
                'query_audit':service.report(),'actual_LLM_calls':0},indent=2)+'\n',encoding='utf-8')


def test_raw_relation_without_actual_binding_or_endpoint_support_stays_untyped(actual):
    snapshot,collection,out=actual;unit=GRAPH['unit_for'](collection,'storage')
    with FactView(snapshot) as view:
        graph,anchor,target,path,start,goal=GRAPH['guarded_path'](view,unit)
        raw=next(graph.edges[ref]['record'] for ref in path if graph.edges[ref]['record'].binding_refs)
        catalog,source,sink=task_catalog(view,collection,unit,start,goal,anchor,target)
        with book(view,catalog,out/'task-query-missing-binding.sqlite') as ledger,FactQuerySession(out/'task-query-missing-binding-queries.sqlite',view,ledger.run_config.queries) as service:
            packet=ledger.prepare_packet();p=update_proposal(packet)
            p['issue_updates']=[{'issue_id':'need_bound_path','description':'Missing verified storage identity and endpoints.',
                'bc_ids':list(catalog['bcs']),'finding_ids':[],'evidence_refs':[],'status':'open','resolution':None}]
            p['current_fact_queries']=[{'query_id':'raw_relation_only','query_type':'record',
                'apk_sha256':view.manifest.apk_sha256,'run_ref':view.run_ref,'subject_ref':raw.id,
                'limit':1,'include_support':False,'reason':'Retrieve only the actual relation, not its omitted support.',
                'issue_ids':['need_bound_path']}]
            assert ledger.update(canonical_json(p),packet)['valid']
            receipt=ledger.fulfill_current_queries(service)[0]
            assert [r['id'] for r in receipt['records']]==[raw.id]
            assert not any(e['category']=='relation' and e['record_ref']==raw.id for e in ledger.state()['current_query_grants'].values())
            admission=ledger.state()['typed_query_admissions'][-1]
            assert set(raw.binding_refs)<=set(admission['required_record_refs'])
            assert admission['required_record_refs']
            out.joinpath('task-query-missing-binding.json').write_text(json.dumps({'receipt':receipt,'admission':admission,
                'no_typed_relation_granted':True,'actual_LLM_calls':0},indent=2)+'\n',encoding='utf-8')
