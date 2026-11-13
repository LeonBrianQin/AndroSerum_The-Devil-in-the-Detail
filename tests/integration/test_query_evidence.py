"""Returned program records must enable checked typed updates, with closure gates."""
from collections import deque
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from androserum.facts.bu import BUConfig,build_units,_Graph,_key
from androserum.facts.context_heap import extract_context_heap,ContextHeapConfig
from androserum.facts.control import extend_control
from androserum.facts.identity import fingerprint
from androserum.facts.operations import extend_operations
from androserum.facts.queries import FactQuerySession,FactQueryBudget,CurrentFactQuery
from androserum.facts.query_evidence import adapt_query_evidence
from androserum.facts.sapi import SapiImportConfig,import_catalog
from androserum.facts.store import FactView,import_snapshot
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.checker import check_proposal
from androserum.mining.models import CurrentMiningConfig
from androserum.mining.runner import run_mining
from androserum.mining.verification import verify_package
from androserum.pipeline.evidence import write_encoded_extraction

ROOT=Path(__file__).resolve().parents[2]
OWNER='Lorg/androserum/queryevidence/Cases;'


@pytest.fixture(scope='module')
def actual(tmp_path_factory):
    reuse=os.environ.get('ANDROSERUM_TYPED_QUERY_FIXTURE')
    if reuse:
        from androserum.facts.identity import filesystem_path
        source=filesystem_path(reuse);snapshot=next(next((source/'stores').iterdir()).iterdir())
        collection=json.loads((source/'original-bus.json').read_text('utf-8'))
        out=tmp_path_factory.mktemp('typed-query-reused')
        return snapshot,collection,out
    subprocess.run([sys.executable,'scripts/build_query_evidence_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    apk=ROOT/'artifacts/fixtures/query-evidence/valid.apk'
    roots=[OWNER+'->guarded(Landroid/telephony/TelephonyManager;I)V',OWNER+'->storage(Landroid/telephony/TelephonyManager;)V',
           OWNER+'->twice(Landroid/telephony/TelephonyManager;Landroid/telephony/TelephonyManager;)V']
    result=extend_control(extend_operations(extract_context_heap(apk,config=ContextHeapConfig(root_signatures=roots))))
    out=tmp_path_factory.mktemp('typed-query')
    snapshot=import_snapshot(write_encoded_extraction(result,out/'facts',input_apk=apk),out/'stores')
    catalog=out/'sapi';import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')),catalog)
    with FactView(snapshot) as view:collection=build_units(view,catalog,BUConfig(root_signatures=roots))
    out.joinpath('original-bus.json').write_text(json.dumps(collection,indent=2)+'\n',encoding='utf-8')
    return snapshot,collection,out


def unit_for(collection,name):
    for u in collection['units']:
        record=next(r for r in u['model_visible']['records'] if r['id']==u['anchor']['root_method_ref'])
        if '->'+name+'(' in record['signature']:return u
    raise AssertionError('Missing compiled actual BU')


def stripped_catalog(collection,name,unit_override=None):
    c=deepcopy(collection);unit=deepcopy(unit_override or unit_for(collection,name))
    root=unit['anchor']['root_method_ref']
    # Keep exactly the anchor operation/facts. The future operation and its
    # relationship are known to the fact service, but absent from visible input.
    anchor=next(op for op in unit['operation_records'] if unit['anchor']['callsite_ref'] in op['raw_operation_refs'])
    keep={anchor['operation_ref'],anchor['origin_ref'],anchor['method_ref'],anchor['context_ref'],*anchor['raw_operation_refs']}
    records={r['id']:r for r in unit['model_visible']['records']}
    for ref in list(keep):
        if ref in records:
            for key in ['class_ref','dex_ref']:
                if records[ref].get(key):keep.add(records[ref][key])
    visible={'records':[r for ref,r in records.items() if ref in keep], 'allowed_citation_refs':sorted(keep&set(records)),
             'operation_records':[anchor], 'relation_records':[], 'control_records':[], 'condition_sources':[],
             'event_records':[], 'issues':[{'state':'partial','code':'controlled_visibility_crop','reason':'Independent query admission test'}],
             'raw_files':[], 'all_archive_support_visible':False}
    unit['model_visible']=visible;c['units']=[unit]
    return EvidenceCatalog(c,[unit['bu_id']]),unit


def query_records(view,session,refs,index,*,include_support=True):
    returned=[];receipts=[]
    for ref in refs:
        selector=CurrentFactQuery(query_id='q_'+str(index[0]),query_type='record',apk_sha256=view.manifest.apk_sha256,
            run_ref=view.run_ref,subject_ref=ref,limit=64,include_support=include_support,reason='Request missing typed proof from the current APK')
        index[0]+=1;receipt=session.execute(selector)
        returned.extend(receipt['records']);receipts.append(receipt)
    return returned,receipts


def replenish(view,catalog,unit,refs,path,*,include_support=True):
    receipts=[];admissions=[];next_refs=list(refs);index=[0]
    with FactQuerySession(path,view,FactQueryBudget(max_queries=128,max_records=2048,max_return_chars=1000000)) as service:
        for _ in range(8):
            returned,queries=query_records(view,service,next_refs,index,include_support=include_support);receipts.extend(queries)
            admission=adapt_query_evidence(catalog,view,returned,[unit['bu_id']],query_id=queries[-1]['query']['query_id'])
            admissions.append(admission)
            next_refs=admission['required_record_refs']
            if not next_refs:break
        else:raise AssertionError('Known finite support closure did not converge')
        audit=service.report()
    return receipts,admissions,audit


def guarded_path(view,unit):
    facts=view.export_bundle();g=_Graph(view,facts,unit['anchor']['root_method_ref'])
    target=next(m for m in g.nodes.values() if g.report.projection.method.units[m.index].invoke and
        '->consume(' in g.report.projection.method.units[m.index].invoke.signature and m.role not in {'exception_effect','call_result'})
    anchor=next(m for m in g.nodes.values() if unit['anchor']['callsite_ref'] in g.raw_for_origin.get(m.origin_ref,[])
                and m.frame_ref==unit['anchor']['projection_context_ref'] and m.role not in {'exception_effect','call_result'})
    start=next(item['source'] for item in g.edges.values() if item['source'].element_ref==anchor.node_ref and item['source'].slot_kind=='result')
    goal=next(item['target'] for item in g.edges.values() if item['target'].element_ref==target.node_ref and item['target'].slot_kind=='argument')
    key=lambda p:fingerprint(p.model_dump(mode='json'))
    queue=deque([(start,[])]);seen=set()
    while queue:
        point,path=queue.popleft()
        if key(point) in seen:continue
        seen.add(key(point))
        if key(point)==key(goal):return g,anchor,target,path,start,goal
        for item in g.outgoing.get(_key(point),[]):
            queue.append((item['target'],path+[item['record'].id]))
    raise AssertionError('Actual guarded data path is missing')


def proposal_for(catalog,path,start,goal,anchor,target):
    registry=catalog.render(catalog.entries,set(catalog.units))
    op=lambda ref:next(h for h,e in registry.items() if e['category']=='operation' and e['record_ref']==ref)
    ep=lambda p:next(h for h,e in registry.items() if e['category']=='endpoint' and e['endpoint']==p.model_dump(mode='json'))
    rels=[next(h for h,e in registry.items() if e['category']=='relation' and e['record_ref']==ref) for ref in path]
    a,b=op(anchor.node_ref),op(target.node_ref);source,target_ep=ep(start),ep(goal)
    def action(aid,oh,inputs,outputs):
        conditions=registry[oh]['condition_refs']
        return {'action_id':aid,'function':'Read or pass the recorded value under the visible local scope.',
            'operation_refs':[oh],'objects':{'availability':'unknown','description':'Object purpose remains scoped to static evidence.','endpoint_refs':[]},
            'inputs':inputs,'outputs':outputs,'condition_status':'recorded_local' if conditions else 'unknown',
            'condition_refs':conditions,'effect_refs':[],'support_relation_refs':rels,'support_fact_refs':[],
            'limitation_notes':['Static evidence only; no execution or benignness inferred.']}
    unknown={'availability':'unknown','description':'Not established.','endpoint_refs':[]}
    actions=[action('read',a,unknown,{'availability':'supported','description':'Recorded read result.','endpoint_refs':[source]}),
             action('pass',b,{'availability':'supported','description':'Recorded dependent argument.','endpoint_refs':[target_ep]},unknown)]
    bc={'bc_id':'conditional_pass','description':'A possible guarded transfer of the read result.', 'action_ids':['read','pass'],
        'relations':[{'link_id':'read_to_pass','from_action':'read','to_action':'pass','relation_kind':'data_transfer',
            'source_endpoint_ref':source,'target_endpoint_ref':target_ep,'support_path':rels,'binding_refs':[],
            'condition_refs':list(dict.fromkeys(c for h in rels for c in registry[h]['condition_refs'])),
            'evidence_strength':'recorded_dependency_path','execution_claim':'possible_only'}],
        'boundary':{'inputs':unknown,'outputs':unknown,'potential_effects':'Only the recorded conditional transfer.','condition_refs':[]},
        'limitation_notes':['The local guard applies to the consumer; no complete behavior or runtime execution claim.'],'execution_claim':'possible_only'}
    identity={'source':catalog.identity}
    packet={'request_id':'request:typed-query','base_revision':0,'identity':identity,'evidence':registry,
        'manifest':{'source_bu_refs':list(catalog.units),'evidence_sha256':fingerprint(registry)},
        'ledger_context':{'actions':{},'bcs':{},'unresolved':{}},'source_limits':[]}
    state={'schema_version':'behavior-ledger-state.v1','revision':0,'identity':identity,'actions':{},'bcs':{},'unresolved':{}}
    proposal={'schema_version':'behavior-proposal.v1','request_id':packet['request_id'],'base_revision':0,
        'upsert_actions':actions,'upsert_bcs':[bc],'delete_action_ids':[],'delete_bc_ids':[],
        'unresolved_updates':[],'fact_queries':[],'rationale':'Deterministic controlled response using actual query-admitted evidence; no model invocation.'}
    return packet,state,proposal


def test_actual_queries_add_new_operation_and_connection_accepted_by_checker(actual):
    snapshot,collection,out=actual;catalog,unit=stripped_catalog(collection,'guarded')
    with FactView(snapshot) as view:
        g,anchor,target,path,start,goal=guarded_path(view,unit)
        assert not any(e['category']=='operation' and e['record_ref']==target.node_ref for e in catalog.entries.values())
        receipts,admissions,audit=replenish(view,catalog,unit,[target.node_ref,*path],out/'positive-query.sqlite',include_support=False)
        packet,state,proposal=proposal_for(catalog,path,start,goal,anchor,target)
        checked,candidate=check_proposal(json.dumps(proposal),packet,state,CurrentMiningConfig())
    assert checked['valid'],checked['errors']
    assert candidate['bcs'] and any(e['category']=='condition' for e in packet['evidence'].values())
    assert all(e['root_ref']==unit['anchor']['root_method_ref'] for e in packet['evidence'].values() if e['category'] in {'operation','relation'})
    out.joinpath('query-admission-positive.json').write_text(json.dumps({'receipts':receipts,'admissions':admissions,'query_audit':audit,
        'packet':packet,'proposal':proposal,'check':checked,'candidate':candidate,'actual_model_calls':0},indent=2)+'\n',encoding='utf-8')


@pytest.mark.parametrize('missing_kind',['endpoint','condition','binding'])
def test_missing_actual_endpoint_condition_or_binding_refuses_typed_connection(actual,missing_kind):
    snapshot,collection,out=actual
    name='storage' if missing_kind=='binding' else 'guarded'
    full,unit=stripped_catalog(collection,name)
    with FactView(snapshot) as view:
        if name=='guarded':
            g,anchor,target,path,start,goal=guarded_path(view,unit);seeds=[target.node_ref,*path]
            relation_ref=path[-1]
        else:
            g=_Graph(view,view.export_bundle(),unit['anchor']['root_method_ref'])
            item=next(x for x in g.edges.values() if x['record'].binding_refs and x['binding']['location_refs'])
            relation_ref=item['record'].id;seeds=[relation_ref]
        receipts,_,_=replenish(view,full,unit,seeds,out/('full-'+missing_kind+'.sqlite'),include_support=False)
        returned={r['id']:r for receipt in receipts for r in receipt['records']}
        if missing_kind=='endpoint':blocked=target.node_ref
        elif missing_kind=='condition':blocked=next(ref for ref,r in returned.items() if r.get('kind')=='condition')
        else:blocked=item['record'].binding_refs[0]
        partial,clipped=stripped_catalog(collection,name)
        with FactQuerySession(out/('missing-'+missing_kind+'.sqlite'),view,FactQueryBudget(max_queries=128,max_records=2048,max_return_chars=1000000)) as service:
            actual_records,_=query_records(view,service,[ref for ref in returned if ref!=blocked],[0],include_support=False)
            admitted=adapt_query_evidence(partial,view,actual_records,[unit['bu_id']],query_id='missing_'+missing_kind)
        assert blocked in admitted['required_record_refs']
        assert not any(e['category']=='relation' and e['record_ref']==relation_ref for e in partial.entries.values())
        if name=='guarded':assert not any(e['category']=='operation' and e['record_ref']==target.node_ref for e in partial.entries.values())
    out.joinpath('missing-'+missing_kind+'-receipt.json').write_text(json.dumps({'blocked_ref':blocked,'admission':admitted,
        'typed_link_absent':True,'actual_model_calls':0},indent=2)+'\n',encoding='utf-8')


def test_query_support_does_not_expand_to_shared_source_other_consumer(actual):
    snapshot,collection,out=actual;catalog,unit=stripped_catalog(collection,'guarded')
    with FactView(snapshot) as view:
        g,anchor,target,path,start,goal=guarded_path(view,unit)
        replenish(view,catalog,unit,[target.node_ref,*path],out/'boundary-query.sqlite',include_support=False)
        forbidden={m.node_ref for m in g.nodes.values() if g.report.projection.method.units[m.index].invoke and
            '->unrelated(' in g.report.projection.method.units[m.index].invoke.signature}
    assert forbidden
    assert not any(e['category']=='operation' and e['record_ref'] in forbidden for e in catalog.entries.values())


def test_wrong_snapshot_or_forged_current_record_cannot_grant_typed_visibility(actual):
    snapshot,collection,_=actual;catalog,unit=stripped_catalog(collection,'guarded')
    with FactView(snapshot) as view:
        before=deepcopy(catalog.entries)
        forged=deepcopy(unit['model_visible']['records'][0]);forged['run_ref']='run:another_apk'
        result=adapt_query_evidence(catalog,view,[forged],[unit['bu_id']])
        assert result['decisions'][0]['state']=='rejected' and catalog.entries==before
        wrong=deepcopy(catalog);wrong.identity['source_snapshot_id']='f'*64
        with pytest.raises(ValueError,match='exact current APK/run/snapshot'):
            adapt_query_evidence(wrong,view,[],[unit['bu_id']])


def test_receipt_json_key_order_does_not_change_shown_fields_or_admission(actual):
    snapshot,collection,_=actual
    left,unit=stripped_catalog(collection,'guarded');right,_=stripped_catalog(collection,'guarded')
    with FactView(snapshot) as view:
        _,_,target,path,_,_=guarded_path(view,unit)
        records=[r.model_dump(mode='json') for r in view.get_records([target.node_ref,*path],limit=16).records]
        reordered=json.loads(json.dumps(records,sort_keys=True))
        a=adapt_query_evidence(left,view,records,[unit['bu_id']],query_id='same_receipt')
        b=adapt_query_evidence(right,view,reordered,[unit['bu_id']],query_id='same_receipt')
    assert a==b and left.entries==right.entries


def test_new_cross_method_path_keeps_the_other_concrete_caller_out(actual):
    snapshot,collection,out=actual
    with FactView(snapshot) as view:
        facts=view.export_bundle()
        root=next(m.id for m in facts.elements if m.kind=='method' and m.is_definition and '->twice(' in m.signature)
        calls=sorted([c for c in view.read_call_flow().calls if c.caller_ref==root and '->helper(' in c.declared_signature],key=lambda c:c.unit)
        assert len(calls)==2
        original=next(u for u in collection['units'] if u['anchor']['root_method_ref']==root and
                      u['anchor']['call_path'] and u['anchor']['call_path'][0]['callsite_ref']==calls[0].callsite_ref)
        catalog,unit=stripped_catalog(collection,'twice',original)
        g,anchor,target,path,start,goal=guarded_path(view,unit)
        receipts,admissions,audit=replenish(view,catalog,unit,[target.node_ref,*path],out/'caller-query.sqlite',include_support=False)
        packet,state,proposal=proposal_for(catalog,path,start,goal,anchor,target)
        checked,candidate=check_proposal(json.dumps(proposal),packet,state,CurrentMiningConfig())
        assert checked['valid'],checked['errors']
        other_frames={f.context_ref for f in g.frames.values() if f.call_path and f.call_path[0].callsite_ref==calls[1].callsite_ref}
        forbidden={m.node_ref for m in g.nodes.values() if m.frame_ref in other_frames}
    assert forbidden and not any(e['category']=='operation' and e['record_ref'] in forbidden for e in catalog.entries.values())
    out.joinpath('caller-isolation-receipt.json').write_text(json.dumps({'check':checked,'admissions':admissions,
        'forbidden_other_frame_refs':sorted(forbidden),'other_caller_not_admitted':True,'actual_model_calls':0},indent=2)+'\n',encoding='utf-8')


def test_session_actual_typed_queries_resume_and_full_replay_without_model_calls(actual):
    snapshot,collection,out=actual;catalog,unit=stripped_catalog(collection,'guarded')
    with FactView(snapshot) as view:
        g,anchor,target,path,start,goal=guarded_path(view,unit)
        class ProtocolProvider:
            is_real=False
            description={'name':'actual-facts-typed-query-protocol','real_model':False,
                         'fixture_source':'Compiled current APK facts; deterministic proposals only'}
            def generate(self,packet,directory,config):
                visible=packet['evidence']
                ready=(any(e['category']=='operation' and e['record_ref']==target.node_ref for e in visible.values()) and
                    all(any(e['category']=='relation' and e['record_ref']==ref for e in visible.values()) for ref in path))
                if ready:
                    class Shown:
                        entries=visible;units={b:unit for b in packet['manifest']['source_bu_refs']}
                        identity=packet['identity']['source']
                        def render(self,*_):return visible
                    _,_,proposal=proposal_for(Shown(),path,start,goal,anchor,target)
                else:
                    pending=packet.get('fact_query_results',[])
                    refs=(pending[-1]['typed_admission']['required_record_refs'] if pending else [target.node_ref,*path])
                    if not refs:
                        refs=[ref for ref in path if not any(e['category']=='relation' and e['record_ref']==ref for e in visible.values())]
                    queries=[]
                    for ref in refs[:config.max_queries_per_proposal]:
                        q=CurrentFactQuery(query_id='q_'+fingerprint(ref)[:12],query_type='record',
                            apk_sha256=catalog.identity['apk_sha256'],run_ref=catalog.identity['source_run_ref'],
                            subject_ref=ref,limit=64,include_support=not bool(pending),
                            reason='Resolve the explicitly reported missing typed program support.')
                        queries.append(q.model_dump(mode='json'))
                    proposal={'schema_version':'behavior-proposal.v1','upsert_actions':[],'upsert_bcs':[],
                        'delete_action_ids':[],'delete_bc_ids':[],'unresolved_updates':[],
                        'fact_queries':queries,'rationale':'Protocol-only request for actual missing current facts.'}
                proposal.update(request_id=packet['request_id'],base_revision=packet['base_revision'])
                return json.dumps(proposal),{'real_model':False,'protocol_only':True}
        config=CurrentMiningConfig(max_supplement_records=128,max_query_return_chars=250000,
            max_supplement_rounds=4,max_queries_per_proposal=8,max_model_calls=8,max_chunks=24,
            max_request_chars=350000,max_chunk_chars=65000,max_ledger_context_chars=140000)
        provider=ProtocolProvider()
        first,first_report=run_mining(catalog,view,out/'session-runs',provider,config,call_limit=1)
        assert first_report['stop_reason']=='segment_call_limit'
        assert first_report['query_typed_admissions'] and not first_report['accepted_state']['bcs']
        clean,_=stripped_catalog(collection,'guarded')
        continued,report=run_mining(clean,view,out/'session-runs',provider,config,resume_from=first)
        assert report['accepted_state']['bcs']
        assert report['parent']['prior_attempts']==1 and report['attempts'][0]==first_report['attempts'][0]
        replay_catalog,_=stripped_catalog(collection,'guarded')
        verified=verify_package(continued,replay_catalog,view)
    assert verified['valid'] and report['real_model_attempts']==0
    assert report['current_fact_queries']['uses']
    assert report['budgets']['supplement_rounds']<=4 and report['current_fact_queries']['budget_used']['records']<=128
    out.joinpath('session-typed-query-acceptance.json').write_text(json.dumps({'first_run':str(first),'continued_run':str(continued),
        'verification':verified,'first_stop_reason':first_report['stop_reason'],'final_bc_ids':list(report['accepted_state']['bcs']),
        'query_budget':report['current_fact_queries']['budget_used'],'typed_admissions':report['query_typed_admissions'],
        'actual_model_calls':0,'protocol_responses_are_not_semantic_effectiveness_evidence':True},indent=2)+'\n',encoding='utf-8')
