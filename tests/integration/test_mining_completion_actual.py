"""Post-BU query/review over the existing compiled APK fixture, no LLM."""
from copy import deepcopy
import json

import pytest

from test_query_evidence import actual, stripped_catalog, guarded_path, proposal_for
from androserum.facts.identity import fingerprint
from androserum.facts.queries import CurrentFactQuery
from androserum.facts.store import FactView
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import CurrentMiningConfig
from androserum.mining.runner import run_mining
from androserum.mining.verification import verify_package
from androserum.pipeline.mining_completion import finalize_mining
from androserum.pipeline.workplan import CandidatePlan, discover_plan


@pytest.mark.parametrize('production_two,reverse',[(False,False),(False,True),(True,False)],
                         ids=['configurable16-positive','configurable16-reverse','production2-budget'])
def test_automatic_final_query_actual_typed_admission_and_rejection(actual,reverse,production_two):
    snapshot,collection,output=actual;catalog,unit=stripped_catalog(collection,'guarded')
    case=output/(('production2-' if production_two else '') + ('automatic-final-reverse' if reverse else 'automatic-final-positive'))
    case.mkdir(parents=True,exist_ok=True)
    clean=lambda:EvidenceCatalog({**catalog.identity,'units':[deepcopy(unit)]},[unit['bu_id']])
    config=CurrentMiningConfig(max_model_calls=8,max_supplement_records=128,max_query_return_chars=250000,
        max_supplement_rounds=4,max_queries_per_proposal=2 if production_two else 16,max_request_chars=350000,
        max_chunk_chars=65000,max_ledger_context_chars=140000)
    with FactView(snapshot) as view:
        graph,anchor,target,path,start,goal=guarded_path(view,unit)
        class Provider:
            is_real=False
            description={'kind':'compiled-current-facts-automatic-final-review-protocol','real_model':False}
            def generate(self,packet,directory,config):
                visible=packet['evidence'];oh=next(h for h,e in visible.items() if e['category']=='operation' and e['record_ref']==anchor.node_ref)
                issue={'issue_id':'late_path','subject_ids':['read'],'description':'Need actual current facts to establish or reject the downstream guarded transfer.',
                       'evidence_refs':[oh],'status':'open'}
                empty={'availability':'unknown','description':'Not established from current visible evidence.','endpoint_refs':[]}
                proposal={'schema_version':'behavior-proposal.v1','request_id':packet['request_id'],'base_revision':packet['base_revision'],
                          'upsert_actions':[],'upsert_bcs':[],'delete_action_ids':[],'delete_bc_ids':[],
                          'unresolved_updates':[],'fact_queries':[],'rationale':'Deterministic protocol using actual current compiled APK evidence only.'}
                if not packet.get('work_context',{}).get('review_task'):
                    proposal['upsert_actions']=[{'action_id':'read','function':'Protocol fixture: retain the visible read operation.',
                        'operation_refs':[oh],'objects':empty,'inputs':empty,'outputs':empty,
                        'condition_status':'recorded_local' if visible[oh]['condition_refs'] else 'unknown',
                        'condition_refs':visible[oh]['condition_refs'],'effect_refs':[],'support_relation_refs':[],
                        'support_fact_refs':[],'limitation_notes':['Protocol only; no natural-language quality or execution claim.']}]
                    proposal['unresolved_updates']=[issue]
                elif (any(e['category']=='operation' and e['record_ref']==target.node_ref for e in visible.values()) and
                      all(any(e['category']=='relation' and e['record_ref']==ref for e in visible.values()) for ref in path)):
                    class Shown:
                        entries=visible;units={b:unit for b in packet['manifest']['source_bu_refs']};identity=catalog.identity
                        def render(self,*args):return visible
                    _,_,proposal=proposal_for(Shown(),path,start,goal,anchor,target)
                    proposal.update(request_id=packet['request_id'],base_revision=packet['base_revision'],
                                    unresolved_updates=[{**issue,'status':'resolved'}])
                    if reverse:
                        link=proposal['upsert_bcs'][0]['relations'][0]
                        link['source_endpoint_ref'],link['target_endpoint_ref']=link['target_endpoint_ref'],link['source_endpoint_ref']
                else:
                    pending=packet.get('fact_query_results',[])
                    typed=[p['typed_admission'] for p in pending if 'typed_admission' in p]
                    refs=typed[-1]['required_record_refs'] if typed else [target.node_ref,*path]
                    proposal['fact_queries']=[CurrentFactQuery(query_id='late_'+fingerprint(ref)[:12],query_type='record',
                        apk_sha256=view.manifest.apk_sha256,run_ref=view.run_ref,subject_ref=ref,limit=64,
                        include_support=not bool(pending),reason='Resolve the ledger late_path issue with actual typed program support.').model_dump(mode='json')
                        for ref in refs[:config.max_queries_per_proposal]]
                    if production_two and not pending:
                        proposal['fact_queries']=[CurrentFactQuery(query_id='late_target',query_type='record',
                            apk_sha256=view.manifest.apk_sha256,run_ref=view.run_ref,subject_ref=target.node_ref,
                            limit=64,include_support=True,reason='Query the missing downstream operation and its bounded explicit support.').model_dump(mode='json'),
                            CurrentFactQuery(query_id='late_dependencies',query_type='data_dependency',
                            apk_sha256=view.manifest.apk_sha256,run_ref=view.run_ref,endpoint=start,direction='out',
                            max_hops=4,limit=64,include_support=True,
                            reason='Query the bounded recorded uses of this exact current result endpoint; returned edges require typed admission.').model_dump(mode='json')]
                return json.dumps(proposal),{'real_model':False,'protocol_only':True}
        provider=Provider();base,first=run_mining(clean(),view,case/'runs',provider,config,call_limit=1)
        assert first['coverage']['all_planned_chunks_terminal'] and not first['accepted_state']['bcs']
        prepared={'apk_sha256':view.manifest.apk_sha256,'source_run_ref':view.run_ref,'snapshot':str(snapshot),
                  'available_sapi_roots':[],'selected_roots':[]}
        plan=discover_plan(prepared,{'matches':[]},{**catalog.identity,'units':[unit]},config)
        with CandidatePlan(case/'complete-plan',plan,budget={'max_model_calls':8,'max_input_chars':3000000,
                           'max_reported_input_tokens':200000}) as progress:
            progress.sync_mining(base,first)
            final,report,status=finalize_mining(clean(),view,case/'runs',provider,config,progress,base,first,remaining_segment_calls=7)
            checked=verify_package(final,clean(),view)
            assert checked['valid'] and report['current_fact_queries']['queries']
            assert report['query_typed_admissions']
            budget_limited=production_two and not report['accepted_state']['bcs']
            if budget_limited:
                assert status['status']=='partial'
                assert report['accepted_state']['actions']==first['accepted_state']['actions']
                assert report['accepted_state']['unresolved']['late_path']['status']=='open'
                assert not report['current_fact_queries']['uses']
                assert report['budgets']['model_calls']<=4
                assert report['current_fact_queries']['budget_used']['records']<=128
            elif reverse:
                assert report['accepted_state']['actions']==first['accepted_state']['actions'] and not report['accepted_state']['bcs']
                assert report['attempts'][-1]['base_revision']==report['attempts'][-1]['after_revision']
                assert status['status']=='partial'
            else:
                assert report['accepted_state']['bcs'] and report['current_fact_queries']['uses']
                assert report['accepted_state']['unresolved']['late_path']['status']=='resolved'
            receipt={'schema_version':'automatic-final-compiled-protocol.v1','case':'reversed_path' if reverse else 'positive',
                'base_run':str(base),'final_run':str(final),'verification':checked,'completion':status,
                'source_snapshot':str(snapshot),'source_run_ref':view.run_ref,
                'initial_open_issue':first['accepted_state']['unresolved'],'final_bc_ids':list(report['accepted_state']['bcs']),
                'query_service':report['current_fact_queries'],'typed_admissions':report['query_typed_admissions'],
                'attempt_statuses':[a['status'] for a in report['attempts']],
                'protocol_responses_are_not_real_model_quality':True,'actual_LLM_calls':0,'new_solver_runs':0}
            receipt['protocol_setting']=config.model_dump(mode='json')
            receipt['scope_result']='budget_limited_query_return_without_accepted_use' if budget_limited else 'reversed_link_rejected' if reverse else 'queried_and_accepted_use'
            receipt['production_two_queries_resolved']=production_two and bool(report['accepted_state']['bcs'])
            (case/'acceptance.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')


def test_normal_workplan_multiple_actual_query_rounds_resume_strictly(actual,monkeypatch):
    from androserum.pipeline.workplan import mine_complete_prepared
    snapshot,collection,output=actual;catalog,unit=stripped_catalog(collection,'guarded')
    root=output/'normal-multiple-query-rounds';out=root/'samples'/'normal'
    clean=lambda:EvidenceCatalog({**catalog.identity,'units':[deepcopy(unit)]},[unit['bu_id']])
    config=CurrentMiningConfig(max_model_calls=8,max_supplement_records=128,max_query_return_chars=250000,
        max_supplement_rounds=4,max_queries_per_proposal=16,max_request_chars=350000,
        max_chunk_chars=65000,max_ledger_context_chars=140000)
    def dump(file,value):file.parent.mkdir(parents=True,exist_ok=True);file.write_text(json.dumps(value),encoding='utf-8')
    package=root/'source-collection';dump(package/'collection.json',{**catalog.identity,'units':[unit]})
    source={'mining':{'schema_version':'mining-config.v1'}};dump(out/'config.json',source)
    dump(out/'prepared.json',{'apk_sha256':catalog.identity['apk_sha256'],'source_run_ref':catalog.identity['source_run_ref'],
        'snapshot':str(snapshot),'bu_package':str(package),'config_sha256':fingerprint(source)})
    dump(out/'sapi-matches.json',{'matches':[]})
    dump(root/'experiment-config.json',{'effective_mining_policy':config.model_dump(mode='json'),
        'per_sample_mining_call_limit':8,'aggregate_input_char_limit':3000000,'reported_input_token_stop':200000})
    with FactView(snapshot) as view:
        graph,anchor,target,path,start,goal=guarded_path(view,unit)
        class Provider:
            is_real=False
            description={'kind':'compiled-ordinary-workplan-query-protocol','real_model':False}
            def close(self):pass
            def generate(self,packet,directory,config):
                visible=packet['evidence']
                if (any(e['category']=='operation' and e['record_ref']==target.node_ref for e in visible.values()) and
                    all(any(e['category']=='relation' and e['record_ref']==ref for e in visible.values()) for ref in path)):
                    class Shown:
                        entries=visible;units={b:unit for b in packet['manifest']['source_bu_refs']};identity=catalog.identity
                        def render(self,*args):return visible
                    _,_,proposal=proposal_for(Shown(),path,start,goal,anchor,target)
                else:
                    pending=packet.get('fact_query_results',[])
                    typed=[p['typed_admission'] for p in pending if 'typed_admission' in p]
                    refs=typed[-1]['required_record_refs'] if typed else [target.node_ref,*path]
                    proposal={'schema_version':'behavior-proposal.v1','upsert_actions':[],'upsert_bcs':[],
                        'delete_action_ids':[],'delete_bc_ids':[],'unresolved_updates':[],
                        'fact_queries':[CurrentFactQuery(query_id='normal_'+fingerprint(ref)[:12],query_type='record',
                            apk_sha256=view.manifest.apk_sha256,run_ref=view.run_ref,subject_ref=ref,limit=64,
                            include_support=not bool(pending),reason='Protocol current-fact query for explicit missing typed support.').model_dump(mode='json')
                            for ref in refs[:config.max_queries_per_proposal]],'rationale':'Protocol-only actual current query.'}
                proposal.update(request_id=packet['request_id'],base_revision=packet['base_revision'])
                return json.dumps(proposal),{'real_model':False,'protocol_only':True}
        provider=Provider();loaded=[]
        monkeypatch.setattr('androserum.pipeline.provider.PipelineProvider',lambda *args:provider)
        monkeypatch.setattr('androserum.mining.runner.load_catalog',lambda *args:(loaded.append(True),clean())[1])
        result=mine_complete_prepared(root,'normal',call_limit=7)
        from androserum.facts.identity import filesystem_path
        report=json.loads((filesystem_path(result['mining_run'])/'report.json').read_text())
        checked=verify_package(result['mining_run'],clean(),view)
    assert checked['valid'] and len(loaded)==1
    assert report['budgets']['supplement_rounds']==2 and report['budgets']['model_calls']==3
    assert report['accepted_state']['bcs'] and report['current_fact_queries']['uses']
    assert len(list((out/'mining').glob('mining_*')))==3
    assert len(list((out/'mining-result-history').glob('*.json')))>=2
    dump(root/'acceptance.json',{'schema_version':'normal-workplan-multiple-query-rounds.v1','result':result,
        'verification':checked,'query_service':report['current_fact_queries'],'catalog_loads':len(loaded),
        'immutable_native_segments':3,'actual_model_calls':0,'new_solver_runs':0,
        'protocol_setting':config.model_dump(mode='json'),'production_round_config_changed':False})
