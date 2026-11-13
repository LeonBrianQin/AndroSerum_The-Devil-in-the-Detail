"""Full discovered denominators and cumulative continuation, not APK coverage quality."""
from copy import deepcopy
from types import SimpleNamespace
import json

import pytest
from test_mining_protocol import collection,ProtocolProvider,ProtocolView
from androserum.facts.identity import fingerprint
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import CurrentMiningConfig
from androserum.mining.runner import run_mining
from androserum.mining.verification import verify_package
from androserum.pipeline.workplan import CandidatePlan,discover_plan


class View(ProtocolView):
    run_ref='run:synthetic-mining-protocol'
    snapshot_id='b'*64
    manifest=SimpleNamespace(apk_sha256='a'*64,coverage={'data_flow':'partial'})


def material():
    c=collection(second_bu=True)
    prepared={'apk_sha256':'a'*64,'source_run_ref':c['source_run_ref'],'snapshot':'synthetic-protocol-store',
        'selected_roots':['Lfixture/Case;->root()V'],'available_sapi_roots':['Lfixture/Case;->root()V','Lfixture/Case;->pending()V']}
    matches={'matches':[{'callsite_ref':'instruction:source','method_ref':'method:root','match_id':'match:one'}]}
    return c,prepared,matches


def test_plan_keeps_all_discovered_blocks_and_unmaterialized_root(tmp_path):
    c,p,m=material();config=CurrentMiningConfig(max_chunks=1)
    plan=discover_plan(p,m,c,config)
    blocks=[x for x in plan['items'] if x['kind']=='block']
    assert len(blocks)==2  # A scheduling cap cannot erase the other BU.
    pending=[x for x in plan['items'] if x['kind']=='root' and not x['payload']['selected_for_materialization']]
    assert len(pending)==1 and pending[0]['initial_state']=='pending'
    with CandidatePlan(tmp_path,plan,budget={'max_model_calls':2,'max_input_chars':1000000,'max_reported_input_tokens':100000}) as progress:
        assert not progress.report()['apk_all_discovered_work_completed']
        assert progress.report()['by_kind']['block']=={'pending':2}


def test_two_segments_preserve_budget_audit_and_full_pending_plan(tmp_path):
    c,p,m=material();config=CurrentMiningConfig(max_model_calls=2)
    catalog=lambda:EvidenceCatalog(c,[u['bu_id'] for u in c['units']])
    plan=discover_plan(p,m,c,config);budget={'max_model_calls':2,'max_input_chars':1000000,'max_reported_input_tokens':100000}
    first,a=run_mining(catalog(),View(),tmp_path/'runs',ProtocolProvider(),config,call_limit=1)
    with CandidatePlan(tmp_path/'progress',plan,budget=budget) as progress:
        progress.sync_mining(first,a)
        assert progress.report()['by_kind']['block']=={'pending':1,'completed':1}
        assert progress.remaining()['max_model_calls']==1
        head=progress.report()['audit_head']
    second,b=run_mining(catalog(),View(),tmp_path/'runs',ProtocolProvider(),config,resume_from=first)
    with CandidatePlan(tmp_path/'progress',plan,budget=budget) as progress:
        progress.sync_mining(second,b);report=progress.report()
        assert report['by_kind']['block']=={'completed':2}
        assert progress.remaining()['max_model_calls']==0
        assert report['audit_head']!=head
        event_count=len(report['events']);progress.sync_mining(second,b)
        assert len(progress.report()['events'])==event_count
        assert not report['apk_all_discovered_work_completed']  # Omitted root still pending.
    assert verify_package(second,catalog(),View())['valid']
    with pytest.raises(ValueError,match='Cannot change'):
        CandidatePlan(tmp_path/'progress',plan,budget={**budget,'max_model_calls':3})


def test_preflight_stop_stays_pending_and_can_continue_without_empty_request_collision(tmp_path):
    class StopProvider(ProtocolProvider):
        def preflight(self,packet,config):return 'complete_plan_cumulative_input_budget'
    c,_,_=material();cat=lambda:EvidenceCatalog(c,[u['bu_id'] for u in c['units']])
    config=CurrentMiningConfig(max_model_calls=2)
    provider=StopProvider()
    first,a=run_mining(cat(),View(),tmp_path,provider,config)
    assert a['budgets']['model_calls']==0 and a['coverage']['states']=={'unprocessed':2}
    assert a['stop_reason']=='complete_plan_cumulative_input_budget'
    assert verify_package(first,cat(),View())['valid']
    second,b=run_mining(cat(),View(),tmp_path,ProtocolProvider(),config,resume_from=first)
    assert b['budgets']['model_calls']==2 and b['coverage']['states']=={'accepted':2}
    assert verify_package(second,cat(),View())['valid']


def test_reservation_survives_reopen_and_budget_mapping_does_not_depend_on_key_order(tmp_path):
    c,p,m=material();plan=discover_plan(p,m,c,CurrentMiningConfig())
    budget={'max_reported_input_tokens':5,'max_input_chars':100,'max_model_calls':1}
    with CandidatePlan(tmp_path,plan,budget=budget) as progress:
        assert progress.remaining()==budget
        assert progress.reserve('request:interrupted',80) is None
    with CandidatePlan(tmp_path,plan,budget=budget) as progress:
        assert progress.remaining()=={'max_model_calls':0,'max_input_chars':20,'max_reported_input_tokens':5}
        assert progress.reserve('request:new',10)=='complete_plan_cumulative_call_budget'
        assert progress.report()['dispatch_reservations'][0]['status']=='reserved_dispatch_not_confirmed'


def test_downstream_uses_actual_candidates_and_keeps_definition_blocks_pending(tmp_path):
    c,p,m=material();config=CurrentMiningConfig(max_model_calls=2)
    cat=EvidenceCatalog(c,[u['bu_id'] for u in c['units']])
    run,report=run_mining(cat,View(),tmp_path/'runs',ProtocolProvider(),config,call_limit=1)
    plan=discover_plan(p,m,c,config);budget={'max_model_calls':2,'max_input_chars':1000000,'max_reported_input_tokens':100000}
    bid=next(iter(report['accepted_state']['bcs']))
    entries=[{'qualified_ref':'qualified:one','bc':report['accepted_state']['bcs'][bid],'ledger_revision':1}]
    encoding=tmp_path/'encoding';encoding.mkdir();(encoding/'manifest.json').write_text('{}')
    recalls=[{'query_ref':'qualified:one','ranked_candidates':[{'instance_ref':'h1','cosine':.8},{'instance_ref':'h2','cosine':.7}]}]
    matches=[{'bc_id':bid,'reference_ref':'h1','accepted':{'decision':'\u8bc1\u636e\u4e0d\u8db3'},'attempts':[{'checked':True}]},
             {'bc_id':bid,'reference_ref':'h2','accepted':None,'attempts':[]}]
    tasks=[{'task_id':'ti','kind':'threat_intelligence','directory':'actual-task-output','result':
        {'status':'completed','state':{'seen_bc_ids':[bid],'synthesis':{'summary':'possible only'}}}},
        {'task_id':'classification','kind':'malware_classification','directory':'blocked-definition','result':{'status':'blocked'}}]
    with CandidatePlan(tmp_path/'progress',plan,budget=budget) as progress:
        progress.sync_mining(run,report)
        progress.sync_downstream(entries,encoding=encoding,recalls=recalls,matches=matches,task_runs=tasks)
        actual=progress.report()
        assert actual['by_kind']['bc_encoding']=={'completed':1}
        assert actual['by_kind']['reference_candidate']=={'completed':1,'pending':1}
        assert actual['by_kind']['bc_matching']=={'pending':1}
        assert actual['by_kind']['task_synthesis']=={'completed':1,'pending':1}
        assert actual['by_kind']['bc_task']=={'pending':1}
        assert not actual['apk_all_discovered_work_completed']
        events=len(actual['events'])
        progress.sync_downstream(entries,encoding=encoding,recalls=recalls,matches=matches,task_runs=tasks)
        assert len(progress.report()['events'])==events
