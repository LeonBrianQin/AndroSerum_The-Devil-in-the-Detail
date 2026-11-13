from copy import deepcopy
import shutil

import pytest
from test_current_fact_queries import snapshot,q
from androserum.facts.store import FactView
from androserum.facts.identity import sha256_file,fingerprint
from androserum.facts.queries import FactQuerySession,FactQueryBudget
from androserum.facts.query_reuse import ReusableFactQuerySession,verify_reuse_report,records_for


def test_exact_reuse_does_not_refund_legacy_duplicates_or_return_them_again(snapshot,tmp_path):
    old=tmp_path/'old.sqlite';new=tmp_path/'new.sqlite';budget=FactQueryBudget(max_queries=6,max_records=2)
    with FactView(snapshot) as view:
        first=q(view,'record',subject_ref='method:run',include_support=False)
        with FactQuerySession(old,view,budget) as service:
            service.execute(first)
            service.execute(first.model_copy(update={'query_id':'duplicate_legacy'}))
            legacy=service.report()
        digest=sha256_file(old);shutil.copyfile(old,new)
        with ReusableFactQuerySession(new,view,budget) as service:
            got=service.execute(first.model_copy(update={'query_id':'cached_new'}))
            assert not got['records'] and len(got['reused_records'])==1
            assert got['state']=='completed'
            assert records_for(got,service.report())[0]['id']=='method:run'
            service.record_use(got['receipt_id'],'accepted_new',['method:run'])
            blocked=service.execute(q(view,'resource',name='query_name',include_support=False))
            assert blocked['state']=='budget_exhausted'
            report=service.report()
            assert report['queries'][:2]==legacy['queries']
            assert report['budget_used']['records']==2
            assert verify_reuse_report(report,view)['valid']
        assert sha256_file(old)==digest
        with ReusableFactQuerySession(new,view,budget) as service:
            assert service.execute(first.model_copy(update={'query_id':'cached_new'}))==got


def test_explicit_cumulative_budget_amendment_and_forged_reuse_rejected(snapshot,tmp_path):
    old=tmp_path/'old.sqlite';new=tmp_path/'new.sqlite'
    with FactView(snapshot) as view:
        with FactQuerySession(old,view,FactQueryBudget(max_queries=6,max_records=1)) as service:
            service.execute(q(view,'record',subject_ref='method:run',include_support=False))
        shutil.copyfile(old,new)
        cap=FactQueryBudget(max_queries=6,max_records=2)
        with pytest.raises(ValueError,match='explicit cumulative'):
            ReusableFactQuerySession(new,view,cap)
        with ReusableFactQuerySession(new,view,cap,amendment_reason='Protocol-only bounded successor; preserve one old charge') as service:
            service.execute(q(view,'resource',name='query_name',include_support=False))
            service.execute(q(view,'record',subject_ref='method:run',include_support=False).model_copy(update={'query_id':'reuse'}))
            report=service.report();assert report['budget_used']['records']==2
            assert verify_reuse_report(report,view)['valid']
            forged=deepcopy(report);r=forged['queries'][-1];r['reused_records'][0]['record_sha256']='0'*64
            r.pop('receipt_id');r['receipt_id']='fact-query:'+fingerprint(r)
            with pytest.raises(ValueError):verify_reuse_report(forged,view)
            with pytest.raises(ValueError):service.record_use(report['queries'][-1]['receipt_id'],'bad',['resource:query'])
            with pytest.raises(ValueError):service.execute(q(view,'record',subject_ref='method:run').model_copy(update={'apk_sha256':'f'*64}))


def test_required_ledger_closure_is_editable_or_no_request_is_dispatched():
    import json
    from test_mining_protocol import collection,initial,valid_proposal
    from androserum.mining.evidence import EvidenceCatalog
    from androserum.mining.models import MiningConfig
    from androserum.mining.assembly import make_packet
    from androserum.mining.checker import check_proposal
    cat=EvidenceCatalog(collection(),['bu:protocol-a']);cfg=MiningConfig()
    chunk=cat.chunks(cfg)[0][0];state=initial(cat)
    packet=make_packet(cat,chunk,state,cfg,'initial')
    check,state=check_proposal(json.dumps(valid_proposal(packet)),packet,state,cfg);assert check['valid']
    visible=make_packet(cat,chunk,state,cfg,'review',required_ledger_ids=['bc_local','a_read'])
    assert 'bc_local' in visible['ledger_context']['bcs'] and 'a_read' in visible['ledger_context']['actions']
    small=cfg.model_copy(update={'max_ledger_context_chars':1})
    ordinary=make_packet(cat,chunk,state,small,'ordinary');assert ordinary['ledger_context_deferred']
    with pytest.raises(ValueError,match='Required review closure'):
        make_packet(cat,chunk,state,small,'must_not_dispatch',required_ledger_ids=['bc_local'])


def test_native_mining_continuation_reuses_query_support_and_preserves_spend(tmp_path,monkeypatch):
    import json
    from test_mining_current_queries import View,QueryProvider
    from test_mining_protocol import collection,ProtocolProvider,valid_proposal
    from androserum.mining.evidence import EvidenceCatalog
    from androserum.mining.models import CurrentMiningConfig
    from androserum.mining.runner import run_mining
    from androserum.mining.verification import verify_package
    from androserum.facts.queries import CurrentFactQuery
    from androserum.facts.query_reuse import POLICY
    def adapter(cat,view,records,bus,*,query_id):
        hs=[cat.supplement(r,query_id,bus) for r in records]
        return {'schema_version':'protocol-raw-query-admission','added_handles':hs,
            'decisions':[{'record_ref':r['id'],'state':'raw_fact_only'} for r in records],'required_record_refs':[]}
    monkeypatch.setattr('androserum.facts.query_evidence.adapt_query_evidence',adapter)
    data=collection()
    for r in data['units'][0]['model_visible']['records']:
        if 'provenance' in r:r['provenance']['support_refs']=[]
    cat=lambda:EvidenceCatalog(data,['bu:protocol-a'])
    cfg=CurrentMiningConfig(max_model_calls=2,max_supplement_rounds=4,max_supplement_records=1,max_queries_per_proposal=1)
    initial,unused=run_mining(cat(),View(),tmp_path/'mining',QueryProvider(),cfg,call_limit=1)
    first,old=run_mining(cat(),View(),tmp_path/'mining',QueryProvider(),cfg,resume_from=initial,call_limit=1)
    assert old['budgets']['model_calls']==2 and old['budgets']['supplement_records']==1
    class ReuseProvider(ProtocolProvider):
        def generate(self,packet,directory,config):
            value=valid_proposal(packet)
            if not packet.get('fact_query_results'):
                value['fact_queries']=[CurrentFactQuery(query_id='reuse_detail',query_type='record',apk_sha256='a'*64,
                    run_ref=View.run_ref,subject_ref='analysis:detail',include_support=False,reason='Reuse exact known detail').model_dump(mode='json')]
            else:
                value['upsert_actions'][0]['support_fact_refs']=[h for h,e in packet['evidence'].items() if e.get('record_ref')=='analysis:detail']
            return json.dumps(value),{'real_model':False}
    task={'amendment_id':'reuse_review','kind':'consolidation','reason':'Protocol exact prior support reuse',
        'instruction':'Review accepted support','target_chunk_ids':[old['chunk_progress'][0]['chunk_id']],
        'max_attempts':2,'required_ledger_ids':['bc_local','a_read']}
    second,new=run_mining(cat(),View(),tmp_path/'mining',ReuseProvider(),cfg.model_copy(update={'max_model_calls':4}),
        resume_from=first,budget_amendment_reason='Protocol cumulative cap4 includes the prior2 attempts',
        work_amendment=task,query_delivery_policy=POLICY)
    assert new['budgets']['model_calls']==4 and new['budgets']['supplement_records']==1
    assert new['attempts'][:2]==old['attempts']
    assert new['current_fact_queries']['queries'][-1]['reused_records']
    assert not new['current_fact_queries']['queries'][-1]['records']
    assert verify_package(second,cat(),View())['valid']
