import json
from copy import deepcopy
import pytest
from androserum.facts.identity import fingerprint,sha256_file
from androserum.inference.provider import write
from androserum.pipeline.provider import PipelineBudget
from androserum.pipeline.batch_budget import initialize,report,reason

def fixture(tmp_path,*,pilot=2,total=3,chars=100,per_apk=2):
    root=tmp_path/'batch';root.mkdir()
    policy={'pilot_caps':{'call_attempts':pilot,'reserved_input_chars':chars,'reported_input_token_stop':10},
        'whole_batch_caps':{'call_attempts':total,'reserved_input_chars':chars*2,'reported_input_token_stop':20},
        'per_apk_call_attempts_cap':per_apk}
    plan={'pilot_sample_ids':['a','b']}
    write(root/'policy.frozen.json',policy);write(root/'measured-dispatch-plan.json',plan);initialize(root,policy,plan)
    cfg={'call_limits':{'mining':20},'aggregate_input_char_limit':10000,'reported_input_token_stop':10000}
    def child(sid):
        p=root/sid;p.mkdir(exist_ok=True)
        body={'batch_root':str(root),'sample_id':sid,'child_config_sha256':fingerprint(cfg),
            'files':{n:sha256_file(root/n) for n in ['policy.frozen.json','measured-dispatch-plan.json']}}
        write(p/'batch-budget-binding.json',{**body,'binding_sha256':fingerprint(body)})
        return PipelineBudget(p/'real-call-budget.sqlite',cfg)
    return root,child

def finish(b,cid,tokens=1):
    b.finish(cid,{'status':'completed','usage':{'input_tokens':tokens,'output_tokens':1,'cached_input_tokens':0}})

def test_atomic_cross_sample_pilot_and_all_stage_reservations(tmp_path):
    root,child=fixture(tmp_path)
    a=child('a');b=child('b')
    a.stage('a',30);a.reserve('mining','a:1')
    b.stage('b',30)
    with pytest.raises(ValueError,match='unconfirmed'):b.reserve('mining','b:1')
    assert not b.report()['calls']
    finish(a,'a:1');b.reserve('mining','b:1');finish(b,'b:1')
    a.stage('a',1)
    with pytest.raises(ValueError,match='pilot_call_cap'):a.reserve('mining','a:2')
    assert len(a.report()['calls'])==1 and report(root)['whole_batch']['call_attempts']==2
    a.close();b.close()

def test_unknown_usage_stops_and_resume_cannot_reset(tmp_path):
    root,child=fixture(tmp_path);a=child('a');a.stage('a',1);a.reserve('mining','a:1')
    a.finish('a:1',{'status':'timeout'});a.close();b=child('b')
    assert reason(b,'b',1)=='batch_unknown_input_usage_stop'
    b.stage('b',1)
    with pytest.raises(ValueError,match='unknown_input_usage'):b.reserve('mining','b:1')
    assert report(root)['whole_batch']['usage_unknown_calls']==1;b.close()

def test_character_reservation_and_reported_token_stop(tmp_path):
    root,child=fixture(tmp_path,chars=40);a=child('a');a.stage('a',41)
    with pytest.raises(ValueError,match='pilot_input_char_cap'):a.reserve('mining','a:1')
    assert report(root)['whole_batch']['call_attempts']==0
    a.stage('a',10);a.reserve('mining','a:1');finish(a,'a:1',10)
    assert reason(a,'a',1)=='pilot_reported_token_stop';a.close()

def test_child_sql_failure_rolls_back_global_reservation(tmp_path):
    root,child=fixture(tmp_path);a=child('a')
    a.db.execute("CREATE TRIGGER reject_test BEFORE INSERT ON calls BEGIN SELECT RAISE(ABORT,'injected local write failure'); END")
    a.stage('a',10)
    with pytest.raises(Exception,match='injected'):a.reserve('mining','a:1')
    assert report(root)['whole_batch']['call_attempts']==0;a.close()

def test_frozen_binding_tamper_rejected(tmp_path):
    root,child=fixture(tmp_path);a=child('a');a.close()
    old=json.loads((root/'policy.frozen.json').read_text());old['per_apk_call_attempts_cap']=999
    write(root/'policy.frozen.json',old)
    with pytest.raises(ValueError,match='identity differs'):child('a')

def test_explicit_refusal_stops_same_sample_without_dropping_cost(tmp_path):
    root,child=fixture(tmp_path);a=child('a');a.stage('a',10);a.reserve('mining','a:1')
    a.finish('a:1',{'status':'failed','service_refusal':True,'usage':{'input_tokens':1,'output_tokens':1,'cached_input_tokens':0}})
    assert reason(a,'a',1)=='sample_terminal_safety_refusal_no_retry'
    b=child('b');assert reason(b,'b',1) is None
    assert report(root)['whole_batch']['call_attempts']==1
    a.close();b.close()

def test_empty_scope_resume_requires_unchanged_source_and_no_pending_anchor(tmp_path):
    from androserum.pipeline.workplan import _no_automatic_work_remaining
    apk=tmp_path/'input.apk';apk.write_bytes(b'protocol identity only')
    snapshot=tmp_path/'snapshot';snapshot.mkdir();db=snapshot/'facts.sqlite';db.write_bytes(b'protocol snapshot hash only')
    write(snapshot/'manifest.json',{'database_sha256':sha256_file(db)})
    prepared={'snapshot':str(snapshot),'input_apk':str(apk),'apk_sha256':sha256_file(apk)}
    previous={'status':'no_materialized_bu','actual_llm_calls':0,'apk_sha256':prepared['apk_sha256'],'mining_run':None}
    assert _no_automatic_work_remaining(tmp_path,prepared,{'items':[]},previous)
    assert not _no_automatic_work_remaining(tmp_path,prepared,{'items':[{'kind':'physical_anchor'}]},previous)
    apk.write_bytes(b'changed')
    with pytest.raises(ValueError,match='source identity changed'):
        _no_automatic_work_remaining(tmp_path,prepared,{'items':[]},previous)
