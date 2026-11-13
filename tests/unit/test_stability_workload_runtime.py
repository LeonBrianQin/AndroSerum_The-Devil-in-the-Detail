"""Stage guards for actual workload execution; no model output is simulated."""
import json
import pytest

from androserum.facts.identity import fingerprint, sha256_file
from androserum.pipeline.provider import PipelineBudget, workload_allowance, workload_stage
from androserum.pipeline.rounds import _limits
from androserum.pipeline.analyze import _authorize_workload_downstream


def workload():
    body = {'schema_version':'stability-workload-budget.v1','scope_sha256':'a'*64,
        'packing_profile':'lossless-compact.v2',
        'per_sample_call_caps':{'mining':8,'matching':6,'task':8},
        'ordinary_mining_call_cap':4,'reserved_final_mining_calls':4,
        'task_synthesis_reserved_calls':2,'measured_block_count':2}
    return {**body,'budget_id':fingerprint(body)}


def config():
    return {'call_limits':{'mining':8,'matching':6,'task':8},
        'per_sample_mining_call_limit':8,'per_sample_matching_call_limit':6,'per_sample_task_call_limit':8,
        'aggregate_input_char_limit':1000000,'reported_input_token_stop':100000,
        'workload_budget':workload()}


def authorize(root, channel, caps):
    manifest=root/'input-manifest.json';manifest.write_text('{}',encoding='utf-8')
    body={'schema_version':'workload-stage-authorization.v1','budget_id':workload()['budget_id'],
        'sample_id':'sample','channel':channel,'stage_call_caps':caps,
        'frozen_inputs':[{'path':str(manifest),'sha256':sha256_file(manifest)}]}
    folder=root/'stage-authorizations';folder.mkdir(exist_ok=True)
    (folder/('sample.'+channel+'.json')).write_text(json.dumps({**body,
        'authorization_sha256':fingerprint(body)}),encoding='utf-8')


def reserve(budget, stage, index, phase='mining'):
    budget.stage('sample',10,stage)
    budget.reserve(phase,'sample:'+str(index))


def test_ordinary_cannot_borrow_final_reserve_and_counts_survive_resume(tmp_path):
    path=tmp_path/'budget.sqlite'
    with pytest.raises(ValueError,match='stage/reserve'):
        b=PipelineBudget(path,config())
        try:
            for index in range(4):reserve(b,'ordinary_mining',index)
            reserve(b,'ordinary_mining',4)
        finally:b.close()
    b=PipelineBudget(path,config())
    try:
        assert len(b.report()['calls'])==4
        with pytest.raises(ValueError,match='stage/reserve'):reserve(b,'final_mining','no-auth')
        authorize(tmp_path,'final_mining',{'final_mining':1})
        reserve(b,'final_mining','final')
        with pytest.raises(ValueError,match='stage/reserve'):reserve(b,'final_mining','extra')
        assert len(b.report()['calls'])==5
    finally:b.close()


def test_actual_stage_authority_cannot_outlive_its_input(tmp_path):
    authorize(tmp_path,'final_mining',{'final_mining':1})
    assert workload_allowance(tmp_path,config(),'sample','final_mining')==1
    (tmp_path/'input-manifest.json').write_text('{"changed":true}',encoding='utf-8')
    with pytest.raises(ValueError,match='input changed'):
        workload_allowance(tmp_path,config(),'sample','final_mining')


def test_incremental_cannot_consume_synthesis_allowance(tmp_path):
    authorize(tmp_path,'downstream',{'task_incremental':2,'task_synthesis':2,'matching':2})
    b=PipelineBudget(tmp_path/'budget.sqlite',config())
    try:
        reserve(b,'task_incremental',0,'task');reserve(b,'task_incremental',1,'task')
        with pytest.raises(ValueError,match='stage/reserve'):reserve(b,'task_incremental',2,'task')
        reserve(b,'task_synthesis',3,'task');reserve(b,'task_synthesis',4,'task')
        assert len(b.report()['calls'])==4
    finally:b.close()


def test_legacy_round_creates_no_new_workload_reservation_table(tmp_path):
    old=config();old.pop('workload_budget')
    b=PipelineBudget(tmp_path/'budget.sqlite',old)
    try:
        b.stage('sample',10);b.reserve('mining','sample:0')
        assert not b.db.execute("SELECT name FROM sqlite_master WHERE name='workload_reservations'").fetchall()
    finally:b.close()


def test_real_packet_stage_shapes_are_classified_without_semantic_guesses():
    assert workload_stage({'work_context':{'review_task':{'amendment_id':'auto-final:123'}}},'mining')=='final_mining'
    assert workload_stage({'work_context':{'review_task':None}},'mining')=='ordinary_mining'
    assert workload_stage({'task_request':{'phase':'synthesis'}},'task')=='task_synthesis'
    assert workload_stage({'task_request':{'phase':'incremental'}},'task')=='task_incremental'


def test_larger_call_caps_require_a_frozen_workload_not_a_silent_clamp():
    supplied={'per_sample_mining_call_limit':8,'per_sample_matching_call_limit':6,'per_sample_task_call_limit':8}
    with pytest.raises(ValueError,match='out of supported bounds'):_limits(1,supplied)
    assert _limits(1,supplied,workload())['per_sample_task_call_limit']==8
    changed=workload();changed['measured_block_count']=999
    with pytest.raises(ValueError,match='identity changed'):_limits(1,supplied,changed)


def test_actual_BC_count_is_checked_before_downstream_dispatch(tmp_path):
    c=config();c.update(task_definitions=[],top_k=1)
    entries=[{'bc':{'bc_id':str(i)}} for i in range(20)]
    result=_authorize_workload_downstream(tmp_path,'sample',c,tmp_path/'not-used',entries,tmp_path/'not-used')
    assert result['status']=='budget_pending_resume'
    assert result['model_dispatches']==0
    assert not (tmp_path/'stage-authorizations').exists()
