import json
import subprocess
from copy import deepcopy
from pathlib import Path
import pytest
from androserum.inference.provider import CallBudget, RealProvider, strict_schema
from androserum.matching.models import MatchProposal
from androserum.matching.fixtures import toy_side,support_response
from androserum.matching.views import make_request
from androserum.inference.matching import run_pair,ResumeIntegrityError
from androserum.inference.provider import write
from androserum.facts.identity import canonical_json


def test_strict_schema_recursive():
    s=strict_schema(MatchProposal.model_json_schema())
    for item in [s,*s['$defs'].values()]:
        if item.get('type')=='object':
            assert item['additionalProperties'] is False
            assert item['required']==list(item['properties'])


def test_persistent_budget_crash_and_resume(tmp_path):
    p=tmp_path/'budget.sqlite';b=CallBudget(p,{'matching':1});b.reserve('matching','a');b.close()
    b=CallBudget(p,{'matching':1})
    with pytest.raises(ValueError,match='exhausted'):b.reserve('matching','b')
    with pytest.raises(ValueError,match='already reserved'):b.reserve('matching','a')
    b.close()
    with pytest.raises(ValueError,match='frozen'):CallBudget(p,{'matching':2})


def options():return {'executable':'never.exe','model':'fixed-test','provider':'test','provider_host':'test.invalid',
                      'reasoning_effort':'high','spec':{}}


def test_timeout_consumes_call_and_keeps_audit(tmp_path,monkeypatch):
    def timeout(*args,**kwargs):raise subprocess.TimeoutExpired('never',1,output=b'{"type":"thread.started"}\n',stderr=b'timeout')
    monkeypatch.setattr(subprocess,'run',timeout)
    b=CallBudget(tmp_path/'budget',{'matching':1})
    with pytest.raises(ValueError,match='timeout'):
        RealProvider(options()).generate({}, {'type':'object','properties':{}},'prompt',tmp_path/'call',
                                        budget=b,phase='matching',call_id='a')
    assert b.report()['calls'][0]['status']=='timeout'
    assert json.loads((tmp_path/'call/receipt.json').read_text())['status']=='timeout'
    assert not (tmp_path/'call/raw-model-output.json').exists()
    b.close()


def test_request_over_budget_never_dispatches(tmp_path,monkeypatch):
    def no(*a,**kw):pytest.fail('must not dispatch')
    monkeypatch.setattr(subprocess,'run',no);b=CallBudget(tmp_path/'budget',{'matching':1})
    with pytest.raises(ValueError,match='Input budget'):
        RealProvider(options()).generate({'v':'x'*100}, {}, 'prompt', tmp_path/'call',budget=b,
            phase='matching',call_id='a',max_request_chars=10)
    assert not b.report()['calls'];b.close()


def stub_transport(monkeypatch,responses):
    """Exercise transport/audit code without any executable or model call."""
    pending=list(responses);inputs=[]
    def run(args,**kwargs):
        assert pending,'Cached output must not dispatch another model request'
        inputs.append(json.loads(kwargs['input'].decode('utf-8').split('\n',1)[1]))
        output=Path(args[args.index('--output-last-message')+1])
        output.write_text(pending.pop(0),encoding='utf-8')
        return subprocess.CompletedProcess(args,0,b'{"type":"turn.completed","usage":{"input_tokens":1}}\n',b'')
    monkeypatch.setattr(subprocess,'run',run)
    return RealProvider(options()),inputs


def match_material():
    request=make_request(toy_side('inference_query'),toy_side('inference_reference'))
    return request,support_response(request)


def test_real_runner_separates_natural_rejection_and_seeded_exercise(tmp_path,monkeypatch):
    request,proposal=match_material();bad=deepcopy(proposal)
    bad['relation_mappings'][0]['query']['binding_refs']=['bind_000000000000']
    provider,inputs=stub_transport(monkeypatch,[canonical_json(bad),canonical_json(proposal),canonical_json(proposal)])
    budget=CallBudget(tmp_path/'budget',{'matching':3})
    try:
        natural=run_pair(request,tmp_path/'natural',provider,budget,pair_id='natural')
        assert not natural['seeded_repair_exercise'] and [a['check']['valid'] for a in natural['attempts']]==[False,True]
        assert inputs[1]['repair_feedback']['previous_raw']==canonical_json(bad)
        assert 'origin' not in inputs[1]['repair_feedback']
        seeded=run_pair(request,tmp_path/'seeded',provider,budget,pair_id='seeded',seed=bad)
        assert seeded['seeded_repair_exercise'] and len(seeded['attempts'])==1
        assert inputs[2]['repair_feedback']['origin']=='explicit_programmatic_fault_injection_not_model_error'
        assert all('source_audit' not in packet and 'oracle' not in packet for packet in inputs)
        assert len(budget.report()['calls'])==3
        # Replaying both exercises verifies prior raw responses and feedback,
        # preserves the audit/accepted state, and consumes no additional calls.
        assert run_pair(request,tmp_path/'natural',provider,budget,pair_id='natural')==natural
        assert run_pair(request,tmp_path/'seeded',provider,budget,pair_id='seeded')==seeded
        assert len(budget.report()['calls'])==3 and len(inputs)==3
    finally:budget.close()


@pytest.mark.parametrize('changed',[
    'raw_output','receipt_hash','check_result','check_transport','final_report',
    'accepted_output','input_audit','instruction_audit','schema_audit','registered_request',
])
def test_completed_pair_resume_rechecks_audit_and_fails_closed_on_tampering(tmp_path,monkeypatch,changed):
    request,proposal=match_material();provider,inputs=stub_transport(monkeypatch,[canonical_json(proposal)])
    budget=CallBudget(tmp_path/'budget',{'matching':2});root=tmp_path/'pair'
    try:
        run_pair(request,root,provider,budget,pair_id='audit')
        directory=root/'attempt-0'
        if changed=='raw_output':
            path=directory/'raw-model-output.json';path.write_text(path.read_text('utf-8')+'\n',encoding='utf-8')
        elif changed=='receipt_hash':
            path=directory/'receipt.json';value=json.loads(path.read_text('utf-8'));value['output_sha256']='0'*64;write(path,value)
        elif changed in {'check_result','check_transport'}:
            path=root/'check-0.json';value=json.loads(path.read_text('utf-8'))
            if changed=='check_result':value['check']['valid']=False
            else:value['transport']['configured_model']='changed'
            write(path,value)
        elif changed=='final_report':
            path=root/'report.json';value=json.loads(path.read_text('utf-8'));value['status']='unresolved_after_budget';write(path,value)
        elif changed=='accepted_output':
            path=root/'accepted.json';value=json.loads(path.read_text('utf-8'));value['rationale']='modified after checking';write(path,value)
        elif changed in {'input_audit','instruction_audit'}:
            path=directory/('input.txt' if changed=='input_audit' else 'instructions.txt')
            path.write_text(path.read_text('utf-8')+' ',encoding='utf-8')
        elif changed=='schema_audit':
            write(directory/'proposal.schema.json',{})
        else:
            path=root/'request.json';value=json.loads(path.read_text('utf-8'));value['rules']['execution']='modified';write(path,value)
        with pytest.raises(ResumeIntegrityError):run_pair(request,root,provider,budget,pair_id='audit')
        assert len(inputs)==1 and len(budget.report()['calls'])==1
    finally:budget.close()


def test_completed_call_before_check_is_reused_without_second_dispatch(tmp_path,monkeypatch):
    request,proposal=match_material();provider,inputs=stub_transport(monkeypatch,[canonical_json(proposal)])
    budget=CallBudget(tmp_path/'budget',{'matching':1});root=tmp_path/'pair'
    try:
        original=run_pair(request,root,provider,budget,pair_id='interrupted')
        # Simulate interruption after output/receipt, before accepting a check.
        for name in ['check-0.json','accepted.json','report.json']:(root/name).unlink()
        replay=run_pair(request,root,provider,budget,pair_id='interrupted')
        assert replay==original and len(inputs)==1 and len(budget.report()['calls'])==1
    finally:budget.close()
