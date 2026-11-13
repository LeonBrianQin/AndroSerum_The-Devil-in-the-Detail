"""Real native SummaryTaintWrapper contribution and current-evidence controls."""
from copy import deepcopy
import json
from pathlib import Path
import runpy

import pytest

from androserum.facts.extractor import extract_apk
from androserum.facts.flow_summaries import ENTRY as SUMMARY_ENTRY, summary_evidence,verify_summary_evidence
from androserum.facts import flow_summaries
from androserum.facts.selected_flow import SummaryFlowConfig,extend_selected_flow
from androserum.facts.identity import canonical_json

ROOT=Path(__file__).resolve().parents[2]
OWNER='Lorg/androserum/flowsummary/Cases;'
METHODS=['positiveCrossMethod','positiveReceiverState','negativeFixed','negativeDifferentObject','negativeHelperReturnsConstant']
SINKS=['positiveSink','receiverSink','fixedSink','separateSink','sanitizedSink']


@pytest.fixture(scope='module')
def actual():
    builder=runpy.run_path(str(ROOT/'scripts/build_local_fixture.py'),run_name='builder')
    builder['main'](source=ROOT/'tests/fixtures/flow_summaries',output=ROOT/'artifacts/fixtures/flow-summaries',label='native library-summary comparison')
    apk=ROOT/'artifacts/fixtures/flow-summaries/valid.apk';results={}
    for mode in ['none','flowdroid_summary']:
        config=SummaryFlowConfig(sources=[OWNER+'->source()Ljava/lang/String;'],
            sinks=[OWNER+'->'+x+'(Ljava/lang/String;)V' for x in SINKS],
            entry_scope='conditional_explicit_methods_not_android_reachability',
            entry_methods=[OWNER+'->'+x+'()V' for x in METHODS],taint_wrapper=mode,timeout_seconds=90,solver_timeout=45)
        result=extend_selected_flow(extract_apk(apk),apk,config)
        read=lambda e:result.blobs[result.entry_digests[e]]
        results[mode]=(result,json.loads(read('analysis/selected-flow/report.json')),summary_evidence(result.facts,read))
    return results


def test_real_wrapper_is_loaded_and_changes_only_expected_library_propagation(actual):
    without,with_summary=actual['none'],actual['flowdroid_summary']
    assert without[0].facts.run.run_id!=with_summary[0].facts.run.run_id
    assert without[1]['state']==with_summary[1]['state']=='complete'
    assert without[2]['resource_state']=='disabled' and without[1]['mapped']==[]
    assert with_summary[2]['resource_state']=='loaded'
    targets={x['sink']['statement']['invoke_signature'] for x in with_summary[1]['mapped']}
    assert targets=={OWNER+'->'+x+'(Ljava/lang/String;)V' for x in ['positiveSink','receiverSink']}
    assert not targets & {OWNER+'->'+x+'(Ljava/lang/String;)V' for x in ['fixedSink','separateSink','sanitizedSink']}
    audit=with_summary[2]['worker_audit']
    assert audit['provider_loading_errors'] is False and audit['fallback_wrapper'] is None
    assert audit['supported_wrapper_calls']>0 and len(audit['loaded_classes'])>=347


def test_actual_receiver_parameter_return_and_state_roles_are_currently_mapped(actual):
    _,_,query=actual['flowdroid_summary'];applications=query['applications']
    assert applications and all(x['mapping_state']=='mapped' for x in applications)
    append=[x for x in applications if '->append(' in x['callsite']['invoke_signature']]
    stringify=[x for x in applications if '->toString()' in x['callsite']['invoke_signature']]
    assert append and stringify
    assert all(x['input']['endpoint_candidates'][0]['slot_kind']=='argument' for x in append)
    assert all(any(y['different_from_incoming'] and any(e['slot_kind']=='receiver' for e in y['roles']['endpoint_candidates']) for y in x['outputs']) for x in append)
    assert all(x['input']['endpoint_candidates'][0]['slot_kind']=='receiver' for x in stringify)
    assert all(any(y['different_from_incoming'] and any(e['slot_kind']=='result' for e in y['roles']['endpoint_candidates']) for y in x['outputs']) for x in stringify)
    native=[rule for x in applications for cls in x['native_summary_candidates'] for rule in cls['rules']]
    assert all(x['mapping_state']=='mapped' and x['XML_rule_candidates'] for x in native)
    assert {('parameter','receiver_state'),('receiver_state','return')}<={(x['roles']['from']['role'],x['roles']['to']['role']) for x in native}
    assert all(x['individually_fired_rule_proven'] is False for x in native)
    assert all(x['complete_call_frame_binding_asserted'] is False for x in applications)
    assert query['JCA_special_model_separate'] and not query['fine_grained_paths_claimed']


def test_real_solver_path_retains_cross_method_witness_and_unmapped_nodes(actual):
    _,flow,_=actual['flowdroid_summary']
    path=next(x for x in flow['mapped'] if 'positiveSink' in x['sink']['statement']['invoke_signature'])
    signatures={x['statement']['method_signature'] for x in path['path']}
    assert {OWNER+'->'+x+'(Ljava/lang/String;)Ljava/lang/String;' for x in ['before','build','after']}<=signatures
    assert not path['path_mapping_complete'] and any(x['state']=='unresolved' for x in path['path'])
    assert flow['framework_entry_joint_validation']=='not_applicable_explicit_method_scope'


@pytest.mark.parametrize('mutation',['current_call','slot','native_role','resource_state'])
def test_forged_current_call_slot_native_role_or_loading_claim_is_rejected(actual,mutation):
    result=actual['flowdroid_summary'][0];report=deepcopy(actual['flowdroid_summary'][2]);row=report['applications'][0]
    if mutation=='current_call':row['current_call_ref']='instruction:invented'
    elif mutation=='slot':row['input']['endpoint_candidates'][0]['slot_kind']='state'
    elif mutation=='native_role':row['native_summary_candidates'][0]['rules'][0]['roles']['from']['role']='invented_state_alias'
    else:report['resource_state']='disabled'
    changed=canonical_json(report).encode()
    read=lambda e:changed if e==SUMMARY_ENTRY else result.blobs[result.entry_digests[e]]
    with pytest.raises(ValueError,match='mapping differs'):
        verify_summary_evidence(result.facts,read)


def test_missing_summary_resource_preserves_base_facts_and_never_claims_loaded(actual,tmp_path,monkeypatch):
    monkeypatch.setattr(flow_summaries,'RESOURCE',tmp_path/'absent-resources')
    apk=ROOT/'artifacts/fixtures/flow-summaries/valid.apk'
    result=extend_selected_flow(extract_apk(apk),apk,SummaryFlowConfig())
    read=lambda e:result.blobs[result.entry_digests[e]]
    flow=json.loads(read('analysis/selected-flow/report.json'));query=summary_evidence(result.facts,read)
    assert flow['state']=='unavailable' and flow['reason']
    assert result.facts.elements and not flow['mapped']
    assert query['resource_state']=='not_confirmed' and not query['applications']
    assert query['issues'][0]['kind']=='summary_loading_not_confirmed'
