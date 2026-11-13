"""F7 selected trigger/ICC models and actual FlowDroid callback agreement."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import subprocess,sys
import pytest
from androserum.facts.events import ENTRY,TOOL,MODEL,analyze_events,extend_events,verify_events
from androserum.facts.control import extract_control
from androserum.facts.selected_flow import FlowConfig
from androserum.facts.stage_checks import select
from androserum.facts.extractor import write_extraction
from androserum.facts.store import FactView,import_snapshot

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def event_actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_pipeline_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    base=extract_control(ROOT/'artifacts/fixtures/pipeline/valid.apk',flow_config=FlowConfig(callbacks=True));result=extend_events(deepcopy(base))
    out=tmp_path_factory.mktemp('events');snapshot=import_snapshot(write_extraction(result,out/'facts'),out/'stores')
    return result,snapshot,base


def read(result,entry):return result.blobs[result.entry_digests[entry]]
def report(result):return json.loads(read(result,ENTRY))


def test_lifecycle_and_registration_models_are_distinct_from_execution(event_actual):
    result,_,_=event_actual;r=report(result)
    assert {x['kind'] for x in r['roots']}=={'lifecycle','click','post','thread'}
    assert len([x for x in r['roots'] if x['kind']=='lifecycle'])==2
    assert all(not x['execution_asserted'] for x in r['roots']) and not r['event_order_proven']
    assert r['issues'] # absent APK implementations of other lifecycle methods remain explicit


def test_two_listener_objects_do_not_swap_callback_targets(event_actual):
    result,_,_=event_actual;r=report(result);records={x.id:x for x in result.facts.elements}
    clicks=[x for x in r['roots'] if x['kind']=='click']
    assert len(clicks)==2 and len({x['object']['object_key'] for x in clicks})==2
    assert {records[x['target_method_ref']].signature.split('->')[0] for x in clicks}=={'Lorg/androserum/pipeline/MainActivity$Clicker;','Lorg/androserum/pipeline/MainActivity$OtherClicker;'}
    for root in clicks:assert not any(e.relation_kind=='candidate_call' and e.source.element_ref==root['source_ref'] and e.target and e.target.element_ref==root['target_method_ref'] for e in result.facts.relations)


def test_joint_operation_has_only_applicable_click_background(event_actual):
    result,path,_=event_actual
    with FactView(path) as view:q=view.event_evidence(select(result.facts,'guarded','jointSink'))
    backgrounds=q['operations'][0]['background']
    assert len(backgrounds)==1 and backgrounds[0]['root']['kind']=='click' and len(backgrounds[0]['call_background']['call_path_refs'])==2
    assert not q['operations'][0]['registration_implies_immediate_execution']


def test_actual_flowdroid_entry_and_click_callback_joint_validation(event_actual):
    result,_,_=event_actual;joint=report(result)['flow_joint_validation']
    assert joint['callbacks_enabled'] and joint['state']=='selected_entry_callback_models_agree' and joint['flow_rows'] and len(joint['event_refs'])==1


def test_explicit_target_and_current_payload_have_separate_evidence(event_actual):
    result,_,_=event_actual;r=report(result);refs=select(result.facts,'guarded','startActivity')
    item=next(x for x in r['icc'] if x['callsite_ref'] in refs)
    assert item['targets'][0]['resolution']=='resolved' and item['targets'][0]['basis']=='explicit_class'
    assert item['payload_state']=='bound_sources' and item['payloads'][0]['key']=='payload' and item['condition_refs']
    assert item['dominance_evidence']
    assert any(x.relation_kind=='icc_target' and x.source.element_ref in refs for x in result.facts.relations)
    assert any(x.relation_kind=='icc_data' for x in result.facts.relations)


def test_target_known_does_not_invent_unknown_payload(event_actual):
    result,_,_=event_actual;r=report(result);refs=select(result.facts,'unknownPayload','startActivity')
    item=next(x for x in r['icc'] if x['callsite_ref'] in refs)
    assert item['targets'] and item['payload_state']=='unknown' and not item['payloads']
    assert any('Payload key unknown' in x for x in item['issues'])


def test_static_filter_matching_uses_action_category_and_data(event_actual):
    result,_,_=event_actual;r=report(result);ref=select(result.facts,'implicit','startActivity')[0]
    item=next(x for x in r['icc'] if x['callsite_ref']==ref)
    assert len(item['targets'])==1 and item['targets'][0]['basis']=='static_intent_filter' and item['targets'][0]['filter_ref']
    changed=deepcopy(result.facts)
    for element in changed.elements:
        if element.kind=='configuration' and element.configuration_kind=='intent_filter':
            for child in element.value.value['children']:
                if child['tag']=='action' and child['attributes'].get('{http://schemas.android.com/apk/res/android}name')=='org.androserum.VIEW':
                    child['attributes']['{http://schemas.android.com/apk/res/android}name']='unrelated.ACTION'
    negative=analyze_events(changed,lambda e:read(result,e))
    assert not next(x for x in negative['icc'] if x['callsite_ref']==ref)['targets']


@pytest.mark.parametrize('damage',['callback','target','payload','model'])
def test_forged_event_or_icc_links_rejected(event_actual,damage):
    result=deepcopy(event_actual[0]);r=report(result)
    if damage=='model':entry='analysis/rules/android-events.json';raw=b'{}'
    else:
        entry=ENTRY
        if damage=='callback':next(x for x in r['roots'] if x['kind']=='click')['target_method_ref']=r['roots'][0]['target_method_ref']
        elif damage=='target':next(x for x in r['icc'] if x['targets'])['targets'][0]['component_ref']='configuration:forged'
        else:next(x for x in r['icc'] if x['payloads'])['payloads'][0]['key']='forged-key'
        raw=json.dumps(r).encode()
    digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[entry]=digest
    with pytest.raises(ValueError):verify_events(result.facts,lambda e:read(result,e))


def test_event_publication_retains_partial_coverage_and_model_nodes(event_actual):
    result,path,_=event_actual
    with FactView(path) as view:assert view.verify()['valid'] and view.manifest.coverage['events']=='partial'
    model_nodes=[x for x in result.facts.elements if x.provenance.tool_ref==TOOL]
    assert model_nodes and all(x.position.kind=='model' and x.provenance.rule_ref==MODEL for x in model_nodes)
