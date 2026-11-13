"""Actual pinned FlowDroid positive/negative paths and publication boundaries."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import subprocess,sys
import pytest
from androserum.facts.context_heap import extract_context_heap
from androserum.facts.selected_flow import (FlowConfig,ENTRY,TOOL,build_flow_backend,verify_flow_build,extend_selected_flow,verify_selected_flow,map_flow)
from androserum.facts.extractor import write_extraction
from androserum.facts.store import FactView,import_snapshot

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def flow_actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_pipeline_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    from androserum.facts.java_backend import verify_build,build_java_backend
    try:verify_build()
    except (ValueError,OSError):build_java_backend()
    try:verify_flow_build()
    except (ValueError,OSError):build_flow_backend()
    base=extract_context_heap(ROOT/'artifacts/fixtures/pipeline/valid.apk')
    result=extend_selected_flow(deepcopy(base),ROOT/'artifacts/fixtures/pipeline/valid.apk')
    output=tmp_path_factory.mktemp('selected-flow');snapshot=import_snapshot(write_extraction(result,output/'facts'),output/'stores')
    return result,snapshot,base


def read(result,entry):return result.blobs[result.entry_digests[entry]]
def report(result):return json.loads(read(result,ENTRY))


def test_real_source_helper_sink_and_fixed_string_negative(flow_actual):
    result,_,_=flow_actual;r=report(result);raw=json.loads(read(result,r['raw_entry']))
    assert r['state']=='complete' and len(r['mapped'])>=1
    sinks={x['sink']['statement']['invoke_signature'] for x in r['mapped']}
    assert any('->positiveSink(' in s for s in sinks) and not any('->negativeSink(' in s for s in sinks)
    assert any('->helper(' in x.get('method_signature','') for f in raw['flows'] for x in f['path'])
    assert all(not x['issues'] and x['source_endpoint'] and x['sink_endpoint'] for x in r['mapped'])


def test_raw_path_mapping_gaps_remain_explicit(flow_actual):
    r=report(flow_actual[0]);assert any(x['state']=='unresolved' for row in r['mapped'] for x in row['path'])
    assert r['framework_entry_joint_validation']=='pending_F7'


def test_mapping_failure_is_not_a_fake_current_endpoint(flow_actual):
    result,_,_=flow_actual;r=report(result);raw=json.loads(read(result,r['raw_entry']))
    raw['flows'][0]['source']['offsets_code_units']=[999999]
    mapped=map_flow(result.facts,FlowConfig(),raw)
    assert mapped[0]['issues'] and mapped[0]['source_endpoint'] is None


def test_real_process_timeout_keeps_failure_scope_and_other_facts(flow_actual):
    _,_,base=flow_actual
    result=extend_selected_flow(deepcopy(base),ROOT/'artifacts/fixtures/pipeline/valid.apk',FlowConfig(timeout_seconds=0.001))
    r=report(result)
    assert r['state']=='truncated' and 'timeout' in r['reason'] and not r['mapped']
    assert any(x.kind=='instruction' for x in result.facts.elements)
    assert not any(x.relation_kind=='information_flow' for x in result.facts.relations)


@pytest.mark.parametrize('damage',['source','rule','extra','mapping'])
def test_invalid_flow_connections_rejected(flow_actual,damage):
    result=deepcopy(flow_actual[0]);edge=next(x for x in result.facts.relations if x.provenance.tool_ref==TOOL)
    if damage=='source':edge.source=edge.target.model_copy(deep=True)
    elif damage=='rule':edge.provenance.rule_ref='rule:local-flow'
    elif damage=='extra':
        extra=edge.model_copy(deep=True);extra.id='relation:forged-flow';result.facts.relations.append(extra)
    else:
        r=report(result);r['mapped'][0]['source']['record_ref']='instruction:forged';raw=json.dumps(r).encode();digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[ENTRY]=digest
    with pytest.raises(ValueError):verify_selected_flow(result.facts,lambda e:read(result,e))


def test_flow_snapshot_current_rules_and_partial_scope(flow_actual):
    result,path,_=flow_actual
    with FactView(path) as view:
        assert view.verify()['valid'] and view.manifest.coverage['data_flow']=='partial'
        assert view.manifest.coverage['control']==view.manifest.coverage['events']=='not_started'
    for edge in result.facts.relations:
        if edge.provenance.tool_ref==TOOL:assert edge.relation_kind=='information_flow' and edge.source_selector and edge.provenance.support_refs
