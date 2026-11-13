"""Explicit public joint evidence, actual SAPI, data, controls, events and gaps."""
import json,subprocess,sys
from pathlib import Path
import pytest
from androserum.facts.events import extract_events
from androserum.facts.sapi import SapiImportConfig,import_catalog
from androserum.facts.stage_checks import select
from androserum.facts.extractor import write_extraction
from androserum.facts.store import FactView,import_snapshot

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def joint_actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_pipeline_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    result=extract_events(ROOT/'artifacts/fixtures/pipeline/valid.apk');out=tmp_path_factory.mktemp('joint')
    path=import_snapshot(write_extraction(result,out/'facts'),out/'stores')
    catalog=import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')),out/'catalog')
    refs=select(result.facts,'guarded','getDeviceId')+select(result.facts,'guarded','jointSink')+select(result.facts,'guarded','startActivity')+select(result.facts,'unknownPayload','startActivity')
    return result,path,catalog,refs


def test_joint_query_has_actual_source_storage_condition_event_and_icc(joint_actual):
    result,path,catalog,refs=joint_actual
    with FactView(path) as view:q=view.joint_evidence(refs,catalog)
    assert len(q['sapi']['matches'])==1 and q['sapi']['matches'][0]['callsite_ref']==refs[0]
    sink=q['operations'][1];assert sink['arguments'][0]['candidates'][0]['metadata']['signature']=='Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;'
    assert any('context-heap' in x['source_selector'] for x in sink['arguments'][0]['candidates'][0]['path'])
    assert q['control']['operations'][1]['conditions'][0]['record']['expected_value']['value'] is True
    assert q['events']['operations'][1]['background'][0]['root']['kind']=='click'
    assert q['events']['operations'][2]['icc'][0]['payloads']
    assert q['events']['operations'][3]['icc'][0]['targets'] and q['events']['operations'][3]['icc'][0]['payload_state']=='unknown'
    assert q['selected_flows'] and q['events']['flow_joint_validation']['state']=='selected_entry_callback_models_agree'


def test_joint_support_is_closed_and_retains_limits(joint_actual):
    _,path,catalog,refs=joint_actual
    with FactView(path) as view:q=view.joint_evidence(refs,catalog,limit=5000)
    assert not q['support']['truncated'] and not q['support']['missing_refs']
    assert q['support']['file_closure_complete'] and not q['support']['missing_files']
    assert any(x['archive_entry']=='analysis/selected-flow/raw.json' for x in q['support']['analysis_files'])
    assert any(x['archive_entry'].startswith('analysis/java/cfg/') and x['archive_entry'].endswith('.commit.json') for x in q['support']['analysis_files'])
    assert q['remaining_gaps']['sapi_sources'] and not q['remaining_gaps']['path_feasibility_checked']
    assert not q['is_bu_extraction'] and q['selected_refs']==refs


def test_joint_support_budget_does_not_look_complete(joint_actual):
    _,path,catalog,refs=joint_actual
    with FactView(path) as view:q=view.joint_evidence(refs,catalog,limit=1)
    assert q['support']['truncated'] and q['support']['pending_refs']


def test_joint_selection_does_not_add_other_same_entry_operations(joint_actual):
    result,path,catalog,refs=joint_actual
    with FactView(path) as view:q=view.joint_evidence([refs[1]],catalog)
    assert [x['operation_ref'] for x in q['operations']]==[refs[1]]
    assert q['selected_refs']==[refs[1]] and not q['is_bu_extraction']
    assert not any(x['operation_ref'] in select(result.facts,'negative','negativeSink') for x in q['operations'])
