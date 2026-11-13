"""F5 candidate values, explicit sources, resource links and finite state effects."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import subprocess,sys
import pytest
from androserum.facts.operations import OperationConfig,ENTRY,TOOL,build_operations,extend_operations,extract_operations,verify_operations
from androserum.facts.store import FactView,import_snapshot
from androserum.facts.extractor import write_extraction

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def operation_actual(tmp_path_factory):
    from androserum.facts.selected_flow import extract_selected_flow
    subprocess.run([sys.executable,'scripts/build_pipeline_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    base=extract_selected_flow(ROOT/'artifacts/fixtures/pipeline/valid.apk');result=extend_operations(deepcopy(base))
    out=tmp_path_factory.mktemp('operations');snapshot=import_snapshot(write_extraction(result,out/'facts'),out/'stores')
    return result,snapshot,base


def read(result,entry):return result.blobs[result.entry_digests[entry]]
def report(result):return json.loads(read(result,ENTRY))
def find_rows(result,caller,target):
    records={x.id:x for x in result.facts.elements}
    return [x for x in report(result)['operations'] if ('->'+caller+'(') in records[x['method_ref']].signature and records[x['operation_ref']].declared_target
        and ('->'+target+'(') in records[x['operation_ref']].declared_target.signature]


def test_static_void_nonapplicability_and_fixed_argument(operation_actual):
    row=find_rows(operation_actual[0],'negative','negativeSink')[0]
    assert row['receiver']['value_status']==row['result']['value_status']=='not_applicable'
    assert [x['value']['value'] for x in row['arguments'][0]['candidates']]==['fixed']
    assert row['conditions']['state']=='deferred_until_F6'


def test_current_source_survives_helper_object_storage_path(operation_actual):
    row=find_rows(operation_actual[0],'guarded','jointSink')[0];arg=row['arguments'][0]
    assert arg['value_status']=='unknown' and any(x['metadata'].get('signature')=='Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;' for x in arg['candidates'])
    assert all(x['source_refs'] and x['path'] for x in arg['candidates'])


def test_branch_candidates_are_retained_without_premature_conditions(operation_actual):
    rows=find_rows(operation_actual[0],'bothBranches','negativeSink')
    assert any({c['value']['value'] for c in row['arguments'][0]['candidates']}=={'yes','no'} for row in rows)
    assert all(row['conditions']['state']=='deferred_until_F6' for row in rows)


def test_intent_effects_require_known_object_and_exact_rule(operation_actual):
    r=report(operation_actual[0]);effects=r['effects']
    assert {'target','extra','action','category','data'}<={e['property'] for e in effects}
    assert all(e['normal_completion_required'] and e['rule_ref']=='model:intent-state-v1' for e in effects)
    payload=next(e for e in effects if e['property']=='extra' and e['key']=='payload')
    assert payload['object'] and payload['value']['candidates'][0]['source_kind']=='call_result'
    assert any(e['property']=='data' and e['value']['candidates'][0]['value']['value']=={'uri':'androserum://test/item'} for e in effects)
    assert any(e['property']=='extra' and e['key'] is None and e['issues'] for e in effects)
    unmodeled=find_rows(operation_actual[0],'onCreate','setOnClickListener')
    assert all(not e['effects'] for e in unmodeled)


def test_resource_evidence_retains_real_resource_content_and_qualifiers():
    from androserum.facts.extractor import extract_apk
    apk=ROOT/'artifacts/fixtures/f1/valid.apk'
    if not apk.is_file():subprocess.run([sys.executable,'scripts/build_extraction_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    result=extract_apk(apk)
    def missing(entry):raise KeyError(entry)
    r=build_operations(result.facts,missing,OperationConfig())
    resources=[x for row in r['operations'] for x in row['resource_records']]
    assert resources and all(x['kind']=='resource' and x['value'] for x in resources)
    assert len({x['qualifiers'] for x in resources})>=2


def test_operation_budget_is_explicit(operation_actual):
    _,_,base=operation_actual;r=report(extend_operations(deepcopy(base),OperationConfig(max_operations=1)))
    assert len(r['operations'])==1 and r['issues'][0]['pending_refs']


@pytest.mark.parametrize('damage',['value','model','binding','edge'])
def test_bad_values_or_state_effects_rejected(operation_actual,damage):
    result=deepcopy(operation_actual[0]);r=report(result)
    if damage=='value':
        row=next(x for x in r['operations'] if any(c['value']['status']=='known' for a in x['arguments'] for c in a['candidates']))
        next(c for a in row['arguments'] for c in a['candidates'] if c['value']['status']=='known')['value']['value']='forged-constant'
        raw=json.dumps(r).encode();digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[ENTRY]=digest
    elif damage=='model':
        raw=b'{}';digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests['analysis/rules/intent-state.json']=digest
    elif damage=='binding':
        bound=next(x for x in result.facts.bindings if x.provenance.tool_ref==TOOL)
        effect=next(e for e in r['effects'] if e['value'])
        from androserum.facts.models import Endpoint
        bound.endpoints[0]=Endpoint(**effect['value']['endpoint'])
    else:next(x for x in result.facts.relations if x.provenance.tool_ref==TOOL).relation_kind='field_dependency'
    with pytest.raises(ValueError):verify_operations(result.facts,lambda e:read(result,e))


def test_public_operation_view_keeps_unknown_and_unanalyzed_distinct(operation_actual):
    result,path,_=operation_actual;row=find_rows(result,'guarded','jointSink')[0]
    with FactView(path) as view:
        assert view.verify()['valid'];q=view.operation_evidence([row['operation_ref']])
        assert q['operations'][0]['conditions']['state']=='not_started'
        assert not q['operations'][0]['conditions']['absence_is_unconditional']
