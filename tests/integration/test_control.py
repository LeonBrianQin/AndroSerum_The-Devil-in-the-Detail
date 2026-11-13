"""F6 source-level expectations checked against compiled CFG and public views."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import subprocess,sys
import pytest
from androserum.facts.control import ControlConfig,ENTRY,TOOL,extend_control,verify_control
from androserum.facts.operations import extract_operations
from androserum.facts.stage_checks import select
from androserum.facts.extractor import write_extraction
from androserum.facts.store import FactView,import_snapshot

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def control_actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_pipeline_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    base=extract_operations(ROOT/'artifacts/fixtures/pipeline/valid.apk');result=extend_control(deepcopy(base))
    out=tmp_path_factory.mktemp('control');snapshot=import_snapshot(write_extraction(result,out/'facts'),out/'stores')
    return result,snapshot,base


def read(result,entry):return result.blobs[result.entry_digests[entry]]


def test_early_return_requires_true_and_source_is_boolean_parameter(control_actual):
    result,path,_=control_actual;ref=select(result.facts,'earlyReturn','negativeSink')[0]
    with FactView(path) as view:q=view.control_evidence([ref])['operations'][0]
    assert len(q['conditions'])==1
    cond=q['conditions'][0]
    assert cond['record']['expected_value']['value'] is True and cond['analysis']['normalization']=='boolean_local'
    assert [x['root']['details']['parameter_index'] for s in cond['analysis']['source_evidence'] for x in s['roots']]==[0]
    assert q['scope']=='method_normal_completion' and not q['absence_is_unconditional']


def test_nested_constraints_keep_both_scopes(control_actual):
    result,path,_=control_actual
    with FactView(path) as view:q=view.control_evidence(select(result.facts,'nestedConditions','negativeSink'))['operations'][0]
    assert len(q['conditions'])==2 and all(c['record']['expected_value']['value'] is True for c in q['conditions'])
    assert {x['root']['details']['parameter_index'] for c in q['conditions'] for s in c['analysis']['source_evidence'] for x in s['roots']}=={0,1}


def test_merged_branch_call_is_not_given_one_branch_constraint(control_actual):
    result,path,_=control_actual
    with FactView(path) as view:q=view.control_evidence(select(result.facts,'bothBranches','negativeSink'))
    assert all(not x['conditions'] for x in q['operations'])


def test_f5_candidates_gain_local_conditions_after_f6(control_actual):
    result,path,_=control_actual;elements={x.id:x for x in result.facts.elements}
    with FactView(path) as view:rows=view.operation_evidence(select(result.facts,'bothBranches','negativeSink'))['operations']
    row=next(x for x in rows if len(x['arguments'][0]['candidates'])==2)
    actual={}
    for candidate in row['arguments'][0]['candidates']:
        refs=[c for s in candidate['local_conditions']['source_scopes'] for c in s['condition_refs']]
        actual[candidate['value']['value']]={elements[c].expected_value.value for c in refs}
        assert not candidate['local_conditions']['combined_path_checked']
    assert actual=={'yes':{True},'no':{False}}


def test_joint_candidate_and_operation_condition_stay_current_and_local(control_actual):
    result,path,_=control_actual
    with FactView(path) as view:q=view.operation_evidence(select(result.facts,'guarded','jointSink'))['operations'][0]
    assert q['conditions']['refs'] and q['arguments'][0]['candidates'][0]['local_conditions']['operation_condition_refs']==q['conditions']['refs']
    assert q['conditions']['state']=='available_normal_flow_scope'


def test_control_budget_does_not_publish_partial_conditions_as_complete(control_actual):
    _,_,base=control_actual;result=extend_control(deepcopy(base),ControlConfig(max_visits=1))
    report=json.loads(read(result,ENTRY));truncated=[x for x in report['methods'] if x['state']=='truncated']
    assert truncated and all(not x['conditions'] and not x['controls'] for x in truncated)


@pytest.mark.parametrize('damage',['truth','scope','extra','source'])
def test_incorrect_condition_or_control_relation_rejected(control_actual,damage):
    result=deepcopy(control_actual[0]);report=json.loads(read(result,ENTRY))
    edge=next(x for x in result.facts.relations if x.provenance.tool_ref==TOOL and x.relation_kind=='control_dependency')
    if damage=='truth':
        c=next(x for m in report['methods'] for x in m['conditions']);c['expected_value']=not c['expected_value']
        raw=json.dumps(report).encode();digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[ENTRY]=digest
    elif damage=='scope':edge.target.element_ref=select(result.facts,'bothBranches','negativeSink')[-1]
    elif damage=='source':edge.condition_refs=[]
    else:
        extra=edge.model_copy(deep=True);extra.id='relation:forged-control';result.facts.relations.append(extra)
    with pytest.raises(ValueError):verify_control(result.facts,lambda e:read(result,e))


def test_control_publication_remains_partial_without_events(control_actual):
    with FactView(control_actual[1]) as view:
        assert view.verify()['valid'] and view.manifest.coverage['control']=='partial' and view.manifest.coverage['events']=='not_started'
