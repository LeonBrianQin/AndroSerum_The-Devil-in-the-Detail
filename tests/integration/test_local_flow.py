"""F4-A semantic acceptance: fixed IR expectations plus real compiled APK/Soot oracles."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from androserum.facts import java_backend
from androserum.facts.extractor import write_extraction
from androserum.facts.identity import canonical_json, filesystem_path
from androserum.facts.jimple import IRUnit, IRValue, JimpleMethod
from androserum.facts.local_flow import (LocalFlowConfig, MethodCFG, MethodFlow, analyze_method, extract_local,
    solve_reaching, validate_cfg, verify_local_flow_evidence)
from androserum.facts.models import Endpoint
from androserum.facts.store import FactView, export_snapshot, import_snapshot

ROOT = Path(__file__).resolve().parents[2]
CASE = "Lorg/androserum/local/Cases;"


def model_json(data):
    return json.dumps(data,default=lambda model:model.model_dump(mode="json"),allow_nan=False)


def value(local=None, constant=None, *, parameter=None, identity=None, kind=None, children=()):
    data = dict(kind=kind or ("JimpleLocal" if local is not None else "ParameterRef" if parameter is not None else "IntConstant"),
        type_descriptor="I", text="synthetic operand", local_index=local, parameter_index=parameter, identity_kind=identity,
        constant_kind="int" if constant is not None else None, constant=constant, field_signature=None, children=list(children), truncated=False)
    return IRValue.model_validate_json(model_json(data))


def unit(index, operation, *, define=None, right=None, argument=None, targets=(), fall=True, kind="parameter"):
    left = value(define) if define is not None else None
    uses = [right] if right is not None else []
    call = None
    if operation == "invoke":
        call = {"signature": "Ltest/Fixture;->send(I)V" if define is None else "Ltest/Fixture;->read()I", "kind": "static",
                "arguments": [argument] if argument is not None else [], "receiver": None, "phantom_owner": False}
        uses = [argument] if argument is not None else []
    data = dict(index=index, text=f"synthetic {operation} {index}", operation=operation, definitions=[left] if left else [], uses=uses,
        invoke=call, targets=list(targets), switch_keys=[], condition=None, falls_through=fall, branches=bool(targets),
        left=left, right=right, offsets_code_units=[], tag_names=[], line_number=-1)
    return IRUnit.model_validate_json(model_json(data))


def synthetic(units, *, traps=(), exceptional=()):
    method = JimpleMethod.model_validate_json(canonical_json(dict(schema_version="jimple-method.v1", signature="Ltest/Fixture;->test(I)V",
        soot_signature="synthetic IR: storage/algorithm test only", modifiers=8, state="complete", reason=None, declared_unit_count=len(units),
        locals=[{"index": i, "name": f"v{i}", "type_descriptor": "I"} for i in range(4)],
        units=[item.model_dump(mode="json") for item in units], traps=list(traps))))
    normal = sorted({(item.index, target) for item in method.units for target in item.targets} |
                    {(item.index, item.index + 1) for item in method.units if item.falls_through and item.index + 1 < len(units)})
    digest = hashlib.sha256(method.model_dump_json().encode()).hexdigest()
    cfg = MethodCFG.model_validate_json(canonical_json(dict(schema_version="jimple-cfg.v1", method_signature=method.signature,
        method_sha256=digest, unit_count=len(units), exception_model="soot-4.7.1-unit-throw-analysis", normal_edges=normal,
        exception_edges=list(exceptional), escaping_exceptions=[], normal_defs_oracle=[])))
    return method, cfg


def analyze(pair, config=None):
    method, cfg = pair
    return analyze_method(method, cfg, run_ref="run:synthetic-local", method_ref="method:test",
        node_refs=[f"analysis:unit{i}" for i in range(len(method.units))], ir_entry="synthetic/ir.json", ir_sha256=cfg.method_sha256,
        cfg_entry="synthetic/cfg.json", cfg_sha256="1" * 64, config=config or LocalFlowConfig())


def definitions(report, unit, local):
    return next(item for item in report.uses if item.unit == unit and item.local_index == local)


def test_copy_chain_has_exact_expected_def_use_and_no_call_result_invention():
    pair = synthetic([unit(0,"identity",define=0,right=value(parameter=0,identity="parameter")),
        unit(1,"assignment",define=1,right=value(0)), unit(2,"assignment",define=2,right=value(1)),
        unit(3,"invoke",argument=value(2)), unit(4,"return",fall=False)])
    report = analyze(pair)
    assert definitions(report,1,0).definitions == [0]
    assert definitions(report,2,1).definitions == [1]
    assert definitions(report,3,2).definitions == [2]
    assert {(link.source.element_ref,link.target.element_ref) for link in report.links if link.kind=="reaching_definition"} == {
        ("analysis:unit0","analysis:unit1"),("analysis:unit1","analysis:unit2"),("analysis:unit2","analysis:unit3")}
    assert any(link.kind=="argument_input" and link.target.slot_kind=="argument" for link in report.links)
    assert [root.kind for root in report.roots] == ["parameter"]


def test_assignment_kill_excludes_overwritten_definition():
    pair = synthetic([unit(0,"identity",define=0,right=value(parameter=0,identity="parameter")),
        unit(1,"assignment",define=1,right=value(0)),unit(2,"constant",define=1,right=value(constant=9)),
        unit(3,"assignment",define=2,right=value(1)),unit(4,"invoke",argument=value(2)),unit(5,"return",fall=False)])
    report = analyze(pair)
    assert definitions(report,3,1).definitions == [2]
    assert not any(link.kind=="reaching_definition" and link.source.element_ref=="analysis:unit1" and link.target.element_ref=="analysis:unit3" for link in report.links)


def test_branch_alternatives_are_distinct_partial_may_definitions():
    pair = synthetic([unit(0,"identity",define=0,right=value(parameter=0,identity="parameter")),unit(1,"branch",right=value(0),targets=[4]),
        unit(2,"assignment",define=1,right=value(0)),unit(3,"branch",targets=[5],fall=False),
        unit(4,"constant",define=1,right=value(constant=0)),unit(5,"invoke",argument=value(1)),unit(6,"return",fall=False)])
    report = analyze(pair)
    assert definitions(report,5,1).definitions == [2,4]
    links = [link for link in report.links if link.kind=="reaching_definition" and link.target.element_ref=="analysis:unit5"]
    assert len(links)==2 and all(link.resolution=="partial" and link.alternatives==[2,4] and link.witness for link in links)


def test_loop_fixed_point_keeps_initial_and_loop_carried_definitions():
    add = value(kind="JAddExpr",children=[value(1),value(constant=1)])
    pair = synthetic([unit(0,"identity",define=0,right=value(parameter=0,identity="parameter")),unit(1,"assignment",define=1,right=value(0)),
        unit(2,"branch",right=value(1),targets=[5]),unit(3,"assignment",define=1,right=add),unit(4,"branch",targets=[2],fall=False),
        unit(5,"invoke",argument=value(1)),unit(6,"return",fall=False)])
    report = analyze(pair)
    assert report.state=="complete" and definitions(report,3,1).definitions==[1,3] and definitions(report,5,1).definitions==[1,3]
    assert any(link.source.element_ref==link.target.element_ref=="analysis:unit3" and link.kind=="reaching_definition" for link in report.links)


def exception_pair():
    return synthetic([unit(0,"identity",define=0,right=value(parameter=0,identity="parameter")),unit(1,"assignment",define=1,right=value(0)),
        unit(2,"invoke",define=1),unit(3,"invoke",argument=value(1)),unit(4,"return",fall=False),
        unit(5,"identity",define=2,right=value(identity="caught_exception",kind="CaughtExceptionRef")),
        unit(6,"invoke",argument=value(1)),unit(7,"return",fall=False)],
        traps=[{"exception_type":"Ljava/lang/RuntimeException;","begin":2,"end":3,"handler":5}],
        exceptional=[{"source":2,"target":5,"trap_index":0,"exception_type":"Ljava/lang/RuntimeException;","transfer":"before_unit","included_types":["java.lang.RuntimeException"],"excluded_types":[]}])


def test_throwing_assignment_does_not_kill_prior_value_on_exception_path():
    report = analyze(exception_pair())
    assert definitions(report,3,1).definitions==[2]
    assert definitions(report,6,1).definitions==[1]
    edge = next(link for link in report.links if link.kind=="reaching_definition" and link.target.element_ref=="analysis:unit6")
    assert "x:2:5:0" in edge.witness and edge.source.element_ref=="analysis:unit1"


def test_normal_only_does_not_claim_exception_handler_was_analyzed():
    report = analyze(exception_pair(), LocalFlowConfig(exception_policy="normal_only"))
    assert report.reachable==[0,1,2,3,4]
    assert not any(use.unit==6 for use in report.uses)


def test_argument_read_does_not_require_normal_return_of_consuming_call():
    report=analyze(exception_pair())
    assert all(not link.requires_normal_completion for link in report.links if link.kind in {"argument_input","receiver_input"})
    assert all(link.requires_normal_completion for link in report.links if link.kind in {"reaching_definition","value_copy","expression_input"})


def test_uninitialized_alternative_stays_unknown_not_a_fake_definition():
    pair = synthetic([unit(0,"branch",targets=[2]),unit(1,"constant",define=1,right=value(constant=7)),
        unit(2,"invoke",argument=value(1)),unit(3,"return",fall=False)])
    report=analyze(pair)
    assert definitions(report,2,1).definitions==[1] and definitions(report,2,1).undefined
    assert any(root.kind=="undefined_local" for root in report.roots)
    assert all(link.resolution=="partial" for link in report.links if link.kind=="reaching_definition")


@pytest.mark.parametrize("config",[{"max_worklist_visits":1},{"max_cfg_edges":1},{"max_witness_visits":1}])
def test_unfinished_solver_never_publishes_partial_def_use_as_complete(config):
    report=analyze(exception_pair(),LocalFlowConfig(**config))
    assert report.state=="truncated" and not report.links and not report.roots and report.pending_units


@pytest.mark.parametrize("damage",["missing-normal","wrong-handler","after-exception","cross-method"])
def test_invalid_cfg_basis_is_rejected(damage):
    method,cfg=exception_pair()
    data=cfg.model_dump(mode="json")
    if damage=="missing-normal":data["normal_edges"].pop()
    elif damage=="wrong-handler":data["exception_edges"][0]["target"]=3
    elif damage=="after-exception":data["exception_edges"][0]["transfer"]="after_unit"
    else:data["method_signature"]="Ltest/Other;->other()V"
    with pytest.raises(ValueError):validate_cfg(method,MethodCFG.model_validate_json(canonical_json(data)))


@pytest.fixture(scope="session")
def local_prepared():
    try:java_backend.verify_build()
    except (ValueError,OSError):java_backend.build_java_backend()
    subprocess.run([sys.executable,"scripts/build_local_fixture.py"],cwd=ROOT,check=True,capture_output=True,timeout=90)


@pytest.fixture(scope="module")
def actual(local_prepared,tmp_path_factory):
    result=extract_local(ROOT/"artifacts/fixtures/f4a/valid.apk")
    out=filesystem_path(tmp_path_factory.mktemp("f4a"))
    package=write_extraction(result,out/"facts")
    store=import_snapshot(package,out/"stores")
    return result,store


def flows(result):
    return {item["signature"]:MethodFlow.model_validate_json(result.blobs[result.entry_digests[item["entry"]]]) for item in result.summary["local_flow"]["methods"]}


def calls_for(result,flow,signature):
    method=JimpleMethod.model_validate_json(result.blobs[result.entry_digests[flow.ir_entry]])
    return [Endpoint(element_ref=flow.node_refs[unit.index],slot_kind="argument",slot_index=0,position_label=f"unit:{unit.index}")
            for unit in method.units if unit.invoke and unit.invoke.signature==signature]


def trace(actual,name):
    result,path=actual
    flow=next(value for signature,value in flows(result).items() if signature.startswith(CASE+"->"+name+"("))
    calls=calls_for(result,flow,CASE+"->send(Ljava/lang/String;)V")
    with FactView(path) as view:return [view.trace_local_sources(endpoint) for endpoint in calls]


def test_real_cfg_and_reaching_definitions_match_independent_soot_query(actual):
    result,_=actual; checked=0; covered=set()
    for flow in flows(result).values():
        method=JimpleMethod.model_validate_json(result.blobs[result.entry_digests[flow.ir_entry]])
        cfg=MethodCFG.model_validate_json(result.blobs[result.entry_digests[flow.cfg_entry]])
        normal=solve_reaching(method,cfg,LocalFlowConfig(exception_policy="normal_only"))
        for oracle in cfg.normal_defs_oracle:
            if oracle.unit not in normal["reachable"]:continue
            expected=sorted(value for value in normal["in"][oracle.unit][oracle.local_index] if value>=0)
            assert expected==oracle.definitions
            checked+=1
            covered.add(method.signature.split("->")[1].split("(")[0])
    assert checked>0 and {"copied","branch","loop","exception","differentFields","opaqueCall"}<=covered


def test_real_copy_reaches_parameter_and_overwrite_reaches_only_literal(actual):
    copied=trace(actual,"copied")[0]
    assert [(item["root"]["kind"],item["root"]["details"].get("parameter_index")) for item in copied["roots"]]==[("parameter",0)]
    for name in ["overwritten","readThenFixed"]:
        out=trace(actual,name)[0]
        assert len(out["roots"])==1 and out["roots"][0]["root"]["kind"]=="constant"
        assert out["roots"][0]["root"]["details"]["operand"]["constant"]=="fixed"
        assert not any(item["root"]["kind"]=="call_result" for item in out["roots"])


def test_real_branch_and_loop_keep_may_sources_without_path_feasibility_claim(actual):
    branch=trace(actual,"branch")[0]
    assert {item["root"]["kind"] for item in branch["roots"]}=={"parameter","constant"}
    assert not branch["path_feasibility_checked"] and not branch["cycles"]
    result,path=actual
    flow=next(value for signature,value in flows(result).items() if "->loop(" in signature)
    endpoint=calls_for(result,flow,CASE+"->sendInt(I)V")[0]
    with FactView(path) as view:out=view.trace_local_sources(endpoint)
    assert not out["truncated"] and out["cycles"] and {item["root"]["kind"] for item in out["roots"]}>={"parameter","constant"}


def test_real_exception_paths_keep_old_value_in_handler(actual):
    outputs=trace(actual,"exception")
    assert len(outputs)==2
    assert {tuple(item["root"]["kind"] for item in output["roots"]) for output in outputs}=={("parameter",),("call_result",)}


@pytest.mark.parametrize("name",["differentFields","differentArrays"])
def test_heap_connections_stay_unknown_in_this_delivery(actual,name):
    out=trace(actual,name)[0]
    assert {item["root"]["kind"] for item in out["roots"]}=={"heap_read"}
    assert out["heap_and_callee_resolved"] is False


def test_callee_return_is_opaque_not_implicitly_bound_to_argument(actual):
    out=trace(actual,"opaqueCall")[0]
    assert len(out["roots"])==1 and out["roots"][0]["root"]["kind"]=="call_result"
    assert "->transform(" in out["roots"][0]["root"]["details"]["signature"]


@pytest.mark.parametrize("damage",["cross-method","wrong-source","wrong-kind","missing-selector","extra-link","bad-witness","bad-cfg-commit"])
def test_incorrect_connections_rejected_before_snapshot_publication(actual,tmp_path,damage):
    result,_=actual;changed=deepcopy(result)
    links=[edge for edge in changed.facts.relations if edge.provenance.tool_ref=="tool:local-flow"]
    assert links
    if damage=="bad-cfg-commit":
        report_entry=links[0].source_selector.split("#")[0]
        report=MethodFlow.model_validate_json(changed.blobs[changed.entry_digests[report_entry]])
        commit_entry=report.cfg_entry.replace(".json",".commit.json")
        data=json.loads(changed.blobs[changed.entry_digests[commit_entry]])
        data["request_sha256"]="0"*64
        raw=canonical_json(data).encode();digest=hashlib.sha256(raw).hexdigest()
        changed.blobs[digest]=raw;changed.entry_digests[commit_entry]=digest
    elif damage=="bad-witness":
        report_entry=links[0].source_selector.split("#")[0]
        report=MethodFlow.model_validate_json(changed.blobs[changed.entry_digests[report_entry]])
        report.links[0].witness=["n:999:1000"]
        data=report.model_dump_json().encode();digest=hashlib.sha256(data).hexdigest()
        changed.blobs[digest]=data;changed.entry_digests[report_entry]=digest
    elif damage=="cross-method":
        other=next(edge for edge in links if edge.provenance.support_refs[0]!=links[0].provenance.support_refs[0])
        links[0].target=other.target.model_copy(deep=True)
    elif damage=="wrong-source":links[0].source=links[-1].source.model_copy(deep=True)
    elif damage=="wrong-kind":links[0].relation_kind="state_dependency"
    elif damage=="missing-selector":links[0].source_selector=None
    else:
        extra=links[0].model_copy(deep=True);extra.id="relation:unjustified-extra";changed.facts.relations.append(extra)
    with pytest.raises(ValueError):verify_local_flow_evidence(changed.facts,lambda path:changed.blobs[changed.entry_digests[path]])
    package=write_extraction(changed,tmp_path/"facts")
    with pytest.raises(ValueError):import_snapshot(package,tmp_path/"store")
    assert not (tmp_path/"store").exists()


def test_roundtrip_moved_snapshot_retains_scope_and_evidence(actual,tmp_path):
    result,path=actual
    with FactView(path) as view:
        assert view.verify()["valid"]
        assert view.manifest.coverage["data_flow"]=="partial"
        assert all(view.manifest.coverage[name]=="not_started" for name in ["calls","objects","control","events"])
        assert not any(edge.relation_kind in {"argument_to_parameter","return_to_result","field_dependency","array_dependency","information_flow","control_dependency","event_trigger"} for edge in view.export_bundle().relations)
        exported=export_snapshot(view,tmp_path/"export",format="jsonl");expected=view.snapshot_id
    imported=import_snapshot(exported,tmp_path/"imported")
    moved=filesystem_path(tmp_path/"moved");shutil.copytree(imported,moved)
    with FactView(moved) as view:assert view.verify()["valid"] and view.snapshot_id==expected


def test_method_budget_keeps_old_facts_but_no_unfinished_data_links(local_prepared):
    result=extract_local(ROOT/"artifacts/fixtures/f4a/valid.apk",config=LocalFlowConfig(max_worklist_visits=1))
    assert any(item["state"]=="truncated" for item in result.summary["local_flow"]["methods"])
    assert not any(edge.provenance.tool_ref=="tool:local-flow" for edge in result.facts.relations)
    assert result.summary["coverage"]["data_flow"]=="partial" and result.summary["coverage"]["dex"]=="complete"
