"""F4-B expected source sets on compiled APKs and negative call-binding checks."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from androserum.facts.call_flow import (CallConfig, CallFrame, CallReport, ENTRY, TOOL, extend_calls, trace_sources, verify_call_evidence)
from androserum.facts.extractor import write_extraction
from androserum.facts.identity import canonical_json, filesystem_path
from androserum.facts.jimple import JimpleMethod
from androserum.facts.local_flow import extract_local
from androserum.facts.models import Endpoint
from androserum.facts.store import FactView, RefFilter, export_snapshot, import_snapshot

ROOT=Path(__file__).resolve().parents[2]
CASE="Lorg/androserum/calls/Cases;"


@pytest.fixture(scope="module")
def call_actual(tmp_path_factory):
    subprocess.run([sys.executable,"scripts/build_call_fixture.py"],cwd=ROOT,check=True,capture_output=True)
    from androserum.facts.java_backend import verify_build,build_java_backend
    try: verify_build()
    except (ValueError,OSError): build_java_backend()
    base=extract_local(ROOT/"artifacts/fixtures/f4b/valid.apk")
    result=extend_calls(deepcopy(base))
    directory=tmp_path_factory.mktemp("f4b")
    package=write_extraction(result,directory/"facts")
    snapshot=import_snapshot(package,directory/"stores")
    return result,snapshot,base


def read(result,entry): return result.blobs[result.entry_digests[entry]]


def report(result): return CallReport.model_validate_json(read(result,ENTRY))


def sink_points(result,name,sink="send"):
    records={item.id:item for item in result.facts.elements}
    return [Endpoint(element_ref=site.unit_ref,position_label=f"unit:{site.unit}",slot_kind="argument",slot_index=0)
            for site in report(result).calls if ("->"+name+"(") in records[site.caller_ref].signature and site.declared_signature.startswith(CASE+"->"+sink+"(")]


def traces(result,name,sink="send"):
    return [trace_sources(result.facts,lambda e:read(result,e),point) for point in sink_points(result,name,sink)]


@pytest.fixture(scope="module")
def call_reviews(call_actual):
    result,_,_=call_actual
    return {name:traces(result,name) for name in ["callerA","callerB","sameCaller","ignored","nested","wideCaller",
        "exceptional","throwCaller","interfaceCaller","virtualCaller","receiverCaller","recursiveCaller","libraryCaller","overloadCaller"]}


def root_signature(out):
    return {(item["root"]["kind"],item["root"]["details"].get("parameter_index"),
             item["root"]["details"].get("operand",{}).get("constant")) for item in out["roots"]}


@pytest.mark.parametrize("name,expected",[("callerA",("constant",None,"id-A")),("callerB",("constant",None,"fixed-B")),
    ("ignored",("constant",None,"fixed")),("nested",("parameter",0,None)),("wideCaller",("parameter",0,None))])
def test_exact_source_sets_for_distinct_callers_nested_and_ignored_input(call_reviews,name,expected):
    out=call_reviews[name][0]
    assert root_signature(out)=={expected} and not out["truncated"]


def test_same_caller_two_calls_do_not_swap_returns(call_reviews):
    assert [root_signature(x) for x in call_reviews["sameCaller"]]==[{("constant",None,"fixed")},{("parameter",0,None)}]


def test_normal_and_exceptional_paths_keep_distinct_input_values(call_reviews,call_actual):
    assert {frozenset(root_signature(x)) for x in call_reviews["exceptional"]}=={
        frozenset({("parameter",0,None)}),frozenset({("parameter",1,None)})}
    result,_,_=call_actual
    site=next(s for s in report(result).calls if "->normalAndThrow(" in s.declared_signature)
    assert site.candidates[0].normal_return_units and site.candidates[0].escaping_exception_units


def test_throw_only_never_creates_return_binding(call_reviews,call_actual):
    result,_,_=call_actual;r=report(result)
    site=next(s for s in r.calls if "->onlyThrow(" in s.declared_signature)
    assert site.candidates and not site.candidates[0].normal_return_units
    assert not any(x.role=="normal_return_binding" and x.callsite_ref==site.callsite_ref for x in r.links)
    assert {kind for kind,_,_ in root_signature(call_reviews["throwCaller"][0])}=={"call_result"}


@pytest.mark.parametrize("name,method,owners",[("interfaceCaller","map",{"Cases$First;","Cases$Second;"}),
    ("virtualCaller","pass",{"Cases$Base;","Cases$Child;"})])
def test_cha_candidate_sets_separate_declaration_and_keep_open_world_unknown(call_actual,call_reviews,name,method,owners):
    result,_,_=call_actual;records={x.id:x for x in result.facts.elements}
    site=next(s for s in report(result).calls if ("->"+name+"(") in records[s.caller_ref].signature and ("->"+method+"(") in s.declared_signature)
    assert {x.signature.split('->')[0].split('/')[-1] for x in site.candidates}==owners
    assert site.state=="partial" and all(x.rule=="application_cha" for x in site.candidates)
    assert "call_result" in {x[0] for x in root_signature(call_reviews[name][0])}


def test_special_super_and_private_targets_are_exact(call_actual):
    result,_,_=call_actual
    sites=[s for s in report(result).calls if "->privateIdentity(" in s.declared_signature or "Cases$Base;->pass(" in s.declared_signature and s.invoke_kind=="special"]
    assert len(sites)==2 and all(s.state=="complete" and len(s.candidates)==1 and s.candidates[0].rule=="exact_special" for s in sites)


def test_receiver_reference_binding_is_preserved_without_heap_claim(call_actual):
    result,_,_=call_actual
    out=traces(result,"receiverReturn","sendObject")[0]
    assert ("parameter",0,None) in root_signature(out) and not out["heap_resolved"]
    assert any(x.role=="receiver_binding" and x.binding_kind=="object" for x in report(result).links)


def test_overload_signatures_do_not_merge(call_reviews):
    assert [root_signature(x) for x in call_reviews["overloadCaller"]]==[{("parameter",0,None)},{("constant",None,"integer")}]


def test_missing_library_implementation_remains_opaque(call_reviews):
    roots=call_reviews["libraryCaller"][0]["roots"]
    assert len(roots)==1 and roots[0]["root"]["kind"]=="call_result"
    assert "getProperty" in roots[0]["root"]["details"]["signature"]


def test_recursion_stops_at_explicit_depth_without_context_merging(call_reviews):
    out=call_reviews["recursiveCaller"][0]
    assert out["truncated"] and any("depth" in x["reason"] for x in out["stops"])
    assert ("parameter",0,None) in root_signature(out)


def test_selected_callee_context_does_not_fan_out_to_other_callers(call_actual):
    result,_,_=call_actual;r=report(result)
    method=next(x for x in result.facts.elements if getattr(x,"signature",None)==CASE+"->identity(Ljava/lang/String;)Ljava/lang/String;" and x.is_definition)
    point=Endpoint(element_ref=method.id,slot_kind="return")
    without=trace_sources(result.facts,lambda e:read(result,e),point)
    assert root_signature(without)=={("parameter",0,None)}
    records={x.id:x for x in result.facts.elements}
    for caller,expected in [("callerA","id-A"),("callerB","fixed-B")]:
        site=next(s for s in r.calls if ("->"+caller+"(") in records[s.caller_ref].signature and "->identity(" in s.declared_signature)
        c=site.candidates[0]
        frame=CallFrame(callsite_ref=site.callsite_ref,callee_ref=c.method_ref,context_ref=c.context_ref)
        out=trace_sources(result.facts,lambda e:read(result,e),point,initial_call_path=[frame])
        assert root_signature(out)=={("constant",None,expected)}
    with pytest.raises(ValueError):
        trace_sources(result.facts,lambda e:read(result,e),sink_points(result,"callerA")[0],initial_call_path=[frame])


@pytest.mark.parametrize("configuration",[{"max_calls":1},{"max_candidates_per_call":1},{"max_trace_depth":1}])
def test_enumeration_candidate_and_depth_budgets_do_not_pretend_complete(call_actual,configuration):
    _,_,base=call_actual
    changed=extend_calls(deepcopy(base),CallConfig(**configuration));r=report(changed)
    if "max_calls" in configuration: assert r.truncated and r.pending_methods
    elif "max_candidates_per_call" in configuration:
        assert any(s.state=="truncated" and not s.candidates for s in r.calls)
    else: assert traces(changed,"nested")[0]["truncated"]


@pytest.mark.parametrize("config",[{"max_trace_depth":0},{"context_policy":"merged"},{"max_candidates_per_call":0}])
def test_invalid_call_configuration_rejected(config):
    with pytest.raises(ValueError): CallConfig(**config)


def test_missing_verified_call_position_retains_unknown_without_fabricated_bindings(call_actual):
    _,_,base=call_actual;changed=deepcopy(base)
    records={x.id:x for x in changed.facts.elements}
    caller=next(x.id for x in changed.facts.elements if getattr(x,"signature",None)==CASE+"->callerA()V" and x.is_definition)
    changed.facts.relations=[e for e in changed.facts.relations if not (e.relation_kind=="dex_jimple_mapping" and records[e.target.element_ref].method_ref==caller)]
    result=extend_calls(changed);r=report(result)
    sites=[s for s in r.calls if s.caller_ref==caller]
    assert sites and all(s.state=="unavailable" and not s.candidates for s in sites)
    out=traces(result,"callerA")[0]
    assert root_signature(out)=={("call_result",None,None)}


def test_unavailable_method_scope_is_explicit_for_abstract_declarations(call_actual):
    result,_,_=call_actual;r=report(result)
    method=next(x for x in result.facts.elements if getattr(x,"signature",None)==CASE[:-1]+"$Mapper;->map(Ljava/lang/String;)Ljava/lang/String;" and x.is_definition)
    assert method.id in r.unavailable_methods and "abstract" in r.unavailable_methods[method.id]
    assert any(s.capability=="calls" and s.scope.element_ref==method.id and s.state=="unavailable" for s in result.facts.statuses)


@pytest.mark.parametrize("damage",["wrong-source","wrong-callsite","wrong-context","wrong-kind","extra-edge","missing-selector","altered-report","removed-report-node"])
def test_wrong_bindings_rejected_before_publication(call_actual,tmp_path,damage):
    original,_,_=call_actual;changed=deepcopy(original)
    edges=[e for e in changed.facts.relations if e.provenance.tool_ref==TOOL]
    edge=next(e for e in edges if e.relation_kind=="return_to_result")
    if damage=="wrong-source": edge.source=next(e.source for e in edges if e.relation_kind=="argument_to_parameter").model_copy(deep=True)
    elif damage=="wrong-callsite": edge.callsite_ref=next(e.callsite_ref for e in edges if e.callsite_ref and e.callsite_ref!=edge.callsite_ref)
    elif damage=="wrong-context": edge.context_ref=next(e.context_ref for e in edges if e.context_ref and e.context_ref!=edge.context_ref)
    elif damage=="wrong-kind": edge.relation_kind="state_dependency"
    elif damage=="missing-selector": edge.source_selector=None
    elif damage=="extra-edge":
        extra=edge.model_copy(deep=True);extra.id="relation:forged";changed.facts.relations.append(extra)
    elif damage=="removed-report-node":
        changed.facts.elements=[e for e in changed.facts.elements if not (e.provenance.tool_ref==TOOL and getattr(e,"position",None) and e.position.position_label=="call-flow")]
    else:
        data=json.loads(read(changed,ENTRY));data["links"][0]["source"]=data["links"][0]["target"]
        raw=canonical_json(data).encode();digest=hashlib.sha256(raw).hexdigest();changed.blobs[digest]=raw;changed.entry_digests[ENTRY]=digest
    with pytest.raises(ValueError): verify_call_evidence(changed.facts,lambda e:read(changed,e))
    try: package=write_extraction(changed,tmp_path/"facts")
    except ValueError: return
    with pytest.raises(ValueError): import_snapshot(package,tmp_path/"stores")
    assert not (tmp_path/"stores").exists()


def test_call_bindings_queryable_with_original_endpoints_context_and_binding(call_actual):
    result,path,_=call_actual
    edge=next(e for e in result.facts.relations if e.provenance.tool_ref==TOOL and e.relation_kind=="argument_to_parameter")
    with FactView(path) as view:
        q=view.get_relations(edge.source,direction="out",relation_kinds=["argument_to_parameter"],context=RefFilter(mode="exact",ref=edge.context_ref),binding=RefFilter(mode="exact",ref=edge.binding_refs[0]))
        assert edge.id in {x.id for x in q.records}


def test_roundtrip_move_preserves_proofs_and_stage_boundaries(call_actual,tmp_path):
    result,path,_=call_actual
    with FactView(path) as view:
        assert view.verify()["valid"]
        assert all(view.manifest.coverage[x]=="partial" for x in ["calls","data_flow","dex_jimple_mapping"])
        assert all(view.manifest.coverage[x]=="not_started" for x in ["objects","control","events"])
        assert not any(e.relation_kind in {"field_dependency","array_dependency","information_flow","control_dependency","event_trigger"} for e in result.facts.relations)
        expected=view.snapshot_id;exported=export_snapshot(view,tmp_path/"export",format="jsonl")
    imported=import_snapshot(exported,tmp_path/"reimport")
    moved=filesystem_path(tmp_path/"moved");shutil.copytree(imported,moved)
    with FactView(moved) as view:
        assert view.verify()["valid"] and view.snapshot_id==expected
        assert root_signature(view.trace_call_sources(sink_points(result,"callerA")[0]))=={("constant",None,"id-A")}
