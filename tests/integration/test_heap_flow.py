"""F4-C1 semantic tests on a compiled APK, including invalid storage connections."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from androserum.facts.call_flow import extract_calls
from androserum.facts.extractor import write_extraction
from androserum.facts.heap_flow import (HeapConfig, HeapMethod, TOOL, extend_heap, method_entry, trace_heap_sources, verify_heap_evidence)
from androserum.facts.identity import canonical_json, filesystem_path
from androserum.facts.models import Endpoint
from androserum.facts.store import FactView, RefFilter, export_snapshot, import_snapshot

ROOT=Path(__file__).resolve().parents[2]
CASE="Lorg/androserum/heap/Cases;"


@pytest.fixture(scope="module")
def heap_actual(tmp_path_factory):
    subprocess.run([sys.executable,"scripts/build_heap_fixture.py"],cwd=ROOT,check=True,capture_output=True)
    from androserum.facts.java_backend import verify_build,build_java_backend
    try:verify_build()
    except (ValueError,OSError):build_java_backend()
    base=extract_calls(ROOT/"artifacts/fixtures/f4c1/valid.apk")
    result=extend_heap(deepcopy(base))
    directory=tmp_path_factory.mktemp("heap")
    snapshot=import_snapshot(write_extraction(result,directory/"facts"),directory/"stores")
    return result,snapshot,base


def read(result,entry):return result.blobs[result.entry_digests[entry]]


def method(result,name):
    ref=next(x.id for x in result.facts.elements if getattr(x,"signature","").startswith(CASE+"->"+name+"(") and x.is_definition)
    return HeapMethod.model_validate_json(read(result,method_entry(ref)))


def sink_points(result,name):
    report=method(result,name)
    from androserum.facts.call_flow import CallReport,ENTRY
    calls=CallReport.model_validate_json(read(result,ENTRY))
    return [Endpoint(element_ref=x.unit_ref,slot_kind="argument",slot_index=0,position_label=f"unit:{x.unit}")
            for x in calls.calls if x.caller_ref==report.method_ref and x.declared_signature==CASE+"->send(Ljava/lang/String;)V"]


def traces(result,name):
    return [trace_heap_sources(result.facts,lambda e:read(result,e),p) for p in sink_points(result,name)]


def roots(out):
    return {(v["root"]["kind"],v["root"]["details"].get("parameter_index"),v["root"]["details"].get("operand",{}).get("constant")) for v in out["roots"]}


@pytest.fixture(scope="module")
def reviews(heap_actual):
    result,_,_=heap_actual
    return {name:traces(result,name) for name in ["sameObject","alias","differentObjects","differentFields","hiddenFields","overwritten",
        "readBeforeWrite","sameArray","arrayAlias","differentIndices","differentArrays","arrayOverwrite","unknownIndex","unknownReadIndex",
        "parameterBases","unknownBaseWrite","callEffect","exceptionalCall","exceptionalArray","branch","loop","repeatedAllocation",
        "multipleObjects","staticSame","staticDifferent","staticOverwrite"]}


@pytest.mark.parametrize("name",["sameObject","alias","sameArray","arrayAlias","staticSame"])
def test_same_object_storage_and_aliases_reach_only_written_parameter(reviews,name):
    assert roots(reviews[name][0])=={("parameter",0,None)}
    assert not reviews[name][0]["truncated"]


@pytest.mark.parametrize("name",["differentObjects","differentFields","differentIndices","differentArrays","staticDifferent","readBeforeWrite"])
def test_disjoint_storage_and_later_writes_do_not_create_connections(reviews,heap_actual,name):
    assert roots(reviews[name][0])=={("heap_read",None,None)}
    report=method(heap_actual[0],name)
    assert not any(value.role=="storage_read" for value in report.links)


@pytest.mark.parametrize("name",["overwritten","arrayOverwrite","staticOverwrite"])
def test_proven_singleton_overwrite_kills_prior_write(reviews,heap_actual,name):
    assert roots(reviews[name][0])=={("constant",None,"fixed")}
    report=method(heap_actual[0],name)
    dependencies=[v for v in report.links if v.role=="storage_read"]
    writes=[v for v in report.accesses if v.write_value]
    assert len(dependencies)==1 and dependencies[0].write_unit==writes[-1].unit


def test_hidden_fields_keep_full_declaring_signatures(reviews,heap_actual):
    assert roots(reviews["hiddenFields"][0])=={("parameter",0,None)}
    assert ("constant",None,"child") in roots(reviews["hiddenFields"][1])
    assert ("parameter",0,None) not in roots(reviews["hiddenFields"][1])
    report=method(heap_actual[0],"hiddenFields")
    signatures={x.field_signature for x in report.locations}
    assert signatures=={CASE[:-1]+"$Parent;->value:Ljava/lang/String;",CASE[:-1]+"$Child;->value:Ljava/lang/String;"}


def test_unknown_index_is_a_weak_may_write_not_absence(reviews,heap_actual):
    assert roots(reviews["unknownIndex"][0])=={("constant",None,"old"),("parameter",0,None)}
    report=method(heap_actual[0],"unknownIndex")
    assert any(x.unknown_index and not x.strong_update for x in report.accesses if x.write_value)
    assert any(x.resolution=="partial" for x in report.links if x.role=="storage_read")


def test_unknown_read_index_collects_may_locations_and_preserves_gap(reviews):
    assert roots(reviews["unknownReadIndex"][0])=={("heap_read",None,None),("constant",None,"other"),("parameter",0,None)}


def test_formal_parameter_bases_are_unknown_without_invented_aliases(reviews,heap_actual):
    assert roots(reviews["parameterBases"][0])=={("heap_read",None,None)}
    report=method(heap_actual[0],"parameterBases")
    assert all(x.unknown_base for x in report.accesses) and not report.objects


def test_unknown_base_write_havocs_potentially_overlapping_storage(reviews):
    out=roots(reviews["unknownBaseWrite"][0])
    assert out=={("heap_read",None,None),("constant",None,"old")}
    # Input x may affect the location, but v1 cannot justify an object binding.
    assert ("parameter",0,None) not in out


@pytest.mark.parametrize("name",["callEffect","exceptionalCall"])
def test_call_may_change_storage_on_normal_and_exceptional_exit(reviews,name):
    assert roots(reviews[name][0])=={("heap_read",None,None),("parameter",0,None)}


def test_throwing_write_does_not_commit_new_value_in_handler(reviews):
    actual={frozenset(roots(x)) for x in reviews["exceptionalArray"]}
    assert actual=={frozenset({("parameter",0,None)}),frozenset({("parameter",0,None),("parameter",1,None)})}


def test_branch_and_loop_fixed_points_preserve_alternatives(reviews):
    assert roots(reviews["branch"][0])=={("parameter",0,None),("constant",None,"other")}
    assert roots(reviews["loop"][0])=={("parameter",0,None),("constant",None,"loop")}
    assert not reviews["loop"][0]["truncated"] and not reviews["branch"][0]["path_feasibility_checked"]


def test_repeated_allocation_is_not_a_proven_singleton(reviews,heap_actual):
    report=method(heap_actual[0],"repeatedAllocation")
    assert report.objects and all(not x.single_allocation_per_invocation for x in report.objects)
    assert all(not x.strong_update for x in report.accesses if x.write_value)
    assert ("heap_read",None,None) in roots(reviews["repeatedAllocation"][0])


def test_multiple_possible_objects_require_weak_updates_and_specific_bindings(reviews,heap_actual):
    assert roots(reviews["multipleObjects"][0])=={("constant",None,"left"),("parameter",0,None)}
    report=method(heap_actual[0],"multipleObjects")
    chosen=next(x for x in report.accesses if len(x.objects)==2)
    assert not chosen.strong_update
    bindings={b.id:b for b in report.bindings}
    for edge in report.links:
        if edge.role=="storage_read":
            assert all(any(p.element_ref==edge.object_ref for p in bindings[ref].endpoints) for ref in edge.binding_refs)


@pytest.mark.parametrize("configuration",[{"max_locations":1},{"max_worklist_visits":1},{"max_origin_visits":1},{"max_witness_visits":1}])
def test_budget_exhaustion_does_not_publish_incomplete_storage_dependencies(heap_actual,configuration):
    _,_,base=heap_actual
    changed=extend_heap(deepcopy(base),HeapConfig(**configuration))
    reports=[HeapMethod.model_validate_json(read(changed,x["entry"])) for x in changed.summary["heap_flow"]["methods"]]
    assert any(x.state=="truncated" for x in reports)
    for report in reports:
        if report.state=="truncated":assert not report.links and not report.nodes and not report.bindings


@pytest.mark.parametrize("config",[{"max_locations":0},{"max_origin_visits":0},{"call_effect":"pure"}])
def test_invalid_heap_configuration_rejected(config):
    with pytest.raises(ValueError):HeapConfig(**config)


@pytest.mark.parametrize("damage",["different-object","different-location","wrong-source","wrong-type","extra-edge","missing-selector","bad-witness","bad-object-report","bad-binding","removed-report"])
def test_wrong_object_location_or_dependency_rejected_before_publication(heap_actual,tmp_path,damage):
    original,_,_=heap_actual;changed=deepcopy(original)
    edge=next(x for x in changed.facts.relations if x.provenance.tool_ref==TOOL and x.relation_kind=="field_dependency" and x.binding_refs)
    selected=next(x for x in changed.facts.relations if x.provenance.tool_ref==TOOL and x.relation_kind=="field_dependency" and x.id!=edge.id)
    entry=edge.source_selector.split('#')[0]
    if damage=="wrong-source":edge.source=selected.source.model_copy(deep=True)
    elif damage=="wrong-type":edge.relation_kind="array_dependency"
    elif damage=="extra-edge":
        extra=edge.model_copy(deep=True);extra.id="relation:forged-heap";changed.facts.relations.append(extra)
    elif damage=="missing-selector":edge.source_selector=None
    elif damage=="bad-binding":
        bound=next(x for x in changed.facts.bindings if x.id in edge.binding_refs)
        bound.endpoints[0]=selected.target.model_copy(deep=True)
    elif damage=="removed-report":
        changed.facts.elements=[x for x in changed.facts.elements if not(x.provenance.tool_ref==TOOL and x.position.artifact_path==entry and x.position.position_label=="heap-flow")]
    else:
        data=json.loads(read(changed,entry))
        index=int(edge.source_selector.rsplit('/',1)[1])
        if damage=="bad-witness":data['links'][index]['witness']=['n:999:1000']
        elif damage=="different-object":data['links'][index]['object_ref']='analysis:wrong-object'
        elif damage=="different-location":data['links'][index]['location_ref']='analysis:wrong-storage'
        else:data['objects'][0]['single_allocation_per_invocation']=not data['objects'][0]['single_allocation_per_invocation']
        raw=canonical_json(data).encode();digest=hashlib.sha256(raw).hexdigest()
        changed.blobs[digest]=raw;changed.entry_digests[entry]=digest
    with pytest.raises(ValueError):verify_heap_evidence(changed.facts,lambda e:read(changed,e))
    try:package=write_extraction(changed,tmp_path/"facts")
    except ValueError:return
    with pytest.raises(ValueError):import_snapshot(package,tmp_path/"stores")
    assert not (tmp_path/"stores").exists()


def test_object_binding_and_dependency_direction_query_are_preserved(heap_actual):
    result,path,_=heap_actual
    edge=next(x for x in result.facts.relations if x.provenance.tool_ref==TOOL and x.relation_kind=="field_dependency" and x.binding_refs)
    with FactView(path) as view:
        out=view.get_relations(edge.source,direction="out",relation_kinds=["field_dependency"],context=RefFilter(mode="missing"),binding=RefFilter(mode="exact",ref=edge.binding_refs[0]))
        back=view.get_relations(edge.target,direction="in",relation_kinds=["field_dependency"],context=RefFilter(mode="missing"),binding=RefFilter(mode="all"))
        assert edge.id in {x.id for x in out.records} and edge.id in {x.id for x in back.records}


def test_exchange_move_retains_storage_proofs_and_analysis_boundaries(heap_actual,tmp_path):
    result,path,_=heap_actual
    with FactView(path) as view:
        assert view.verify()['valid']
        assert all(view.manifest.coverage[x]=='partial' for x in ['objects','data_flow','calls','dex_jimple_mapping'])
        assert all(view.manifest.coverage[x]=='not_started' for x in ['control','events'])
        assert not any(x.relation_kind in {'information_flow','control_dependency','event_trigger'} for x in result.facts.relations)
        expected=view.snapshot_id;exported=export_snapshot(view,tmp_path/'export',format='jsonl')
    imported=import_snapshot(exported,tmp_path/'reimport')
    moved=filesystem_path(tmp_path/'moved');shutil.copytree(imported,moved)
    with FactView(moved) as view:
        assert view.verify()['valid'] and view.snapshot_id==expected
        assert roots(view.trace_heap_sources(sink_points(result,'sameObject')[0]))=={('parameter',0,None)}
