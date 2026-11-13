"""Cross-method object/store identity, frame separation and public evidence paths."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from androserum.facts.context_heap import (ContextHeapConfig,ContextHeapReport,TOOL,entry_for,extend_context_heap,trace_context_sources,verify_context_heap)
from androserum.facts.extractor import write_extraction
from androserum.facts.heap_flow import extract_heap
from androserum.facts.identity import canonical_json,filesystem_path
from androserum.facts.models import Endpoint
from androserum.facts.store import FactView,export_snapshot,import_snapshot

ROOT=Path(__file__).resolve().parents[2];CASE='Lorg/androserum/context/Cases;'


@pytest.fixture(scope='module')
def context_actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_context_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    from androserum.facts.java_backend import verify_build,build_java_backend
    try:verify_build()
    except (ValueError,OSError):build_java_backend()
    base=extract_heap(ROOT/'artifacts/fixtures/f4c2/valid.apk')
    result=extend_context_heap(deepcopy(base));out=tmp_path_factory.mktemp('context')
    snapshot=import_snapshot(write_extraction(result,out/'facts'),out/'stores')
    return result,snapshot,base


def read(result,entry):return result.blobs[result.entry_digests[entry]]
def root_ref(result,name):return next(x.id for x in result.facts.elements if getattr(x,'signature','').startswith(CASE+'->'+name+'(') and x.is_definition)
def report(result,name):return ContextHeapReport.model_validate_json(read(result,entry_for(root_ref(result,name))))


def points(result,name):
    from androserum.facts.call_flow import CallReport,ENTRY
    calls=CallReport.model_validate_json(read(result,ENTRY));owner=root_ref(result,name)
    return [Endpoint(element_ref=x.unit_ref,position_label=f'unit:{x.unit}',slot_kind='argument',slot_index=0) for x in calls.calls if x.caller_ref==owner and x.declared_signature==CASE+'->send(Ljava/lang/String;)V']


def traces(result,name):return [trace_context_sources(result.facts,lambda e:read(result,e),root_ref(result,name),p) for p in points(result,name)]
def roots(out):return {(x['root']['kind'],x['root']['details'].get('parameter_index'),x['root']['details'].get('operand',{}).get('constant')) for x in out['roots']}


@pytest.fixture(scope='module')
def reviews(context_actual):
    result,_,_=context_actual
    return {name:traces(result,name) for name in ['twoObjects','fixedRight','callerA','callerB','overwritten','alias','privateHelpers','nested','factories','wrongField','unknownEffect','exceptional','arrays','recursion','sourceUse']}


@pytest.mark.parametrize('name',['twoObjects','factories','arrays'])
def test_two_objects_or_storage_positions_keep_separate_inputs(reviews,name):
    assert [roots(x) for x in reviews[name]]==[{('parameter',0,None)},{('parameter',1,None)}]


@pytest.mark.parametrize('name,expected',[('fixedRight','fixed'),('callerA','A'),('callerB','B'),('overwritten','fixed')])
def test_fixed_values_and_callers_do_not_inherit_other_inputs(reviews,name,expected):
    assert roots(reviews[name][0])=={('constant',None,expected)}


@pytest.mark.parametrize('name',['alias','privateHelpers','nested'])
def test_alias_receiver_and_nested_wrappers_preserve_value(reviews,name):
    assert roots(reviews[name][0])=={('parameter',0,None)}


def test_same_helper_gets_distinct_full_call_frames_and_object_bindings(context_actual):
    result,_,_=context_actual;r=report(result,'twoObjects');records={x.id:x for x in result.facts.elements}
    puts=[f for f in r.projection.frames if '->put(' in records[f.method_ref].signature]
    gets=[f for f in r.projection.frames if '->get(' in records[f.method_ref].signature]
    assert len(puts)==len(gets)==2 and len({f.context_ref for f in puts+gets})==4
    assert len({x.object_ref for x in r.heap.locations if x.kind=='instance_field'})==2
    bindings={x.id:x for x in r.heap.bindings}
    for edge in r.heap.links:
        if edge.role=='storage_read':assert all(any(p.element_ref==edge.object_ref for p in bindings[b].endpoints) for b in edge.binding_refs)


def test_public_path_contains_real_argument_storage_and_return_evidence(context_actual,reviews):
    result,path,_=context_actual
    with FactView(path) as view:
        out=view.trace_context_sources(root_ref(result,'twoObjects'),points(result,'twoObjects')[0])
    assert roots(out)=={('parameter',0,None)} and out['snapshot_id']
    steps=out['roots'][0]['relations_to_target']
    roles={s['target'].get('role') for s in steps}
    assert {'argument_binding','return_binding','call_result'}<=roles
    store=next(x for x in steps if x['relation']['relation_kind']=='field_dependency')
    assert '->put(' in store['source']['method_signature'] and '->get(' in store['target']['method_signature']
    assert store['source']['context_ref']!=store['target']['context_ref']
    assert store['target']['call_path'] and store['relation']['binding_refs']
    assert any(s['target'].get('support_refs') for s in steps if s['target'].get('role')=='argument_binding')


def test_wrong_field_is_not_a_put_get_connection(reviews):assert roots(reviews['wrongField'][0])=={('heap_read',None,None)}


def test_unknown_call_influence_is_not_silently_dropped(reviews):assert roots(reviews['unknownEffect'][0])=={('heap_read',None,None),('parameter',0,None)}


def test_exceptional_call_does_not_use_normal_committed_heap_as_exact_fact(reviews):
    assert {frozenset(roots(x)) for x in reviews['exceptional']}=={frozenset({('parameter',1,None)}),frozenset({('heap_read',None,None),('parameter',0,None)})}
    assert all(x['exceptional_heap_precision']=='unknown_cross_method_effects' for x in reviews['exceptional'])


def test_recursion_depth_cut_keeps_unknown_and_does_not_merge_frames(reviews):
    out=reviews['recursion'][0]
    assert out['truncated'] and any('Depth budget' in x['reason'] for x in out['unresolved_effects'])
    assert ('parameter',0,None) in roots(out) and any(x[0]=='call_result' for x in roots(out))


def test_normal_result_endpoint_and_original_position_are_validated(context_actual):
    result,_,_=context_actual;r=report(result,'twoObjects')
    from androserum.facts.call_flow import CallReport,ENTRY
    site=next(s for s in CallReport.model_validate_json(read(result,ENTRY)).calls if s.caller_ref==r.root_method_ref and '->get(' in s.declared_signature)
    point=Endpoint(element_ref=site.unit_ref,position_label=f'unit:{site.unit}',slot_kind='result')
    out=trace_context_sources(result.facts,lambda e:read(result,e),r.root_method_ref,point)
    assert roots(out) in [{('parameter',0,None)},{('parameter',1,None)}]
    with pytest.raises(ValueError):trace_context_sources(result.facts,lambda e:read(result,e),r.root_method_ref,point.model_copy(update={'position_label':'forged'}))


@pytest.mark.parametrize('config',[{'max_nodes':1},{'max_frames':1},{'scalar':{'max_worklist_visits':1}},{'heap':{'max_locations':1}}])
def test_projection_and_solver_budgets_publish_no_incomplete_relations(context_actual,config):
    _,_,base=context_actual
    from androserum.facts.models import MethodRecord
    signature=next(x.signature for x in base.facts.elements if isinstance(x,MethodRecord) and x.signature.startswith(CASE+'->twoObjects('))
    changed=extend_context_heap(deepcopy(base),ContextHeapConfig.model_validate({'root_signatures':[signature],**config}))
    r=report(changed,'twoObjects')
    assert r.state=='truncated' and r.heap is None and r.projection is None
    assert not any(x.provenance.tool_ref==TOOL for x in changed.facts.relations)


@pytest.mark.parametrize('damage',['frame','object','location','coverage','path','wrong-source','extra-edge','missing-selector','return-binding'])
def test_bad_context_object_storage_or_coverage_is_rejected(context_actual,tmp_path,damage):
    original,_,_=context_actual;changed=deepcopy(original);root=root_ref(changed,'twoObjects');entry=entry_for(root)
    edge=next(x for x in changed.facts.relations if x.provenance.tool_ref==TOOL and x.relation_kind=='field_dependency' and x.source_selector.startswith(entry+'#'))
    if damage=='wrong-source':edge.source=edge.target.model_copy(deep=True)
    elif damage=='extra-edge':
        extra=edge.model_copy(deep=True);extra.id='relation:forged-context';changed.facts.relations.append(extra)
    elif damage=='missing-selector':edge.source_selector=None
    else:
        data=json.loads(read(changed,entry));link=next(x for x in data['heap']['links'] if x['role']=='storage_read')
        if damage=='frame':data['projection']['frames'][1]['call_path'][0]['callsite_ref']='instruction:wrong-call'
        elif damage=='object':link['object_ref']='analysis:wrong-object'
        elif damage=='location':link['location_ref']='analysis:wrong-location'
        elif damage=='coverage':next(x for x in data['heap']['accesses'] if x['strong_update'])['strong_update']=False
        elif damage=='path':link['witness']=['n:999:1000']
        else:next(x for x in data['projection']['nodes'] if x['role']=='return_binding' and x['support_refs'])['support_refs']=[]
        raw=canonical_json(data).encode();digest=hashlib.sha256(raw).hexdigest();changed.blobs[digest]=raw;changed.entry_digests[entry]=digest
    with pytest.raises(ValueError):verify_context_heap(changed.facts,lambda e:read(changed,e))
    try:package=write_extraction(changed,tmp_path/'facts')
    except ValueError:return
    with pytest.raises(ValueError):import_snapshot(package,tmp_path/'stores')


def test_exchange_move_retains_cross_method_paths_and_partial_boundaries(context_actual,tmp_path):
    result,path,_=context_actual
    with FactView(path) as view:
        assert view.verify()['valid'];expected=view.snapshot_id
        assert all(view.manifest.coverage[x]=='partial' for x in ['objects','data_flow','calls'])
        assert all(view.manifest.coverage[x]=='not_started' for x in ['control','events'])
        assert not any(x.relation_kind=='information_flow' for x in result.facts.relations)
        exported=export_snapshot(view,tmp_path/'export',format='jsonl')
    imported=import_snapshot(exported,tmp_path/'imported');moved=filesystem_path(tmp_path/'moved');shutil.copytree(imported,moved)
    with FactView(moved) as view:
        assert view.verify()['valid'] and view.snapshot_id==expected
        assert roots(view.trace_context_sources(root_ref(result,'twoObjects'),points(result,'twoObjects')[1]))=={('parameter',1,None)}


def test_real_pinned_source_signature_matches_three_distinct_calls_but_not_sink(context_actual,tmp_path):
    from androserum.facts.sapi import SapiImportConfig,import_catalog,match_sapi,load_catalog
    result,_,_=context_actual
    config=SapiImportConfig.model_validate_json((ROOT/'configs/sapi-import.example.json').read_text('utf-8'))
    catalog=import_catalog(config,tmp_path/'sapi')
    matched=match_sapi(result.facts,load_catalog(tmp_path/'sapi'))
    assert len(matched['matches'])==3 and len({x['callsite_ref'] for x in matched['matches']})==3
    for match in matched['matches']:
        assert match['receiver'] and match['result'] and not match['arguments']
        assert all(x['signature']=='Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;' for x in match['routes'])
        assert any('READ_PHONE_STATE' in origin['metadata'] for entry in match['catalog_entries'] for origin in entry['origins'])
        assert not match['maliciousness_inferred']
    assert len(catalog['issues'])==13 and not catalog['multi_source_catalog_complete']


def test_candidate_matching_uses_actual_target_evidence_and_context(context_actual,tmp_path):
    from androserum.facts.sapi import SapiImportConfig,SapiSource,import_catalog,match_sapi
    result,_,_=context_actual
    raw=b'<org.androserum.context.Cases$ReaderImpl: java.lang.String read()> -> _SOURCE_\n'
    path=tmp_path/'synthetic-signatures.txt';path.write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
    config=SapiImportConfig(sources=[SapiSource(source_id='fixture-only-candidate-test',version='1',path=str(path),sha256=digest,resource_sha256=digest)])
    matches=match_sapi(result.facts,import_catalog(config,tmp_path/'catalog'))['matches']
    candidate=next(x for x in matches if x['method_ref']==root_ref(result,'candidateUse'))
    assert candidate['context_ref'] and all(x['basis']=='candidate' for x in candidate['routes'])
    assert any(len(x['evidence_refs'])==3 for x in candidate['routes'])
    assert not any(x['method_ref']==root_ref(result,'sourceUse') for x in matches)
