"""Actual Spark allocation constraints must resolve and feed distinct call frames."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from androserum.facts.call_flow import CallConfig,CallReport,ENTRY as CALL_ENTRY,extract_calls,verify_call_evidence
from androserum.facts.context_heap import ContextHeapConfig,extend_context_heap,entry_for,trace_context_sources,verify_context_heap
from androserum.facts.heap_flow import extend_heap
from androserum.facts.identity import canonical_json
from androserum.facts.java_backend import JavaConfig
from androserum.facts.points_to import ENTRY,RAW,TOOL,PointsToConfig,extend_points_to,points_to_evidence,verify_points_to
from androserum.facts.local_flow import extract_local
from androserum.facts.models import Endpoint
from androserum.pipeline.evidence import write_encoded_extraction
from androserum.facts.store import FactView,import_snapshot
from androserum.facts.sapi import SapiImportConfig,import_catalog
from androserum.facts.bu import BUConfig,build_units

ROOT=Path(__file__).resolve().parents[2]
OWNER='Lorg/androserum/points/Cases;'


@pytest.fixture(scope='module')
def actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_points_to_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    apk=ROOT/'artifacts/fixtures/points-to/valid.apk'
    result=extract_calls(apk,java_config=JavaConfig(platform_api=28),config=CallConfig(dispatch='cha_spark_points_to'))
    signatures=[m.signature for m in result.facts.elements if m.kind=='method' and m.is_definition and
                any(('->'+name+'(') in m.signature for name in ['distinct','merged','twoHelpers','across','fields','arrays','inherited'])]
    result=extend_context_heap(extend_heap(result),ContextHeapConfig(root_signatures=signatures))
    output=tmp_path_factory.mktemp('actual-spark')
    package=write_encoded_extraction(result,output/'facts',input_apk=apk)
    snapshot=import_snapshot(package,output/'stores')
    catalog=output/'sapi';import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')),catalog)
    def read(e):return result.blobs[result.entry_digests[e]]
    report=json.loads(read(ENTRY))
    (output/'points-to-report.json').write_bytes(read(ENTRY))
    (output/'call-report.json').write_bytes(read(CALL_ENTRY))
    return result,snapshot,catalog,report,read,output


def calls(actual,name):
    return [c for c in actual[3]['calls'] if '->'+name+'(' in c['caller_signature'] and c['invoke_kind']=='interface']


def targets(call):return {t['signature'].split('->')[0].split('$')[-1] for t in call['targets']}


def test_distinct_local_receivers_filter_cha_using_real_spark_allocations(actual):
    result,_,_,report,read,_=actual
    raw=json.loads(read(RAW))
    assert raw['solver_class']=='soot.jimple.spark.pag.PAG' and raw['allocation_node_count']>0
    assert not raw['flow_sensitive'] and not raw['context_sensitive']
    selected=calls(actual,'distinct');assert len(selected)==2
    assert {frozenset(targets(c)) for c in selected}=={frozenset({'A;'}),frozenset({'B;'})}
    assert set(selected[0]['receiver_object_refs']).isdisjoint(selected[1]['receiver_object_refs'])
    report=CallReport.model_validate_json(read(CALL_ENTRY));assert report.points_to_analysis_performed
    rows=[c for c in report.calls if c.unit_ref in {c['unit_ref'] for c in selected}]
    assert all(len(c.candidates)==1 and c.candidates[0].rule=='spark_points_to' for c in rows)
    assert all('Cases$C;' not in c.candidates[0].signature for c in rows)


def test_multiple_receiver_and_array_may_sets_do_not_become_one_definite_target(actual):
    for name in ['merged','arrays']:
        call,=calls(actual,name)
        assert targets(call)=={'A;','B;'} and len(call['receiver_object_refs'])==2
        assert all(t['allocation_ids'] and t['binding_refs'] for t in call['targets'])
    report=CallReport.model_validate_json(actual[4](CALL_ENTRY))
    assert all(c.state=='partial' and len(c.candidates)==2 for c in report.calls if c.unit_ref in {calls(actual,'merged')[0]['unit_ref'],calls(actual,'arrays')[0]['unit_ref']})


def test_cross_method_actual_parameter_return_field_and_inheritance_points_to(actual):
    helper,=calls(actual,'helper')
    assert targets(helper)=={'A;','B;'}
    assert all('Cases$C;' not in t['signature'] for t in helper['targets'])
    field,=calls(actual,'fields');assert targets(field)=={'A;'}
    inherited,=calls(actual,'inherited');assert targets(inherited)=={'A;'}
    allocations={a['allocation_id']:a for a in actual[3]['allocations']}
    assert any(allocations[aid]['type_descriptor'].endswith('$Child;') for aid in inherited['receiver_allocation_ids'])
    assert len(helper['receiver_allocation_ids'])==3


def test_empty_receiver_does_not_fall_back_to_positive_cha_candidates(actual):
    empty,=calls(actual,'nullReceiver')
    assert not empty['receiver_allocation_ids'] and not empty['targets']
    site=next(c for c in CallReport.model_validate_json(actual[4](CALL_ENTRY)).calls if c.unit_ref==empty['unit_ref'])
    assert not site.candidates and site.state=='partial' and 'no positive CHA target' in site.reason


def test_context_heap_consumes_each_target_as_a_distinct_supported_frame(actual):
    result,_,_,_,read,output=actual
    root=next(m.id for m in result.facts.elements if m.kind=='method' and m.is_definition and '->merged(' in m.signature)
    projection=json.loads(read(entry_for(root)))['projection']
    methods={m.id:m.signature for m in result.facts.elements if m.kind=='method'}
    frames=[f for f in projection['frames'] if f['call_path'] and '->map(' in methods[f['method_ref']]]
    assert len(frames)==2 and len({f['context_ref'] for f in frames})==2
    assert len({f['call_path'][-1]['context_ref'] for f in frames})==2
    assert {methods[f['method_ref']].split('$')[-1].split('->')[0] for f in frames}=={'A;','B;'}
    assert any(i.get('candidate_relation_refs') and len(i['candidate_context_refs'])==2 for i in projection['issues'])
    (output/'merged-context-projection.json').write_text(json.dumps(projection,indent=2)+'\n',encoding='utf-8')


def test_public_cross_method_source_paths_keep_callers_separate(actual):
    result,snapshot,_,_,_,output=actual
    records={r.id:r for r in result.facts.elements};receipts=[]
    with FactView(snapshot) as view:
        call_report=view.read_call_flow()
        for name in ['distinct','twoHelpers']:
            root=next(m.id for m in result.facts.elements if m.kind=='method' and m.is_definition and '->'+name+'(' in m.signature)
            sites=sorted([c for c in call_report.calls if c.caller_ref==root and '->send(' in c.declared_signature],key=lambda c:c.unit)
            assert len(sites)==2
            queries=[]
            for site in sites:
                q=view.trace_context_sources(root,Endpoint(element_ref=site.callsite_ref,
                    position_label=records[site.callsite_ref].position.position_label,slot_kind='argument',slot_index=0))
                assert not q['truncated'] and all(r['relations_to_target'] for r in q['roots'])
                queries.append(q)
            parameter_sets=[{r['root']['details']['parameter_index'] for r in q['roots'] if r['root']['kind']=='parameter'} for q in queries]
            if name=='distinct':
                assert parameter_sets==[{0},set()]
                assert any(r['root']['details'].get('operand',{}).get('constant')=='B-fixed' for r in queries[1]['roots'])
            else:
                # Spark is CI: each helper may dispatch to A/B, but distinct
                # concrete caller frames cannot borrow the other input.
                assert parameter_sets==[{0},{1}]
            receipts.append({'method':name,'queries':queries,'parameter_sets':[sorted(s) for s in parameter_sets]})
    (output/'public-cross-method-source-paths.json').write_text(json.dumps(receipts,indent=2)+'\n',encoding='utf-8')


def test_public_queries_and_real_sapi_bu_retain_dispatch_bindings_without_other_target(actual):
    result,snapshot,catalog,report,read,output=actual
    root=next(m.signature for m in result.facts.elements if m.kind=='method' and m.is_definition and '->distinct(' in m.signature)
    with FactView(snapshot) as view:
        query=view.points_to_evidence()
        assert query['calls'] and query['allocations']
        units=build_units(view,catalog,BUConfig(root_signatures=[root]))
    selected=[u for u in units['units'] if any('MessageDigest;->getInstance(' in r['signature'] for r in u['anchor']['routes'])]
    assert len(selected)==1
    unit=selected[0];visible=unit['model_visible'];records={r['id']:r for r in visible['records']}
    dispatch=[r for r in records.values() if r.get('relation_kind')=='candidate_call' and r.get('target',{}).get('element_ref') in {
        m.id for m in result.facts.elements if m.kind=='method' and '$A;->map(' in m.signature}]
    assert dispatch and all(r['binding_refs'] and r['context_ref'] for r in dispatch)
    assert any(r.get('provenance',{}).get('tool_ref')==TOOL and r.get('node_kind')=='object' for r in records.values())
    assert all(not (r.get('signature','').endswith('Cases$B;->map(Ljava/lang/String;)Ljava/lang/String;') or
                    r.get('signature','').endswith('Cases$C;->map(Ljava/lang/String;)Ljava/lang/String;')) for r in records.values())
    assert not visible['raw_files'] and not visible['all_archive_support_visible']
    (output/'actual-distinct-bu.json').write_text(json.dumps(units,indent=2)+'\n',encoding='utf-8')


@pytest.mark.parametrize('kind',['object_binding','solver_report','candidate_context','configured_entries'])
def test_tampering_is_rejected_by_current_program_evidence_replay(actual,kind):
    result=deepcopy(actual[0]);read=lambda e:result.blobs[result.entry_digests[e]]
    if kind=='object_binding':
        binding=next(b for b in result.facts.bindings if b.provenance.tool_ref==TOOL)
        binding.endpoints[1]=binding.endpoints[0]
        with pytest.raises(ValueError,match='pointer bindings'):verify_points_to(result.facts,read)
    elif kind=='solver_report':
        raw=json.loads(read(RAW));raw['calls'][0]['text']='forged current call'
        data=canonical_json(raw).encode();digest=hashlib.sha256(data).hexdigest();result.blobs[digest]=data;result.entry_digests[RAW]=digest
        with pytest.raises(ValueError,match='committed run receipt'):verify_points_to(result.facts,read)
    elif kind=='candidate_context':
        edge=next(r for r in result.facts.relations if r.relation_kind=='candidate_call' and r.binding_refs)
        edge.context_ref=None
        with pytest.raises(ValueError,match='call-flow relations'):verify_call_evidence(result.facts,read)
    else:
        result.facts.run.configuration.options['points_to']['entry_methods']=[OWNER+'->distinct(Ljava/lang/String;Ljava/lang/String;)V']
        with pytest.raises(ValueError,match='declared run/configuration/platform'):verify_points_to(result.facts,read)


def test_timeout_and_solver_budget_are_explicit_without_positive_pointer_claims(tmp_path):
    apk=ROOT/'artifacts/fixtures/points-to/valid.apk'
    base=extract_local(apk,java_config=JavaConfig(platform_api=28))
    for config in [PointsToConfig(timeout_seconds=0.001),PointsToConfig(max_methods=1)]:
        result=extend_points_to(deepcopy(base),apk,config)
        report=json.loads(result.blobs[result.entry_digests[ENTRY]])
        assert report['state']=='failed' and report['reason'] and not report['calls']
