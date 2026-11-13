"""Finite selected-site proofs on compiled platform calls; not a dynamic solver."""
from copy import deepcopy
from pathlib import Path
import hashlib,json,subprocess,sys
import pytest
from androserum.facts.audio_read_sites import (AudioReadConfig,ReadSelection,ENTRY,TOOL,DOUBLE_ENTRY,
    extend_audio_read_sites,verify_audio_read_sites,analyze_audio_reads)
from androserum.facts.selected_flow import extract_selected_flow,FlowConfig
from androserum.facts.operations import extend_operations
from androserum.facts.control import extend_control
from androserum.facts.events import extend_events
from androserum.facts.buffer_state import extend_buffer_state,SIGNATURE
from androserum.facts.extractor import write_extraction
from androserum.facts.store import import_snapshot,FactView
from androserum.facts.bu import BUConfig,write_units,verify_units
from androserum.facts.sapi import import_catalog,SapiImportConfig
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import MiningConfig
from androserum.mining.assembly import make_packet

ROOT=Path(__file__).resolve().parents[2];P='Lorg/androserum/audiosites/Cases;'
HELPERS={'positive':'pair','shortResult':'pair','failed':'pair','zero':'pair','different':'pair',
    'overwrite':'pair','opaque':'pair','badInit':'startsOne','badGuard':'nonStrict','badStep':'stepTwo',
    'repeatedHelper':'pair','unsupportedCount':'pair'}


def scope_for(facts,names):
    methods={e.id:e.signature for e in facts.elements if e.kind=='method'};selections=[]
    for name in names:
        signature=next(s for s in methods.values() if s.startswith(P+'->'+name+'('))
        helper=P+'->'+HELPERS[name]+'([S)I'
        writer=next(e for e in facts.elements if getattr(e,'declared_target',None) and e.declared_target.signature==SIGNATURE and methods[e.position.method_ref]==signature)
        offsets=sorted({e.position.offset_bytes//2 for e in facts.elements if e.kind=='instruction' and
            e.operation=='array_read' and methods[e.position.method_ref]==helper})
        assert len(offsets)==2
        selections.append(ReadSelection(root_signature=signature,writer_offset_code_units=writer.position.offset_bytes//2,
            reader_signature=helper,reader_offsets_code_units=offsets))
    return AudioReadConfig(apk_sha256=facts.run.apk_sha256,selections=selections)


@pytest.fixture(scope='module')
def actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_audio_read_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    base=extend_buffer_state(extend_events(extend_control(extend_operations(extract_selected_flow(
        ROOT/'artifacts/fixtures/audio-read-sites/valid.apk',config=FlowConfig(sources=[SIGNATURE],sinks=[P+'->positive(Landroid/media/AudioRecord;)V']))))))
    cfg=scope_for(base.facts,HELPERS);result=extend_audio_read_sites(deepcopy(base),cfg)
    out=tmp_path_factory.mktemp('audio-read-sites');snapshot=import_snapshot(write_extraction(result,out/'facts'),out/'stores')
    catalog=out/'sapi';import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')),catalog)
    return result,snapshot,catalog,out,base,cfg


def read(result,entry=ENTRY):return result.blobs[result.entry_digests[entry]]
def rows(result,name):return [r for r in json.loads(read(result))['reads'] if r['selection']['root_signature'].startswith(P+'->'+name+'(')]


@pytest.mark.parametrize('name',['positive','shortResult'])
def test_each_read_has_conditional_identity_loop_range_and_return_evidence(actual,name):
    r=rows(actual[0],name);assert len(r)==2 and all(x['state']=='conditional_connection' for x in r)
    assert len({x['raw_reader_ref'] for x in r})==2 and r[0]['reader_object_refs']==r[1]['reader_object_refs']==[r[0]['writer_object_ref']]
    for x in r:
        assert x['call_path'] and x['identity_paths']['allocation_to_writer'] and x['identity_paths']['allocation_to_reader']
        assert x['loop_proof']['not_an_actual_count_guard']
        assert x['return_evidence']['move_result_ref'] and not x['return_evidence']['runtime_value_known']
        assert not x['ranges']['all_iterations_written_claimed']
        assert x['ranges']['actual_written']=='[0,n)' and x['ranges']['loop_reads']=='[0,L)'
        assert x['ranges']['eligible_written_subset']=='[0,min(n,L))'
        assert not x['ranges']['separate_field_reads_equal_assumed']
        assert x['ranges']['requested_count']['expression']['kind']=='java_int_subtract_one'
        assert x['footprint_models'] and all(not p['short_array_write'] for p in x['footprint_models'])
        edge=next(e for e in actual[0].facts.relations if e.id==x['relation_ref'])
        assert edge.resolution=='partial' and edge.provenance.kind=='model_assisted'
        assert {x['api_condition_ref'],x['range_condition_ref'],*x['loop_condition_refs']}==set(edge.condition_refs)
        if name=='shortResult':
            assert x['return_bounds_on_witness']==[1,1]  # Only i=0 can be newly written.
            predicates=x['witness_return_constraints']
            assert predicates and predicates[0]['normalized_operator']=='JEqExpr' and predicates[0]['constant']==1
            assert predicates[0]['condition_refs']
            node=next(e for e in actual[0].facts.elements if e.id==x['range_node_ref'])
            assert 'normal_witness_return_predicates' in node.text


@pytest.mark.parametrize('name,reason',[
    ('different','array_identity_different_or_unresolved'),('failed','path_requires_nonpositive_read_result'),
    ('zero','path_requires_nonpositive_read_result'),('overwrite','intervening_array_overwrite'),
    ('opaque','unmodeled_call_can_affect_buffer'),('badInit','index_not_zero_then_unit_increment'),
    ('badGuard','strict_same_array_length_guard_not_uniquely_supported'),('badStep','index_not_zero_then_unit_increment'),
    ('repeatedHelper','reader_call_frame_not_unique'),('unsupportedCount','expression_outside_constant_symbol_subtract_one')])
def test_each_counterexample_has_a_concrete_gap_and_no_fabricated_connection(actual,name,reason):
    r=rows(actual[0],name);assert len(r)==2
    assert all(x['state']=='unresolved' and reason in x['reason'] and 'relation_ref' not in x for x in r),r


@pytest.mark.parametrize('damage',['report_range','return_position','condition','binding','source'])
def test_forged_range_return_condition_binding_or_footprint_refused(actual,damage):
    r=deepcopy(actual[0])
    if damage in {'report_range','return_position','source'}:
        entry=DOUBLE_ENTRY if damage=='source' else ENTRY
        if damage=='source':raw=b'pretend all calls preserve arrays'
        else:
            q=json.loads(read(r));row=next(x for x in q['reads'] if x['state']=='conditional_connection')
            if damage=='report_range':row['ranges']['all_iterations_written_claimed']=True
            else:row['return_evidence']['move_result_position']['offset_bytes']+=2
            raw=json.dumps(q).encode()
        digest=hashlib.sha256(raw).hexdigest();r.blobs[digest]=raw;r.entry_digests[entry]=digest
    else:
        edge=next(e for e in r.facts.relations if e.provenance.tool_ref==TOOL)
        if damage=='condition':edge.condition_refs=[]
        else:edge.binding_refs=[]
    with pytest.raises(ValueError):verify_audio_read_sites(r.facts,lambda e:read(r,e))


def test_budget_and_unselected_sites_remain_explicit(actual):
    cfg=actual[5].model_copy(update={'max_visits':1});r=analyze_audio_reads(actual[0].facts,lambda e:read(actual[0],e),cfg)
    assert len(r['reads'])==24 and all(x['state']=='unresolved' for x in r['reads'])
    assert any('budget' in x['reason'] for x in r['reads']) and not r['general_dynamic_range_solver']
    cfg=scope_for(actual[0].facts,['positive']);r=analyze_audio_reads(actual[0].facts,lambda e:read(actual[0],e),cfg)
    assert len(r['reads'])==2 and all(x['selection']['root_signature'].startswith(P+'->positive(') for x in r['reads'])


def test_public_query_support_and_bu_model_visibility(actual):
    result,snapshot,catalog,out,_,_=actual;r=rows(result,'positive');selected={x['relation_ref'] for x in r}
    with FactView(snapshot) as v:
        assert v.verify()['valid']
        q=v.audio_read_evidence([r[0]['root_ref']]);assert q['reads']==r
        package,bus=write_units(v,catalog,out/'bu',BUConfig(root_signatures=[r[0]['selection']['root_signature']]))
        assert verify_units(package,v)['valid']
        for row in r:
            support=v.collect_support([row['relation_ref']],limit=10000).to_dict()
            assert not support['missing_refs'] and not support['truncated']
    assert len(bus['units'])==1
    u=bus['units'][0];visible=u['model_visible'];assert selected<={e['record_ref'] for e in visible['relation_records']}
    assert not any(i['code']=='buffer_state_not_connected' and i.get('candidate_read_ref') in {r[0]['read_ref'],r[1]['read_ref']} for i in visible['issues'])
    assert sum(i['code']=='selected_audio_element_precondition' for i in visible['issues'])==2
    c=EvidenceCatalog(bus,[u['bu_id']]);cfg=MiningConfig(max_chunk_chars=500000,max_request_chars=1000000,max_ledger_context_chars=300000)
    packet=make_packet(c,c.chunks(cfg)[0][0],{'revision':0,'identity':{'source':c.identity},'actions':{},'bcs':{},'unresolved':{}},cfg,'request:sites')
    rels=[e for e in packet['evidence'].values() if e['category']=='relation' and e['record_ref'] in selected]
    assert len(rels)==2 and all(not e['unresolved_condition_refs'] and len(e['condition_refs'])>=3 for e in rels)
    assert all(e['provenance_kind']=='model_assisted' and e['kind']=='state_dependency' for e in rels)
