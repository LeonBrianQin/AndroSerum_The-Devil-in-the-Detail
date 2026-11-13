"""Real platform calls in a compiled APK: conditional state and false-link gates."""
from copy import deepcopy
import hashlib,json,subprocess,sys
from pathlib import Path
import pytest
from androserum.facts.buffer_state import (BufferConfig,ENTRY,SIGNATURE,TOOL,analyze_buffers,
    extend_buffer_state,verify_buffer_state)
from androserum.facts.selected_flow import extract_selected_flow,FlowConfig
from androserum.facts.operations import extend_operations
from androserum.facts.control import extend_control
from androserum.facts.events import extend_events
from androserum.facts.extractor import write_extraction
from androserum.facts.store import import_snapshot,FactView
from androserum.facts.bu import BUConfig,write_units,verify_units
from androserum.facts.sapi import SapiImportConfig,import_catalog
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.assembly import make_packet
from androserum.mining.models import MiningConfig

ROOT=Path(__file__).resolve().parents[2];P='Lorg/androserum/buffer/Cases;'


@pytest.fixture(scope='module')
def actual(tmp_path_factory):
    subprocess.run([sys.executable,'scripts/build_buffer_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    base=extend_events(extend_control(extend_operations(extract_selected_flow(ROOT/'artifacts/fixtures/buffer-state/valid.apk',
        config=FlowConfig(sources=[SIGNATURE],sinks=[P+'->sink(S)V'])))))
    result=extend_buffer_state(deepcopy(base));out=tmp_path_factory.mktemp('buffer-state')
    snapshot=import_snapshot(write_extraction(result,out/'facts'),out/'stores')
    catalog=out/'sapi';import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')),catalog)
    return result,snapshot,catalog,out,base


def read(result,entry=ENTRY):return result.blobs[result.entry_digests[entry]]
def report(result):return json.loads(read(result))
def case(result,name):
    owner=next(x.id for x in result.facts.elements if getattr(x,'is_definition',False) and getattr(x,'signature','').startswith(P+'->'+name+'('))
    r=report(result);effect=next(x for x in r['effects'] if x['root_ref']==owner)
    return effect,[x for x in r['read_decisions'] if x['effect_ref']==effect['effect_ref']]


@pytest.mark.parametrize('name',['same','helper','unknownResult'])
def test_same_buffer_is_conditional_with_actual_count_and_call_context(actual,name):
    result=actual[0];effect,reads=case(result,name)
    assert len(reads)==1 and reads[0]['state']=='included_conditional'
    assert effect['offset']==0 and effect['requested_count']==4 and effect['object_ref']
    assert not effect['success_proven'] and reads[0]['actual_count_bounds']==[1,4]
    edge=next(x for x in result.facts.relations if x.provenance.tool_ref==TOOL and x.target.element_ref==reads[0]['read_ref'])
    assert edge.relation_kind=='state_dependency' and edge.resolution=='partial'
    assert edge.condition_refs==[effect['condition_ref']] and len(edge.binding_refs)==2
    if name=='helper':assert reads[0]['read_context_ref']!=effect['context_ref']
    if name=='unknownResult':assert effect['result_endpoint'] is None and any('not mapped' in x for x in effect['issues'])


@pytest.mark.parametrize('name,reason',[
    ('different','different_buffer_allocation'),('failed','nonpositive_or_short_read_branch'),
    ('zero','nonpositive_or_short_read_branch'),('shortRead','nonpositive_or_short_read_branch'),
    ('disjoint','outside_requested_interval'),('overwritten','intervening_buffer_overwrite'),
    ('exceptional','no_normal_cfg_path'),('priorContents','nonpositive_or_short_read_branch'),
    ('zeroRequest','invalid_or_empty_request'),('invalidRange','invalid_or_empty_request'),
    ('opaqueCall','intervening_opaque_call_effect_unknown')])
def test_incorrect_storage_failure_range_and_order_connections_refused(actual,name,reason):
    effect,reads=case(actual[0],name)
    assert reads and all(x['state']=='rejected' and reason in x['reason'] for x in reads)
    assert not effect['reads']
    assert not any(x.provenance.tool_ref==TOOL and x.source.element_ref==effect['effect_ref'] for x in actual[0].facts.relations)
    assert not report(actual[0])['failed_read_erases_prior_contents']


@pytest.mark.parametrize('name,reason',[('dynamicIndex','read_index_unknown'),('unknownBuffer','writer_object_or_range_unknown')])
def test_unknowns_are_exposed_without_fabricated_read_connection(actual,name,reason):
    _,reads=case(actual[0],name)
    assert reads and all(x['state']=='not_adapted' and x['reason']==reason for x in reads)


@pytest.mark.parametrize('damage',['condition','binding','endpoint','report','model','upstream'])
def test_replay_rejects_forged_state_or_model(actual,damage):
    r=deepcopy(actual[0])
    if damage=='upstream':
        from androserum.facts.buffer_state import UPSTREAM_ENTRY
        r.blobs[r.entry_digests[UPSTREAM_ENTRY]]=b'forged public contract'
    elif damage in {'report','model'}:
        entry=ENTRY if damage=='report' else 'analysis/rules/buffer-state.json'
        data=json.loads(read(r,entry))
        if damage=='report':data['effects'][0]['success_proven']=True
        else:data['normal_write_condition']='Always writes the whole requested interval'
        raw=json.dumps(data).encode();digest=hashlib.sha256(raw).hexdigest();r.blobs[digest]=raw;r.entry_digests[entry]=digest
    else:
        edge=next(x for x in r.facts.relations if x.provenance.tool_ref==TOOL and (damage!='binding' or x.binding_refs))
        if damage=='condition':edge.condition_refs=[]
        elif damage=='binding':edge.binding_refs=[]
        else:edge.target=edge.source
    with pytest.raises(ValueError):verify_buffer_state(r.facts,lambda e:read(r,e))


def test_budget_preserves_explicit_truncation(actual):
    r=analyze_buffers(actual[0].facts,lambda e:read(actual[0],e),BufferConfig(max_visits=1))
    assert r['issues'] and r['issues'][-1]['state']=='truncated' and not r['complete_array_coverage_claimed']


def test_public_query_and_bu_deliver_state_conditions_without_archive_leak(actual):
    result,snapshot,catalog,out,_=actual;effect,reads=case(result,'same')
    with FactView(snapshot) as view:
        assert view.verify()['valid']
        q=view.buffer_evidence([effect['root_ref']]);assert q['effects']==[effect] and q['read_decisions']==reads
        package,bus=write_units(view,catalog,out/'bu',BUConfig(root_signatures=[P+'->same(Landroid/media/AudioRecord;)V']))
        assert verify_units(package,view)['valid'] and len(bus['units'])==1
    unit=bus['units'][0];visible=unit['model_visible']
    edges={x['record_ref'] for x in visible['relation_records']};refs={x.id for x in result.facts.relations if x.provenance.tool_ref==TOOL and x.target.element_ref in {effect['effect_ref'],reads[0]['read_ref']}}
    assert refs<=edges and len(refs)==2
    assert any('->sink(' in (x.get('declared_target') or {}).get('signature','') for x in visible['records'])
    assert visible['model_conditions'][0]['scope']=='model_relation_precondition_not_execution_guard'
    assert not visible['raw_files'] and not visible['all_archive_support_visible']
    c=EvidenceCatalog(bus,[unit['bu_id']]);cfg=MiningConfig(max_chunk_chars=190000,max_request_chars=600000,max_ledger_context_chars=300000)
    state={'revision':0,'identity':{'source':c.identity},'actions':{},'bcs':{},'unresolved':{}}
    packet=make_packet(c,c.chunks(cfg)[0][0],state,cfg,'request:buffer')
    modeled=[x for x in packet['evidence'].values() if x['category']=='relation' and x['record_ref'] in refs]
    assert len(modeled)==2 and all(x['condition_refs'] and not x['unresolved_condition_refs'] for x in modeled)
    cond=[x for x in packet['evidence'].values() if x['category']=='condition' and x['record_ref']==effect['condition_ref']]
    assert cond and cond[0]['scope']=='model_relation_precondition_not_execution_guard'
    assert all(x['resolution']=='partial' and x['provenance_kind']=='model_assisted' for x in modeled)
    # A deterministic state BC exercises the same public registry/checker.
    # It is not a real-model proposal or a semantic accuracy measurement.
    from androserum.mining.checker import check_proposal
    first=next(x for x in modeled if packet['evidence'][x['source_endpoint_ref']]['owner_operation_ref'] and
        packet['evidence'][x['source_endpoint_ref']]['endpoint']['element_ref']==effect['writer_ref'])
    second=next(x for x in modeled if x is not first);registry=packet['evidence']
    source=first['source_endpoint_ref'];target=second['target_endpoint_ref']
    def field(eps):return {'availability':'supported' if eps else 'unknown','description':'Selected endpoint; runtime unknown','endpoint_refs':eps}
    actions=[]
    for name,ep in [('buffer_write',source),('buffer_read',target)]:
        op=registry[registry[ep]['owner_operation_ref']]
        actions.append({'action_id':name,'function':'Selected modeled write' if name=='buffer_write' else 'Selected array read',
            'operation_refs':[op['handle']],'objects':field([]),'inputs':field([ep] if name=='buffer_write' else []),
            'outputs':field([ep] if name=='buffer_read' else []),'condition_status':'recorded_local' if op['condition_refs'] else 'unknown',
            'condition_refs':op['condition_refs'],'effect_refs':[],'support_relation_refs':[],'support_fact_refs':[],
            'limitation_notes':['Conditional normal successful write only; actual n bounds and partial coverage remain']})
    link={'link_id':'conditional_buffer_state','from_action':'buffer_write','to_action':'buffer_read','relation_kind':'state_transfer',
        'source_endpoint_ref':source,'target_endpoint_ref':target,'support_path':[first['handle'],second['handle']],
        'evidence_strength':'model_assisted_relation','binding_refs':sorted({h for e in modeled for h in e['binding_refs']}),
        'condition_refs':sorted({h for e in modeled for h in e['condition_refs']}),'execution_claim':'possible_only'}
    proposal={'schema_version':'behavior-proposal.v1','request_id':packet['request_id'],'base_revision':0,'upsert_actions':actions,
        'delete_action_ids':[],'upsert_bcs':[{'bc_id':'conditional_audio_read','description':'Conditional buffer state reaching the selected array element',
        'action_ids':['buffer_write','buffer_read'],'relations':[link],'boundary':{'inputs':field([]),'outputs':field([]),
        'potential_effects':'Possible recorded state; success and actual execution unknown','condition_refs':[]},'limitation_notes':['Partial'],
        'execution_claim':'possible_only'}],'delete_bc_ids':[],'unresolved_updates':[],'fact_queries':[],'rationale':'Deterministic conditional model protocol gate'}
    assert check_proposal(json.dumps(proposal),packet,state,cfg)[0]['valid']
    for damage in ['fine_path','omit_condition','omit_binding']:
        bad=deepcopy(proposal);edge=bad['upsert_bcs'][0]['relations'][0]
        if damage=='fine_path':edge.update(relation_kind='data_transfer',evidence_strength='recorded_dependency_path')
        elif damage=='omit_condition':edge['condition_refs']=[]
        else:edge['binding_refs']=[]
        assert not check_proposal(json.dumps(bad),packet,state,cfg)[0]['valid']


def test_no_model_does_not_rewrite_existing_snapshot_or_claim_support(actual):
    _,_,_,_,base=actual
    verify_buffer_state(base.facts,lambda e:read(base,e))
    from androserum.facts.buffer_state import buffer_evidence
    assert buffer_evidence(base.facts,lambda e:read(base,e),[])['state']=='not_started'
