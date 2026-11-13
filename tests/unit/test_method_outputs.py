"""Real compiled explicit returns and deterministic boundary-proof protocol."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import pytest

from androserum.facts.context_heap import ContextHeapConfig, extend_context_heap
from androserum.facts.heap_flow import extract_heap
from androserum.facts.identity import canonical_json, fingerprint
from androserum.facts.method_outputs import extend_method_outputs, verify_method_outputs, ENTRY
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.checker import check_proposal
from androserum.mining.models import MiningConfig

ROOT = Path(__file__).resolve().parents[2]
OWNER = 'Lorg/androserum/outputs/ReturnCases;'


@pytest.fixture(scope='module')
def actual():
    subprocess.run([sys.executable, 'scripts/build_method_output_fixture.py'], cwd=ROOT, check=True, capture_output=True)
    result = extract_heap(ROOT/'artifacts/fixtures/method-outputs/valid.apk')
    roots = [e.signature for e in result.facts.elements if e.kind=='method' and e.is_definition
             and e.signature.startswith(OWNER+'->') and '-><' not in e.signature]
    result = extend_context_heap(result, ContextHeapConfig(root_signatures=roots))
    before = deepcopy(result)
    result = extend_method_outputs(result)
    report = json.loads(result.blobs[result.entry_digests[ENTRY]])
    return before, result, report


def method_name(facts, ref):
    return next(e.signature.split('->',1)[1].split('(',1)[0] for e in facts.elements if e.id==ref)


def test_normal_multiple_void_and_exceptional_channels_are_distinct(actual):
    _, result, report = actual
    rows = report['returns']; facts = result.facts
    assert len([r for r in rows if method_name(facts,r['root_ref'])=='branch']) == 2
    assert len({r['output_endpoint']['element_ref'] for r in rows}) == len(rows)
    assert any(method_name(facts,r['root_ref'])=='mayThrow' for r in rows)
    assert not any(method_name(facts,r['root_ref']) in {'neverReturns','voidReturn'} for r in rows)
    assert any(method_name(facts,r['root_ref'])=='voidReturn' for r in report['void_returns'])
    assert any(method_name(facts,r['root_ref'])=='neverReturns' for r in report['exceptional_exits'])
    handler = [r for r in rows if r['arrival_scope']=='handler_arrival_witness']
    assert len(handler)==1 and handler[0]['value']['value']=='fallback'
    assert any(e['kind']=='exception' for e in handler[0]['cfg_witness'])
    assert all(r['normal_return'] and not r['execution_established'] for r in rows)


def test_nested_and_root_results_keep_distinct_frame_and_return_identity(actual):
    _, result, report = actual
    rows=[r for r in report['returns'] if method_name(result.facts,r['method_ref'])=='identity']
    assert len(rows)==2 and len({r['context_ref'] for r in rows})==2
    assert {r['projection_role'] for r in rows}=={'original','return_binding'}
    assert all(r['source_endpoint']!=r['output_endpoint'] for r in rows)


def test_forged_internal_source_or_normal_return_cannot_pass_reconstruction(actual):
    _, result, report = actual
    for field, value in [('normal_return',False),('source_endpoint',report['returns'][-1]['source_endpoint'])]:
        changed=deepcopy(report);changed['returns'][0][field]=value
        reader=lambda e: canonical_json(changed).encode() if e==ENTRY else result.blobs[result.entry_digests[e]]
        with pytest.raises(ValueError,match='explicit returns'):
            verify_method_outputs(result.facts,reader)


def packet_for_return(result, report, *, nested=False):
    row=next(r for r in report['returns'] if (r['parent_context_ref'] is not None)==nested
             and method_name(result.facts,r['method_ref'])=='identity')
    records={e.id:e.model_dump(mode='json') for group in [result.facts.elements,result.facts.relations,
        result.facts.contexts,result.facts.bindings,result.facts.statuses] for e in group}
    opref=row['owner_projection_ref']; record=records[opref]
    op={'operation_ref':opref,'origin_ref':row['origin_ref'],'raw_operation_refs':row['raw_return_refs'],
        'method_ref':row['method_ref'],'context_ref':row['context_ref'],'call_path':row['call_path'],
        'operation':'return','slots':record['slots']}
    visible={'records':list(records.values()),'allowed_citation_refs':list(records),
        'operation_records':[op],'relation_records':[{'record_ref':row['relation_ref'],
            'traversal_source':row['source_endpoint'],'traversal_target':row['output_endpoint']}],
        'control_records':[],'method_output_records':[row],'issues':[]}
    collection={'apk_sha256':result.facts.run.apk_sha256,'source_run_ref':result.facts.run.run_id,
        'source_snapshot_id':'0'*64,'extraction_run_ref':'bu-run:protocol',
        'units':[{'bu_id':'bu:normal-return-protocol','anchor':{'root_method_ref':row['root_ref']},
                  'model_visible':visible,'extraction_status':{'state':'partial'}}]}
    catalog=EvidenceCatalog(collection,['bu:normal-return-protocol']);registry=catalog.entries
    identity={'source':{'source_run_ref':result.facts.run.run_id}}
    state={'schema_version':'behavior-ledger-state.v1','revision':0,'identity':identity,'actions':{},'bcs':{},'unresolved':{}}
    packet={'request_id':'request:normal-return-protocol','base_revision':0,'identity':identity,'evidence':registry,
        'manifest':{'evidence_sha256':fingerprint(registry)},'ledger_context':{'actions':{},'bcs':{},'unresolved':{}},'source_limits':[]}
    op_h=next(h for h,e in registry.items() if e['category']=='operation')
    output=next(h for h,e in registry.items() if e.get('boundary_role')=='explicit_normal_method_result')
    internal=next(h for h,e in registry.items() if e['category']=='endpoint' and e['endpoint']==row['source_endpoint'])
    not_app={'availability':'not_applicable','description':'No object receiver.','endpoint_refs':[]}
    action={'action_id':'return_value','function':'Return the recorded local value to this method frame result.',
        'operation_refs':[op_h],'objects':not_app,'inputs':{'availability':'supported','description':'Internal return operand.','endpoint_refs':[internal]},
        'outputs':{'availability':'supported','description':'Distinct method-frame result if return is reached.','endpoint_refs':[output]},
        'condition_status':'unknown','condition_refs':[],'effect_refs':[],
        'support_relation_refs':[h for h,e in registry.items() if e['category']=='relation'],
        'support_fact_refs':[],'limitation_notes':['Static normal return does not establish runtime execution.']}
    bc={'bc_id':'local_return','description':'A possible explicit local method return.',
        'action_ids':['return_value'],'relations':[],
        'boundary':{'inputs':action['inputs'],'outputs':action['outputs'],'potential_effects':'Possible return only.','condition_refs':[]},
        'limitation_notes':['Caller use and concrete runtime value remain unknown.'],'execution_claim':'possible_only'}
    proposal={'schema_version':'behavior-proposal.v1','request_id':packet['request_id'],'base_revision':0,
        'upsert_actions':[action],'upsert_bcs':[bc],'delete_action_ids':[],'delete_bc_ids':[],
        'unresolved_updates':[],'fact_queries':[],'rationale':'Deterministic protocol test of real compiled return evidence; no model interpretation.'}
    return packet,state,proposal,output,internal


def test_verified_outward_result_is_accepted_without_relaxing_internal_boundary(actual):
    _, result, report=actual
    packet,state,proposal,_,_=packet_for_return(result,report)
    checked,_=check_proposal(canonical_json(proposal),packet,state,MiningConfig(max_response_chars=100000))
    assert checked['valid'],checked['errors']


def test_arbitrary_internal_operand_cannot_borrow_method_result_proof(actual):
    _,result,report=actual
    packet,state,proposal,output,internal=packet_for_return(result,report)
    packet['evidence'][output]['endpoint']=deepcopy(packet['evidence'][internal]['endpoint'])
    packet['manifest']['evidence_sha256']=fingerprint(packet['evidence'])
    checked,_=check_proposal(canonical_json(proposal),packet,state,MiningConfig(max_response_chars=100000))
    assert not checked['valid'] and any(e['code']=='method_result_support' for e in checked['errors'])


def test_nested_return_has_an_output_for_its_exact_frame_only(actual):
    _,result,report=actual
    packet,state,proposal,output,_=packet_for_return(result,report,nested=True)
    checked,_=check_proposal(canonical_json(proposal),packet,state,MiningConfig(max_response_chars=100000))
    assert checked['valid'],checked['errors']
    ep=packet['evidence'][output]
    wrong=next(h for h,e in packet['evidence'].items() if e['category']=='fact'
        and e['record'].get('binding_kind')=='value'
        and e['record'].get('context_ref')!=ep['context_ref']
        and e['record'].get('provenance',{}).get('tool_ref')=='tool:method-outputs')
    ep['method_return_binding_ref']=wrong
    packet['manifest']['evidence_sha256']=fingerprint(packet['evidence'])
    rejected,_=check_proposal(canonical_json(proposal),packet,state,MiningConfig(max_response_chars=100000))
    assert not rejected['valid'] and any(e['code']=='method_result_support' for e in rejected['errors'])


def test_old_facts_without_output_tool_remain_valid(actual):
    before,_,_=actual
    verify_method_outputs(before.facts,lambda e:before.blobs[before.entry_digests[e]])
