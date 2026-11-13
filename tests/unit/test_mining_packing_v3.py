"""Per-BU evidence-role projection; no model or static-analysis quality claim."""
from copy import deepcopy
import json
import pytest
from test_mining_protocol import collection,initial,valid_proposal
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import MiningConfig
from androserum.mining.assembly import make_packet
from androserum.mining.checker import check_proposal
from androserum.mining_packing import PackedEvidenceCatalog,clone_catalog
from androserum.mining_packing_v3 import ScopedPackedEvidenceCatalog,PROFILE
from androserum.inference.compact import compact_packet,expand_compact

def role_collection():
    data=collection(condition=True,binding=True,second_bu=True)
    data['units'][0]['model_visible']['relation_records'][0]['evidence_role']='explicit_normal_method_result'
    return data

def test_per_bu_roles_retain_both_scopes_without_changing_relation_identity():
    data=role_collection()
    with pytest.raises(ValueError):EvidenceCatalog(data,[u['bu_id'] for u in data['units']])
    with pytest.raises(ValueError):PackedEvidenceCatalog(data,[u['bu_id'] for u in data['units']])
    cat=ScopedPackedEvidenceCatalog(data,[u['bu_id'] for u in data['units']])
    for unit in data['units']:
        bu=unit['bu_id'];raw=EvidenceCatalog(data,[bu])
        original=next(h for h,e in raw.entries.items() if e['category']=='relation')
        rel=next(h for h,e in cat.entries.items() if e['category']=='relation' and bu in e['bu_ids'])
        single=raw.render([original],{bu});rendered=cat.render([rel],{bu})
        for h,e in rendered.items():
            projected=deepcopy(e)
            if e['category']=='relation':
                base=projected.pop('base_relation_handle');projected['handle']=base
            else:base=h
            assert projected==single[base]
    relations=[h for h,e in cat.entries.items() if e['category']=='relation']
    both=cat.render(relations,set(cat.units))
    assert len(relations)==2
    assert {both[h]['role'] for h in relations}=={'explicit_normal_method_result','program_dependency'}
    assert all(len(both[h]['bu_ids'])==1 for h in relations)
    assert clone_catalog(cat).identity==cat.identity and clone_catalog(cat).entries==cat.entries
    envelope,metrics=compact_packet({'evidence':both})
    assert expand_compact(envelope)=={'evidence':both} and metrics['evidence_removed']==0

def test_scoped_role_adapter_rejects_any_other_payload_or_summary_conflict():
    data=role_collection();cat=ScopedPackedEvidenceCatalog(data,[u['bu_id'] for u in data['units']])
    rel=next(e for e in cat.entries.values() if e['category']=='relation')
    incoming=deepcopy(rel);incoming['handle']=incoming.pop('base_relation_handle');incoming.pop('bu_ids')
    for key,value in [('target_endpoint_ref','ep_ffffffffffff'),('unresolved_condition_refs',['condition:hidden']),
                      ('binding_refs',[]),('role','information_flow_summary')]:
        damaged={**incoming,key:value}
        with pytest.raises(ValueError):cat.add(damaged,'bu:third')
    with pytest.raises(ValueError):cat.add({**incoming,'role':'information_flow_summary'},'bu:protocol-a')

def test_scoped_program_roles_keep_normal_checker_and_condition_rejection():
    data=role_collection();cat=ScopedPackedEvidenceCatalog(data,[u['bu_id'] for u in data['units']]);cfg=MiningConfig()
    chunks,pending=cat.chunks(cfg);assert not pending
    packet=make_packet(cat,chunks[0],initial(cat),cfg,'request:scoped-v3')
    proposal=valid_proposal(packet);checked,_=check_proposal(json.dumps(proposal),packet,initial(cat),cfg)
    assert checked['valid'],checked
    proposal['upsert_actions'][0]['condition_refs']=[]
    checked,_=check_proposal(json.dumps(proposal),packet,initial(cat),cfg)
    assert not checked['valid']


def test_second_role_cannot_hide_a_different_endpoint_or_binding():
    data=role_collection();cat=ScopedPackedEvidenceCatalog(data,[data['units'][0]['bu_id']])
    entry=next(e for e in cat.entries.values() if e['category']=='relation')
    incoming=deepcopy(entry);incoming['handle']=incoming.pop('base_relation_handle');incoming.pop('bu_ids')
    incoming['role']='program_dependency'
    for field,value in [('target_endpoint_ref','ep_ffffffffffff'),('binding_refs',[])]:
        with pytest.raises(ValueError,match='Role variation cannot change'):
            cat.add({**incoming,field:value},'bu:other')


def test_scoped_native_continuation_preserves_roles_and_replays(tmp_path):
    from test_mining_protocol import ProtocolProvider,ProtocolView
    from androserum.mining.runner import run_mining
    from androserum.mining.verification import verify_package
    data=role_collection()
    make=lambda:ScopedPackedEvidenceCatalog(data,[u['bu_id'] for u in data['units']])
    cfg=MiningConfig(max_model_calls=2,max_bu=4);provider=ProtocolProvider()
    first,a=run_mining(make(),ProtocolView(),tmp_path,provider,cfg,call_limit=1)
    second,b=run_mining(make(),ProtocolView(),tmp_path,provider,cfg,resume_from=first,call_limit=1)
    assert b['attempts'][:len(a['attempts'])]==a['attempts']
    assert verify_package(second,make(),ProtocolView())['valid']
    assert b['identity']['source']['packing_profile']==PROFILE


def test_same_raw_condition_in_multiple_frames_uses_relation_frame_not_last_row():
    data=collection(condition=True,second_bu=True)
    for unit in data['units']:
        visible=unit['model_visible']
        next(r for r in visible['records'] if r['id']=='relation:flow')['condition_refs']=['condition:guard']
        extra=deepcopy(visible['control_records'][0]);extra['context_ref']='context:other-call'
        visible['control_records'].append(extra)
    data['units'][1]['model_visible']['control_records'].reverse()
    cat=ScopedPackedEvidenceCatalog(data,[u['bu_id'] for u in data['units']])
    rel=next(e for e in cat.entries.values() if e['category']=='relation')
    assert len(rel['bu_ids'])==2
    assert all(cat.entries[h]['context_ref']==rel['context_ref'] for h in rel['condition_refs'])
    assert len([e for e in cat.entries.values() if e['category']=='condition'])==2
    damaged=deepcopy(data)
    for unit in damaged['units']:
        unit['model_visible']['control_records']=[r for r in unit['model_visible']['control_records'] if r['context_ref']!='context:frame']
    with pytest.raises(ValueError,match='exact call frame'):
        ScopedPackedEvidenceCatalog(damaged,[u['bu_id'] for u in damaged['units']])
