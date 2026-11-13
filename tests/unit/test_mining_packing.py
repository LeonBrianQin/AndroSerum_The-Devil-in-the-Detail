"""Explicit packing profile: complete visible input and immutable continuation."""
from copy import deepcopy
import json,os
from pathlib import Path
import pytest

from test_mining_protocol import collection,initial,ProtocolProvider,ProtocolView,valid_proposal
from androserum.mining.evidence import EvidenceCatalog,size
from androserum.mining.models import MiningConfig
from androserum.mining.assembly import make_packet
from androserum.mining.runner import run_mining
from androserum.mining.verification import verify_package
from androserum.mining.checker import check_proposal
from androserum.mining_packing import PackedEvidenceCatalog,catalog_for,clone_catalog,PROFILE,RULE_SHA256
from androserum.inference.compact import compact_packet,expand_compact
from androserum.facts.identity import sha256_file
from androserum.mining_storage import assert_writable,StorageGateError


def test_legacy_default_keeps_exact_four_field_identity_and_raw_chunks():
    data=collection();old=EvidenceCatalog(data,['bu:protocol-a']);current=catalog_for(data,['bu:protocol-a'])
    assert type(current) is EvidenceCatalog and len(current.identity)==4
    assert old.entries==current.entries and old.chunks(MiningConfig())==current.chunks(MiningConfig())
    assert clone_catalog(current).identity==old.identity


def test_packed_profile_preserves_every_record_and_has_strict_clone_identity():
    data=collection(condition=True,binding=True);raw=EvidenceCatalog(data,['bu:protocol-a'])
    packed=PackedEvidenceCatalog(data,['bu:protocol-a'])
    assert packed.entries==raw.entries and packed.facts==raw.facts and packed.atoms==raw.atoms
    assert packed.identity['packing_profile']==PROFILE and packed.identity['packing_rule_sha256']==RULE_SHA256
    assert clone_catalog(packed).identity==packed.identity
    assert catalog_for({**packed.identity,'units':data['units']},['bu:protocol-a']).identity==packed.identity
    with pytest.raises(ValueError):catalog_for(data,['bu:protocol-a'],packing_profile='unknown')
    with pytest.raises(ValueError):PackedEvidenceCatalog({**data,'packing_rule_sha256':'f'*64},['bu:protocol-a'])


def test_same_bundle_roundtrip_preserves_conditions_unknowns_and_editable_closure():
    c=PackedEvidenceCatalog(collection(condition=True,binding=True),['bu:protocol-a']);cfg=MiningConfig(max_request_chars=100000)
    chunk=c.chunks(cfg)[0][0];state=initial(c);first=make_packet(c,chunk,state,cfg,'request:first')
    ok,state=check_proposal(json.dumps(valid_proposal(first)),first,state,cfg);assert ok['valid']
    packet=make_packet(c,chunk,state,cfg,'request:review');envelope,metrics=compact_packet(packet)
    assert expand_compact(envelope)==packet and metrics['evidence_removed']==0
    assert set(packet['ledger_context']['actions'])==set(state['actions'])
    assert set(packet['ledger_context']['bcs'])==set(state['bcs']) and not packet['ledger_context_deferred']
    assert packet['evidence']==c.render(packet['evidence'],set(packet['manifest']['source_bu_refs']))
    assert packet['source_limits'][0]['status']['state']=='partial'
    damaged=valid_proposal(packet);damaged['upsert_actions'][0]['condition_refs']=[]
    checked,_=check_proposal(json.dumps(damaged),packet,state,cfg)
    assert not checked['valid'] and 'action_conditions' in {e['code'] for e in checked['errors']}


def test_packed_resume_links_only_immutable_assets_and_strictly_replays(tmp_path):
    data=collection(second_bu=True);cat=lambda:PackedEvidenceCatalog(data,[u['bu_id'] for u in data['units']])
    cfg=MiningConfig(max_model_calls=2,max_bu=4);provider=ProtocolProvider()
    first,a=run_mining(cat(),ProtocolView(),tmp_path,provider,cfg,call_limit=1)
    protected={p.relative_to(first).as_posix():sha256_file(p) for p in first.rglob('*') if p.is_file()}
    second,b=run_mining(cat(),ProtocolView(),tmp_path,provider,cfg,resume_from=first,call_limit=1)
    assert b['budgets']['model_calls']==2 and b['attempts'][:len(a['attempts'])]==a['attempts']
    assert verify_package(second,cat(),ProtocolView())['valid']
    assert os.path.samefile(first/'source-visible.json',second/'source-visible.json')
    assert not os.path.samefile(first/'ledger.sqlite',second/'ledger.sqlite')
    assert os.path.samefile(first/'requests/000/request.json',second/'requests/000/request.json')
    with pytest.raises(StorageGateError):assert_writable(second/'requests/000/request.json',segment_root=second)
    assert all(sha256_file(first/name)==digest for name,digest in protected.items())
    assert json.loads((second/'storage-reuse.json').read_text())['new_content_bytes']==0
