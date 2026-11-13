"""Flow v2 entry assumptions are capability metadata, never new evidence."""
from types import SimpleNamespace
from copy import deepcopy
import json
from pathlib import Path

from androserum.facts.identity import canonical_json, fingerprint
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import MiningConfig
from androserum.mining.runner import load_catalog
from androserum.mining.session import run_session
from test_mining_protocol import collection


class EmptyProvider:
    is_real=False
    description={'provider':'deterministic-empty-protocol'}
    def __init__(self):self.packets=[]
    def generate(self,packet,directory,config):
        self.packets.append(deepcopy(packet))
        return canonical_json({'schema_version':'behavior-proposal.v1','request_id':packet['request_id'],
            'base_revision':packet['base_revision'],'upsert_actions':[],'delete_action_ids':[],
            'upsert_bcs':[],'delete_bc_ids':[],'unresolved_updates':[],'fact_queries':[],
            'rationale':'Protocol-only scope preservation; no behavior interpretation.'}),{'real_model':False}


def prepare(tmp_path,monkeypatch,version):
    original=collection();directory=tmp_path/'unit';directory.mkdir()
    (directory/'collection.json').write_text(json.dumps(original),'utf-8')
    monkeypatch.setattr('androserum.mining.runner.verify_units',lambda path,view:None)
    scope={'schema_version':version,'entry_scope':'conditional_explicit_methods_not_android_reachability',
           'entry_methods':['Lfixture/Case;->root()V'],'sources':['Ljava/lang/String;->getBytes()[B'],
           'sinks':['Ljava/security/MessageDigest;->update([B)V']}
    view=SimpleNamespace(export_bundle=lambda:SimpleNamespace(run=SimpleNamespace(configuration=SimpleNamespace(options={'selected_flow':scope}))))
    ids=[u['bu_id'] for u in original['units']]
    return original,load_catalog(directory,view,ids),view


def test_v1_catalog_bytes_are_unchanged(tmp_path,monkeypatch):
    original,catalog,_=prepare(tmp_path,monkeypatch,'selected-flow-config.v1')
    before=EvidenceCatalog(original,list(catalog.units))
    assert catalog.statuses==before.statuses and catalog.entries==before.entries
    assert all('analysis_scope_limits' not in s for s in catalog.statuses.values())


def test_v2_adds_no_citations_and_survives_session_clean_rebuild(tmp_path,monkeypatch):
    original,catalog,view=prepare(tmp_path,monkeypatch,'selected-method-flow-config.v2')
    before=EvidenceCatalog(original,list(catalog.units))
    assert catalog.entries==before.entries and catalog.units==before.units
    provider=EmptyProvider()
    _,report=run_session(catalog,view,tmp_path/'runs',provider,MiningConfig(max_model_calls=1,max_chunks=2,max_bu=2))
    assert provider.packets and report['real_model_attempts']==0
    packet=provider.packets[0]
    assert set(packet['evidence'])<=set(before.entries)
    scope=packet['source_limits'][0]['analysis_scope_limits'][0]
    assert scope['entry_methods']==['Lfixture/Case;->root()V']
    assert scope['android_reachability_established'] is False
    assert scope['mechanical_sources_are_automatically_privacy_sources'] is False
    assert scope['role']=='analysis_capability_metadata_not_behavior_evidence'
