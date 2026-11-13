"""Deterministic continuation/coverage/enrichment gates, not model semantics."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from test_mining_protocol import collection,ProtocolProvider,ProtocolView,valid_proposal
from androserum.facts.identity import sha256_file
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import MiningConfig
from androserum.mining.runner import run_mining
from androserum.mining.verification import verify_package


def catalog(q=None):
    q=q or collection(second_bu=True)
    return EvidenceCatalog(q,[u['bu_id'] for u in q['units']])


def test_resume_preserves_versions_audit_and_parent_bytes(tmp_path):
    c=catalog();config=MiningConfig(max_chunks=2)
    first,a=run_mining(c,ProtocolView(),tmp_path,ProtocolProvider(),config,call_limit=1)
    assert a['stop_reason']=='segment_call_limit' and a['coverage']['states']=={'accepted':1,'unprocessed':1}
    before={p.relative_to(first).as_posix():sha256_file(p) for p in first.rglob('*') if p.is_file()}
    second,b=run_mining(c,ProtocolView(),tmp_path,ProtocolProvider(),config,resume_from=first)
    assert b['identity']==a['identity'] and b['accepted_state']['revision']==2
    assert b['attempts'][:1]==a['attempts'] and b['budgets']['model_calls']==2 and b['budgets']['segment_model_calls']==1
    assert b['coverage']['all_selected_evidence_submitted'] and b['coverage']['all_planned_chunks_terminal']
    assert all(sha256_file(first/p)==h for p,h in before.items())
    assert verify_package(second,catalog(),ProtocolView())['checker_replayed']==2


def test_resume_does_not_reset_global_budget(tmp_path):
    config=MiningConfig(max_chunks=2,max_model_calls=1)
    first,a=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider(),config)
    second,b=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider(),config,resume_from=first)
    assert b['budgets']['model_calls']==1 and b['budgets']['segment_model_calls']==0
    assert b['coverage']['states']['unprocessed']==1


def test_explicit_budget_amendment_retains_consumed_calls(tmp_path):
    first,a=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider(),MiningConfig(max_chunks=2,max_model_calls=1))
    second,b=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider(),MiningConfig(max_chunks=2,max_model_calls=2),
        resume_from=first,budget_amendment_reason='Reallocate previously reserved cohort calls')
    assert b['budgets']['model_calls']==2 and b['budgets']['segment_model_calls']==1
    assert json.loads((second/'run.json').read_text('utf-8'))['budget_amendment']['calls_already_used']==1
    assert verify_package(second,catalog(),ProtocolView())['valid']


def test_one_policy_recheck_preserves_old_repair_count_and_refusals(tmp_path):
    config=MiningConfig(max_chunks=1,max_repairs_per_chunk=1)
    first,a=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider('invalid'),config)
    provider=ProtocolProvider();provider.description=ProtocolProvider('invalid').description
    second,b=run_mining(catalog(),ProtocolView(),tmp_path,provider,config,resume_from=first,
        budget_amendment_reason='Compiler monotonic-support correction',recheck_rejected=True)
    assert len(b['attempts'])==3 and b['attempts'][:2]==a['attempts']
    assert b['chunk_progress'][0]['repairs_used']==1 and b['chunk_progress'][0]['policy_rechecks_used']==1
    assert b['accepted_state']['revision']==1 and verify_package(second,catalog(),ProtocolView())['valid']


def test_pause_repair_then_resume_does_not_reset_repair_budget(tmp_path):
    config=MiningConfig(max_chunks=1,max_repairs_per_chunk=1)
    first,a=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider('invalid'),config,call_limit=1)
    assert a['chunk_progress'][0]['repairs_used']==1
    second,b=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider('invalid'),config,resume_from=first)
    assert len(b['attempts'])==2 and b['chunk_progress'][0]['state']=='rejected'
    assert b['accepted_state']['revision']==0
    assert verify_package(second,catalog(),ProtocolView())['checker_replayed']==0


def test_pause_after_query_continues_with_admitted_fact(tmp_path):
    config=MiningConfig(max_chunks=1,max_supplement_rounds=1)
    first,a=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider('query'),config,call_limit=1)
    assert a['chunk_progress'][0]['state']=='pending_supplement'
    provider=ProtocolProvider('query');provider.calls=1
    second,b=run_mining(catalog(),ProtocolView(),tmp_path,provider,config,resume_from=first)
    assert b['budgets']['supplement_rounds']==1 and b['accepted_state']['revision']==2
    assert b['accepted_state']['unresolved']['detail_checked']['status']=='resolved'
    assert verify_package(second,catalog(),ProtocolView())['valid']


@pytest.mark.parametrize('changed',['config','provider','missing_manifest'])
def test_resume_rejects_changed_contract_or_incomplete_package(tmp_path,changed):
    config=MiningConfig(max_chunks=1);first,_=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider(),config,call_limit=0)
    provider=ProtocolProvider()
    if changed=='config':config=MiningConfig(max_chunks=2)
    if changed=='provider':provider.description={'kind':'different'}
    if changed=='missing_manifest':(first/'manifest.json').unlink()
    with pytest.raises((ValueError,OSError)):
        run_mining(catalog(),ProtocolView(),tmp_path,provider,config,resume_from=first)


def test_repeated_bu_evidence_is_not_new_support(tmp_path):
    _,r=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider(),MiningConfig(max_chunks=2))
    assert not r['support_additions']


def test_new_bu_dependency_is_recorded_as_substantive_support(tmp_path):
    q=collection(second_bu=True);u=q['units'][1]
    edge=deepcopy(u['model_visible']['records'][-1]);edge['id']='relation:new-support'
    u['model_visible']['records'].append(edge);u['model_visible']['allowed_citation_refs'].append(edge['id'])
    meta=deepcopy(u['model_visible']['relation_records'][0]);meta['record_ref']=edge['id'];u['model_visible']['relation_records'].append(meta)
    class Provider(ProtocolProvider):
        def generate(self,packet,directory,config):
            p=valid_proposal(packet)
            new=[h for h,e in packet['evidence'].items() if e['category']=='relation' and e['record_ref']=='relation:new-support']
            if new:p['upsert_actions'][1]['support_relation_refs']=new
            return json.dumps(p),{'real_model':False}
    _,r=run_mining(catalog(q),ProtocolView(),tmp_path,Provider(),MiningConfig(max_chunks=2))
    assert r['support_additions'] and r['support_additions'][0]['new_bu_refs']==['bu:protocol-b']


def test_compact_record_enrichment_supplies_new_fields_used_later(tmp_path):
    q=collection();record={'id':'resource:label','kind':'resource','run_ref':q['source_run_ref'],
        'resource_id':2130771968,'name':'diagnostic_tag','value':{'status':'known','value':'IdentityAudit'}}
    u=q['units'][0];u['model_visible']['records'].append(record);u['model_visible']['allowed_citation_refs'].append(record['id'])
    from types import SimpleNamespace
    class View(ProtocolView):
        def get_records(self,refs,limit=1):return SimpleNamespace(records=[SimpleNamespace(model_dump=lambda **kw:deepcopy(record))],missing_refs=[])
    class Provider(ProtocolProvider):
        def generate(self,packet,directory,config):
            self.calls+=1;p=valid_proposal(packet)
            h=next(h for h,e in packet['evidence'].items() if e.get('record_ref')==record['id'])
            if self.calls==1:p['fact_queries']=[{'query_id':'tag_detail','record_refs':[record['id']],'reason':'Actual label content omitted'}]
            else:
                assert packet['evidence'][h]['record']['value']['value']=='IdentityAudit'
                p['upsert_actions'][1]['support_fact_refs']=[h]
            return json.dumps(p),{'real_model':False}
    c=catalog(q);run,r=run_mining(c,View(),tmp_path,Provider(),MiningConfig(max_chunks=1))
    assert 'value' in r['queries'][0]['added_fields'] and r['accepted_state']['actions']['a_consume']['support_fact_refs']
    assert verify_package(run,catalog(q),View())['valid']


def test_false_progress_claim_rejected_even_after_manifest_rehash(tmp_path):
    from androserum.mining.session import save
    run,r=run_mining(catalog(),ProtocolView(),tmp_path,ProtocolProvider(),MiningConfig(max_chunks=2),call_limit=0)
    r['chunk_progress'][0]['state']='accepted';save(run/'report.json',r)
    m=json.loads((run/'manifest.json').read_text('utf-8'));m['files']['report.json']={'sha256':sha256_file(run/'report.json'),'bytes':(run/'report.json').stat().st_size};save(run/'manifest.json',m)
    with pytest.raises(ValueError,match='falsely marked accepted'):verify_package(run,catalog(),ProtocolView())
