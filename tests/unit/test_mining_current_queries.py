"""Model-protocol selected query, actual return, later visibility and use."""
import json
from types import SimpleNamespace

from test_mining_protocol import collection,ProtocolProvider,ProtocolView,valid_proposal
from androserum.facts.queries import CurrentFactQuery
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import CurrentMiningConfig
from androserum.mining.runner import run_mining
from androserum.mining.verification import verify_package


class View(ProtocolView):
    run_ref='run:synthetic-mining-protocol'
    snapshot_id='b'*64
    manifest=SimpleNamespace(apk_sha256='a'*64,coverage={'data_flow':'partial'})
    def get_records(self,refs,limit=1):
        result=super().get_records(refs,limit=limit)
        result.truncated=False;result.filters={}
        return result


class QueryProvider(ProtocolProvider):
    def generate(self,packet,directory,config):
        proposal=valid_proposal(packet)
        added=[h for h,e in packet['evidence'].items() if e.get('supplement_query_id')=='detail']
        if added:
            proposal['upsert_actions'][0]['support_fact_refs']=added
        else:
            proposal['fact_queries']=[CurrentFactQuery(query_id='detail',query_type='record',apk_sha256='a'*64,
                run_ref=View.run_ref,subject_ref='analysis:detail',reason='Resolve the missing current fact detail').model_dump(mode='json')]
        return json.dumps(proposal),{'real_model':False}


def test_structured_query_admission_and_actual_use_continue_one_ledger(tmp_path,monkeypatch):
    # This fixture is deliberately only a protocol view. Actual typed graph
    # admission over a compiled APK is covered in test_query_evidence.py.
    def raw_protocol_adapter(catalog,view,records,bus,*,query_id):
        handles=[catalog.supplement(r,query_id,bus) for r in records]
        return {'schema_version':'protocol-raw-query-admission','added_handles':handles,
            'decisions':[{'record_ref':r['id'],'state':'raw_fact_only'} for r in records],
            'required_record_refs':[]}
    monkeypatch.setattr('androserum.facts.query_evidence.adapt_query_evidence',raw_protocol_adapter)
    data=collection()
    for unit in data['units']:
        for record in unit['model_visible']['records']:
            if 'provenance' in record:record['provenance']['support_refs']=[]
    catalog=lambda:EvidenceCatalog(data,['bu:protocol-a'])
    config=CurrentMiningConfig(max_model_calls=2,max_supplement_rounds=1,max_queries_per_proposal=1)
    first,a=run_mining(catalog(),View(),tmp_path,QueryProvider(),config,call_limit=1)
    assert a['accepted_state']['revision']==1 and a['chunk_progress'][0]['state']=='pending_supplement'
    assert a['current_fact_queries']['queries'][0]['records'][0]['id']=='analysis:detail'
    assert not a['current_fact_queries']['uses']
    second,b=run_mining(catalog(),View(),tmp_path,QueryProvider(),config,resume_from=first)
    assert b['accepted_state']['revision']==2 and b['budgets']['model_calls']==2
    assert b['current_fact_queries']['uses'][0]['record_refs']==['analysis:detail']
    assert b['coverage']['all_selected_evidence_submitted']
    assert verify_package(second,catalog(),View())['valid']
