"""Actual immutable fact-store queries; no LLM or semantic accuracy claim."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from androserum.facts.io import load_facts,loads_facts
from androserum.facts.identity import canonical_json,sha256_file
from androserum.facts.models import Endpoint
from androserum.facts.queries import CurrentFactQuery,FactQuerySession,FactQueryBudget,verify_query_report
from androserum.facts.store import FactView,create_snapshot


@pytest.fixture
def snapshot(tmp_path):
    raw=load_facts(Path(__file__).parents[1]/'fixtures/contracts/valid.json').model_dump(mode='json')
    run=raw['run']['run_id']
    raw['elements'].append({'id':'resource:query','run_ref':run,'kind':'resource',
        'position':{'kind':'archive','path':'resources.arsc','selector':'query-only'},
        'provenance':{'kind':'direct','tool_ref':'tool:synthetic'},'resource_id':12,
        'resource_type':'string','name':'query_name','value':{'status':'known','value':'query value'}})
    return create_snapshot(loads_facts(canonical_json(raw)),tmp_path/'store')


def q(view,kind,**kwargs):
    return CurrentFactQuery(query_id='query_'+kind,query_type=kind,apk_sha256=view.manifest.apk_sha256,
        run_ref=view.run_ref,reason='Resolve the recorded question using actual current facts',**kwargs)


def test_all_query_types_return_existing_records_or_explicit_no_match(snapshot,tmp_path):
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'queries.sqlite',view,
            FactQueryBudget(max_queries=20,max_records=100)) as service:
        facts=view.export_bundle();method=next(x for x in facts.elements if x.id=='method:run')
        endpoint=next(x.target for x in facts.relations if x.relation_kind=='data_dependency')
        queries=[q(view,'record',subject_ref=method.id),q(view,'method',method_signature=method.signature),
            q(view,'operation',subject_ref=method.id),q(view,'call',subject_ref='instruction:send-identifier'),
            q(view,'data_dependency',endpoint=endpoint),q(view,'condition',subject_ref='instruction:send-identifier'),
            q(view,'event',subject_ref='instruction:send-identifier'),q(view,'resource',name='query_name')]
        for query in queries:
            response=service.execute(query)
            assert response['state'] in {'completed','ran_no_matching_fact'}
            for record in response['records']:
                assert view.get_records([record['id']]).records[0].model_dump(mode='json')==record
        assert service.execute(queries[4])['records']
        assert service.execute(queries[7])['records'][0]['name']=='query_name'
        assert service.report()['budget_used']['queries']==8


def test_identity_selectors_and_sql_are_not_authorized(snapshot,tmp_path):
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'queries.sqlite',view) as service:
        wrong=q(view,'method',subject_ref='method:run').model_copy(update={'apk_sha256':'f'*64})
        with pytest.raises(ValueError,match='current APK'):service.execute(wrong)
        with pytest.raises(ValidationError):
            CurrentFactQuery.model_validate({**q(view,'method',subject_ref='method:run').model_dump(), 'sql':'DELETE FROM records'})
        with pytest.raises(ValidationError):q(view,'operation')
        injection=q(view,'resource',name="' OR 1=1 --")
        assert service.execute(injection)['state']=='ran_no_matching_fact'
        with pytest.raises(ValidationError):
            CurrentFactQuery.model_validate({**injection.model_dump(),'query_type':'dynamic_execution'})


def test_cumulative_budget_replay_actual_returns_and_use_survive_resume(snapshot,tmp_path):
    path=tmp_path/'queries.sqlite';budget=FactQueryBudget(max_queries=1,max_records=1)
    before=sha256_file(snapshot/'facts.sqlite')
    with FactView(snapshot) as view,FactQuerySession(path,view,budget) as service:
        first=q(view,'method',subject_ref='method:run');receipt=service.execute(first)
        assert len(receipt['records'])==1
        assert service.execute(first)==receipt
        service.record_use(receipt['receipt_id'],'accepted_request_1',['method:run'])
        with pytest.raises(ValueError,match='actually returned'):
            service.record_use(receipt['receipt_id'],'bad',['method:save'])
        blocked=service.execute(q(view,'resource',name='query_name'))
        assert blocked['state']=='budget_exhausted' and not blocked['records']
    with FactView(snapshot) as view,FactQuerySession(path,view,budget) as service:
        assert service.execute(first)==receipt
        assert service.report()['uses'][0]['record_refs']==['method:run']
        with pytest.raises(ValueError,match='different content'):
            service.execute(first.model_copy(update={'subject_ref':'method:save'}))
    assert sha256_file(snapshot/'facts.sqlite')==before


def test_return_character_budget_cannot_authorize_unreturned_record(snapshot,tmp_path):
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'q.sqlite',view,
            FactQueryBudget(max_return_chars=1)) as service:
        result=service.execute(q(view,'method',subject_ref='method:run'))
        assert result['state']=='budget_exhausted' and not result['records'] and result['truncated']


def test_operation_signature_is_an_actual_filter(snapshot,tmp_path):
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'q.sqlite',view) as service:
        absent=service.execute(q(view,'operation',method_signature='Lnot/Present;->absent()V'))
        assert absent['state']=='ran_no_matching_fact' and not absent['records']


def test_call_queries_use_declared_target_signature_and_dex_method_owner(snapshot,tmp_path):
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'q.sqlite',view,
            FactQueryBudget(max_queries=4,max_records=64)) as service:
        instruction=view.get_records(['instruction:send-identifier']).records[0]
        by_method=service.execute(q(view,'call',subject_ref='method:run',include_support=False))
        assert any(r['id']==instruction.id for r in by_method['records'])
        signature=instruction.declared_target.signature
        by_signature=service.execute(q(view,'call',method_signature=signature,include_support=False).model_copy(update={'query_id':'signature'}))
        assert any(r.get('declared_target',{}).get('signature')==signature for r in by_signature['records'])


def test_forged_empty_query_result_is_rejected_even_with_new_content_hash(snapshot,tmp_path):
    from androserum.facts.identity import fingerprint
    with FactView(snapshot) as view,FactQuerySession(tmp_path/'q.sqlite',view) as service:
        service.execute(q(view,'method',subject_ref='method:run'))
        report=service.report();assert verify_query_report(report,view)['valid']
        forged=deepcopy(report);receipt=forged['queries'][0]
        receipt.update(state='ran_no_matching_fact',records=[],returned_chars=0)
        receipt.pop('receipt_id');receipt['receipt_id']='fact-query:'+fingerprint(receipt)
        with pytest.raises(ValueError,match='actual selection'):verify_query_report(forged,view)
