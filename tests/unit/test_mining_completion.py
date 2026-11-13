"""Automatic post-BU orchestration; deterministic protocol, zero real models."""
from copy import deepcopy
import json

import pytest

from test_mining_protocol import collection, ProtocolProvider, valid_proposal
from test_mining_current_queries import View
from androserum.facts.queries import CurrentFactQuery
from androserum.mining.evidence import EvidenceCatalog
from androserum.mining.models import CurrentMiningConfig
from androserum.mining.runner import run_mining
from androserum.mining.verification import verify_package
from androserum.pipeline.mining_completion import finalize_mining
from androserum.pipeline.workplan import CandidatePlan, discover_plan


class Provider(ProtocolProvider):
    def __init__(self, *, stop_after_query=False, invalid_final=False, query=True):
        super().__init__(); self.stop_after_query=stop_after_query; self.invalid_final=invalid_final
        self.query=query; self.final_queries=0; self.calls=0

    def preflight(self, packet, config):
        if self.stop_after_query and self.final_queries: return 'protocol_segment_stop_after_query'
        return None

    def generate(self, packet, directory, config):
        self.calls += 1; value=valid_proposal(packet)
        relation=next(h for h,e in packet['evidence'].items() if e['category']=='relation')
        issue={'issue_id':'late_detail','subject_ids':['a_read','bc_local'],
               'description':'Resolve a concrete missing current fact after all BU evidence has been considered.',
               'evidence_refs':[relation],'status':'open'}
        review=packet.get('work_context',{}).get('review_task')
        if not review:
            value['unresolved_updates']=[issue]
        elif self.invalid_final:
            value['base_revision'] += 100
        elif packet.get('fact_query_results'):
            added=[h for h,e in packet['evidence'].items() if e.get('supplement_query_id')=='late_detail_query']
            value['upsert_actions'][0]['support_fact_refs']=added
            value['unresolved_updates']=[{**issue,'status':'resolved'}]
        elif self.query:
            value['fact_queries']=[CurrentFactQuery(query_id='late_detail_query',query_type='record',apk_sha256='a'*64,
                run_ref=View.run_ref,subject_ref='analysis:detail',reason='Resolve the model-recorded late detail issue').model_dump(mode='json')]
            self.final_queries += 1
        return json.dumps(value), {'real_model':False}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    def raw_protocol_adapter(catalog,view,records,bus,*,query_id):
        handles=[catalog.supplement(r,query_id,bus) for r in records]
        return {'schema_version':'protocol-raw-query-admission','added_handles':handles,
                'decisions':[{'record_ref':r['id'],'state':'raw_fact_only'} for r in records], 'required_record_refs':[]}
    monkeypatch.setattr('androserum.facts.query_evidence.adapt_query_evidence',raw_protocol_adapter)
    def build(*,two=False,limit=None,max_calls=8):
        data=collection(second_bu=two)
        for unit in data['units']:
            for record in unit['model_visible']['records']:
                if 'provenance' in record: record['provenance']['support_refs']=[]
        cat=lambda:EvidenceCatalog(data,[u['bu_id'] for u in data['units']])
        cfg=CurrentMiningConfig(max_model_calls=max_calls,max_supplement_rounds=2,max_queries_per_proposal=1)
        prepared={'apk_sha256':'a'*64,'source_run_ref':data['source_run_ref'],'snapshot':'synthetic-protocol-store',
                  'selected_roots':[],'available_sapi_roots':[]}
        plan=discover_plan(prepared,{'matches':[]},data,cfg)
        provider=Provider();run,report=run_mining(cat(),View(),tmp_path/'mining',provider,cfg,call_limit=limit)
        progress=CandidatePlan(tmp_path/'complete-plan',plan,budget={'max_model_calls':max_calls,
            'max_input_chars':2000000,'max_reported_input_tokens':200000})
        progress.sync_mining(run,report)
        return cat,cfg,provider,run,report,progress,tmp_path/'mining'
    return build


def test_automatic_late_query_returns_and_review_uses_same_native_ledger(setup):
    cat,cfg,provider,run,report,progress,output=setup()
    try:
        assert report['coverage']['all_planned_chunks_terminal'] and report['budgets']['model_calls']==1
        final,actual,status=finalize_mining(cat(),View(),output,provider,cfg,progress,run,report,remaining_segment_calls=4)
        assert status['new_final_review_calls']==2
        assert actual['budgets']['model_calls']==3
        assert actual['accepted_state']['unresolved']['late_detail']['status']=='resolved'
        assert actual['current_fact_queries']['uses'][0]['record_refs']==['analysis:detail']
        assert actual['attempts'][:len(report['attempts'])]==report['attempts']
        assert verify_package(final,cat(),View())['valid']
        before=provider.calls
        again,replay,stamp=finalize_mining(cat(),View(),output,provider,cfg,progress,final,actual,remaining_segment_calls=4)
        assert provider.calls==before and again==final and stamp['new_final_review_calls']==0
        assert progress.plan['plan_id']==json.loads((progress.root/'plan.json').read_text())['plan']['plan_id']
        assert 'mining_finalization' in progress.report()['by_kind']
    finally: progress.close()


def test_query_return_segment_stop_then_one_call_resume_does_not_requery(setup):
    cat,cfg,provider,run,report,progress,output=setup()
    try:
        stopped=Provider(stop_after_query=True)
        first,a,stamp=finalize_mining(cat(),View(),output,stopped,cfg,progress,run,report,remaining_segment_calls=2)
        assert stamp['new_final_review_calls']==1 and len(a['current_fact_queries']['queries'])==1
        state=json.loads((progress.root.parent/'mining-completion/state.json').read_text())
        assert any(i.get('outcome')=='queried_review_pending' for i in state['items'].values())
        assert not a['current_fact_queries']['uses']
        follow=Provider()
        second,b,stamp=finalize_mining(cat(),View(),output,follow,cfg,progress,first,a,remaining_segment_calls=1)
        assert follow.calls==1 and follow.final_queries==0
        assert len(b['current_fact_queries']['queries'])==1 and b['current_fact_queries']['uses']
        assert verify_package(second,cat(),View())['valid']
    finally: progress.close()


@pytest.mark.parametrize('case',['original_pending','unscheduled','one_call','no_queries_left','no_open','no_accepted'])
def test_finalization_gates_do_not_spend_calls_or_invent_completion(setup,case):
    cat,cfg,provider,run,report,progress,output=setup(two=case=='original_pending',limit=1 if case=='original_pending' else None)
    try:
        value=deepcopy(report);allowance=4
        if case=='unscheduled': value['coverage']['unscheduled']=[{'reason':'not packed'}]
        if case=='one_call': allowance=1
        if case=='no_queries_left': value['budgets']['supplement_rounds']=cfg.max_supplement_rounds
        if case=='no_open': value['accepted_state']['unresolved']={}
        if case=='no_accepted':
            for row in value['chunk_progress']:row['state']='rejected'
        before=provider.calls
        _,_,status=finalize_mining(cat(),View(),output,provider,cfg,progress,run,value,remaining_segment_calls=allowance)
        assert provider.calls==before and status['new_final_review_calls']==0
        if case in {'original_pending','unscheduled'}: assert status['status']=='pending_original_blocks'
        if case in {'one_call','no_queries_left'}:
            assert status['status']=='partial'
            assert progress.report()['by_kind']['mining_finalization']['pending']>=1
    finally: progress.close()


def test_rejected_final_update_keeps_old_state_and_is_not_retried(setup):
    cat,cfg,provider,run,report,progress,output=setup()
    try:
        reject=Provider(invalid_final=True)
        final,actual,status=finalize_mining(cat(),View(),output,reject,cfg,progress,run,report,remaining_segment_calls=3)
        assert actual['accepted_state']==report['accepted_state'] and reject.calls==3
        assert status['status']=='partial'
        before=reject.calls
        finalize_mining(cat(),View(),output,reject,cfg,progress,final,actual,remaining_segment_calls=3)
        assert reject.calls==before
    finally: progress.close()


def test_normal_workplan_persists_query_return_before_use_and_loads_catalog_once(tmp_path, monkeypatch):
    from test_mining_current_queries import QueryProvider
    from androserum.pipeline.workplan import mine_complete_prepared
    from androserum.facts.identity import fingerprint
    from androserum.pipeline.approval import freeze_program_checked
    data=collection()
    for unit in data['units']:
        for record in unit['model_visible']['records']:
            if 'provenance' in record:record['provenance']['support_refs']=[]
    cat=lambda:EvidenceCatalog(data,['bu:protocol-a'])
    def raw_adapter(catalog,view,records,bus,*,query_id):
        return {'schema_version':'protocol-raw-query-admission',
                'added_handles':[catalog.supplement(r,query_id,bus) for r in records],
                'decisions':[{'record_ref':r['id'],'state':'raw_fact_only'} for r in records], 'required_record_refs':[]}
    monkeypatch.setattr('androserum.facts.query_evidence.adapt_query_evidence',raw_adapter)
    def dump(file,value):file.parent.mkdir(parents=True,exist_ok=True);file.write_text(json.dumps(value),encoding='utf-8')
    out=tmp_path/'samples'/'normal';package=tmp_path/'package';snapshot=tmp_path/'snapshot'
    dump(package/'collection.json',data)
    dump(snapshot/'manifest.json',{'snapshot_id':'b'*64,'run_ref':View.run_ref,'apk_sha256':'a'*64})
    source={'mining':{'schema_version':'mining-config.v1'}};dump(out/'config.json',source)
    dump(out/'prepared.json',{'apk_sha256':'a'*64,'source_run_ref':View.run_ref,'snapshot':str(snapshot),
         'bu_package':str(package),'config_sha256':fingerprint(source)})
    dump(out/'sapi-matches.json',{'matches':[]})
    cfg=CurrentMiningConfig(max_model_calls=8,max_supplement_rounds=2)
    dump(tmp_path/'experiment-config.json',{'effective_mining_policy':cfg.model_dump(mode='json'),
        'per_sample_mining_call_limit':8,'aggregate_input_char_limit':2000000,'reported_input_token_stop':200000})
    class ContextView(View):
        def __init__(self,*args):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
    class NormalProvider(QueryProvider):
        def close(self):pass
    provider=NormalProvider();loads=[]
    monkeypatch.setattr('androserum.facts.store.FactView',ContextView)
    monkeypatch.setattr('androserum.pipeline.provider.PipelineProvider',lambda *args:provider)
    monkeypatch.setattr('androserum.mining.runner.load_catalog',lambda *args:(loads.append(True),cat())[1])
    result=mine_complete_prepared(tmp_path,'normal',call_limit=7)
    report=json.loads((__import__('androserum.facts.identity',fromlist=['filesystem_path']).filesystem_path(result['mining_run'])/'report.json').read_text())
    assert len(loads)==1 and report['budgets']['model_calls']==2
    assert report['current_fact_queries']['uses']
    assert len(list((out/'mining-result-history').glob('*.json')))>=1
    assert len(list((out/'mining').glob('mining_*')))==2
    assert verify_package(result['mining_run'],cat(),View())['valid']
    assert result['native_dispatch_segment_size']==1
    # Freeze consumes this exact native replay entry. Protocol responses cannot
    # be relabeled real-model approved BCs; verify that admission still rejects.
    freeze_replay=[]
    def replay_for_freeze(run,package,view):
        freeze_replay.append(True);return verify_package(run,cat(),View())
    monkeypatch.setattr('androserum.mining.verification.verify_mining',replay_for_freeze)
    with pytest.raises(ValueError,match='real-model'):
        freeze_program_checked(result['mining_run'],snapshot,package,tmp_path/'protocol-freeze',source_case='normal',replay=True)
    assert freeze_replay==[True]


def test_issue_scope_refreshes_before_fixed_frontier(setup):
    from androserum.pipeline.mining_completion import Completion
    cat,cfg,provider,run,report,progress,output=setup()
    try:
        state=Completion(progress.root.parent/'planning-only',progress)
        state.candidates(report);key=next(iter(state.state['items']))
        second=deepcopy(report)
        second['accepted_state']['actions']['a_read']['operation_refs'].append('op_second_visible')
        second['accepted_state']['actions']['a_read']['evidence_handles'].append('op_second_visible')
        second['chunk_progress'].append({'chunk_id':'later_accepted_source','state':'accepted',
            'chunk':{'bu_ids':['bu:protocol-a'],'handles':['op_second_visible']}})
        state.candidates(second)
        assert 'later_accepted_source' in state.state['items'][key]['scope']['target_chunk_ids']
        assert state.state['frontier'] is None
    finally:progress.close()


def test_old_receipt_with_reused_query_id_is_not_current_final_query(tmp_path):
    from androserum.pipeline.mining_completion import _trace
    directory=tmp_path/'requests/0';directory.mkdir(parents=True)
    issue={'issue_id':'late','subject_ids':[]}
    selector={'query_id':'shared','subject_ref':'new-target'}
    (directory/'request.json').write_text(json.dumps({'ledger_context':{'unresolved':{'late':issue}}}))
    (directory/'proposal.json').write_text(json.dumps({'fact_queries':[selector]}))
    report={'chunk_progress':[{'chunk_id':'review','state':'accepted','request_ids':['current'],
        'work_amendment':{'amendment_id':'late'}}], 'attempts':[{'request_id':'current','status':'accepted'}],
        'requests':[{'request_id':'current','directory':'requests/0'}],
        'query_typed_admissions':[{'request_id':'old','receipt_id':'old-receipt'}],
        'current_fact_queries':{'queries':[{'query':{'query_id':'shared','subject_ref':'old-target'},
            'receipt_id':'old-receipt','records':[]}],'uses':[]}}
    trace=_trace(tmp_path,report,'late',issue)
    assert not trace['actual_receipts']
    assert trace['unfulfilled_accepted_model_queries'][0]['query']==selector


@pytest.mark.parametrize('mode',['deferred','missing_subject','same_request','valid'])
def test_return_receipt_requires_same_later_accepted_editable_request(tmp_path,mode):
    from androserum.pipeline.mining_completion import _trace
    issue={'issue_id':'issue','subject_ids':['action']};selector={'query_id':'q','subject_ref':'fact:detail'}
    contexts={'unresolved':{'issue':issue},'actions':{'action':{}}}
    packets=[{'ledger_context':contexts,'fact_query_results':[]},
             {'ledger_context':deepcopy(contexts),'fact_query_results':[{'receipt_id':'receipt:actual'}]}]
    if mode=='deferred':
        packets[1]['ledger_context']={};packets[1]['ledger_context_deferred']=[{'editable':False,'reason':'ledger_context_budget'}]
    if mode=='missing_subject':packets[1]['ledger_context']['actions']={}
    if mode=='same_request':
        packets[0]['fact_query_results']=[{'receipt_id':'receipt:actual'}];packets[1]['fact_query_results']=[]
    for i,packet in enumerate(packets):
        d=tmp_path/'requests'/str(i);d.mkdir(parents=True)
        (d/'request.json').write_text(json.dumps(packet));(d/'proposal.json').write_text(json.dumps({'fact_queries':[selector] if i==0 else []}))
    report={'chunk_progress':[{'chunk_id':'review','state':'accepted','request_ids':['r1','r2'],
        'work_amendment':{'amendment_id':'final'}}], 'attempts':[{'request_id':r,'status':'accepted'} for r in ['r1','r2']],
        'requests':[{'request_id':r,'directory':'requests/'+str(i)} for i,r in enumerate(['r1','r2'])],
        'query_typed_admissions':[{'request_id':'r1','receipt_id':'receipt:actual'}],
        'current_fact_queries':{'queries':[{'receipt_id':'receipt:actual','query':selector,'records':[]}],'uses':[]}}
    trace=_trace(tmp_path,report,'final',issue)
    assert bool(trace['returned_without_later_accepted_review']) == (mode!='valid')
    if mode in {'deferred','missing_subject'}:assert not trace['target_issue_editable_in_accepted_review']


def test_no_query_uses_final_accepted_request_editability(tmp_path):
    from androserum.pipeline.mining_completion import _trace
    issue={'issue_id':'issue','subject_ids':['action']}
    for i,context in enumerate([{'unresolved':{'issue':issue},'actions':{'action':{}}},{}]):
        d=tmp_path/'requests'/str(i);d.mkdir(parents=True)
        (d/'request.json').write_text(json.dumps({'ledger_context':context}));(d/'proposal.json').write_text('{"fact_queries":[]}')
    report={'chunk_progress':[{'chunk_id':'review','state':'accepted','request_ids':['r1','r2'],
        'work_amendment':{'amendment_id':'final'}}], 'attempts':[{'request_id':r,'status':'accepted'} for r in ['r1','r2']],
        'requests':[{'request_id':r,'directory':'requests/'+str(i)} for i,r in enumerate(['r1','r2'])]}
    assert not _trace(tmp_path,report,'final',issue)['target_issue_editable_in_accepted_review']


@pytest.mark.parametrize('damage',[None,'other_hash','frontier','last_run','trace','native_final'])
def test_only_exact_unstarted_legacy_completion_metadata_can_migrate(setup,damage):
    from androserum.pipeline.mining_completion import Completion,migrate_unstarted_completion,LEGACY_UNSTARTED_HELPER,LOADED_ORCHESTRATION_SHA
    from androserum.facts.identity import sha256_file
    cat,cfg,provider,run,report,progress,output=setup()
    try:
        root=progress.root.parent/'mining-completion';completion=Completion(root,progress)
        completion.candidates(report);completion.save('Protocol fixture pending gate')
        value=json.loads(completion.file.read_text());value['binding']['orchestration_sha256']=LEGACY_UNSTARTED_HELPER
        if damage=='other_hash':value['binding']['orchestration_sha256']='f'*64
        if damage=='frontier':value['frontier']=[]
        if damage=='last_run':value['last_run']='an-existing-final-run'
        if damage=='trace':next(iter(value['items'].values()))['trace']={'requests':['already dispatched']}
        completion.file.write_text(json.dumps(value),encoding='utf-8')
        if damage=='native_final':
            d=output/'mining_retained_final';d.mkdir();(d/'run.json').write_text(json.dumps({'new_work_amendment':{'amendment_id':'auto-final:already-created'}}))
        before=completion.file.read_bytes()
        if damage:
            with pytest.raises(ValueError):migrate_unstarted_completion(root)
            assert completion.file.read_bytes()==before
        else:
            receipt=migrate_unstarted_completion(root)
            assert receipt['status']=='migrated' and receipt['native_final_work_count']==0
            assert __import__('pathlib').Path(receipt['old_state_archive']).read_bytes()==before
            assert json.loads(completion.file.read_text())['binding']['orchestration_sha256']==LOADED_ORCHESTRATION_SHA
            assert receipt['after_state_sha256']==sha256_file(completion.file)
            assert migrate_unstarted_completion(root)['status']=='already_current'
    finally:progress.close()
