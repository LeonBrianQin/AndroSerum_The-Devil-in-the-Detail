"""Interrupted live-task sidecars recover from committed native audit, without new calls."""
from copy import deepcopy
from pathlib import Path
import runpy
import pytest
from androserum.facts.identity import canonical_json
from androserum.matching.fixtures import toy_side
from androserum.tasking import TaskConfig, TaskLedger


API=runpy.run_path(str(Path(__file__).resolve().parents[2]/'scripts/run_live_task.py'))
restore=API['restore_task_check']
validate_stage=API['validate_task_stage_result']
write=API['write']


def book_at(tmp_path):
    side=toy_side('resume_only');side['bc']['bc_id']='current'
    catalog={'bcs':{'current':side},'supplemental':{'fact:later':{'handle':'fact:later','category':'fact',
        'record':{'run_ref':'run:current','record_id':'fact:later','value':'Retrieved current detail'}}}}
    return TaskLedger(tmp_path/'ledger.sqlite',{'apk_sha256':'a'*64,'source_run_ref':'run:current'},
                      config=TaskConfig(allow_synthetic_protocol=True),source_catalog=catalog)


def proposal(packet):
    return {'schema_version':'apk-task-proposal.v1','request_id':packet['request_id'],
        'base_revision':packet['base_revision'],'upsert_findings':[],'delete_finding_ids':[],
        'issue_updates':[],'fact_queries':[],'synthesis':None,'rationale':'Deterministic interruption control only.'}


def completed_call(tmp_path,phase,index,raw):
    directory=tmp_path/(phase+'-attempt-'+str(index));directory.mkdir(parents=True,exist_ok=True)
    (directory/'raw-model-output.json').write_text(raw,encoding='utf-8')
    write(directory/'receipt.json',{'status':'completed','call_id':'task:'+phase+':'+str(index)})
    return directory


def recover(book,tmp_path,packet,index=0,phase='first',**options):
    return restore(book,packet,index,tmp_path/(phase+'-check-'+str(index)+'.json'),
                   tmp_path/(phase+'-attempt-'+str(index)),'task:'+phase+':'+str(index),**options)


def test_committed_accepted_response_restored_without_resubmission(tmp_path):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();raw=canonical_json(proposal(packet))
        completed_call(tmp_path,'first',0,raw)
        assert book.update(raw,packet)['valid']
        before=book.report()
        restored=recover(book,tmp_path,packet)
        assert restored['valid'] and restored['revision']==1 and restored['recovered_from_native_audit']
        assert book.report()==before  # No stale second submission, native audit or budget change.
        assert recover(book,tmp_path,packet)==restored


def test_rejected_commit_recovers_then_one_legal_repair(tmp_path):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();p=proposal(packet);bad=deepcopy(p);bad['base_revision']=42
        raw=canonical_json(bad);completed_call(tmp_path,'first',0,raw)
        assert not book.update(raw,packet)['valid']
        first=recover(book,tmp_path,packet);assert not first['valid'] and first['revision']==0
        raw=canonical_json(p);completed_call(tmp_path,'first',1,raw)
        assert book.update(raw,packet)['valid']
        second=recover(book,tmp_path,packet,1)
        assert second['valid'] and second['revision']==1
        assert len(book.report()['audits'])==2


@pytest.mark.parametrize('field,value',[('valid',False),('revision',90),('call_id','foreign'),('audit_sequence',90),('audit_sha256','f'*64)])
def test_existing_check_cannot_contradict_native_audit(tmp_path,field,value):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();raw=canonical_json(proposal(packet));completed_call(tmp_path,'first',0,raw)
        assert book.update(raw,packet)['valid']
        row=recover(book,tmp_path,packet);row[field]=value;write(tmp_path/'first-check-0.json',row)
        with pytest.raises(ValueError,match='Task check'):
            recover(book,tmp_path,packet)


def test_check_file_without_committed_native_attempt_is_rejected(tmp_path):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();write(tmp_path/'first-check-0.json',{'valid':True})
        with pytest.raises(ValueError,match='no corresponding'):
            recover(book,tmp_path,packet)


def test_rolled_back_commit_reuses_retained_response_once(tmp_path):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();raw=canonical_json(proposal(packet));completed_call(tmp_path,'first',0,raw)
        def crash():raise RuntimeError('Simulated crash before native commit')
        with pytest.raises(RuntimeError):book.update(raw,packet,before_commit=crash)
        assert recover(book,tmp_path,packet) is None
        assert book.update(raw,packet)['valid']
        assert recover(book,tmp_path,packet,recovered=False)['recovered_from_native_audit'] is False
        assert len(book.report()['audits'])==1


@pytest.mark.parametrize('mutation',['raw','receipt','packet'])
def test_saved_artifacts_must_match_native_registration(tmp_path,mutation):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();raw=canonical_json(proposal(packet));directory=completed_call(tmp_path,'first',0,raw)
        assert book.update(raw,packet)['valid']
        if mutation=='raw':(directory/'raw-model-output.json').write_text('{}',encoding='utf-8')
        elif mutation=='receipt':write(directory/'receipt.json',{'status':'completed','call_id':'other-invocation'})
        else:packet['task']='changed-task'
        with pytest.raises(ValueError):recover(book,tmp_path,packet)


def test_stage_boundary_accounts_for_retrieval_and_later_revisions(tmp_path):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();p=proposal(packet)
        p['issue_updates']=[{'issue_id':'i','description':'Current detail missing','bc_ids':['current'],
            'finding_ids':[],'evidence_refs':[],'status':'open','resolution':None}]
        p['fact_queries']=[{'query_id':'q','requested_refs':['fact:later'],'purpose':'Bounded retrieval','issue_ids':['i']}]
        raw=canonical_json(p);completed_call(tmp_path,'first',0,raw)
        assert book.update(raw,packet)['valid'];first=recover(book,tmp_path,packet)
        book.fulfill_queries({'q':['fact:later']})
        stage={'phase':'first','attempts':[first],'revision':2}
        later=book.prepare_packet();raw=canonical_json(proposal(later));completed_call(tmp_path,'second',0,raw)
        assert book.update(raw,later)['valid'];recover(book,tmp_path,later,phase='second')
        assert book.state()['revision']==3
        assert validate_stage(book,packet,stage,tmp_path)==stage
        corrupted=deepcopy(stage);corrupted['revision']=3
        with pytest.raises(ValueError,match='boundary'):
            validate_stage(book,packet,corrupted,tmp_path)
        corrupted=deepcopy(stage);corrupted['attempts'][0]['errors']=[{'code':'invented'}]
        with pytest.raises(ValueError,match='result contradicts'):
            validate_stage(book,packet,corrupted,tmp_path)


def test_retained_transport_failure_does_not_reinvoke_or_mutate_revision(tmp_path):
    with book_at(tmp_path) as book:
        packet=book.prepare_packet();directory=tmp_path/'first-attempt-0';directory.mkdir()
        write(directory/'receipt.json',{'status':'timeout','call_id':'task:first:0','error':'Frozen timeout'})
        assert not book.update('',packet)['valid']
        row=recover(book,tmp_path,packet)
        assert row['transport_error']=='Frozen timeout' and not row['valid'] and row['revision']==0
        assert len(book.report()['audits'])==1
