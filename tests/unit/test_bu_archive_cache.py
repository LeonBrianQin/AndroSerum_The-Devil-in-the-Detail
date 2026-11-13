"""Shared dependency scans must not bypass repeated evidence-byte validation."""
from copy import deepcopy
from types import SimpleNamespace
from androserum.facts.bu import collect_archive,BUConfig
from androserum.facts.store import EvidenceFile,read_evidence_file
from androserum.facts.identity import sha256_file
import pytest

def test_archive_scan_cache_preserves_limits_and_rechecks_mutated_bytes(tmp_path):
    a=tmp_path/'a.json';b=tmp_path/'b.json'
    a.write_text('{"artifact_path":"analysis/b.json"}',encoding='utf8');b.write_text('{"x":1}',encoding='utf8')
    files=[EvidenceFile(archive_entry='analysis/'+name+'.json',sha256=sha256_file(p),bytes=p.stat().st_size,path=p.name)
           for name,p in [('a',a),('b',b)]]
    calls=[];by_name={f.archive_entry:f for f in files}
    class View:
        manifest=SimpleNamespace(files=files)
        def collect_support(self,refs,limit):
            value={'records':[],'files':[files[0].model_dump(mode='json')],'truncated':False}
            return SimpleNamespace(to_dict=lambda:deepcopy(value))
        def read_evidence(self,path):
            calls.append(path);return read_evidence_file(tmp_path,by_name[path])
    view=View();cache={}
    expected=collect_archive(view,[],BUConfig())
    assert collect_archive(view,[],BUConfig(),dependency_cache=cache)==expected
    before=len(calls)
    assert collect_archive(view,[],BUConfig(),dependency_cache=cache)==expected
    assert len(calls)-before==2
    limited=collect_archive(view,[],BUConfig(max_support_files=1),dependency_cache=cache)
    assert limited['pending_files']==['analysis/b.json'] and limited['truncated']
    b.write_text('{"x":2}',encoding='utf8')
    changed=collect_archive(view,[],BUConfig(),dependency_cache=cache)
    assert not changed['file_closure_complete'] and changed['missing_files']

def test_checked_scope_reuses_bytes_and_rejects_changes_before_publication(tmp_path):
    from androserum.facts.store import FactView
    db=tmp_path/'facts.sqlite';db.write_bytes(b'protocol identity')
    (tmp_path/'manifest.json').write_text('{}')
    source=tmp_path/'source.json';source.write_text('{"x":1}')
    item=EvidenceFile(archive_entry='analysis/source.json',sha256=sha256_file(source),bytes=source.stat().st_size,path=source.name)
    class View:
        root=tmp_path
        manifest=SimpleNamespace(database_sha256=sha256_file(db))
        read_evidence=FactView.read_evidence
        checked_evidence_reads=FactView.checked_evidence_reads
        reads=0
        def _read_evidence_uncached(self,entry):
            self.reads+=1;return read_evidence_file(self.root,item)
    view=View()
    with view.checked_evidence_reads():
        assert view.read_evidence(item.archive_entry)==view.read_evidence(item.archive_entry)
        assert view.reads==1
    assert view.reads==2
    with pytest.raises(ValueError):
        with view.checked_evidence_reads():
            view.read_evidence(item.archive_entry)
            source.write_text('{"x":2}')
            view.read_evidence(item.archive_entry)
    assert view._checked_evidence_cache is None

def test_shared_queries_copy_success_and_keep_failures_local(monkeypatch):
    from androserum.facts.bu import _Unit
    from androserum.facts import control
    shared={};calls=[];issues=[]
    def unit():
        u=_Unit.__new__(_Unit);u.queries={};u.shared_queries=shared
        u.facts=object();u.view=SimpleNamespace(read_evidence=lambda _:b'')
        u.issue=lambda *args,**kwargs:issues.append((args,kwargs))
        return u
    def query(facts,read,refs):
        calls.append(refs[0])
        if refs[0]=='fault' and calls.count('fault')==1:raise OSError('one query failed')
        return {'operations':[{'operation_ref':refs[0],'conditions':[{'value':1}]}]}
    monkeypatch.setattr(control,'control_evidence',query)
    first=unit()._query('control','ok');first['conditions'][0]['value']=2
    assert unit()._query('control','ok')['conditions'][0]['value']==1
    assert calls.count('ok')==1
    failed=unit();assert failed._query('control','fault') is None
    assert failed._query('control','fault') is None and len(issues)==1
    assert unit()._query('control','fault')['operation_ref']=='fault'
    assert calls.count('fault')==2
