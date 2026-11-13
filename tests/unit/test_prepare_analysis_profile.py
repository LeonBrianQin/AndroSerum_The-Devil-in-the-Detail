"""Explicit preparation profiles bind new runs while legacy resumes stay intact."""
from copy import deepcopy
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

import pytest

from androserum.facts.identity import fingerprint, sha256_file
from androserum.facts.selected_flow import FlowConfig, MethodFlowConfig
from androserum.pipeline.config import PipelineConfig
from androserum.pipeline import prepare, runner

ROOT = Path(__file__).resolve().parents[2]
OWNER = 'Lorg/androserum/profile/Cases;'


@pytest.fixture
def stub_pipeline(tmp_path, monkeypatch):
    apk = tmp_path/'compiled-input.apk'; apk.write_bytes(b'bounded preparation interface input')
    calls = []; state = {'roots': True, 'catalog_id': 'catalog:first'}
    facts = SimpleNamespace(elements=[SimpleNamespace(id='method:one', signature=OWNER+'->run()V')],
                            statuses=[], relations=[], run=SimpleNamespace(run_id='run:profile'))
    result = SimpleNamespace(facts=facts, summary={'outcome': 'partial'})
    def heap(*args, **kwargs): calls.append('heap'); return result
    monkeypatch.setattr(prepare, 'extract_heap', heap)
    monkeypatch.setattr(prepare, 'load_catalog', lambda _: {'catalog_id': state['catalog_id']})
    monkeypatch.setattr(prepare, 'match_sapi', lambda *args: {'matches': [
        {'method_ref': 'method:one', 'callsite_ref': 'instruction:one'}] if state['roots'] else []})
    def extension(name):
        def apply(value, *args):
            calls.append(name)
            if name == 'flow': state['flow'] = args[1]
            return value
        return apply
    for attr, name in [('extend_context_heap', 'context'), ('extend_selected_flow', 'flow'),
                       ('extend_operations', 'operations'), ('extend_control', 'control'),
                       ('extend_events', 'events'), ('extend_method_outputs', 'method_outputs'),
                       ('extend_jca_state', 'jca')]:
        monkeypatch.setattr(prepare, attr, extension(name))
    monkeypatch.setattr(prepare, 'write_encoded_extraction', lambda *args, **kwargs: 'extraction')
    monkeypatch.setattr(prepare, 'import_snapshot', lambda *args: tmp_path/'snapshot')
    class View:
        def __init__(self, *_): pass
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def export_bundle(self): return facts
    monkeypatch.setattr(prepare, 'FactView', View)
    monkeypatch.setattr(prepare, 'write_units', lambda *args: (tmp_path/'bu-package', {'units': [{'bu_id': 'bu:one'}]}))
    return apk, calls, state


def method_flow():
    return MethodFlowConfig(entry_methods=[OWNER+'->run()V'],
                            sources=[OWNER+'->source()Ljava/lang/String;'],
                            sinks=[OWNER+'->sink(Ljava/lang/String;)V'])


def test_default_stages_and_cached_json_remain_legacy(stub_pipeline, tmp_path):
    apk, calls, state = stub_pipeline; out = tmp_path/'old-default'
    result = prepare.prepare_apk(apk, out, 'catalog')
    assert calls == ['heap', 'context', 'flow', 'operations', 'control', 'events']
    assert 'analysis_profile' not in result and not (out/'preparation-identity.json').exists()
    assert state['flow'].model_dump(mode='json') == prepare._default_flow().model_dump(mode='json')
    original = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    calls.clear()
    assert prepare.prepare_apk(apk, out, 'unused-legacy-catalog') == result
    assert not calls and original == {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    with pytest.raises(ValueError, match='Legacy preparation'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1')
    with pytest.raises(ValueError, match='Legacy preparation'):
        prepare.prepare_apk(apk, out, 'catalog', flow_config=state['flow'])


@pytest.mark.parametrize('flow', [None, FlowConfig(), method_flow()])
def test_bounded_orders_extensions_and_binds_effective_v1_or_v2(stub_pipeline, tmp_path, flow):
    apk, calls, state = stub_pipeline; out = tmp_path/'bounded'
    raw = flow.model_dump(mode='json') if flow else None
    result = prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1', flow_config=raw)
    assert calls == ['heap', 'context', 'flow', 'operations', 'control', 'events', 'method_outputs', 'jca']
    assert result['analysis_profile'] == 'bounded.v1' and result['bounded_extensions_started']
    identity = json.loads((out/'preparation-identity.json').read_text('utf-8'))
    assert identity['analysis_profile'] == 'bounded.v1' and identity['sapi_catalog_id'] == 'catalog:first'
    assert identity['selected_flow_config'] == state['flow'].model_dump(mode='json')
    assert identity['apk_sha256'] == sha256_file(apk)
    assert result['preparation_identity_sha256'] == fingerprint(identity)
    calls.clear()
    assert prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1', flow_config=state['flow']) == result
    assert not calls
    with pytest.raises(ValueError, match='profile/flow/catalog'):
        prepare.prepare_apk(apk, out, 'catalog')
    changed = deepcopy(identity['selected_flow_config']); changed['solver_timeout'] += 1
    with pytest.raises(ValueError, match='profile/flow/catalog'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1', flow_config=changed)
    state['catalog_id'] = 'catalog:other'
    with pytest.raises(ValueError, match='profile/flow/catalog'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1', flow_config=raw)


def test_explicit_flow_without_extensions_is_also_bound(stub_pipeline, tmp_path):
    apk, calls, _ = stub_pipeline; out = tmp_path/'explicit-flow'
    result = prepare.prepare_apk(apk, out, 'catalog', flow_config=method_flow())
    assert 'method_outputs' not in calls and 'jca' not in calls
    assert result['analysis_profile'] is None and not result['bounded_extensions_started']
    with pytest.raises(ValueError, match='profile/flow/catalog'):
        prepare.prepare_apk(apk, out, 'catalog')


def test_interrupted_bound_preparation_cannot_switch_profile_or_flow(stub_pipeline, tmp_path, monkeypatch):
    apk, calls, _ = stub_pipeline; out = tmp_path/'interrupted'
    def fail(*args, **kwargs): raise RuntimeError('bounded extraction failed')
    monkeypatch.setattr(prepare, 'extract_heap', fail)
    with pytest.raises(RuntimeError, match='extraction failed'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1', flow_config=method_flow())
    assert (out/'preparation-identity.json').exists() and not (out/'prepared.json').exists()
    with pytest.raises(ValueError, match='profile/flow/catalog'):
        prepare.prepare_apk(apk, out, 'catalog')
    with pytest.raises(ValueError, match='profile/flow/catalog'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1')
    with pytest.raises(RuntimeError, match='extraction failed'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1', flow_config=method_flow())


def test_incomplete_legacy_directory_cannot_be_relabelled(stub_pipeline, tmp_path):
    apk, _, _ = stub_pipeline; out = tmp_path/'legacy-interrupted'; out.mkdir()
    (out/'input.apk').write_bytes(apk.read_bytes())
    with pytest.raises(ValueError, match='no bound profile/flow'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1')
    assert not (out/'preparation-identity.json').exists()


def test_bound_receipt_loss_or_tampered_prepared_cannot_fall_back(stub_pipeline, tmp_path):
    apk, _, _ = stub_pipeline; out = tmp_path/'bound'
    prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1')
    bound = (out/'preparation-identity.json').read_bytes()
    (out/'preparation-identity.json').unlink()
    with pytest.raises(ValueError, match='identity is missing'):
        prepare.prepare_apk(apk, out, 'catalog')
    missing_hash = json.loads((out/'prepared.json').read_text('utf-8'))
    original_prepared = deepcopy(missing_hash)
    missing_hash.pop('preparation_identity_sha256')
    (out/'prepared.json').write_text(json.dumps(missing_hash), encoding='utf-8')
    with pytest.raises(ValueError, match='identity is missing'):
        prepare.prepare_apk(apk, out, 'catalog')
    (out/'prepared.json').write_text(json.dumps(original_prepared), encoding='utf-8')
    (out/'preparation-identity.json').write_bytes(bound)
    result = json.loads((out/'prepared.json').read_text('utf-8')); result['selected_flow_config']['solver_timeout'] += 1
    (out/'prepared.json').write_text(json.dumps(result), encoding='utf-8')
    with pytest.raises(ValueError, match='differs from its bound'):
        prepare.prepare_apk(apk, out, 'catalog', analysis_profile='bounded.v1')


def test_no_sapi_root_does_not_expand_explicit_flow_or_extensions(stub_pipeline, tmp_path):
    apk, calls, state = stub_pipeline; state['roots'] = False
    result = prepare.prepare_apk(apk, tmp_path/'no-root', 'catalog', analysis_profile='bounded.v1', flow_config=method_flow())
    assert calls == ['heap'] and not result['selected_flow_started'] and not result['bounded_extensions_started']
    assert not result['selected_bu_ids'] and result['bu_package'] is None


def test_unknown_profile_or_flow_schema_is_rejected(stub_pipeline, tmp_path):
    apk, calls, _ = stub_pipeline
    with pytest.raises(ValueError, match='Unknown preparation'):
        prepare.prepare_apk(apk, tmp_path/'unknown', 'catalog', analysis_profile='all-dynamic')
    with pytest.raises(ValueError):
        prepare.prepare_apk(apk, tmp_path/'bad-flow', 'catalog', flow_config={'schema_version':'selected-method-flow-config.v99'})
    assert not calls


def test_runner_forwards_options_only_into_fresh_prepare(tmp_path, monkeypatch):
    captured = {}
    def stub(*args, **kwargs): captured.update(kwargs); return {'source': 'stub'}
    monkeypatch.setattr(runner, 'prepare_apk', stub)
    monkeypatch.setattr(runner, 'mine_prepared', lambda *args: {'actual_llm_calls':0})
    result = runner.run_apk('new.apk', tmp_path, 'new-sample', 'catalog', analysis_profile='bounded.v1', flow_config=method_flow(),
                            admission='explicit_semantic_review')
    assert result['status'] == 'pending_explicit_semantic_review'
    assert captured == {'analysis_profile':'bounded.v1','flow_config':method_flow()}
    for options in [{'analysis_profile':'bounded.v1'}, {'flow_config':method_flow()}]:
        with pytest.raises(ValueError, match='existing freeze'):
            runner.run_apk('new.apk', tmp_path, 'new-sample', freeze='frozen', **options)


def test_default_freeze_consumes_existing_bounded_source_without_preparing(tmp_path, monkeypatch):
    apk = tmp_path/'new.apk'; apk.write_bytes(b'existing reviewed bounded source')
    out = tmp_path/'round/samples/new'; out.mkdir(parents=True)
    (out/'prepared.json').write_text(json.dumps({'apk_sha256':sha256_file(apk),'analysis_profile':'bounded.v1'}), encoding='utf-8')
    monkeypatch.setattr(runner, 'prepare_apk', lambda *args, **kwargs: pytest.fail('freeze must not prepare again'))
    monkeypatch.setattr(runner, 'mine_prepared', lambda *args: pytest.fail('freeze must not mine again'))
    monkeypatch.setattr(runner, 'load_frozen', lambda _: ({'role':'query'}, []))
    from androserum.pipeline import analyze
    monkeypatch.setattr(analyze, 'analyze_apk', lambda *args: {'stage':'existing-freeze-analysis'})
    assert runner.run_apk(apk, tmp_path/'round', 'new', freeze='existing', history='history') == {'stage':'existing-freeze-analysis'}


def test_fresh_default_uses_program_checked_freeze_without_semantic_review(tmp_path,monkeypatch):
    called=[]
    monkeypatch.setattr(runner,'prepare_apk',lambda *a,**k:{'source':'fresh'})
    monkeypatch.setattr(runner,'mine_prepared',lambda *a,**k:{'actual_llm_calls':0})
    monkeypatch.setattr(runner,'freeze_mined',lambda *a,**k:pytest.fail('Default must not require a manual BC review'))
    def automatic(*args,**kwargs):called.append(args);return 'automatic-query-freeze'
    monkeypatch.setattr(runner,'freeze_automined',automatic)
    monkeypatch.setattr(runner,'load_frozen',lambda p:({'role':'query'},[]))
    from androserum.pipeline import analyze
    monkeypatch.setattr(analyze,'analyze_apk',lambda *a,**k:{'stage':'automatic-mainline'})
    assert runner.run_apk('fresh.apk',tmp_path,'new','catalog',history='history')=={'stage':'automatic-mainline'}
    assert len(called)==1


@pytest.mark.parametrize('script', ['prepare_pipeline_apk.py', 'run_apk_pipeline.py'])
def test_both_cli_entries_forward_explicit_profile_and_flow(script, tmp_path, monkeypatch, capsys):
    flow_file = tmp_path/'flow.json'; flow_file.write_text(method_flow().model_dump_json(), encoding='utf-8')
    received = {}
    def stub(*args, **kwargs): received.update(kwargs); return {'actual_model_calls':0}
    if script.startswith('prepare'):
        monkeypatch.setattr(prepare, 'prepare_apk', stub)
        args = ['--apk','new.apk','--output',str(tmp_path/'out'),'--sapi','catalog']
    else:
        monkeypatch.setattr(runner, 'run_apk', stub)
        args = ['--apk','new.apk','--root',str(tmp_path/'round'),'--sample','new','--sapi','catalog']
    monkeypatch.setattr(sys, 'argv', [script,*args,'--analysis-profile','bounded.v1','--flow-config',str(flow_file)])
    runpy.run_path(str(ROOT/'scripts'/script), run_name='__main__')
    assert received['analysis_profile'] == 'bounded.v1' and received['flow_config'] == method_flow().model_dump(mode='json')
    assert json.loads(capsys.readouterr().out)['actual_model_calls'] == 0


@pytest.mark.parametrize('freeze_flag', ['--freeze', '--freeze-only'])
def test_run_cli_refuses_prepare_flags_on_freeze_branches(freeze_flag, tmp_path, monkeypatch):
    args = ['--root',str(tmp_path),'--sample','new','--analysis-profile','bounded.v1']
    args += ['--freeze','frozen','--apk','new.apk'] if freeze_flag == '--freeze' else ['--freeze-only','--review','review.json']
    monkeypatch.setattr(sys, 'argv', ['run_apk_pipeline.py',*args])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(ROOT/'scripts/run_apk_pipeline.py'), run_name='__main__')
    assert exc.value.code == 2
