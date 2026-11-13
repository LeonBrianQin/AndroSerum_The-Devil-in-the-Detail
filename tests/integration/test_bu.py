"""BU algorithm acceptance on real compiled APKs and pinned SAPI resources."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from androserum.facts.bu import BUConfig, build_units, write_units, verify_units
from androserum.facts.events import extract_events
from androserum.facts.extractor import write_extraction
from androserum.facts.identity import filesystem_path, sha256_file
from androserum.facts.sapi import SapiImportConfig, import_catalog
from androserum.facts.store import FactView, import_snapshot

ROOT = Path(__file__).resolve().parents[2]
CASE = 'Lorg/androserum/bu/Cases;'


@pytest.fixture(scope='module')
def bu_actual(tmp_path_factory):
    subprocess.run([sys.executable, 'scripts/build_bu_fixture.py'], cwd=ROOT, capture_output=True, check=True)
    result = extract_events(ROOT/'artifacts/fixtures/bu/valid.apk')
    output = tmp_path_factory.mktemp('bu')
    snapshot = import_snapshot(write_extraction(result, output/'facts'), output/'stores')
    catalog = output/'sapi'
    import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')), catalog)
    return result, snapshot, catalog


def config_for(result, name, **options):
    signature = next(x.signature for x in result.facts.elements if getattr(x, 'is_definition', False) and
                     getattr(x, 'signature', '').startswith(CASE+'->'+name+'('))
    return BUConfig(root_signatures=[signature], **options)


def extract_case(actual, name, **options):
    result, snapshot, catalog = actual
    with FactView(snapshot) as view:
        return build_units(view, catalog, config_for(result, name, **options))


def calls(unit):
    return {x['declared_target']['signature'] for x in unit['model_visible']['records']
            if x.get('kind') == 'instruction' and x.get('declared_target') and x['declared_target']['signature']}


@pytest.fixture(scope='module')
def cases(bu_actual):
    return {name: extract_case(bu_actual, name) for name in
            ['twoCalls', 'twoObjects', 'shared', 'loop', 'recursive', 'unknown', 'onCreate', 'guarded']}


def test_automatic_actual_matches_keep_positions_and_full_call_contexts(cases):
    q = cases['twoCalls']; units = q['units']
    assert q['selection']['contextual_anchors'] == len(units) == 2
    assert len({x['anchor']['match_id'] for x in units}) == 1
    assert len({x['anchor']['projection_context_ref'] for x in units}) == 2
    assert len({json.dumps(x['anchor']['call_path'], sort_keys=True) for x in units}) == 2
    assert all(x['anchor']['routes'] and x['anchor']['catalog_entries'] and x['anchor']['result'] for x in units)
    # There are also different physical SAPI positions in the APK, not one
    # fabricated generic anchor or a sensitive-name search.
    assert cases['twoObjects']['units'][0]['anchor']['callsite_ref'] != units[0]['anchor']['callsite_ref']


def test_cross_method_returns_do_not_join_other_callers(cases):
    units = cases['twoCalls']['units']
    sets = [calls(x) for x in units]
    assert sum(CASE+'->sinkA(Ljava/lang/String;)V' in x for x in sets) == 1
    assert sum(CASE+'->sinkB(Ljava/lang/String;)V' in x for x in sets) == 1
    assert not any(CASE+'->sinkA(Ljava/lang/String;)V' in x and CASE+'->sinkB(Ljava/lang/String;)V' in x for x in sets)
    assert all(any(x['projection_role'] == 'return_binding' for x in u['operation_records']) for u in units)


def test_same_put_get_separates_two_objects_and_rejects_fixed_other_send(cases):
    unit = cases['twoObjects']['units'][0]; selected = calls(unit)
    assert CASE+'->sinkA(Ljava/lang/String;)V' in selected
    assert CASE+'->sinkB(Ljava/lang/String;)V' not in selected
    storage = [x for x in unit['relation_records'] if x['binding']['location_refs']]
    assert storage and all(x['binding']['object_refs'] for x in storage)
    assert len({o for x in storage for o in x['binding']['object_refs']}) == 1
    assert any(x['binding']['object_refs'] and x['binding']['location_refs'] for x in unit['tasks'])


def test_backward_shared_source_never_turns_into_other_consumer(cases):
    unit = cases['shared']['units'][0]; selected = calls(unit)
    assert 'Ljava/security/MessageDigest;->digest([B)[B' in selected
    assert CASE+'->consumeBytes([B)V' in selected
    assert CASE+'->unrelatedBytes([B)V' not in selected
    assert any(x['reason'] == 'recorded_source' and x['source']['kind'] == 'parameter' for x in unit['stops'])
    assert {t['direction'] for t in unit['tasks']} == {'source', 'use'}


def test_same_entry_unrelated_operation_is_not_collected(cases):
    units = cases['onCreate']['units']; assert units
    for unit in units:
        assert CASE+'->consume(Ljava/lang/String;)V' in calls(unit)
        assert CASE+'->unrelated()V' not in calls(unit)
        assert not any(x.get('signature') == CASE+'->unrelated()V' for x in unit['model_visible']['records'])
        assert any(x['conditions'] for x in unit['control_records'])
        assert any(x['background'] for x in unit['event_records'])


def test_every_selected_record_and_relation_has_inclusion_provenance(cases):
    for q in cases.values():
        for unit in q['units']:
            refs = {x['record_ref'] for x in unit['inclusion_refs']}
            assert set(unit['model_visible']['allowed_citation_refs']) <= refs
            assert {x['record_ref'] for x in unit['relation_records']} <= refs
            assert all(t['root_method_ref'] and 'binding' in t and 'context_ref' in t and 'call_path' in t for t in unit['tasks'])
            assert all(x['reason'] and x['purpose'] for x in unit['inclusion_refs'])


def test_loop_work_queue_deduplicates_and_terminates(cases):
    unit = cases['loop']['units'][0]
    assert unit['extraction_status']['queue_drained']
    assert unit['deduplicated_tasks']
    keys = [json.dumps({k:t[k] for k in ['endpoint', 'context_ref', 'root_method_ref', 'direction', 'binding']}, sort_keys=True) for t in unit['tasks']]
    assert len(keys) == len(set(keys))
    assert CASE+'->consume(Ljava/lang/String;)V' in calls(unit)


def test_existing_loop_collects_predicate_count_and_constants(cases):
    unit = cases['loop']['units'][0]
    groups = [x for x in unit['condition_sources'] if x['normalization'] == 'predicate_truth']
    assert groups and any(t['purpose'] == 'condition_source' for t in unit['tasks'])
    assert all(x['source_collection_state'] == 'collected' for x in groups)
    assert any(r['source']['kind'] == 'parameter' and r['source']['details'].get('parameter_index') == 1
               for x in groups for r in x['source_origins'])
    assert any(v['constant'] == 0 for x in groups for v in x['constant_operands'])
    assert any(r['source']['kind'] == 'constant' for x in groups for r in x['source_origins'])
    assert all(x['condition_recognized'] and x['traversed_relation_refs'] for x in groups)
    assert not any(i['code'] in {'condition_mapping', 'condition_input_adaptation'} for i in unit['issue_refs'])


def test_condition_recognition_and_source_budget_are_distinct(bu_actual, cases):
    complete = cases['loop']['units'][0]
    first_input = complete['condition_sources'][0]['inputs'][0]['task_ref']
    before_condition_source = next(i for i,t in enumerate(complete['tasks']) if t['task_id'] == first_input)
    assert before_condition_source > 0
    q = extract_case(bu_actual, 'loop', max_tasks=before_condition_source)
    unit = q['units'][0]
    assert unit['condition_sources']
    assert all(x['condition_recognized'] for x in unit['condition_sources'])
    assert any(x['source_collection_state'] == 'truncated' for x in unit['condition_sources'])


def test_recursion_does_not_merge_existing_bounded_frames(cases):
    units = cases['recursive']['units']; assert len(units) > 1
    assert len({x['anchor']['projection_context_ref'] for x in units}) == len(units)
    assert all(x['extraction_status']['queue_drained'] for x in units)
    assert any(i['state'] == 'truncated' and 'Depth budget' in i['reason'] for u in units for i in u['issue_refs'])


def test_opaque_call_does_not_fabricate_parameter_to_return_flow(cases):
    unit = cases['unknown']['units'][0]
    assert CASE+'->opaque(Ljava/lang/String;)Ljava/lang/String;' in calls(unit)
    assert CASE+'->consume(Ljava/lang/String;)V' not in calls(unit)
    assert any(x['code'] == 'opaque_call' for x in unit['issue_refs'])


@pytest.mark.parametrize('options,code', [({'max_tasks':1}, 'task_budget'), ({'max_operations':1}, 'operation_budget'),
    ({'max_support_records':1}, 'archive_budget'), ({'max_support_files':1}, 'archive_budget')])
def test_independent_budgets_report_pending_or_stopped_work(bu_actual, options, code):
    q = extract_case(bu_actual, 'twoObjects', **options); unit = q['units'][0]
    assert unit['extraction_status']['state'] == 'truncated'
    assert any(x['code'] == code for x in unit['issue_refs'])
    if code == 'task_budget':
        assert unit['extraction_status']['pending_task_refs'] and not unit['extraction_status']['queue_drained']
    assert not unit['extraction_status']['complete_behavior_claimed']


def test_anchor_budget_preserves_unprocessed_contexts(bu_actual):
    q = extract_case(bu_actual, 'twoCalls', max_units=1)
    assert len(q['units']) == 1 and q['summary']['anchor_budget_exhausted']
    assert len(q['selection']['pending_anchors']) == 1


def test_root_scan_budget_cannot_claim_all_contexts_were_searched(bu_actual):
    _, path, catalog = bu_actual
    with FactView(path) as view:
        q = build_units(view, catalog, BUConfig(max_roots=1))
    assert q['summary']['root_budget_exhausted'] and q['selection']['pending_roots']


def test_context_query_failure_keeps_actual_anchor_and_failure(bu_actual, monkeypatch):
    result, path, catalog = bu_actual
    with FactView(path) as view:
        monkeypatch.setattr(view, 'read_context_heap', lambda ref: (_ for _ in ()).throw(OSError('injected independent context IO failure')))
        q = build_units(view, catalog, config_for(result, 'twoObjects'))
    assert q['selection']['graph_failures']
    assert q['units'] and q['units'][0]['anchor']['routes']
    assert q['units'][0]['extraction_status']['state'] == 'failed'


def test_related_query_failure_is_preserved_and_other_branches_continue(bu_actual, monkeypatch):
    result, path, catalog = bu_actual
    with FactView(path) as view:
        from androserum.facts import control
        def failing_control(*args,**kwargs):raise OSError('injected control IO failure')
        monkeypatch.setattr(control, 'control_evidence', failing_control)
        q = build_units(view, catalog, config_for(result, 'twoObjects'))
    unit = q['units'][0]
    assert unit['extraction_status']['state'] == 'failed'
    assert unit['relation_records'] and CASE+'->sinkA(Ljava/lang/String;)V' in calls(unit)
    assert any(x['code'] == 'control_query' for x in unit['issue_refs'])


def test_archive_query_failure_does_not_erase_traced_records(bu_actual, monkeypatch):
    result, path, catalog = bu_actual
    with FactView(path) as view:
        monkeypatch.setattr(view, 'collect_support', lambda *args, **kwargs: (_ for _ in ()).throw(OSError('injected support IO failure')))
        q = build_units(view, catalog, config_for(result, 'twoObjects'))
    unit = q['units'][0]
    assert unit['extraction_status']['state'] == 'failed' and unit['archive_support']['failure']
    assert CASE+'->sinkA(Ljava/lang/String;)V' in calls(unit)
    assert unit['model_visible']['records']


def test_missing_mapping_has_no_guessed_context_and_keeps_anchor(bu_actual, monkeypatch):
    from androserum.facts.bu import _Graph
    original = _Graph.__init__
    def no_mapping(self, *args):
        original(self, *args); self.raw_for_origin.clear()
    monkeypatch.setattr(_Graph, '__init__', no_mapping)
    q = extract_case(bu_actual, 'twoObjects'); unit = q['units'][0]
    assert unit['anchor']['projection_context_ref'] is None and not unit['tasks']
    assert unit['extraction_status']['state'] == 'unavailable'


def test_actual_f1_only_snapshot_retains_not_started_capabilities(bu_actual, tmp_path):
    from androserum.facts.extractor import extract_apk
    _, _, catalog = bu_actual
    result = extract_apk(ROOT/'artifacts/fixtures/bu/valid.apk')
    path = import_snapshot(write_extraction(result, tmp_path/'facts'), tmp_path/'stores')
    with FactView(path) as view:
        q = build_units(view, catalog, config_for(result, 'twoObjects'))
    assert q['units'] and all(x['extraction_status']['state'] == 'unavailable' for x in q['units'])
    assert q['summary']['coverage']['data_flow'] == 'not_started'
    assert not any(x['tasks'] for x in q['units'])


def test_existing_recursive_projection_cutoff_is_reported_without_invented_steps(cases):
    assert all(any(i['code'] == 'context_scope_truncated' for i in u['issue_refs']) for u in cases['recursive']['units'])


def test_model_event_background_must_match_selected_concrete_call_suffix(cases):
    # read() is also reachable from Activity.onCreate through guarded(), but
    # the twoCalls() frames are different concrete callers.
    assert all(not row['background'] for u in cases['twoCalls']['units'] for row in u['event_records'])


def test_conditions_have_source_tasks_and_finite_scope(cases):
    unit = cases['onCreate']['units'][0]
    assert any(t['purpose'] == 'condition_source' and t['direction'] == 'source' for t in unit['tasks'])
    assert all(not c['combined_path_checked'] for c in unit['control_records'])
    assert all(x['extraction_status']['coverage']['control'] == 'partial' for x in cases['guarded']['units'])


def test_archive_support_and_future_model_input_have_separate_boundaries(cases):
    unit = cases['shared']['units'][0]
    visible = unit['model_visible']
    assert visible['raw_files'] == [] and not visible['all_archive_support_visible']
    assert unit['archive_support']['analysis_files']
    assert len(unit['archive_support']['records']) > len(visible['records'])
    assert CASE+'->unrelatedBytes([B)V' not in json.dumps(visible)


def test_package_replay_move_public_cli_and_source_read_only(bu_actual, tmp_path):
    result, snapshot, catalog = bu_actual
    before = {p.relative_to(snapshot).as_posix():sha256_file(p) for p in filesystem_path(snapshot).rglob('*') if p.is_file()}
    with FactView(snapshot) as view:
        package, q = write_units(view, catalog, tmp_path/'output', config_for(result, 'twoCalls'))
        assert verify_units(package, view)['valid']
    moved = filesystem_path(tmp_path/'moved'); shutil.copytree(package, moved)
    check = subprocess.run([sys.executable, '-m', 'androserum', 'bu-check', str(moved), '--snapshot', str(snapshot)], cwd=ROOT, capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    query = subprocess.run([sys.executable, '-m', 'androserum', 'bu-query', str(moved), '--snapshot', str(snapshot), '--bu-id', q['units'][0]['bu_id']],
                           cwd=ROOT, capture_output=True, text=True, encoding='utf-8')
    assert query.returncode == 0, query.stderr
    assert json.loads(query.stdout) == q['units'][0]['model_visible']
    assert all(sha256_file(filesystem_path(snapshot)/p) == d for p,d in before.items())


@pytest.mark.parametrize('damage', ['path', 'context', 'inclusion', 'visible', 'source', 'archive'])
def test_rehashed_forged_package_is_rejected_by_replay(bu_actual, tmp_path, damage):
    result, snapshot, catalog = bu_actual
    with FactView(snapshot) as view:
        package, q = write_units(view, catalog, tmp_path/'out', config_for(result, 'twoObjects'))
        unit = q['units'][0]
        if damage == 'path': unit['relation_records'][0]['traversal_source'] = unit['relation_records'][0]['traversal_target']
        elif damage == 'context': unit['anchor']['projection_context_ref'] = 'context:forged'
        elif damage == 'inclusion': unit['inclusion_refs'][0]['reason'] = 'invented'
        elif damage == 'visible': unit['model_visible']['raw_files'] = ['analysis/events/report.json']
        elif damage == 'source': q['source_run_ref'] = 'run:other'
        else:
            entry = 'archive/'+unit['archive_support']['analysis_files'][0]['archive_entry']
            (package/entry).write_bytes(b'forged audit evidence')
            manifest = json.loads((package/'manifest.json').read_text('utf-8'))
            manifest['files'][entry] = {'sha256':sha256_file(package/entry), 'bytes':len(b'forged audit evidence')}
            (package/'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            with pytest.raises(ValueError, match='archived fact evidence'):
                verify_units(package, view)
            return
        data = json.dumps(q).encode(); (package/'collection.json').write_bytes(data)
        manifest = json.loads((package/'manifest.json').read_text('utf-8'))
        manifest['files']['collection.json'] = {'sha256':sha256_file(package/'collection.json'), 'bytes':len(data)}
        (package/'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        with pytest.raises(ValueError, match='replay mismatch'):
            verify_units(package, view)
