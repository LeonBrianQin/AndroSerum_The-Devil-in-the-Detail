"""Actual F6 predicate inputs and FlowDroid summaries must reach BU evidence."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from androserum.facts.bu import BUConfig, build_units
from androserum.facts.control import extract_control
from androserum.facts.events import extend_events
from androserum.facts.extractor import write_extraction
from androserum.facts.identity import filesystem_path
from androserum.facts.sapi import SapiImportConfig, import_catalog
from androserum.facts.selected_flow import FlowConfig
from androserum.facts.store import FactView, import_snapshot

ROOT = Path(__file__).resolve().parents[2]
CASE = 'Lorg/androserum/buadapter/Cases;'
SOURCE = 'Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;'


@pytest.fixture(scope='module')
def adapter_actual(tmp_path_factory):
    subprocess.run([sys.executable, 'scripts/build_bu_adapter_fixture.py'], cwd=ROOT, check=True, capture_output=True)
    apk = ROOT/'artifacts/fixtures/bu-adapter/valid.apk'
    flow_config = FlowConfig.model_validate_json((ROOT/'configs/bu-adapter-flow.example.json').read_text('utf-8'))
    result = extend_events(extract_control(apk, flow_config=flow_config))
    out = tmp_path_factory.mktemp('bu-adapters')
    path = import_snapshot(write_extraction(result, out/'facts'), out/'stores')
    catalog_path = out/'sapi'
    import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')), catalog_path)
    with FactView(path) as view:
        q = build_units(view, catalog_path)
        provider = json.loads(view.read_evidence('analysis/selected-flow/report.json'))
    return result, path, catalog_path, q, provider


def units(actual, name):
    facts, _, _, q, _ = actual
    refs = {x.id for x in facts.facts.elements if getattr(x, 'is_definition', False) and x.signature.startswith(CASE+'->'+name+'(')}
    return [x for x in q['units'] if x['anchor']['root_method_ref'] in refs]


def calls(unit):
    return {x['declared_target']['signature'] for x in unit['model_visible']['records']
            if x.get('kind') == 'instruction' and x.get('declared_target')}


def roots(group):
    return {x['source']['details'].get('parameter_index') for x in group['source_origins'] if x['source']['kind'] == 'parameter'}


def test_nonboolean_positive_condition_uses_f6_inputs(adapter_actual):
    selected = units(adapter_actual, 'ifPositive'); assert selected
    groups = [g for u in selected for g in u['condition_sources'] if g['normalization'] == 'predicate_truth']
    assert groups and all(g['source_collection_state'] == 'collected' for g in groups)
    assert any(1 in roots(g) for g in groups)
    assert any(c['constant'] == 0 for g in groups for c in g['constant_operands'])
    assert all(i['predicate_input_relation_ref'] and i['task_ref'] for g in groups for i in g['inputs'])
    assert not any(i['code'] == 'condition_mapping' for u in selected for i in u['issue_refs'])


def test_two_operand_predicate_collects_both_parameter_origins(adapter_actual):
    selected = units(adapter_actual, 'compare'); assert selected
    groups = [g for u in selected for g in u['condition_sources'] if g['normalization'] == 'predicate_truth']
    assert groups and all(len(g['inputs']) == 2 and roots(g) == {1,2} for g in groups)
    assert all(g['condition_recognized'] and g['source_collection_state'] == 'collected' for g in groups)


def test_predicate_sources_use_each_concrete_call_frame(adapter_actual):
    selected = units(adapter_actual, 'compareTwice'); assert len(selected) == 2
    source_sets = []
    for u in selected:
        groups = [g for g in u['condition_sources'] if g['normalization'] == 'predicate_truth']
        assert groups and all(g['source_collection_state'] == 'collected' for g in groups)
        source_sets.append(set.union(*(roots(g) for g in groups)))
    assert {frozenset(x) for x in source_sets} == {frozenset({1,2}),frozenset({3,4})}


def test_actual_flowdroid_run_supplies_summary_relations(adapter_actual):
    result, _, _, _, provider = adapter_actual
    assert provider['state'] == 'complete' and provider['mapped']
    edges = [e for e in result.facts.relations if e.relation_kind == 'information_flow']
    assert edges and all(e.source_selector and e.provenance.rule_ref for e in edges)


def test_flow_summary_bridges_supported_coarse_gap_and_is_visible(adapter_actual):
    selected = units(adapter_actual, 'virtualFlow'); assert len(selected) == 1
    u = selected[0]
    assert CASE+'->flowSink(Ljava/lang/String;)V' in calls(u)
    summaries = [e for e in u['relation_records'] if e.get('evidence_role') == 'information_flow_summary']
    assert summaries and any(t['via_relation_ref'] in {e['record_ref'] for e in summaries} and t['direction'] == 'use' for t in u['tasks'])
    visible = {x['id'] for x in u['model_visible']['records'] if x.get('relation_kind') == 'information_flow'}
    archived = {x['id'] for x in u['archive_support']['records'] if x.get('relation_kind') == 'information_flow'}
    assert {e['record_ref'] for e in summaries} <= visible & archived
    assert all(not e['fine_grained_path_claimed'] and e['flow_summary']['evidence_role'] == 'information_flow_summary' for e in summaries)
    assert u['model_visible']['information_flow_evidence']
    assert any(i['code'] == 'opaque_call' for i in u['issue_refs'])


def test_fixed_string_negative_does_not_receive_an_information_flow(adapter_actual):
    selected = units(adapter_actual, 'negative'); assert selected
    assert all(CASE+'->flowSink(Ljava/lang/String;)V' not in calls(u) for u in selected)
    assert all(not u['model_visible']['information_flow_evidence'] for u in selected)
    records = {x.id:x for x in adapter_actual[0].facts.elements}
    method_refs = {x.id for x in records.values() if getattr(x,'is_definition',False) and x.signature.startswith(CASE+'->negative(')}
    assert not any(records[e.source.element_ref].position.method_ref in method_refs
                   for e in adapter_actual[0].facts.relations if e.relation_kind == 'information_flow')


def test_flow_summary_is_used_backwards_for_sensitive_input(adapter_actual):
    u = next(u for u in units(adapter_actual, 'reverseSummary') if any(
        r['signature'].startswith('Ljava/security/MessageDigest;->getInstance(') for r in u['anchor']['routes']))
    refs = {e['record_ref'] for e in u['relation_records'] if e.get('evidence_role') == 'information_flow_summary'}
    assert refs and any(t['via_relation_ref'] in refs and t['direction'] == 'source' for t in u['tasks'])
    assert SOURCE in calls(u)
    assert CASE+'->originalSink(Ljava/lang/String;)V' not in calls(u)
    assert all(not e['fine_grained_path_claimed'] for e in u['model_visible']['information_flow_evidence'])


def test_shared_source_found_backwards_does_not_expand_flow_consumers(adapter_actual):
    selected = units(adapter_actual, 'sharedSource')
    u = next(u for u in selected if any(r['signature'].startswith('Ljava/security/MessageDigest;->getInstance(') for r in u['anchor']['routes']))
    assert CASE+'->unrelatedSink(Ljava/lang/String;)V' not in calls(u)
    skipped = [x for x in u['information_flow_adaptations'] if x['reason_code'] == 'source_reached_only_backwards_no_consumer_expansion']
    assert skipped and all(x['archive_selected'] and not x['model_visible'] for x in skipped)
    assert {x['relation_ref'] for x in skipped} <= {x.get('id') for x in u['archive_support']['records']}


def test_repeated_calls_do_not_inherit_unbound_provider_flow_context(adapter_actual):
    selected = units(adapter_actual, 'twice'); assert len(selected) == 2
    for u in selected:
        assert CASE+'->flowSink(Ljava/lang/String;)V' not in calls(u)
        skipped = [x for x in u['information_flow_adaptations'] if x['state'] == 'not_adapted']
        assert any(x['reason_code'] == 'repeated_or_recursive_method_frames' for x in skipped)
        assert not u['model_visible']['information_flow_evidence']
        assert all(not x['model_visible'] for x in skipped)


def test_recursive_flow_context_is_refused_with_specific_reason(adapter_actual):
    selected = units(adapter_actual, 'recursiveFlow'); assert len(selected) > 1
    assert all(any(x['reason_code'] == 'repeated_or_recursive_method_frames' for x in u['information_flow_adaptations']) for u in selected)
    assert all(not u['model_visible']['information_flow_evidence'] for u in selected)


def test_cross_method_summary_is_archived_without_guessing_call_pair(adapter_actual):
    selected = units(adapter_actual, 'crossMethod'); assert selected
    assert all(any(x['reason_code'] == 'cross_method_flow_context_not_recorded' and x['archive_selected'] for x in u['information_flow_adaptations']) for u in selected)
    assert all(not u['model_visible']['information_flow_evidence'] for u in selected)


def test_each_existing_flow_has_per_bu_admission_or_reason(adapter_actual):
    result, _, _, q, _ = adapter_actual
    expected = {e.id for e in result.facts.relations if e.relation_kind == 'information_flow'}
    for u in q['units']:
        assert {x['relation_ref'] for x in u['information_flow_adaptations']} == expected
        assert all(x['reason_code'] or x['state'] == 'included_summary' for x in u['information_flow_adaptations'])
        assert not u['model_visible']['raw_files']
        assert CASE+'->unrelated()V' not in calls(u)


def test_flow_provider_io_failure_preserves_independent_fine_evidence(adapter_actual, monkeypatch):
    result, path, catalog, _, _ = adapter_actual
    signature = next(x.signature for x in result.facts.elements if getattr(x,'is_definition',False) and x.signature.startswith(CASE+'->virtualFlow('))
    with FactView(path) as view:
        verified = view.verify(); original = view.read_evidence
        monkeypatch.setattr(view, 'verify', lambda: verified)
        def unavailable(entry):
            if entry == 'analysis/selected-flow/report.json':
                raise OSError('injected transport failure after snapshot verification')
            return original(entry)
        monkeypatch.setattr(view, 'read_evidence', unavailable)
        q = build_units(view, catalog, BUConfig(root_signatures=[signature]))
    u = q['units'][0]
    assert u['extraction_status']['state'] == 'failed'
    assert CASE+'->originalSink(Ljava/lang/String;)V' in calls(u)
    assert any(x['reason_code'] == 'flow_provider_read_failed' for x in u['information_flow_adaptations'])
    assert not u['model_visible']['information_flow_evidence']


@pytest.mark.parametrize('damage', ['fine_path_claim', 'predicate_input'])
def test_adapter_evidence_cannot_be_forged_by_rehashing(adapter_actual, tmp_path, damage):
    from androserum.facts.bu import write_units, verify_units
    from androserum.facts.identity import sha256_file
    result, snapshot, catalog, _, _ = adapter_actual
    name = 'virtualFlow' if damage == 'fine_path_claim' else 'compare'
    signature = next(x.signature for x in result.facts.elements if getattr(x,'is_definition',False) and x.signature.startswith(CASE+'->'+name+'('))
    with FactView(snapshot) as view:
        package, q = write_units(view, catalog, tmp_path/'out', BUConfig(root_signatures=[signature]))
        u = q['units'][0]
        if damage == 'fine_path_claim':
            u['model_visible']['information_flow_evidence'][0]['fine_grained_path_claimed'] = True
        else:
            u['condition_sources'][0]['inputs'][0]['projected_endpoint']['element_ref'] = 'analysis:wrong-predicate-input'
        (package/'collection.json').write_text(json.dumps(q), encoding='utf-8')
        manifest = json.loads((package/'manifest.json').read_text('utf-8'))
        manifest['files']['collection.json'] = {'sha256':sha256_file(package/'collection.json'), 'bytes':(package/'collection.json').stat().st_size}
        (package/'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        with pytest.raises(ValueError, match='replay mismatch'):
            verify_units(package, view)


def test_quantity_table_has_physical_root_path_and_recursion_correspondence(adapter_actual):
    q = adapter_actual[3]; rows = q['anchor_context_table']
    assert len(rows) == len(q['units'])
    assert all(x['physical_anchor_ref'] and x['method_signature'] and x['root_signature'] for x in rows)
    assert all(x['call_depth'] == len(x['call_path']) and not x['is_independent_behavior'] for x in rows)
    recursive = [x for x in rows if '->recursiveFlow(' in x['root_signature']]
    assert {x['recursion_expansion_level'] for x in recursive} == set(range(5))
