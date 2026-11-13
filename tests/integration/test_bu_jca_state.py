"""Compiled JCA result evidence must enter its BU without consumer expansion."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from androserum.facts.bu import BUConfig, build_units
from androserum.facts.context_heap import extract_context_heap
from androserum.facts.extractor import write_extraction
from androserum.facts.jca_state import extend_jca_state
from androserum.facts.sapi import SapiImportConfig, import_catalog
from androserum.facts.store import FactView, import_snapshot

ROOT = Path(__file__).resolve().parents[2]
OWNER = 'Lorg/androserum/bujca/Cases;'
DIGEST = 'Ljava/security/MessageDigest;->digest()[B'


@pytest.fixture(scope='module')
def actual(tmp_path_factory):
    subprocess.run([sys.executable, 'scripts/build_bu_jca_fixture.py'], cwd=ROOT, check=True, capture_output=True)
    result = extend_jca_state(extract_context_heap(ROOT/'artifacts/fixtures/bu-jca-state/valid.apk'))
    output = tmp_path_factory.mktemp('bu-jca-state')
    snapshot = import_snapshot(write_extraction(result, output/'facts'), output/'stores')
    catalog = output/'sapi'
    import_catalog(SapiImportConfig.model_validate_json((ROOT/'configs/sapi-expanded.example.json').read_text('utf-8')), catalog)
    with FactView(snapshot) as view:
        units = build_units(view, catalog)
        report = json.loads(view.read_evidence('analysis/jca-state/report.json'))
    methods = {e.id:e.signature for e in result.facts.elements if e.kind=='method'}
    # Preserve the exact actual graph and queue receipt for independent review.
    (output/'bu-collection.json').write_text(json.dumps(units, indent=2)+'\n', encoding='utf-8')
    (output/'jca-report.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return result, units, report, methods


def selected(actual, method):
    _, collection, _, methods = actual
    return [u for u in collection['units'] if methods[u['anchor']['root_method_ref']].startswith(OWNER+'->'+method+'(')
            and any(r['signature']==DIGEST for r in u['anchor']['routes'])]


def calls(unit):
    return {r['declared_target']['signature'] for r in unit['model_visible']['records']
            if r.get('kind')=='instruction' and r.get('declared_target')}


@pytest.mark.parametrize('method', ['adjacentIndependent', 'sharedInput'])
def test_exact_anchor_result_receives_all_three_conditional_state_edges(actual, method):
    _, _, report, _ = actual
    units = selected(actual, method)
    assert len(units)==2
    effects = {e['consumer_projection_ref']:e for e in report['effects'] if e['root_ref']==units[0]['anchor']['root_method_ref']}
    object_sets=[]
    for unit in units:
        anchor = next(o for o in unit['operation_records'] if unit['anchor']['callsite_ref'] in o['raw_operation_refs'])
        effect = effects[anchor['operation_ref']]
        refs=set(effect['relation_refs'])
        assert len(refs)==3
        assert refs <= {r['record_ref'] for r in unit['relation_records']}
        assert refs <= set(unit['model_visible']['allowed_citation_refs'])
        assert refs <= {r.get('id') for r in unit['archive_support']['records']}
        tasks=[t for t in unit['tasks'] if t['reason']=='anchor_result_recorded_state']
        assert tasks and all(t['direction']=='source' and t['purpose']=='anchor_result' for t in tasks)
        assert all(t['binding']['object_refs']==[effect['object_ref']] and t['binding']['state_refs']==[effect['effect_ref']] for t in tasks)
        assert all(t['endpoint']['element_ref']==anchor['operation_ref'] and t['endpoint']['slot_kind']=='result' for t in tasks)
        assert any(r['source']['kind']=='parameter' for r in unit['stops'] if r['reason']=='recorded_source')
        model = unit['model_visible']['model_conditions']
        assert model and all(c['scope']=='model_relation_precondition_not_execution_guard' for c in model)
        assert unit['extraction_status']['queue_drained']
        object_sets.append({o for r in unit['relation_records'] for o in r['binding']['object_refs']})
    assert object_sets[0].isdisjoint(object_sets[1])


@pytest.mark.parametrize('method', ['adjacentIndependent', 'sharedInput'])
def test_adjacent_or_shared_input_bu_never_collects_other_consumer(actual, method):
    units=selected(actual, method)
    assert len(units)==2
    selected_calls=[calls(u) for u in units]
    assert sum(OWNER+'->consumeA([B)V' in c for c in selected_calls)==1
    assert sum(OWNER+'->consumeB([B)V' in c for c in selected_calls)==1
    assert not any(OWNER+'->consumeA([B)V' in c and OWNER+'->consumeB([B)V' in c for c in selected_calls)
    for unit in units:
        assert len([o for o in unit['operation_records'] if o.get('operation')=='invoke' and
                    any(r.get('id') in o['raw_operation_refs'] and r.get('declared_target',{}).get('signature')==DIGEST
                        for r in unit['model_visible']['records'] if r.get('kind')=='instruction')])==1


def test_later_consumer_of_same_state_is_not_followed_back_outward(actual):
    units=selected(actual,'sameStateLater')
    assert len(units)==2
    adapted=[u for u in units if any(t['reason']=='anchor_result_recorded_state' for t in u['tasks'])]
    assert len(adapted)==1
    assert OWNER+'->consumeA([B)V' in calls(adapted[0])
    assert OWNER+'->consumeB([B)V' not in calls(adapted[0])
    other=next(u for u in units if u is not adapted[0])
    assert not any(r['modeled'] for r in other['relation_records'])


def test_non_result_anchor_inputs_do_not_receive_finalization_source_tasks(actual):
    _, collection, _, _=actual
    others=[u for u in collection['units'] if not any(r['signature']==DIGEST for r in u['anchor']['routes'])]
    assert others
    assert all(not any(t['reason']=='anchor_result_recorded_state' for t in u['tasks']) for u in others)
