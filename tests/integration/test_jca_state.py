"""Compiled JCA calls: state/identity/order and explicit failure counterexamples."""
from copy import deepcopy
from pathlib import Path
import json,subprocess,sys
import pytest
from androserum.facts.context_heap import extract_context_heap
from androserum.facts.jca_state import (ENTRY,TOOL,JCAConfig,analyze_jca,extend_jca_state,verify_jca_state)

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def actual():
    subprocess.run([sys.executable,'scripts/build_jca_fixture.py'],cwd=ROOT,check=True,capture_output=True)
    result=extend_jca_state(extract_context_heap(ROOT/'artifacts/fixtures/jca-state/valid.apk'))
    report=json.loads(result.blobs[result.entry_digests[ENTRY]])
    methods={e.id:e.signature for e in result.facts.elements if e.kind=='method'}
    return result,report,methods


def rows(actual,name):
    result,report,methods=actual
    return [row for row in report['decisions'] if '->'+name+'(' in methods[row['root_ref']]]


@pytest.mark.parametrize('name',['digest','encrypt','decrypt'])
def test_ordered_unique_object_pair_is_only_conditionally_connected(actual,name):
    decisions=rows(actual,name)
    assert len(decisions)==1 and decisions[0]['state']=='included_conditional'
    result,report,_=actual;effect=next(e for e in report['effects'] if e['effect_ref']==decisions[0]['effect_ref'])
    assert effect['success_proven'] is False and effect['fine_grained_byte_path'] is False
    edges=[r for r in result.facts.relations if r.id in effect['relation_refs']]
    assert len(edges)==3
    assert all(r.provenance.kind=='model_assisted' and r.resolution=='partial' and r.condition_refs and r.binding_refs for r in edges)
    if name!='digest':assert effect['cipher_mode']==(1 if name=='encrypt' else 2)


@pytest.mark.parametrize('name,reason',[
    ('different','different_factory_object'),('differentCipher','different_factory_object'),
    ('reversed','intervening_object_state_call'),('reset','intervening_object_state_call'),
    ('failed','nonlinear_or_missing_normal_corridor'),('failedInit','nonlinear_or_missing_normal_corridor'),
    ('invalidMode','cipher_mode_outside_encrypt_decrypt_scope'),('repeated','factory_identity_unknown_or_ambiguous'),
    ('nullUpdate','known_null_writer_input'),('nullKey','known_null_writer_input'),
    ('wrongFactoryFamily','factory_family_mismatch')])
def test_wrong_object_order_failed_path_or_invalid_mode_cannot_supply_state(actual,name,reason):
    decisions=rows(actual,name)
    assert decisions and all(r['state']!='included_conditional' for r in decisions)
    assert any(reason in r['reason'] for r in decisions)


def test_intervening_opaque_mutation_cannot_be_assumed_irrelevant(actual):
    decisions=rows(actual,'unknownEffect')
    assert decisions and all(r['state']!='included_conditional' for r in decisions)
    assert any('intervening_invoke_alias_or_state_unknown' in r['reason'] for r in decisions)


def test_intervening_reinitialization_is_outside_single_writer_scope(actual):
    decisions=rows(actual,'overwrite')
    assert decisions and all(r['state']!='included_conditional' for r in decisions)
    assert any('intervening_object_state_call' in r['reason'] for r in decisions)


@pytest.mark.parametrize('field',['source','context_ref','condition_refs','binding_refs'])
def test_forged_state_evidence_is_rejected(actual,field):
    result=deepcopy(actual[0]);edge=next(r for r in result.facts.relations if r.provenance.tool_ref==TOOL)
    if field=='source':edge.source=edge.target
    elif field=='context_ref':edge.context_ref=None
    else:setattr(edge,field,[])
    with pytest.raises(ValueError,match='Forged JCA'):
        verify_jca_state(result.facts,lambda e:result.blobs[result.entry_digests[e]])


def test_budget_is_explicit_and_does_not_claim_complete_crypto(actual):
    result=actual[0]
    report=analyze_jca(result.facts,lambda e:result.blobs[result.entry_digests[e]],JCAConfig(max_visits=1))
    assert any(i['state']=='truncated' for i in report['issues'])
    assert not report['complete_crypto_behavior_claimed']
