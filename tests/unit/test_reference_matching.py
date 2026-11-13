"""P5B protocol correctness is separate from actual model prediction quality."""
from copy import deepcopy
from pathlib import Path
import json
import pytest
from androserum.facts.identity import canonical_json,fingerprint
from androserum.matching.models import MatchProposal,MatchConfig
from androserum.matching.fixtures import protocol_cases,toy_side,support_response
from androserum.matching.views import make_request
from androserum.matching.checker import check_match
from androserum.matching.runner import run_fixed

CASES=protocol_cases()


@pytest.mark.parametrize('case',CASES,ids=[c['case'] for c in CASES])
def test_predeclared_fixed_protocol_cases(case):
    checked=check_match(canonical_json(case['response']),case['request'])
    assert checked['valid']==case['expected_valid']
    assert (checked['accepted']['decision'] if checked['accepted'] else None)==case['expected_decision']


def test_failed_later_update_preserves_accepted_response(tmp_path):
    case=CASES[0];good=canonical_json(case['response']);bad=deepcopy(case['response']);bad['pair_sha256']='wrong'
    run,report=run_fixed(case['request'],[good,canonical_json(bad),'{}'],tmp_path)
    assert report['accepted']==case['response'] and report['attempts'][1]['rejected_update_preserved_state']
    assert report['budget_exhausted'] and report['pending_responses']==1 and report['generative_llm_calls']==0


def test_bounded_repair_accepts_only_checked_revision(tmp_path):
    case=CASES[0];bad=deepcopy(case['response']);bad['relation_mappings'][0]['query']['binding_refs']=['bind_000000000000']
    _,report=run_fixed(case['request'],[canonical_json(bad),canonical_json(case['response'])],tmp_path)
    assert [a['valid'] for a in report['attempts']]==[False,True] and report['accepted']==case['response']


def test_request_tamper_and_duplicate_json_keys_rejected():
    case=CASES[0];request=deepcopy(case['request']);request['sides']['query']['bc']['description']='altered'
    assert not check_match(canonical_json(case['response']),request)['valid']
    raw=canonical_json(case['response']);raw=raw[:-1]+',"decision":"\u652f\u6301\u5339\u914d"}'
    assert not check_match(raw,case['request'])['valid']


def test_endpoint_side_correspondence_cannot_be_reversed_silently():
    case=CASES[0];p=deepcopy(case['response']);mapping=p['relation_mappings'][0]
    mapping['endpoint_correspondence'][0]['reference_endpoint']=mapping['reference']['target_endpoint']
    result=check_match(canonical_json(p),case['request'])
    assert not result['valid'] and 'endpoint_correspondence' in {x['code'] for x in result['errors']}


def test_relation_metadata_ref_lists_are_unordered_but_not_duplicable():
    case=CASES[0];p=deepcopy(case['response']);p['relation_mappings'][0]['query']['condition_refs']*=2
    assert not check_match(canonical_json(p),case['request'])['valid']


def test_unknown_condition_is_not_known_equivalence():
    q=toy_side('unknown_q');r=toy_side('unknown_r')
    for c in r['condition_semantics'].values():c['predicate_key']=None
    request=make_request(q,r);p=support_response(request)
    assert not check_match(canonical_json(p),request)['valid']
    p['condition_mappings'][0]['comparison']='unknown'
    p['decision']='\u8bc1\u636e\u4e0d\u8db3';p['unresolved']=['Predicate correspondence is not normalized for the reference condition.']
    p['differences']=[{'difference_id':'predicate_gap','kind':'evidence','impact':'unresolved',
        'citations':[{'side':s,'kind':'condition','ref':p['condition_mappings'][0][s+'_condition']} for s in ['query','reference']],
        'explanation':'The reference predicate meaning cannot be confirmed from the bounded condition adapter.'}]
    assert check_match(canonical_json(p),request)['valid']


def test_unmapped_difference_must_cite_correct_visible_sides():
    case=next(c for c in CASES if c['case']=='purpose');p=deepcopy(case['response'])
    p['differences'][0]['citations'][0]['ref']='nonexistent_action'
    assert not check_match(canonical_json(p),case['request'])['valid']


def test_pair_request_excludes_source_background_labels():
    q=toy_side('q_labels');r=toy_side('r_labels');r['source_background']={'malware_family':'not_model_input'}
    packet=make_request(q,r)
    assert 'not_model_input' not in canonical_json(packet) and not packet['rules']['history_labels_included']


def test_matching_schema_snapshot_and_limits():
    root=Path(__file__).resolve().parents[2]
    assert json.loads((root/'schemas/behavior-match-proposal.v1.json').read_text('utf-8'))==MatchProposal.model_json_schema()
    with pytest.raises(ValueError):MatchConfig(max_pair_attempts=0)
    q=toy_side('budget_q');q['limitations']=['x'*3000]*5
    with pytest.raises(ValueError):make_request(q,toy_side('budget_r'),MatchConfig(max_request_chars=10000))


def test_grouping_all_actions_cannot_hide_unmapped_relationships():
    case=CASES[0];p=deepcopy(case['response']);p['scope']='partial'
    p['action_mappings']=[{**p['action_mappings'][0],'query_actions':['left','right'],'reference_actions':['left','right']}]
    p['relation_mappings']=[];p['condition_mappings']=[]
    p['unmapped']['query_links']=['flow0'];p['unmapped']['reference_links']=['flow0']
    checked=check_match(canonical_json(p),case['request'])
    assert not checked['valid'] and 'group_support' in {e['code'] for e in checked['errors']}
