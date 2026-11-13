"""English wire decisions preserve typed evidence checks and legacy results."""
from copy import deepcopy
import json

import pytest
from androserum.matching.decisions import LEGACY_TO_ENGLISH,is_supported
from androserum.matching.fixtures import toy_side,support_response
from androserum.matching.views import make_request,make_request_v2,make_request_v3
from androserum.matching.checker import check_match
from androserum.inference.matching import match_protocol


def pair():
    return toy_side('query'),toy_side('reference')


@pytest.mark.parametrize('decision',['supported_match','different_behavior','insufficient_evidence'])
def test_english_schema_decisions_and_legacy_values_remain_separate(decision):
    request=make_request_v3(*pair());model,prompt=match_protocol(request)
    assert request['schema_version']=='behavior-match-request.v3'
    assert model.model_json_schema()['properties']['decision']['enum']==list(LEGACY_TO_ENGLISH.values())
    assert not any('\u3400'<=c<='\u9fff' for c in prompt)
    response=support_response(request);response['schema_version']='behavior-match-proposal.v3';response['decision']=decision
    for relation in response['relation_mappings']:
        relation['query']['path_kind']='bc_links';relation['reference']['path_kind']='bc_links'
    # Schema validation is separate from whether a non-support explanation is justified.
    assert model.model_validate(response).decision==decision
    legacy=next(k for k,v in LEGACY_TO_ENGLISH.items() if v==decision)
    wrong={**response,'decision':legacy}
    assert not check_match(json.dumps(wrong),request)['valid']


def test_support_uses_same_evidence_and_direction_guard():
    request=make_request_v3(*pair());response=support_response(request)
    response.update(schema_version='behavior-match-proposal.v3',decision='supported_match')
    for relation in response['relation_mappings']:
        relation['query']['path_kind']='bc_links';relation['reference']['path_kind']='bc_links'
    result=check_match(json.dumps(response),request)
    assert result['valid'],result
    assert is_supported(result['accepted']['decision'])
    bad=deepcopy(response);bad['relation_mappings'][0]['direction']='reversed'
    rejected=check_match(json.dumps(bad),request)
    assert not rejected['valid'] and 'direction_conflict' in {e['code'] for e in rejected['errors']}
    for factory,version in [(make_request,'v1'),(make_request_v2,'v2')]:
        old_request=factory(*pair());old=support_response(old_request);old['schema_version']='behavior-match-proposal.'+version
        if version=='v2':
            for relation in old['relation_mappings']:
                relation['query']['path_kind']='bc_links';relation['reference']['path_kind']='bc_links'
        old_result=check_match(json.dumps(old),old_request)
        assert old_result['valid'],old_result
        assert old_result['accepted']['decision']==old['decision']


def test_english_reference_is_selected_and_granted_to_task_ledger(tmp_path):
    from androserum.matching.retrieval import choose_reference
    from androserum.tasking import TaskConfig, TaskLedger

    query, reference = pair()
    request = make_request_v3(query, reference)
    response = support_response(request)
    response.update(schema_version='behavior-match-proposal.v3', decision='supported_match')
    for relation in response['relation_mappings']:
        relation['query']['path_kind'] = 'bc_links'
        relation['reference']['path_kind'] = 'bc_links'
    checked = check_match(json.dumps(response), request)
    chosen = choose_reference([{'reference_ref': 'english-reference', 'cosine': 0.8, 'check': checked}])
    assert chosen['reference_ref'] == 'english-reference'
    bid = query['bc']['bc_id']
    with TaskLedger(tmp_path / 'task.sqlite',
                    {'apk_sha256': 'a' * 64, 'source_run_ref': 'run:current'},
                    config=TaskConfig(allow_synthetic_protocol=True),
                    source_catalog={'bcs': {bid: query}, 'supplemental': {}}) as book:
        packet = book.prepare_packet([bid], legal_matches=[{
            'match_ref': 'english-reference', 'request': request, 'proposal': response}])
        assert 'english-reference' in packet['legal_references']
