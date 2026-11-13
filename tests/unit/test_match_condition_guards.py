"""Independent condition counterexamples, beyond the original protocol cases."""
from copy import deepcopy
import pytest
from androserum.facts.identity import canonical_json
from androserum.matching.checker import check_match
from androserum.matching.fixtures import toy_side,support_response
from androserum.matching.views import make_request


def checked(query,reference,modify=None):
    request=make_request(query,reference);proposal=support_response(request)
    if modify:modify(proposal)
    return check_match(canonical_json(proposal),request)


def replace_truth(side,value):
    for h,c in side['condition_semantics'].items():
        c['expected_value']=deepcopy(value);side['registry'][h]['expected_value']=deepcopy(value)


@pytest.mark.parametrize('value',[
    {'status':'unknown'}, {'status':'known'}, {'status':'known','value':1},
    {'status':'known','value':'true'},
])
def test_equal_unknown_or_nonboolean_truth_is_not_equivalence(value):
    query=toy_side('truth_a');reference=toy_side('truth_b')
    for side in [query,reference]:replace_truth(side,value)
    result=checked(query,reference)
    assert not result['valid'] and 'condition_equivalence' in {e['code'] for e in result['errors']}


@pytest.mark.parametrize('difference',['predicate','scope','truth_unknown'])
def test_compatibility_requires_the_supported_finite_identity_rule(difference):
    query=toy_side('compatible_a');reference=toy_side('compatible_b')
    for c in reference['condition_semantics'].values():
        if difference=='predicate':c['predicate_key']='synthetic:another_requirement'
        elif difference=='scope':c['scope']='another_scope'
    if difference=='truth_unknown':replace_truth(reference,{'status':'unknown'})
    result=checked(query,reference,lambda p:p['condition_mappings'][0].update(comparison='compatible_with_limits'))
    assert not result['valid'] and 'condition_compatibility' in {e['code'] for e in result['errors']}


def test_compatibility_may_keep_limits_for_identical_known_requirements():
    result=checked(toy_side('identity_a'),toy_side('identity_b'),
        lambda p:p['condition_mappings'][0].update(comparison='compatible_with_limits'))
    assert result['valid']


def boundary_only(side):
    side['bc']['boundary']['condition_refs']=list(side['condition_semantics'])
    for e in side['registry'].values():
        if e['category']=='relation':e['condition_refs']=[]
    for link in side['bc']['relations']:link['condition_refs']=[]
    return side


def test_full_scope_cannot_drop_conditions_attached_only_to_bc_boundary():
    result=checked(boundary_only(toy_side('boundary_a')),boundary_only(toy_side('boundary_b')))
    assert not result['valid'] and 'condition_coverage' in {e['code'] for e in result['errors']}


def test_full_boundary_condition_has_explicit_whole_correspondence_scope():
    query=boundary_only(toy_side('boundary_known_a'));reference=boundary_only(toy_side('boundary_known_b'))
    def add_boundary(proposal):
        proposal['condition_mappings']=[{'mapping_id':'boundary_condition',
            'query_condition':next(iter(query['condition_semantics'])),
            'reference_condition':next(iter(reference['condition_semantics'])),
            'comparison':'equivalent','affected_mappings':['actions0','actions1','path'],
            'explanation':'The recorded BC-wide predicate applies to every correspondence in this full scope.'}]
    result=checked(query,reference,add_boundary)
    assert result['valid']


def test_partial_scope_does_not_automatically_claim_the_bc_boundary():
    query=boundary_only(toy_side('partial_boundary_a'));reference=boundary_only(toy_side('partial_boundary_b'))
    result=checked(query,reference,lambda p:p.update(scope='partial'))
    assert result['valid']


def test_unknown_truth_can_remain_explicitly_unresolved_without_false_conflict():
    query=toy_side('unresolved_a');reference=toy_side('unresolved_b')
    replace_truth(reference,{'status':'unknown'})
    def unresolved(proposal):
        proposal['decision']='\u8bc1\u636e\u4e0d\u8db3';proposal['condition_mappings'][0]['comparison']='unknown'
        proposal['unresolved']=['Required predicate truth is not known on the reference side.']
        proposal['differences']=[{'difference_id':'predicate_gap','kind':'evidence','impact':'unresolved',
            'citations':[{'side':s,'kind':'condition','ref':next(iter(side['condition_semantics']))}
                for s,side in [('query',query),('reference',reference)]],
            'explanation':'Unknown truth does not establish either equivalence or a contradictory predicate.'}]
    assert checked(query,reference,unresolved)['valid']
