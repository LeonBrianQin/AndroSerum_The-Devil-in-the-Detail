"""Displayed-only freeze unions: metadata growth cannot change semantics."""
from copy import deepcopy
import pytest

from androserum.pipeline.approval import _merge_displayed


def condition(bu='bu:one',state='partial'):
    return {'handle':'cond_same','category':'condition','record_ref':'condition:same',
        'expected_value':{'status':'known','value':True},'context_ref':'context:same',
        'bu_ids':[bu],'source_collection_by_bu':{bu:state}}


def test_same_condition_unions_only_displayed_membership_and_per_bu_state():
    a,b=condition(),condition('bu:two')
    merged=_merge_displayed(a,b)
    assert merged['bu_ids']==['bu:one','bu:two']
    assert merged['source_collection_by_bu']=={'bu:one':'partial','bu:two':'partial'}
    assert merged['expected_value']==a['expected_value']
    assert a['bu_ids']==['bu:one'] and b['bu_ids']==['bu:two']


def test_same_bu_contradictory_collection_state_is_rejected():
    with pytest.raises(ValueError,match='per-BU'):_merge_displayed(condition(),condition(state='collected'))


def test_condition_metadata_cannot_invent_unshown_bu_membership():
    other=condition();other['source_collection_by_bu']['bu:not-shown']='collected'
    with pytest.raises(ValueError,match='membership'):_merge_displayed(condition(),other)


@pytest.mark.parametrize('category,field,value',[
    ('condition','expected_value',{'status':'known','value':False}),
    ('condition','context_ref','context:other'),
    ('endpoint','endpoint',{'element_ref':'different','slot_kind':'result'}),
    ('binding','endpoints',['endpoint:other']),
    ('relation','kind','control_dependency'),
    ('relation','source_endpoint_ref','endpoint:other'),
    ('relation','condition_refs',['condition:other']),
    ('relation','binding_refs',['binding:other']),
])
def test_membership_growth_does_not_allow_semantic_identity_changes(category,field,value):
    a={'handle':'same','category':category,'bu_ids':['bu:one'],field:'original'}
    b=deepcopy(a);b['bu_ids']=['bu:two'];b[field]=value
    with pytest.raises(ValueError):_merge_displayed(a,b)


def fact(record,bu='bu:one'):
    return {'handle':'fact_same','category':'fact','record_ref':'fact:same','record_sha256':'a'*64,
            'record':record,'shown_fields':list(record),'detail_fields_available':[],
            'fact_refs':['fact:same'],'bu_ids':[bu]}


def test_monotonic_displayed_fact_keeps_richer_actual_record_and_bu_union():
    a=fact({'id':'fact:same'});b=fact({'id':'fact:same','text':'actually displayed'},'bu:two')
    merged=_merge_displayed(a,b)
    assert merged['record']==b['record'] and merged['bu_ids']==['bu:one','bu:two']


@pytest.mark.parametrize('damage',['content','hash','reference','nonmonotonic','category'])
def test_conflicting_fact_identity_or_content_is_rejected(damage):
    a=fact({'id':'fact:same','text':'actual'});b=deepcopy(a);b['bu_ids']=['bu:two']
    if damage=='content':b['record']['text']='invented'
    elif damage=='hash':b['record_sha256']='b'*64
    elif damage=='reference':b['record_ref']='fact:different'
    elif damage=='nonmonotonic':b['record']={'id':'fact:same','other':'different projection'}
    else:b['category']='condition'
    with pytest.raises(ValueError):_merge_displayed(a,b)
