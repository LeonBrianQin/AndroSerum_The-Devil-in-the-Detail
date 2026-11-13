"""Origin exclusion, metric denominators and fixed checked-reference selection."""
from copy import deepcopy
import numpy as np
import pytest
from androserum.matching.retrieval import recall,recall_measure,choose_reference


def data():
    rows=[{'instance_ref':'a','apk_sha256':'apk_a','ledger_ref':'ledger_a'},
        {'instance_ref':'b','apk_sha256':'apk_b','ledger_ref':'ledger_b'}]
    z=np.zeros((2,768),np.float32);z[0,0]=1;z[1,1]=1
    origin={'material_kind':'controlled_compiled_apk','apk_sha256':'new_apk','ledger_ref':'new_ledger'}
    return rows,z,origin


def test_correct_reference_in_top_k_is_separate_from_matching():
    rows,z,origin=data();result=recall('q',origin,z[0],rows,z,k=1)
    assert result['ranked_candidates'][0]['instance_ref']=='a' and recall_measure(result,['a'])['hit']
    assert not recall_measure(result,['b'])['hit'] and result['threshold'] is None


@pytest.mark.parametrize('mode',['same_apk','same_ledger','identical_instance'])
def test_changed_query_id_does_not_bypass_related_origin_exclusion(mode):
    rows,z,origin=data();query='different_id'
    if mode=='same_apk':origin['apk_sha256']='apk_a'
    elif mode=='same_ledger':origin['ledger_ref']='ledger_a'
    else:query='a'
    result=recall(query,origin,z[0],rows,z,k=2)
    assert result['excluded'][0]['instance_ref']=='a' and mode in result['excluded'][0]['related_origin_reasons']
    assert not recall_measure(result,['a'])['evaluable']


def test_self_smoke_and_same_apk_rewrites_never_count_as_generalization():
    rows,z,origin=data();origin.update(material_kind='same_apk_paraphrase',apk_sha256='apk_a',ledger_ref='ledger_a')
    result=recall('renamed',origin,z[0],rows,z,k=1,exclude_related=False)
    assert result['ranked_candidates'][0]['instance_ref']=='a' and not recall_measure(result,['a'])['evaluable']


def test_cosine_tie_order_is_fixed_and_k_does_not_generate_candidates():
    rows,z,origin=data();q=np.zeros(768,np.float32);q[0]=q[1]=1
    assert [r['instance_ref'] for r in recall('q',origin,q,rows,z,k=3)['ranked_candidates']]==['a','b']


@pytest.mark.parametrize('bad',['zero','nan','shape','k','missing_origin'])
def test_invalid_vectors_or_cross_apk_metadata_refused(bad):
    rows,z,origin=data();q=z[0].copy();k=1
    if bad=='zero':q[:]=0
    elif bad=='nan':q[0]=np.nan
    elif bad=='shape':q=q[:20]
    elif bad=='k':k=0
    else:origin['apk_sha256']=None
    with pytest.raises(ValueError):recall('q',origin,q,rows,z,k=k)


def test_only_checked_support_can_be_selected_and_no_reference_is_valid_output():
    candidates=[{'reference_ref':'invalid_high','cosine':1.,'check':{'valid':False,'accepted':None}},
        {'reference_ref':'different','cosine':.99,'check':{'valid':True,'accepted':{'decision':'\u884c\u4e3a\u4e0d\u540c'}}},
        {'reference_ref':'supported','cosine':.5,'check':{'valid':True,'accepted':{'decision':'\u652f\u6301\u5339\u914d','scope':'partial'}}}]
    assert choose_reference(candidates)['reference_ref']=='supported'
    result=choose_reference(candidates[:2]);assert result['reference_ref'] is None and not result['absence_proves_benign']
