"""Frozen exact cosine top-K with explicit related-origin exclusions."""
from .decisions import is_supported
import numpy as np
from pathlib import Path
from androserum.encoding.runner import read
from androserum.knowledge.store import verify_snapshot


def load_history(snapshot):
    snapshot=Path(snapshot);checked=verify_snapshot(snapshot);entries=read(snapshot/'encoding/audit/approved-pool.json')['entries']
    vectors=np.load(snapshot/'encoding/bc_vectors.npy',allow_pickle=False)
    rows=[{'instance_ref':e['qualified_ref'],'apk_sha256':e['source_apk_sha256'],'ledger_ref':e['source_mining_run']} for e in entries]
    return rows,vectors,checked


def related_reasons(query_ref,origin,row):
    reasons=[]
    if query_ref==row['instance_ref']:reasons.append('identical_instance')
    if origin.get('apk_sha256') and origin['apk_sha256']==row['apk_sha256']:reasons.append('same_apk')
    if origin.get('ledger_ref') and origin['ledger_ref']==row['ledger_ref']:reasons.append('same_ledger')
    return reasons


def recall(query_ref,origin,vector,rows,vectors,*,k,exclude_related=True):
    if type(k) is not int or not 1<=k<=100:raise ValueError('K must be an integer from 1 to 100')
    q=np.asarray(vector,dtype=np.float64);z=np.asarray(vectors,dtype=np.float64)
    if q.shape!=(768,) or z.shape!=(len(rows),768) or not np.isfinite(q).all() or not np.isfinite(z).all():raise ValueError('Invalid recall vector dimensions or values')
    qn=np.linalg.norm(q);zn=np.linalg.norm(z,axis=1)
    if qn<=1e-12 or (zn<=1e-12).any():raise ValueError('Cannot rank zero vectors')
    if exclude_related and (not origin.get('apk_sha256') or not origin.get('ledger_ref')):raise ValueError('Cross-APK recall requires explicit actual origin metadata')
    ranked=[];excluded=[]
    for i,row in enumerate(rows):
        reasons=related_reasons(query_ref,origin,row)
        item={**row,'cosine':float(z[i]@q/(zn[i]*qn)),'related_origin_reasons':reasons}
        if reasons and exclude_related:excluded.append(item)
        else:ranked.append(item)
    ranked.sort(key=lambda x:(-x['cosine'],x['instance_ref']))
    return {'schema_version':'reference-recall.v1','query_ref':query_ref,'origin':origin,'k':k,
        'exclude_related':exclude_related,'ranked_candidates':ranked[:k],'complete_ranking':ranked,
        'excluded':excluded,'eligible_count':len(ranked),'threshold':None,
        'evaluation_role':'controlled_cross_apk' if exclude_related and origin['material_kind']=='controlled_compiled_apk' else 'interface_or_related_origin_only',
        'generalization_validated':False,'retrieval_quality_validated':False}


def recall_measure(result,expected_refs):
    eligible={r['instance_ref'] for r in result['complete_ranking']};expected=set(expected_refs)&eligible
    if result['evaluation_role']!='controlled_cross_apk' or not expected:
        return {'evaluable':False,'hit':None,'reason':'No eligible held-out controlled reference; self/same-APK/ledger tests do not measure cross-sample recall',
            'expected_refs':sorted(expected_refs),'eligible_expected_refs':sorted(expected)}
    retrieved={r['instance_ref'] for r in result['ranked_candidates']}
    return {'evaluable':True,'hit':bool(retrieved&expected),'expected_refs':sorted(expected),'retrieved_relevant_refs':sorted(retrieved&expected),
        'scope':'Controlled independently compiled APK query only; no natural-corpus generalization claim'}


def choose_reference(results):
    eligible=[r for r in results if r.get('check',{}).get('valid') and is_supported(r.get('check',{}).get('accepted',{}).get('decision'))]
    eligible.sort(key=lambda r:(-r['cosine'],r['reference_ref']))
    return {'reference_ref':eligible[0]['reference_ref'] if eligible else None,
        'supporting_scope':eligible[0]['check']['accepted'] if eligible else None,
        'reason':'Highest cosine among checked supporting matches' if eligible else 'No checked supporting reference; continue with current evidence only',
        'absence_proves_benign':False}
