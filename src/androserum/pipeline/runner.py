"""APK-parametric orchestration; Method mainline admits program-checked BCs."""
import json
import time
import re
from pathlib import Path
from androserum.facts.identity import filesystem_path,sha256_file
from androserum.inference.provider import write
from androserum.facts.store import FactView
from androserum.mining.runner import load_catalog,run_mining
from .config import PipelineConfig
from .prepare import prepare_apk
from .provider import PipelineProvider
from .approval import build_reviewed_entry,freeze_reviewed,load_frozen,freeze_program_checked


def read(path):return json.loads(filesystem_path(path).read_text('utf-8'))


def sample_path(root,sample_id):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',sample_id):
        raise ValueError('Sample ID must be a short directory label, without path separators')
    out=filesystem_path(root/'samples'/sample_id)
    if not out.is_relative_to(filesystem_path(root/'samples')):raise ValueError('Sample ID escapes the round')
    return out


def mine_prepared(round_root,sample_id,*,resume=False,call_limit=None):
    root=filesystem_path(round_root);out=sample_path(root,sample_id)
    config=read(root/'experiment-config.json');prepared=read(out/'prepared.json')
    pc=PipelineConfig.model_validate(read(out/'config.json'))
    if pc.mining.schema_version=='mining-config.v2' or config.get('mining_protocol')=='current_facts.v1':
        from .workplan import mine_complete_prepared
        return mine_complete_prepared(root,sample_id,call_limit=call_limit,resume=resume)
    if sha256_file(Path(__file__).parents[1]/'mining/prompt.txt')!=config['mining_prompt_sha256']:
        raise ValueError('Mining prompt differs from the frozen round')
    effective_calls=min(pc.mining.max_model_calls,config['per_sample_mining_call_limit'])
    pc.mining=pc.mining.model_copy(update={'max_model_calls':effective_calls})
    result_file=out/'mining-result.json'
    if result_file.exists():return read(result_file)
    existing=sorted((out/'mining').glob('mining_*')) if (out/'mining').exists() else []
    if existing:
        published=[p for p in existing if (p/'report.json').is_file() and (p/'manifest.json').is_file()]
        if len(published)!=1 or len(existing)!=1:
            raise ValueError('Unfinished mining attempt retained; explicit recovery is required before a new inference session')
        from .approval import verify_files
        run=published[0];verify_files(run);report=read(run/'report.json')
        source=report['identity']['source'];snapshot_manifest=read(filesystem_path(prepared['snapshot'])/'manifest.json')
        if (source['apk_sha256']!=prepared['apk_sha256'] or source['source_run_ref']!=prepared['source_run_ref']
            or source['source_snapshot_id']!=snapshot_manifest['snapshot_id']
            or report['identity']['selected_bu_ids']!=prepared['selected_bu_ids']):
            raise ValueError('Retained mining run belongs to a different APK/fact snapshot/BU selection')
        run_info=read(run/'run.json')
        if run_info['config']!=pc.mining.model_dump(mode='json'):
            raise ValueError('Retained mining session has a different frozen configuration')
        result={'mining_run':str(run),'apk_sha256':prepared['apk_sha256'],
                'actions':len(report['accepted_state']['actions']),'bcs':len(report['accepted_state']['bcs']),
                'budgets':report['budgets'],'coverage':report['coverage'],'elapsed_seconds':None,
                'status':'mined_pending_semantic_review','wrapper_recovered_from_published_run':True}
        write(result_file,result);return result
    if not prepared['selected_bu_ids']:
        result={'mining_run':None,'apk_sha256':prepared['apk_sha256'],'actions':0,'bcs':0,
                'status':'no_bu_evidence','reason':'No formal SAPI BU in the declared scope',
                'full_behavior_coverage_claimed':False,'actual_llm_calls':0}
        write(result_file,result);return result
    started=time.monotonic();provider=PipelineProvider(root,sample_id,config)
    try:
        with FactView(prepared['snapshot']) as view:
            catalog=load_catalog(prepared['bu_package'],view,prepared['selected_bu_ids'])
            run,report=run_mining(catalog,view,out/'mining',provider,pc.mining)
        result={'mining_run':str(run),'apk_sha256':prepared['apk_sha256'],
                'actions':len(report['accepted_state']['actions']),'bcs':len(report['accepted_state']['bcs']),
                'budgets':report['budgets'],'coverage':report['coverage'],
                'elapsed_seconds':time.monotonic()-started,'status':'mined_pending_semantic_review'}
        write(result_file,result);return result
    finally:provider.close()


def freeze_mined(round_root,sample_id,review_file):
    root=filesystem_path(round_root);out=sample_path(root,sample_id);prepared=read(out/'prepared.json')
    result=read(out/'mining-result.json');review=read(review_file)
    pointer=out/'freeze-result.json'
    if pointer.exists():
        previous=read(pointer)
        if previous['review_sha256']==sha256_file(review_file):
            load_frozen(previous['freeze'])
            return filesystem_path(previous['freeze'])
        freeze_id=read(filesystem_path(previous['freeze'])/'manifest.json')['freeze_id']
        history=out/'freeze-history'/(freeze_id+'.json')
        if not history.exists():write(history,previous)
    if review.get('apk_sha256')!=prepared['apk_sha256']:raise ValueError('Review belongs to a different actual APK')
    if review.get('source_run_ref')!=prepared['source_run_ref']:raise ValueError('Review belongs to a different fact run')
    run=review.get('source_mining_run',result.get('mining_run'))
    if run:
        info=read(filesystem_path(run)/'run.json')
        if (info['identity']['source']['apk_sha256']!=prepared['apk_sha256']
            or info['identity']['source']['source_run_ref']!=prepared['source_run_ref']):
            raise ValueError('Reviewed mining source differs from prepared APK/run')
    bcs=read(filesystem_path(run)/'report.json')['accepted_state']['bcs'] if run else {}
    decisions=review['bc_reviews']
    if {x['bc_id'] for x in decisions}!=set(bcs) or len(decisions)!=len(bcs):
        raise ValueError('Review must classify every actual final BC exactly once')
    approved=[];excluded=[]
    for row in decisions:
        if row['decision']=='approve':
            approved.append(build_reviewed_entry(run,prepared['snapshot'],prepared['bu_package'],row['bc_id'],
                source_case=sample_id,qualification=row['qualification']))
        elif row['decision']=='exclude':excluded.append({'candidate_id':row['bc_id'],'reason':row['reason']})
        else:raise ValueError('Review decisions are approve or exclude, not implicit checks')
    metadata={k:v for k,v in review.items() if k!='bc_reviews'}
    source_bindings={'source_snapshot':prepared['snapshot'],'source_bu_package':prepared['bu_package'],
                     'source_mining_run':run,
                     'source_snapshot_id':read(filesystem_path(prepared['snapshot'])/'manifest.json')['snapshot_id']}
    for key,value in source_bindings.items():
        if key in metadata and metadata[key]!=value:
            raise ValueError('Review source binding differs from the actual prepared source: '+key)
        metadata[key]=value
    if prepared['bu_package'] is None:metadata['bu_extraction_status']='no_bu_evidence'
    frozen=freeze_reviewed(approved,excluded,metadata,out/'reviewed',role='query',replay=False)
    write(out/'freeze-result.json',{'freeze':str(frozen),'approved':len(approved),'excluded':len(excluded),
          'review_file':str(filesystem_path(review_file)),'review_sha256':sha256_file(review_file),
          'full_behavior_coverage_claimed':False})
    return frozen


def freeze_automined(round_root, sample_id, *, replay=True):
    root=filesystem_path(round_root);out=sample_path(root,sample_id)
    prepared=read(out/'prepared.json');result=read(out/'mining-result.json')
    pointer=out/'program-freeze-result.json'
    run=result.get('mining_run')
    binding=sha256_file(filesystem_path(run)/'manifest.json') if run else None
    if pointer.exists():
        retained=read(pointer)
        if retained['source_mining_manifest_sha256'] == binding:
            load_frozen(retained['freeze']);return filesystem_path(retained['freeze'])
    frozen=freeze_program_checked(run,prepared['snapshot'],prepared['bu_package'],out/'program-checked',
        source_case=sample_id,role='query',replay=replay,
        source_identity={k:prepared[k] for k in ('apk_sha256','source_run_ref')})
    write(pointer,{'freeze':str(frozen),'source_mining_manifest_sha256':binding,
        'semantic_review_is_required':False,'original_model_content_rewritten':False})
    return frozen


def run_apk(apk,round_root,sample_id,sapi_catalog=None,*,review_file=None,freeze=None,history=None,
            analysis_profile=None,flow_config=None,admission='program_checked'):
    """Execute stages available under the supplied explicit evidence/review inputs.

    Program checks govern the normal mainline. An explicit legacy semantic
    review remains available for development/evaluation and old baselines.
    """
    root=filesystem_path(round_root);out=sample_path(root,sample_id)
    if admission not in {'program_checked','explicit_semantic_review'}:
        raise ValueError('Unknown BC admission policy')
    if freeze is not None and review_file is not None:
        raise ValueError('Supply either a new review or an existing query freeze, not both')
    if freeze is not None and (analysis_profile is not None or flow_config is not None):
        raise ValueError('Preparation profile/flow options cannot be applied to an existing freeze')
    if freeze is not None:
        if not (out/'prepared.json').exists():
            from .adopt import adopt_frozen_source
            prepared=adopt_frozen_source(apk,freeze,out)
        else:
            prepared=read(out/'prepared.json')
            if prepared['apk_sha256']!=sha256_file(apk):
                raise ValueError('Existing prepared source belongs to another actual APK')
            if prepared.get('adopted_frozen_sources'):
                from .adopt import adopt_frozen_source
                prepared=adopt_frozen_source(apk,freeze,out)
        # An independent freeze already binds the accepted native model run.
        # Do not start another extraction/mining session just to consume it.
        mined=None
    else:
        if sapi_catalog is None:raise ValueError('Fresh APK preparation requires a formal SAPI catalog')
        preparation_options={}
        if analysis_profile is None:
            experiment=root/'experiment-config.json'
            if experiment.exists() and read(experiment).get('analysis_profile')=='method.v1':analysis_profile='method.v1'
        if analysis_profile is not None:preparation_options['analysis_profile']=analysis_profile
        if flow_config is not None:preparation_options['flow_config']=flow_config
        policy_file=root/'pipeline-policy.json'
        if policy_file.exists():
            preparation_options['config']=PipelineConfig.model_validate(read(policy_file))
        prepared=prepare_apk(apk,out,sapi_catalog,**preparation_options)
        mined=mine_prepared(root,sample_id)
    if freeze is None and review_file is not None:freeze=freeze_mined(root,sample_id,review_file)
    if freeze is None and admission=='program_checked':freeze=freeze_automined(root,sample_id)
    if freeze is None:
        return {'status':'pending_explicit_semantic_review','prepared':prepared,'mining':mined,
                'instruction':'Review actual accepted BCs and exclusions; pass --review or a new --freeze.'}
    policy,entries=load_frozen(freeze)
    if any(e['source_apk_sha256']!=sha256_file(apk) for e in entries):raise ValueError('Frozen list belongs to another APK')
    if policy['role']!='query':raise ValueError('Current APK analysis requires a query-role freeze')
    from .analyze import analyze_apk
    return analyze_apk(root,sample_id,freeze,history or read(root/'experiment-config.json')['history_snapshot'])
