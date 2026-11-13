"""APK-parametric fact/SAPI/BU preparation; never executes an APK."""
from pathlib import Path
import json
import shutil
import time
from androserum.facts.identity import filesystem_path,sha256_file,fingerprint
from .evidence import write_encoded_extraction
from androserum.facts.context_heap import extend_context_heap,ContextHeapConfig,entry_for as context_entry_for
from androserum.facts.heap_flow import extract_heap
from androserum.facts.java_backend import JavaConfig,_normal
from androserum.facts.selected_flow import extend_selected_flow,FlowConfig,load_flow_config
from androserum.facts.operations import extend_operations
from androserum.facts.control import extend_control
from androserum.facts.events import extend_events
from androserum.facts.method_outputs import extend_method_outputs
from androserum.facts.jca_state import extend_jca_state
from androserum.facts.store import FactView,import_snapshot
from androserum.facts.sapi import load_catalog,match_sapi
from androserum.facts.bu import write_units,BUConfig
from androserum.inference.provider import write
from .config import PipelineConfig


def _default_flow():
    return FlowConfig(sources=['Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;',
                              'Landroid/telephony/TelephonyManager;->getSubscriberId()Ljava/lang/String;'],
                      sinks=['Ljava/security/MessageDigest;->update([B)V','Ljava/net/URL;-><init>(Ljava/lang/String;)V',
                             'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V'],callbacks=True,
                      timeout_seconds=90,solver_timeout=45)


def _sensitive_caller_roots(facts, matches):
    """Reverse closure of actual candidate records, never semantic name guesses."""
    records={e.id:e for e in facts.elements}
    sensitive={m['method_ref'] for m in matches['matches']}
    incoming={}
    for relation in facts.relations:
        if relation.relation_kind!='candidate_call' or relation.target is None:continue
        target=relation.target.element_ref
        call=records.get(relation.source.element_ref)
        caller=getattr(call,'method_ref',None) or getattr(getattr(call,'position',None),'method_ref',None)
        if caller and target in records:
            incoming.setdefault(target,[]).append((caller,relation.id))
    seen=set(sensitive);queue=list(sensitive);basis={ref:[] for ref in sensitive}
    while queue:
        target=queue.pop()
        for caller,relation in incoming.get(target,[]):
            basis.setdefault(caller,[]).append(relation)
            if caller not in seen:seen.add(caller);queue.append(caller)
    roots=[];discovery=[]
    for ref in sorted(seen):
        method=records.get(ref)
        if getattr(method,'kind',None)!='method' or not method.is_definition:continue
        roots.append(method.signature)
        discovery.append({'method_ref':ref,'signature':method.signature,'owns_physical_sapi':ref in sensitive,
            'candidate_call_support_refs':sorted(set(basis.get(ref,[]))),
            'possible_caller_context_only':ref not in sensitive,'execution_established':False})
    return sorted(set(roots)),discovery


def prepare_apk(apk,output,sapi_catalog,config=None,*,analysis_profile=None,flow_config=None,reference_input=False):
    """Opt in to the accepted finite extensions without reinterpreting old runs.

    The omitted profile retains the original preparation stages. Explicit
    profile/flow inputs are bound before extraction, including interrupted runs.
    """
    if analysis_profile not in {None,'bounded.v1','method.v1'}:raise ValueError('Unknown preparation analysis profile')
    if flow_config is not None:flow=load_flow_config(flow_config)
    elif analysis_profile=='method.v1':
        policy=_default_flow().model_dump(mode='json')
        policy.update(schema_version='selected-summary-flow-config.v3',taint_wrapper='flowdroid_summary')
        flow=load_flow_config(policy)
    else:flow=_default_flow()
    config=config or PipelineConfig();apk=filesystem_path(apk);out=filesystem_path(output)
    out.mkdir(parents=True,exist_ok=True);started=time.monotonic()
    prepared_path=out/'prepared.json';binding_path=out/'preparation-identity.json'
    result=json.loads(prepared_path.read_text('utf-8')) if prepared_path.exists() else None
    explicit=analysis_profile is not None or flow_config is not None
    catalog=None;identity=None
    if result is not None:
        if result['apk_sha256']!=sha256_file(apk) or result['config_sha256']!=fingerprint(config.model_dump(mode='json')):
            raise ValueError('Cannot replace APK/configuration on resume')
        if (not binding_path.exists() and not result.get('preparation_identity_sha256')
            and 'analysis_profile' not in result and 'bounded_extensions_started' not in result):
            if explicit:raise ValueError('Legacy preparation has no bound profile/flow; use a new output directory')
            return result
    if explicit or binding_path.exists() or result is not None:
        catalog=load_catalog(sapi_catalog)
        identity={'schema_version':'apk-preparation-identity.v1','apk_sha256':sha256_file(apk),
                  'config_sha256':fingerprint(config.model_dump(mode='json')),
                  'sapi_catalog_id':catalog['catalog_id'],'analysis_profile':analysis_profile,
                  'selected_flow_config':flow.model_dump(mode='json')}
        if reference_input:
            identity['input_storage']={'mode':'read_only_reference','path':str(apk)}
        if binding_path.exists():
            if json.loads(binding_path.read_text('utf-8'))!=identity:
                raise ValueError('Cannot replace preparation profile/flow/catalog on resume')
        elif result is not None:
            raise ValueError('Bound preparation identity is missing; no legacy fallback')
        elif any(out.iterdir()):
            raise ValueError('Existing preparation has no bound profile/flow; use a new output directory')
        else:write(binding_path,identity)
    if result is not None:
        if (result.get('preparation_identity_sha256')!=fingerprint(identity)
            or result.get('analysis_profile')!=analysis_profile
            or result.get('selected_flow_config')!=identity['selected_flow_config']):
            raise ValueError('Prepared result differs from its bound profile/flow identity')
        return result
    def progress(stage, **details):
        if reference_input:
            write(out/'preparation-progress.json',{'stage':stage,'elapsed_seconds':time.monotonic()-started,
                'apk_sha256':identity['apk_sha256'],**details})
    target=apk if reference_input else out/'input.apk'
    if target.exists() and sha256_file(target)!=sha256_file(apk):raise ValueError('Pinned input changed')
    if not target.exists():shutil.copyfile(apk,target)
    write(out/'config.json',config.model_dump(mode='json'))
    # Export all available application methods before choosing BU roots.
    # SAPI-owning methods are selected mechanically, never by a target label.
    extraction_options = {}
    if analysis_profile == 'method.v1':
        from androserum.facts.call_flow import CallConfig
        extraction_options['call_config'] = CallConfig(dispatch='cha_spark_points_to')
    progress('base_facts_calls_points_to_local_heap')
    result=extract_heap(target,java_config=JavaConfig(timeout_seconds=180,max_methods=2000),**extraction_options)
    pre_matches=match_sapi(result.facts,catalog or load_catalog(sapi_catalog));pre_records={e.id:e for e in result.facts.elements}
    pre_roots=sorted({pre_records[m['method_ref']].signature for m in pre_matches['matches']})
    root_discovery=None
    if analysis_profile=='method.v1':
        pre_roots,root_discovery=_sensitive_caller_roots(result.facts,pre_matches)
    if pre_roots:
        progress('cross_method_context_heap',discovered_roots=len(pre_roots),selected_roots=min(len(pre_roots),config.max_sapi_roots),
            base_elements=len(result.facts.elements),base_relations=len(result.facts.relations))
        result=extend_context_heap(result,ContextHeapConfig(root_signatures=pre_roots[:config.max_sapi_roots],
                                  max_nodes=5000,max_frames=256,max_depth=4))
    else:
        # No application source/crypto root is available. Avoid interpreting an
        # empty filter as permission to expand every method's call context.
        write(out/'no-sapi-roots.json',{'reason':'No SAPI-owning declared or candidate call in the complete base fact export',
                                      'context_projection_started':False})
    if pre_roots:
        progress('selected_flowdroid')
        result=extend_selected_flow(result,Path(_normal(target)),flow)
        progress('operation_evidence');result=extend_operations(result)
        progress('local_control');result=extend_control(result)
        progress('events');result=extend_events(result)
        if analysis_profile in {'bounded.v1','method.v1'}:
            progress('method_outputs_and_jca');result=extend_jca_state(extend_method_outputs(result))
    progress('publish_fact_snapshot',elements=len(result.facts.elements),relations=len(result.facts.relations))
    snapshot=import_snapshot(write_encoded_extraction(result,out/'facts',input_apk=target),out/'stores')
    with FactView(snapshot) as view:
        facts=view.export_bundle();records={e.id:e for e in facts.elements}
        matches=match_sapi(facts,load_catalog(sapi_catalog));write(out/'sapi-matches.json',matches)
        roots=sorted({records[m['method_ref']].signature for m in matches['matches']})
        if analysis_profile=='method.v1':roots=pre_roots
        selected=roots[:config.max_sapi_roots]
        if selected:
            progress('bu_materialization',discovered_roots=len(roots),selected_roots=len(selected),sapi_matches=len(matches['matches']))
            package,collection=write_units(view,sapi_catalog,out/'bu',BUConfig(root_signatures=selected,
                max_roots=config.max_sapi_roots,max_units=config.max_bu,max_tasks=config.max_bu_tasks))
            bu_ids=[u['bu_id'] for u in collection['units']]
        else:package=None;collection=None;bu_ids=[]
    prepared={'schema_version':'prepared-apk-pipeline.v1','apk_sha256':sha256_file(target),'source_path':str(apk),
        'input_apk':str(target),'snapshot':str(snapshot),'source_run_ref':facts.run.run_id,
        'bu_package':str(package) if package else None,'selected_bu_ids':bu_ids,
        'root_policy':'All SAPI-owning method signatures, sorted, with explicit root cap; context projections within declared limits.',
        'available_sapi_roots':roots,'selected_roots':selected,'unprocessed_roots':roots[len(selected):],
        'physical_sapi_calls':len({x['callsite_ref'] for x in matches['matches']}),'sapi_matches':len(matches['matches']),
        'bu_count':len(bu_ids),'fact_summary':result.summary,
        'fact_coverage':{s.capability:s.state for s in facts.statuses if s.scope.kind=='run'},
        'elapsed_seconds':time.monotonic()-started,'config_sha256':fingerprint(config.model_dump(mode='json')),
        'apk_execution':False,'labels_used':False,'full_behavior_coverage_claimed':False,
        'selected_flow_config':flow.model_dump(mode='json'),'selected_flow_started':bool(pre_roots),
        'evidence_storage':'Original APK container entry references; raw DEX is never written to an evidence file'}
    if identity is not None:
        prepared.update(analysis_profile=analysis_profile,preparation_identity_sha256=fingerprint(identity),
                        bounded_extensions_started=analysis_profile in {'bounded.v1','method.v1'} and bool(pre_roots))
    if analysis_profile=='method.v1':
        prepared['root_policy']='SAPI-owning methods plus transitive reverse closure of recorded candidate_call edges; sorted explicit cap, possible contexts only'
        prepared['root_discovery']=root_discovery
    if result.summary.get('context_heap'):
        prepared['context_root_coverage']=result.summary['context_heap']['methods']
        prepared['unavailable_context_roots']=[r for r in prepared['context_root_coverage'] if r['state']!='complete']
    write(out/'prepared.json',prepared)
    progress('prepared',bu_count=len(bu_ids),sapi_matches=len(matches['matches']))
    return prepared


def recover_fact_preparation(output,sapi_catalog,snapshot,*,expected_snapshot_id):
    """Continue a failed post-fact stage without rerunning successful analyses.

    Explicit immutable snapshot identity and the existing pre-extraction
    binding are mandatory. This never rewrites the failure or old facts.
    """
    out=filesystem_path(output);snapshot=filesystem_path(snapshot)
    if (out/'prepared.json').exists():raise ValueError('Use the existing prepared result; recovery cannot replace it')
    binding=json.loads((out/'preparation-identity.json').read_text('utf-8'))
    config=PipelineConfig.model_validate_json((out/'config.json').read_text('utf-8'))
    catalog=load_catalog(sapi_catalog)
    target=filesystem_path(binding['input_storage']['path']) if binding.get('input_storage',{}).get('mode')=='read_only_reference' else out/'input.apk'
    if (sha256_file(target)!=binding['apk_sha256'] or catalog['catalog_id']!=binding['sapi_catalog_id'] or
            fingerprint(config.model_dump(mode='json'))!=binding['config_sha256']):
        raise ValueError('Recovery APK/catalog/config differs from the original pre-extraction binding')
    started=time.monotonic()
    with FactView(snapshot,snapshot_id=expected_snapshot_id) as view:
        facts=view.export_bundle()
        if facts.run.apk_sha256!=binding['apk_sha256'] or facts.run.configuration.options.get('selected_flow')!=binding['selected_flow_config']:
            raise ValueError('Snapshot has a different APK or actual selected-flow configuration')
        if binding['analysis_profile']=='method.v1' and not any(t.tool_id=='tool:spark-points-to' for t in facts.run.tools):
            raise ValueError('Method recovery cannot substitute a source without actual points-to analysis')
        matches=match_sapi(facts,catalog);records={e.id:e for e in facts.elements}
        roots=sorted({records[m['method_ref']].signature for m in matches['matches']});discovery=None
        if binding['analysis_profile']=='method.v1':roots,discovery=_sensitive_caller_roots(facts,matches)
        selected=roots[:config.max_sapi_roots]
        if selected:
            package,collection=write_units(view,sapi_catalog,out/'bu-recovered',BUConfig(root_signatures=selected,
                max_roots=config.max_sapi_roots,max_units=config.max_bu,max_tasks=config.max_bu_tasks))
            # build_units performs the full native snapshot verification before
            # collecting any BU, with checked immutable bytes until completion.
            verified={'coverage':collection['summary']['coverage']}
        else:
            verified=view.verify();package=None;collection={'units':[]}
        write(out/'sapi-matches.json',matches)
        summary_path=out/'facts'/facts.run.apk_sha256/facts.run.run_id.replace(':','_')/'summary.json'
        summary=json.loads(summary_path.read_text('utf-8')) if summary_path.exists() else {'recovered_source_coverage':verified['coverage']}
        prepared={'schema_version':'prepared-apk-pipeline.v1','apk_sha256':facts.run.apk_sha256,
            'source_path':str(target),'input_apk':str(target),'snapshot':str(snapshot),'source_run_ref':facts.run.run_id,
            'bu_package':str(package) if package else None,'selected_bu_ids':[u['bu_id'] for u in collection['units']],
            'root_policy':'Original bound root policy; Method uses SAPI owners plus actual candidate-call reverse closure',
            'available_sapi_roots':roots,'selected_roots':selected,'unprocessed_roots':roots[len(selected):],
            'physical_sapi_calls':len({m['callsite_ref'] for m in matches['matches']}),'sapi_matches':len(matches['matches']),
            'bu_count':len(collection['units']),'fact_summary':summary,'fact_coverage':verified['coverage'],
            'elapsed_seconds':None,'recovery_elapsed_seconds':time.monotonic()-started,
            'config_sha256':binding['config_sha256'],'apk_execution':False,'labels_used':False,
            'full_behavior_coverage_claimed':False,'selected_flow_config':binding['selected_flow_config'],
            'selected_flow_started':True,'analysis_profile':binding['analysis_profile'],
            'preparation_identity_sha256':fingerprint(binding),'bounded_extensions_started':binding['analysis_profile'] in {'bounded.v1','method.v1'},
            'root_discovery':discovery,'reused_successful_fact_snapshot':True,
            'original_failure_preserved':str(out/'static-failure.json') if (out/'static-failure.json').exists() else
                str(out/'static-interruption.json') if (out/'static-interruption.json').exists() else None,
            'evidence_storage':'Original APK container entries; source snapshot and failed stage are retained'}
        # Recovery preserves per-root failure/truncation just like a fresh run.
        context_roots=set(facts.run.configuration.options.get('context_heap',{}).get('root_signatures',[]))
        if context_roots:
            coverage=[]
            for method in facts.elements:
                if method.kind!='method' or not method.is_definition or method.signature not in context_roots:continue
                report=view.read_context_heap(method.id)
                coverage.append({'method_ref':method.id,'entry':context_entry_for(method.id),'state':report.state,
                    **({'reason':report.reason} if report.state!='complete' else {})})
            prepared['context_root_coverage']=sorted(coverage,key=lambda r:r['method_ref'])
            prepared['unavailable_context_roots']=[r for r in coverage if r['state']!='complete']
        write(out/'prepared.json',prepared)
        write(out/'preparation-recovery.json',{'source_snapshot_id':view.snapshot_id,
            'database_sha256':sha256_file(snapshot/'facts.sqlite'),'successful_fact_analyses_rerun':False,
            'recovered_stages':['SAPI to BU adapter','candidate inventory'],
            'recovery_elapsed_seconds':prepared['recovery_elapsed_seconds'],'new_model_calls':0})
        return prepared
