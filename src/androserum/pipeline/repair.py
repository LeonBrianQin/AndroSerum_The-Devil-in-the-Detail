"""Fresh, bounded evidence for a previously declared APK/mechanism scope.

Baseline snapshots are inputs to scope/identity selection only. No old facts,
BC descriptions, answers or report labels are copied into the new run.
"""
import json
import shutil
import time
from pathlib import Path
from androserum.facts.identity import filesystem_path,sha256_file,fingerprint
from androserum.facts.context_heap import ContextHeapConfig,extract_context_heap
from androserum.facts.selected_flow import load_flow_config,extend_selected_flow
from androserum.facts.operations import extend_operations
from androserum.facts.control import extend_control
from androserum.facts.events import extend_events
from androserum.facts.method_outputs import extend_method_outputs
from androserum.facts.jca_state import extend_jca_state
from androserum.facts.sapi import load_catalog,match_sapi
from androserum.facts.bu import BUConfig,write_units
from androserum.facts.store import FactView,import_snapshot
from androserum.inference.provider import write
from .config import PipelineConfig
from .evidence import write_encoded_extraction


def prepare_repair_apk(baseline_prepared,sapi_catalog,flow_config,output):
    baseline_prepared=filesystem_path(baseline_prepared);out=filesystem_path(output)
    old=json.loads(baseline_prepared.read_text('utf-8'));apk=filesystem_path(old['input_apk'])
    if sha256_file(apk)!=old['apk_sha256']:raise ValueError('Baseline APK identity changed')
    flow=load_flow_config(flow_config);catalog=load_catalog(sapi_catalog)
    identity={'apk_sha256':old['apk_sha256'],'baseline_prepared_sha256':sha256_file(baseline_prepared),
              'sapi_catalog_id':catalog['catalog_id'],'flow_configuration':flow.model_dump(mode='json'),
              'selected_roots':old['selected_roots'],'extensions':['method_outputs.v1','jca_state.v1']}
    if (out/'prepared.json').exists():
        prior=json.loads((out/'prepared.json').read_text('utf-8'))
        if prior.get('repair_binding_sha256')!=fingerprint(identity):raise ValueError('Retained repair belongs to another scope/configuration')
        if sha256_file(prior['input_apk'])!=old['apk_sha256']:raise ValueError('Retained repair APK changed')
        return prior
    if out.exists() and any(out.iterdir()):raise ValueError('Fresh bounded repair requires an empty output directory')
    started=time.monotonic();out.mkdir(parents=True,exist_ok=True);target=out/'input.apk';shutil.copyfile(apk,target)
    write(out/'repair-inputs.json',identity)
    context=ContextHeapConfig(root_signatures=old['selected_roots'],max_depth=3,max_nodes=1200,max_frames=16)
    cfg=PipelineConfig();write(out/'config.json',cfg.model_dump(mode='json'))
    parts={};clock=time.monotonic()
    print('repair: fresh facts/context start',flush=True)
    result=extract_context_heap(Path(str(target).removeprefix('\\\\?\\')),config=context)
    print('repair: facts/context complete; selected flow start',flush=True)
    parts['fresh_facts_through_context_seconds']=time.monotonic()-clock;clock=time.monotonic()
    result=extend_selected_flow(result,Path(str(target).removeprefix('\\\\?\\')),flow)
    print('repair: selected flow '+result.summary['selected_flow']['state']+'; operation/control/event/output/JCA start',flush=True)
    parts['selected_flow_seconds']=time.monotonic()-clock;clock=time.monotonic()
    result=extend_events(extend_control(extend_operations(result)))
    result=extend_jca_state(extend_method_outputs(result))
    print('repair: finite models complete; snapshot import start',flush=True)
    parts['operations_control_events_outputs_jca_seconds']=time.monotonic()-clock;clock=time.monotonic()
    snapshot=import_snapshot(write_encoded_extraction(result,out/'facts',input_apk=target),out/'stores')
    with FactView(snapshot) as view:
        facts=view.export_bundle();records={e.id:e for e in facts.elements};matches=match_sapi(facts,catalog)
        write(out/'sapi-matches.json',matches)
        roots=sorted({records[m['method_ref']].signature for m in matches['matches']})
        selected=old['selected_roots']
        print('repair: snapshot imported; bounded BU construction start',flush=True)
        package,units=write_units(view,sapi_catalog,out/'bu',BUConfig(root_signatures=selected,max_roots=16,max_units=32,max_tasks=2000))
        jca=view.jca_evidence();write(out/'jca-public-query.json',jca)
        from androserum.facts.method_outputs import method_output_evidence
        outputs=method_output_evidence(facts,view.read_evidence,[]);write(out/'method-output-public-query.json',outputs)
        view.verify()
    print('repair: BU and public queries verified',flush=True)
    parts['snapshot_bu_and_public_queries_seconds']=time.monotonic()-clock
    selected_matches=[m for m in matches['matches'] if records[m['method_ref']].signature in selected]
    prepared={'schema_version':'prepared-apk-pipeline.v1','apk_sha256':old['apk_sha256'],'source_path':str(apk),
        'input_apk':str(target),'snapshot':str(snapshot),'source_run_ref':facts.run.run_id,'bu_package':str(package),
        'selected_bu_ids':[u['bu_id'] for u in units['units']],'bu_count':len(units['units']),
        'sapi_matches':len(matches['matches']),'physical_sapi_calls':len({m['callsite_ref'] for m in matches['matches']}),
        'selected_physical_sapi_calls':len({m['callsite_ref'] for m in selected_matches}),
        'available_sapi_roots':roots,'selected_roots':selected,'unprocessed_roots':[r for r in roots if r not in selected],
        'root_policy':'Same declared mechanism roots as baseline; extra SAPI roots matched but not broadened into this model run',
        'fact_summary':result.summary,'fact_coverage':{s.capability:s.state for s in facts.statuses if s.scope.kind=='run'},
        'elapsed_seconds':time.monotonic()-started,'phase_timings':parts,
        'elapsed_scope':'Fresh F1/context, actual selected FlowDroid, F5/F6/F7, method-output/JCA, import/BU/public checks; excludes model calls and review',
        'config_sha256':fingerprint(cfg.model_dump(mode='json')),'repair_binding_sha256':fingerprint(identity),
        'selected_flow_config':flow.model_dump(mode='json'),'apk_execution':False,'labels_used':False,
        'new_static_analysis_run':True,'baseline_modified':False,'full_behavior_coverage_claimed':False}
    write(out/'prepared.json',prepared);return prepared
