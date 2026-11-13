"""Deterministic coverage disclosure beside an immutable model task report."""
from copy import deepcopy
import json
from pathlib import Path
from .approval import read
from androserum.facts.identity import filesystem_path,sha256_file
from androserum.inference.provider import write


CORE=['identity','status','approved_bc_count','findings','synthesis','issues','processed_bc_ids',
      'recall','matches','selected_legal_reference_count','cost','benign_verdict']


def publish_scope_report(model_report,prepared_file,output=None):
    source=filesystem_path(model_report);prepared_file=filesystem_path(prepared_file)
    output=filesystem_path(output or source.with_name('final-report-reviewed.json'))
    if output==source or output==prepared_file:raise ValueError('Coverage delivery cannot overwrite an accepted source')
    original=read(source);prepared=read(prepared_file)
    if original['identity']!={'apk_sha256':prepared['apk_sha256'],'source_run_ref':prepared['source_run_ref']}:
        raise ValueError('Coverage metadata belongs to a different APK/fact run')
    if sha256_file(prepared['input_apk'])!=prepared['apk_sha256']:raise ValueError('Prepared APK content changed')
    result=deepcopy(original)
    result['schema_version']='apk-pipeline-reviewed-delivery.v1'
    result['source_model_report']={'path':str(source),'sha256':sha256_file(source),'schema_version':original['schema_version'],
        'core_fields_preserved':[k for k in CORE if k in original],
        'model_findings_or_interpretation_edited':False,'new_model_calls':0}
    result.setdefault('engineering',{})['coverage_disclosure']={
        'role':'analysis_capability_and_selection_only_not_behavior_evidence',
        'source_prepared':str(prepared_file),'source_prepared_sha256':sha256_file(prepared_file),
        'source_snapshot':prepared['snapshot'],'source_bu_package':prepared.get('bu_package'),
        'root_policy':prepared.get('root_policy'),
        'selected_roots':prepared.get('selected_roots',[]),'unprocessed_roots':prepared.get('unprocessed_roots',[]),
        'physical_sapi_calls':prepared.get('physical_sapi_calls'),
        'selected_physical_sapi_calls':prepared.get('selected_physical_sapi_calls'),
        'available_BU_count':prepared.get('available_bu_count',prepared.get('bu_count')),
        'model_selected_BU_count':len(prepared['selected_bu_ids']),
        'model_selected_BU_refs':prepared['selected_bu_ids'],'fact_coverage':prepared.get('fact_coverage'),
        'selected_flow_configuration':prepared.get('selected_flow_config'),
        'unprocessed_root_interpretation':'Matched code locations outside this declared model scope; no behavior-absence inference. Extra SAPI component checks are separately audited, not inserted into findings.',
        'whole_APK_behavior_coverage_claimed':False,'additional_behavior_connections_generated':False}
    assert all(result.get(k)==original.get(k) for k in CORE)
    if output.exists():
        if read(output)!=result:raise ValueError('Retained coverage delivery differs; choose a fresh output')
    else:write(output,result)
    return {'path':str(output),'sha256':sha256_file(output),'model_report_sha256':sha256_file(source),
            'core_fields_identical':True,'new_model_calls':0}
