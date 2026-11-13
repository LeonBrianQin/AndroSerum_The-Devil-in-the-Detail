"""Actual Soot Spark pointer solving, retained as source-bound object evidence."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Literal

from pydantic import Field

from androserum import __version__
from .identity import canonical_json, filesystem_path, fingerprint, record_id, sha256_file
from .java_backend import JDK, PROJECT, ROOT, _normal, verify_build
from .models import (AnalysisNodeRecord, AnalysisPosition, AnalysisScope, AnalysisStatus, BindingRecord,
                     Endpoint, MethodRecord, MethodSignature, ProgramSlot, Provenance, StrictModel, ToolVersion, ValueInfo, VersionedArtifact)

TOOL='tool:spark-points-to'
RULE='rule:spark-points-to'
ENTRY='analysis/points-to/report.json'
RAW='analysis/points-to/points-to.json'


class PointsToConfig(StrictModel):
    schema_version: Literal['spark-points-to-config.v1'] = 'spark-points-to-config.v1'
    entry_methods: list[MethodSignature] = Field(default_factory=list)
    timeout_seconds: float = Field(default=180,gt=0,le=3600)
    heap_mb: int = Field(default=2048,ge=128,le=16384)
    max_methods: int = Field(default=100000,ge=1,le=1000000)


def _put(result,entry,data):
    raw=data if isinstance(data,bytes) else (canonical_json(data)+'\n').encode('utf-8')
    digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[entry]=digest


def _derive(facts,read):
    """Map actual solver output only where complete current IR agrees exactly."""
    from .call_flow import _inputs
    raw=json.loads(read(RAW));request=json.loads(read('analysis/points-to/request.json'))
    process=json.loads(read('analysis/points-to/process.json'))
    run=facts.run.run_id
    configured=PointsToConfig.model_validate(facts.run.configuration.options['points_to'])
    platform=facts.run.apk_metadata['java_platform_selection']
    if (request['run_ref']!=run or request['entry_methods']!=configured.entry_methods
            or request['max_methods']!=configured.max_methods or request['android_jar_sha256']!=platform['sha256']):
        raise ValueError('Pointer request differs from declared run/configuration/platform')
    report={'schema_version':'spark-points-to-facts.v1','run_ref':run,'apk_sha256':facts.run.apk_sha256,
            'configuration':facts.run.configuration.options['points_to'],
            'state':raw['state'],'reason':raw.get('reason'),'algorithm':raw['algorithm'],
            'context_sensitive':False,'flow_sensitive':False,'entry_scope':raw['entry_scope'],
            'entry_methods':raw.get('entry_methods',[]),'calls':[],'allocations':[], 'local_sets':[],
            'mapping_issues':[],'solver_report_sha256':hashlib.sha256(read(RAW)).hexdigest(),
            'request_sha256':hashlib.sha256(read('analysis/points-to/request.json')).hexdigest(),
            'process':process,'nodes':[],'bindings':[],
            'inference_limitations':['Flow-insensitive context-insensitive allocation-site may sets; not definite object identity or execution.',
             'Ordinary-method entries do not establish Android entry reachability; unmodeled external inputs/native/reflection retain gaps.']}
    if raw['apk_sha256']!=facts.run.apk_sha256 or request['apk_sha256']!=facts.run.apk_sha256:
        raise ValueError('Pointer solver belongs to another APK')
    if raw.get('request_sha256')!=report['request_sha256'] or process['request_sha256']!=report['request_sha256']:
        raise ValueError('Pointer request identity mismatch')
    if raw['android_jar_sha256']!=request['android_jar_sha256']:
        raise ValueError('Pointer platform identity mismatch')
    if process['state']!='exited':
        report['state']='failed';report['reason']='Pointer solver process '+process['state'];return report
    if raw['state']=='failed':return report
    commit=json.loads(read('analysis/points-to/commit.json'))
    if commit['report_sha256']!=report['solver_report_sha256'] or commit['request_sha256']!=report['request_sha256']:
        raise ValueError('Pointer solver report differs from its committed run receipt')
    if raw.get('solver_class')!='soot.jimple.spark.pag.PAG':raise ValueError('Actual Spark PAG is required')
    if any(raw['spark_options'].get(k)!=v for k,v in {'enabled':'true','vta':'false','rta':'false',
            'on-fly-cg':'true','ignore-types':'false','types-for-sites':'false','field-based':'false'}.items()):
        raise ValueError('Allocation-site Spark settings differ from the declared solver')
    flows,methods,_,_=_inputs(facts,read)
    anchor=record_id(run,'analysis',['spark-report'])
    report['nodes'].append(AnalysisNodeRecord(id=anchor,run_ref=run,kind='analysis_node',node_kind='state',
        position=AnalysisPosition(kind='analysis',artifact_path=ENTRY,position_label='spark-report'),
        provenance=Provenance(kind='static_analysis',tool_ref=TOOL,rule_ref=RULE,support_refs=sorted(methods))).model_dump(mode='json'))
    by_signature={method.signature:(ref,method) for ref,method in methods.items()}
    snapshots={r['signature']:r for r in raw['snapshots']}
    compatible={}
    for signature,(ref,method) in by_signature.items():
        snapshot=snapshots.get(signature)
        expected={'signature':signature,'units':[{'index':u.index,'text':u.text,'offsets_code_units':u.offsets_code_units} for u in method.units],
                  'locals':[l.model_dump(mode='json') for l in method.locals]}
        if snapshot!=expected:
            report['mapping_issues'].append({'method_ref':ref,'signature':signature,'reason':'Solver body/local inventory differs from retained current Jimple; no guessed unit mapping'})
        else:compatible[signature]=(ref,method)
    def point(signature,index,slot,ordinal=None):
        ref,_=compatible[signature]
        return Endpoint(element_ref=flows[ref].node_refs[index],position_label=f'unit:{index}',slot_kind=slot,slot_index=ordinal)
    mapping={}
    for relation in facts.relations:
        if relation.relation_kind=='dex_jimple_mapping' and relation.resolution=='resolved' and relation.target:
            mapping.setdefault(relation.target.element_ref,[]).append(relation.source.element_ref)
    allocation_refs={}
    for allocation in raw['allocations']:
        source=allocation['source'];support=[anchor];position=AnalysisPosition(kind='analysis',artifact_path=RAW,
            position_label='allocation:'+str(allocation['allocation_id']))
        if source and source['method_signature'] in compatible:
            mref,method=compatible[source['method_signature']];unit=method.units[source['unit']]
            if unit.text!=source['text'] or unit.offsets_code_units!=source['offsets_code_units'] or unit.operation!='allocation':
                raise ValueError('Pointer allocation origin disagrees with current IR')
            support=[anchor,mref,flows[mref].node_refs[source['unit']],*mapping.get(flows[mref].node_refs[source['unit']],[])]
        else:mref=None
        object_ref=record_id(run,'analysis',['spark-allocation',allocation['allocation_id']])
        allocation_refs[allocation['allocation_id']]=object_ref
        node=AnalysisNodeRecord(id=object_ref,run_ref=run,kind='analysis_node',node_kind='object',method_ref=mref,
            position=position,text='Spark allocation expression: '+allocation['expression'],slots=[ProgramSlot(slot_kind='value',value=ValueInfo(status='unknown',
                reason='Spark allocation-site may-object abstraction; concrete runtime instance/value is not materialized'))],provenance=Provenance(kind='static_analysis',tool_ref=TOOL,
            rule_ref=RULE,support_refs=support))
        report['nodes'].append(node.model_dump(mode='json'))
        report['allocations'].append({**allocation,'object_ref':object_ref,'source_support_refs':support,
                                     'original_location_mapped':len(support)>1})
    for local in raw['locals']:
        if local['method_signature'] not in compatible:continue
        report['local_sets'].append({**local,'method_ref':compatible[local['method_signature']][0],
                                    'object_refs':[allocation_refs[a] for a in local['allocation_ids']]})
    for call in raw['calls']:
        if call['caller_signature'] not in compatible:continue
        caller,method=compatible[call['caller_signature']];unit=method.units[call['unit']]
        if not unit.invoke or unit.text!=call['text'] or unit.invoke.signature!=call['declared_signature'] or unit.invoke.kind!=call['invoke_kind']:
            raise ValueError('Pointer callsite disagrees with current IR')
        receiver=point(call['caller_signature'],call['unit'],'receiver') if call['receiver_local'] is not None else None
        bindings={}
        for aid in call['receiver_allocation_ids']:
            binding_ref=record_id(run,'binding',['spark-receiver',caller,call['unit'],aid])
            bindings[aid]=binding_ref
            bound=BindingRecord(id=binding_ref,run_ref=run,binding_kind='object',
                endpoints=[receiver,Endpoint(element_ref=allocation_refs[aid],slot_kind='value',position_label='allocation:'+str(aid))],
                provenance=Provenance(kind='static_analysis',tool_ref=TOOL,rule_ref=RULE,
                    support_refs=[caller,receiver.element_ref,allocation_refs[aid],*mapping.get(receiver.element_ref,[])]))
            report['bindings'].append(bound.model_dump(mode='json'))
        targets=[]
        for target in call['targets']:
            targets.append({**target,'object_refs':[allocation_refs[a] for a in target['allocation_ids']],
                            'binding_refs':[bindings[a] for a in target['allocation_ids']]})
        node_ref=flows[caller].node_refs[call['unit']]
        call_ref=record_id(run,'analysis',['spark-dispatch',caller,call['unit']])
        report['nodes'].append(AnalysisNodeRecord(id=call_ref,run_ref=run,kind='analysis_node',node_kind='mapping',method_ref=caller,
            position=AnalysisPosition(kind='analysis',artifact_path=ENTRY,position_label='dispatch:'+str(call['unit'])+':'+caller),
            text=call['declared_signature'],provenance=Provenance(kind='static_analysis',tool_ref=TOOL,rule_ref=RULE,
                support_refs=[caller,node_ref,*mapping.get(node_ref,[]),*bindings.values()])).model_dump(mode='json'))
        report['calls'].append({**call,'caller_ref':caller,'unit_ref':node_ref,'callsite_refs':mapping.get(node_ref,[]),
            'evidence_ref':call_ref,'receiver_endpoint':receiver.model_dump(mode='json') if receiver else None,
            'receiver_object_refs':[allocation_refs[a] for a in call['receiver_allocation_ids']],
            'receiver_binding_refs':list(bindings.values()),'targets':targets,
            'pointer_scope':'Spark global allocation-site may set; concrete balanced frames are applied downstream'})
    if report['mapping_issues']:report['state']='partial'
    return report


def extend_points_to(result,apk,config=None):
    config=PointsToConfig.model_validate((config or PointsToConfig()).model_dump(mode='json'))
    facts=result.facts
    if any(t.tool_id==TOOL for t in facts.run.tools):raise ValueError('Create a new run for a new pointer analysis')
    platform=facts.run.apk_metadata['java_platform_selection']
    if not platform['jar']:raise ValueError('Pointer analysis requires a resolved Android platform')
    build=verify_build();apk=filesystem_path(apk)
    if sha256_file(apk)!=facts.run.apk_sha256:raise ValueError('Pointer APK bytes differ from source facts')
    req={'schema_version':'spark-request.v1','apk_path':_normal(apk),'apk_sha256':facts.run.apk_sha256,
         'android_jar':platform['jar'],'android_jar_sha256':platform['sha256'],'run_ref':facts.run.run_id,
         'entry_methods':config.entry_methods,'max_methods':config.max_methods}
    work=filesystem_path(tempfile.mkdtemp(prefix='spark_',dir=ROOT/'artifacts/work/f3'))
    _put(result,'analysis/points-to/request.json',req)
    request_bytes=result.blobs[result.entry_digests['analysis/points-to/request.json']]
    (work/'request.json').write_bytes(request_bytes)
    argv=[str(JDK/'bin/java.exe'),f'-Xmx{config.heap_mb}m','-Dfile.encoding=UTF-8','-cp',
          str(PROJECT/'target/classes')+';'+str(PROJECT/'target/dependency/*'),
          'org.androserum.backend.PointsToBackend',_normal(work/'request.json'),_normal(work)]
    with (work/'stdout.log').open('wb') as stdout,(work/'stderr.log').open('wb') as stderr:
        try:
            process=subprocess.run(argv,cwd=ROOT,stdout=stdout,stderr=stderr,timeout=config.timeout_seconds)
            state='exited' if process.returncode==0 else 'failed';code=process.returncode
        except subprocess.TimeoutExpired:state='timeout';code=None
    process={'state':state,'exit_code':code,'argv':argv,'request_sha256':hashlib.sha256(request_bytes).hexdigest()}
    for name in ['stdout.log','stderr.log','commit.json']:
        if (work/name).exists():_put(result,'analysis/points-to/'+name,(work/name).read_bytes())
    if (work/'points-to.json').exists():
        raw=(work/'points-to.json').read_bytes();commit=json.loads((work/'commit.json').read_text('utf-8'))
        if commit['report_sha256']!=hashlib.sha256(raw).hexdigest() or commit['request_sha256']!=process['request_sha256']:
            raise ValueError('Pointer backend commit identity mismatch')
        _put(result,RAW,raw)
    else:
        _put(result,RAW,{'schema_version':'spark-points-to-raw.v1','state':'failed','reason':state,
             'apk_sha256':facts.run.apk_sha256,'request_sha256':process['request_sha256'],'android_jar_sha256':platform['sha256'],
             'algorithm':'Spark inclusion-based allocation-site Andersen-style may points-to','entry_scope':'explicit ordinary methods'})
    _put(result,'analysis/points-to/process.json',process);_put(result,'analysis/points-to/build.json',build)
    facts.run.configuration.options['points_to']=config.model_dump(mode='json')
    facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='Soot Spark allocation-site points-to',version='4.7.1'))
    for source in [Path(__file__),PROJECT/'src/main/java/org/androserum/backend/PointsToBackend.java']:
        entry='analysis/rules/'+source.name;_put(result,entry,source.read_bytes())
        facts.run.artifacts.append(VersionedArtifact(artifact_id=RULE if source.suffix=='.py' else 'rule:spark-backend',kind='rule',
            name=source.name,version='1',sha256=result.entry_digests[entry],location=entry))
    report=_derive(facts,lambda e:result.blobs[result.entry_digests[e]])
    _put(result,ENTRY,report)
    facts.elements.extend(AnalysisNodeRecord.model_validate(n) for n in report['nodes'])
    facts.bindings.extend(BindingRecord.model_validate(b) for b in report['bindings'])
    status=next(s for s in facts.statuses if s.scope.kind=='run' and s.capability=='objects')
    status.tool_ref=TOOL;status.state=report['state'] if report['state'] in {'partial','failed'} else 'partial'
    status.reason=report['reason'] or 'Actual Spark may points-to solved; flow/context sensitivity and unmodeled external entry inputs remain explicit limits.'
    status.issue_code='spark_points_to_scope'
    result.summary['points_to']={'state':report['state'],'calls':len(report['calls']),'local_sets':len(report['local_sets']),
        'allocations':len(report['allocations']),'entry_methods':report['entry_methods'],'mapping_issues':report['mapping_issues']}
    from .io import loads_facts
    result.facts=loads_facts(facts.model_dump_json())
    verify_points_to(result.facts,lambda e:result.blobs[result.entry_digests[e]])
    return result


def verify_points_to(facts,read):
    own=lambda v:v.provenance.tool_ref==TOOL
    if not any(t.tool_id==TOOL for t in facts.run.tools):
        if any(own(v) for group in [facts.elements,facts.bindings] for v in group):raise ValueError('Pointer facts lack solver tool')
        return {'active':False}
    report=json.loads(read(ENTRY));expected=_derive(facts,read)
    if report!=expected:raise ValueError('Pointer facts disagree with actual source-bound solver report')
    for group,cls,actual in [('nodes',AnalysisNodeRecord,facts.elements),('bindings',BindingRecord,facts.bindings)]:
        if {v.id:v for v in actual if own(v)}!={v.id:v for v in [cls.model_validate(row) for row in report[group]]}:
            raise ValueError('Forged/missing pointer '+group)
    return {'active':True,'state':report['state'],'calls':len(report['calls']),'allocations':len(report['allocations'])}


def points_to_evidence(facts,read,refs=()):
    verify_points_to(facts,read);report=json.loads(read(ENTRY));selected=set(refs)
    return {**{k:v for k,v in report.items() if k not in {'nodes','bindings','calls'}},
            'calls':[r for r in report['calls'] if not selected or selected & {r['caller_ref'],r['unit_ref'],r['evidence_ref'],*r['callsite_refs']}]}
