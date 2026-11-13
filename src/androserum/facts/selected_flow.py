"""Pinned selected FlowDroid execution and conservative current-fact mapping."""
import hashlib
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Literal

from pydantic import Field,model_validator
from androserum import __version__
from androserum.facts.context_heap import extract_context_heap
from androserum.facts.identity import canonical_json,fingerprint,filesystem_path,parse_method_signature,record_id,sha256_file
from androserum.facts.io import loads_facts,strict_json_syntax
from androserum.facts.models import (AnalysisNodeRecord,AnalysisPosition,AnalysisScope,AnalysisStatus,Endpoint,InstructionRecord,MethodRecord,
    MethodSignature,Provenance,RelationRecord,StrictModel,ToolVersion,VersionedArtifact)

ROOT=Path(__file__).resolve().parents[3];PROJECT=ROOT/'java/flow-backend';ENTRY='analysis/selected-flow/report.json'
TOOL='tool:selected-flow';RULE='rule:selected-flow'
P='Lorg/androserum/pipeline/MainActivity;'


class FlowConfig(StrictModel):
    schema_version:Literal['selected-flow-config.v1']='selected-flow-config.v1'
    platform_api:int=Field(default=28,ge=1)
    sources:list[MethodSignature]=Field(default_factory=lambda:[P+'->source()Ljava/lang/String;','Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;'])
    sinks:list[MethodSignature]=Field(default_factory=lambda:[P+'->'+x+'(Ljava/lang/String;)V' for x in ['positiveSink','negativeSink','jointSink']])
    callbacks:bool=False
    timeout_seconds:float=Field(default=120,gt=0,le=3600)
    solver_timeout:int=Field(default=60,ge=1,le=3600)
    heap_mb:int=Field(default=2048,ge=128,le=16384)
    taint_wrapper:Literal['none']='none'
    implicit_flows:Literal['disabled']='disabled'
    @model_validator(mode='after')
    def selected_scope(self):
        if not self.sources or not self.sinks:raise ValueError('Explicit source/sink sets are required')
        if any(parse_method_signature(s)[3]=='V' for s in self.sources):raise ValueError('v1 sources use return values')
        if any(len(parse_method_signature(s)[2])!=1 for s in self.sinks):raise ValueError('v1 sinks have one explicit argument')
        return self


class MethodFlowConfig(FlowConfig):
    schema_version:Literal['selected-method-flow-config.v2']='selected-method-flow-config.v2'
    entry_methods:list[MethodSignature]=Field(min_length=1,max_length=16)
    callbacks:Literal[False]=False
    entry_scope:Literal['conditional_explicit_methods_not_android_reachability']='conditional_explicit_methods_not_android_reachability'


class SummaryFlowConfig(FlowConfig):
    schema_version:Literal['selected-summary-flow-config.v3']='selected-summary-flow-config.v3'
    taint_wrapper:Literal['none','flowdroid_summary']='flowdroid_summary'
    summary_resource_id:Literal['flowdroid-summaries:2.15.1:summariesManual']='flowdroid-summaries:2.15.1:summariesManual'
    summary_max_events:int=Field(default=4000,ge=1,le=100000)
    entry_scope:Literal['android_model','conditional_explicit_methods_not_android_reachability']='android_model'
    entry_methods:list[MethodSignature]=Field(default_factory=list,max_length=16)
    @model_validator(mode='after')
    def summary_entry(self):
        if self.entry_scope=='conditional_explicit_methods_not_android_reachability':
            if not self.entry_methods or self.callbacks:raise ValueError('Explicit summary entry requires methods and callbacks disabled')
        elif self.entry_methods:raise ValueError('Android summary entry cannot silently use explicit method entries')
        return self


def load_flow_config(value):
    data=value.model_dump() if isinstance(value,FlowConfig) else value
    model={'selected-method-flow-config.v2':MethodFlowConfig,'selected-summary-flow-config.v3':SummaryFlowConfig}.get(data.get('schema_version'),FlowConfig)
    return model.model_validate(data)


def _explicit_entry(config):
    return isinstance(config,MethodFlowConfig) or (isinstance(config,SummaryFlowConfig) and config.entry_scope=='conditional_explicit_methods_not_android_reachability')


def _native(path):
    text=str(Path(path).resolve())
    return ('\\\\'+text[8:] if text.startswith('\\\\?\\UNC\\') else text[4:] if text.startswith('\\\\?\\') else text)


def soot_signature(signature):
    owner,name,params,result=parse_method_signature(signature)
    def value(t):
        if t.startswith('['):return value(t[1:])+'[]'
        return {'V':'void','Z':'boolean','B':'byte','C':'char','S':'short','I':'int','J':'long','F':'float','D':'double'}.get(t,t[1:-1].replace('/','.'))
    return '<'+value(owner)+': '+value(result)+' '+name+'('+','.join(value(p) for p in params)+')>'


def selected_rules(config):
    return '\n'.join([soot_signature(x)+' -> _SOURCE_' for x in config.sources]+[soot_signature(x)+' -> _SINK_' for x in config.sinks])+'\n'


def build_flow_backend():
    env=os.environ.copy();env['JAVA_HOME']=str(ROOT/'.tools/jdk-17');env['PATH']=str(ROOT/'.tools/jdk-17/bin')+os.pathsep+env['PATH']
    argv=[str(ROOT/'.tools/apache-maven-3.9.16/bin/mvn.cmd'),'-o','-B','-s',str(ROOT/'configs/maven-settings.xml'),
        '-Dmaven.repo.local='+str(ROOT/'.tools/m2'),'-f',str(PROJECT/'pom.xml'),'package','dependency:copy-dependencies']
    process=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,timeout=180)
    target=PROJECT/'target';target.mkdir(parents=True,exist_ok=True)
    (target/'build.stdout.log').write_bytes(process.stdout);(target/'build.stderr.log').write_bytes(process.stderr)
    if process.returncode:raise ValueError('Flow backend build failed; see java/flow-backend/target/build.stdout.log')
    sources=[PROJECT/'pom.xml',*sorted((PROJECT/'src').rglob('*.java'))]
    outputs=[target/'flow-backend-0.1.0.jar',*sorted((target/'classes').rglob('*.class')),*sorted((target/'dependency').glob('*.jar'))]
    report={'schema_version':'flow-build.v1','source_sha256':{p.relative_to(ROOT).as_posix():sha256_file(p) for p in sources},
        'output_sha256':{p.relative_to(ROOT).as_posix():sha256_file(p) for p in outputs},'java_sha256':sha256_file(ROOT/'.tools/jdk-17/bin/java.exe'),'argv':argv}
    (target/'build.json').write_text(canonical_json(report),encoding='utf-8');return report


def verify_flow_build():
    report=json.loads((PROJECT/'target/build.json').read_text('utf-8'))
    sources=[PROJECT/'pom.xml',*sorted((PROJECT/'src').rglob('*.java'))]
    if report['source_sha256']!={p.relative_to(ROOT).as_posix():sha256_file(p) for p in sources}:raise ValueError('Stale flow worker; rebuild required')
    if report['java_sha256']!=sha256_file(ROOT/'.tools/jdk-17/bin/java.exe') or any(sha256_file(ROOT/p)!=d for p,d in report['output_sha256'].items()):raise ValueError('Flow worker/runtime checksum mismatch')
    return report


def map_flow(facts,config,raw):
    methods={x.id:x for x in facts.elements if isinstance(x,MethodRecord)}
    calls={}
    for record in facts.elements:
        if isinstance(record,InstructionRecord) and record.operation=='invoke':
            signature=methods[record.position.method_ref].signature
            calls.setdefault((signature,record.position.offset_bytes,record.declared_target.signature),[]).append(record)
    def locate(stmt):
        if stmt is None:return {'state':'unresolved','reason':'Missing FlowDroid statement'}
        offsets=stmt.get('offsets_code_units',[])
        if stmt.get('model_generated') or len(set(offsets))!=1 or not stmt.get('invoke_signature'):
            return {'state':'unresolved','reason':'Model/non-call/missing or ambiguous offset','statement':stmt}
        found=calls.get((stmt.get('method_signature'),offsets[0]*2,stmt['invoke_signature']),[])
        if len(found)!=1:return {'state':'unresolved','reason':'No unique offset/signature-verified current invocation','statement':stmt}
        return {'state':'resolved','record_ref':found[0].id,'statement':stmt}
    result=[]
    for index,flow in enumerate(raw.get('flows',[])):
        source,sink=locate(flow['source']),locate(flow['sink'])
        issues=[]
        if _explicit_entry(config) and flow.get('sink_argument_index')!=0:
            issues.append('Explicit-method flow lacks verified sink argument-zero role')
        if flow['source'].get('invoke_signature') not in config.sources or flow['sink'].get('invoke_signature') not in config.sinks:
            issues.append('Flow endpoints outside configured selected rules')
        if source['state']!='resolved' or sink['state']!='resolved':issues.append('Source/sink mapping incomplete')
        source_point=sink_point=None
        if not issues:
            records={x.id:x for x in facts.elements};a,b=records[source['record_ref']],records[sink['record_ref']]
            if not any(x.slot_kind=='result' for x in a.slots) or not any(x.slot_kind=='argument' and x.slot_index==0 for x in b.slots):issues.append('Selected endpoint slot unavailable')
            else:
                source_point=Endpoint(element_ref=a.id,slot_kind='result',position_label=a.position.position_label).model_dump(mode='json')
                sink_point=Endpoint(element_ref=b.id,slot_kind='argument',slot_index=0,position_label=b.position.position_label).model_dump(mode='json')
        path=[locate(x) for x in flow.get('path',[])]
        result.append({'raw_index':index,'source':source,'sink':sink,'path':path,'source_endpoint':source_point,'sink_endpoint':sink_point,
            'issues':issues,'path_mapping_complete':bool(path) and all(x['state']=='resolved' for x in path)})
    return result


def _emit(facts,report):
    run=facts.run.run_id;anchor=record_id(run,'analysis',['selected-flow'])
    support=[x.id for x in facts.elements if x.provenance.tool_ref!=TOOL][:1]
    if not support:return [],[]
    node=AnalysisNodeRecord(id=anchor,run_ref=run,kind='analysis_node',node_kind='state',position=AnalysisPosition(kind='analysis',artifact_path=ENTRY,position_label='selected-flow'),
        provenance=Provenance(kind='static_analysis',tool_ref=TOOL,rule_ref=RULE,support_refs=support))
    edges=[]
    for row in report['mapped']:
        if row['issues'] or not row['source_endpoint'] or not row['sink_endpoint']:continue
        refs=[anchor,row['source']['record_ref'],row['sink']['record_ref']]
        refs.extend(x['record_ref'] for x in row['path'] if x['state']=='resolved')
        edges.append(RelationRecord(id=record_id(run,'relation',['selected-flow',row['raw_index']]),run_ref=run,
            provenance=Provenance(kind='static_analysis',tool_ref=TOOL,rule_ref=RULE,support_refs=list(dict.fromkeys(refs))),relation_kind='information_flow',
            source=Endpoint(**row['source_endpoint']),target=Endpoint(**row['sink_endpoint']),resolution='partial',
            unresolved_reason='Selected FlowDroid/model inference; intermediate mapping/path feasibility may remain unknown',source_selector=ENTRY+f"#/mapped/{row['raw_index']}"))
    return [node],edges


def extend_selected_flow(result,apk,config=None):
    config=load_flow_config(config or FlowConfig());facts=result.facts;run=facts.run.run_id
    summary_profile=isinstance(config,SummaryFlowConfig);accepted_raw=None
    def blob(entry,data):
        digest=hashlib.sha256(data).hexdigest();result.blobs[digest]=data;result.entry_digests[entry]=digest;return digest
    facts.run.configuration.options['selected_flow']=config.model_dump(mode='json');facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='FlowDroid selected information flow',version='2.15.1'))
    source=Path(__file__).read_bytes();digest=blob('analysis/rules/selected_flow.py',source)
    facts.run.artifacts.append(VersionedArtifact(artifact_id=RULE,kind='rule',name='selected-flow-mapping',version='1',sha256=digest,location='analysis/rules/selected_flow.py'))
    rules=selected_rules(config)
    rules_hash=blob('analysis/selected-flow/SourcesAndSinks.txt',rules.encode())
    facts.run.artifacts.append(VersionedArtifact(artifact_id='rule:selected-source-sink',kind='rule',name='explicit source/sink and configured native-summary policy' if summary_profile else 'explicit source/sink and no-wrapper policy',version='1',sha256=rules_hash,location='analysis/selected-flow/SourcesAndSinks.txt'))
    report={'schema_version':'selected-flow-report.v1','run_ref':run,'apk_sha256':facts.run.apk_sha256,'configuration':config.model_dump(mode='json'),
        'state':'unavailable','reason':None,'raw_entry':None,'mapped':[],'framework_entry_joint_validation':'pending_F7','mapping_policy':'offset_bytes=DEX_code_units*2 and full method/invoke signatures'}
    work=Path(tempfile.mkdtemp(prefix='flow_',dir=ROOT/'artifacts/work'))
    platform=ROOT/f'.tools/android-sdk/platforms/android-{config.platform_api}/android.jar'
    try:
        if summary_profile:
            from .flow_summaries import summary_request,JAR_ENTRY
            summary_policy,summary_assets=summary_request(config)
            for entry,data in summary_assets.items():blob(entry,data)
            if summary_assets:
                facts.run.artifacts.append(VersionedArtifact(artifact_id='rule:flowdroid-native-summaries',kind='summary',
                    name='Official FlowDroid native library summaries, separate from selected JCA model',version='2.15.1',
                    sha256=result.entry_digests[JAR_ENTRY],location=JAR_ENTRY))
            blob('analysis/rules/SummarySupport.java',(PROJECT/'src/main/java/org/androserum/flow/SummarySupport.java').read_bytes())
        build=verify_flow_build();blob('analysis/selected-flow/build.json',canonical_json(build).encode())
        worker_name='SelectedMethodFlowBackend' if _explicit_entry(config) else 'FlowBackend'
        worker=(PROJECT/f'src/main/java/org/androserum/flow/{worker_name}.java').read_bytes();worker_hash=blob('analysis/rules/FlowBackend.java',worker)
        facts.run.artifacts.append(VersionedArtifact(artifact_id='rule:flow-worker',kind='rule',name='FlowDroid worker',version='1',sha256=worker_hash,location='analysis/rules/FlowBackend.java'))
        if not platform.is_file():raise ValueError('Selected Android platform unavailable')
        request={'run_ref':run,'apk':_native(apk),'apk_sha256':facts.run.apk_sha256,'android_jar':_native(platform),
            'android_jar_sha256':sha256_file(platform),'rules_sha256':rules_hash,'rules_file':str(work/'SourcesAndSinks.txt'),
            'callbacks':config.callbacks,'solver_timeout':config.solver_timeout}
        if summary_profile:request['summary_config']=summary_policy
        if _explicit_entry(config):
            request.update(entry_methods=[soot_signature(s) for s in config.entry_methods],
                           source_methods=[soot_signature(s) for s in config.sources],
                           sink_methods=[soot_signature(s) for s in config.sinks],entry_scope=config.entry_scope)
            blob('analysis/rules/FlowBackend-support.java',(PROJECT/'src/main/java/org/androserum/flow/FlowBackend.java').read_bytes())
            report['framework_entry_joint_validation']='not_applicable_explicit_method_scope'
        request_raw=canonical_json(request).encode();blob('analysis/selected-flow/request.json',request_raw)
        (work/'request.json').write_bytes(request_raw);(work/'SourcesAndSinks.txt').write_bytes(rules.encode('utf-8'))
        argv=[str(ROOT/'.tools/jdk-17/bin/java.exe'),f'-Xmx{config.heap_mb}m','-Dfile.encoding=UTF-8','-cp',str(PROJECT/'target/classes')+';'+str(PROJECT/'target/dependency/*'),
            'org.androserum.flow.'+worker_name,str(work/'request.json'),str(work/'result.json')]
        process=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=config.timeout_seconds)
        blob('analysis/selected-flow/stdout.log',process.stdout);blob('analysis/selected-flow/stderr.log',process.stderr)
        report['process']={'argv':argv,'exit_code':process.returncode,'timeout_seconds':config.timeout_seconds}
        if not (work/'result.json').is_file():raise ValueError('Worker produced no complete output')
        raw_bytes=(work/'result.json').read_bytes();strict_json_syntax(raw_bytes.decode('utf-8'));raw=json.loads(raw_bytes)
        if raw['request_sha256']!=hashlib.sha256(request_raw).hexdigest() or raw['run_ref']!=run or raw['apk_sha256']!=facts.run.apk_sha256 or raw['rules_sha256']!=rules_hash or raw['android_jar_sha256']!=request['android_jar_sha256']:
            raise ValueError('Flow output is not bound to current request/APK/rules/platform')
        if summary_profile:
            from .flow_summaries import validate_summary_worker
            validate_summary_worker(raw,config,request,lambda e:result.blobs[result.entry_digests[e]])
        accepted_raw=raw
        report['state'],report['reason']=raw['state'],raw.get('reason')
        report['raw_entry']='analysis/selected-flow/raw.json';report['raw_sha256']=blob(report['raw_entry'],raw_bytes)
        report['mapped']=map_flow(facts,config,raw)
    except subprocess.TimeoutExpired as error:
        report['state'],report['reason']='truncated','FlowDroid process timeout; no complete output accepted'
        blob('analysis/selected-flow/stdout.log',error.stdout or b'');blob('analysis/selected-flow/stderr.log',error.stderr or b'')
    except (OSError,ValueError,KeyError) as error:report['state'],report['reason']='unavailable',str(error)
    blob(ENTRY,canonical_json(report).encode())
    if summary_profile:
        from .flow_summaries import make_summary_report,ENTRY as SUMMARY_ENTRY
        evidence=make_summary_report(facts,report,accepted_raw,lambda e:result.blobs[result.entry_digests[e]])
        blob(SUMMARY_ENTRY,canonical_json(evidence).encode())
    nodes,edges=_emit(facts,report);facts.elements.extend(nodes);facts.relations.extend(edges)
    facts.statuses.append(AnalysisStatus(id=record_id(run,'status',['selected-flow']),run_ref=run,tool_ref=TOOL,capability='data_flow',
        scope=AnalysisScope(kind='element',element_ref=nodes[0].id) if nodes else AnalysisScope(kind='run'),state='partial' if report['state']=='complete' else report['state'],
        reason='Only configured flows; mapping, Android entry/callback coverage and full behavior remain limited' if report['state']=='complete' else report['reason'] or 'Worker analysis incomplete'))
    result.facts=loads_facts(facts.model_dump_json());verify_selected_flow(result.facts,lambda e:result.blobs[result.entry_digests[e]])
    result.summary.update(stage='F4-C3',selected_flow={'state':report['state'],'flows':len(report['mapped']),'mapped_endpoints':len(edges),'reason':report['reason']},outcome='failed' if result.summary['outcome']=='failed' else 'partial',
        element_counts=dict(Counter(x.kind for x in facts.elements)),relation_counts=dict(Counter(x.relation_kind for x in facts.relations)))
    return result


def extract_selected_flow(apk,*,config=None,context_config=None):return extend_selected_flow(extract_context_heap(apk,config=context_config),apk,config)


def verify_selected_flow(facts,read):
    own=lambda x:x.provenance.tool_ref==TOOL or x.provenance.rule_ref==RULE
    nodes={x.id:x for x in facts.elements if own(x)};edges={x.id:x for x in facts.relations if own(x) or x.source_selector and x.source_selector.startswith('analysis/selected-flow/')}
    if not any(x.tool_id==TOOL for x in facts.run.tools):
        if nodes or edges:raise ValueError('Selected flow records lack tool metadata')
        return
    report=json.loads(read(ENTRY));config=load_flow_config(facts.run.configuration.options['selected_flow'])
    if report['run_ref']!=facts.run.run_id or report['apk_sha256']!=facts.run.apk_sha256 or report['configuration']!=config.model_dump(mode='json'):raise ValueError('Flow report identity/config mismatch')
    if read('analysis/selected-flow/SourcesAndSinks.txt')!=selected_rules(config).encode():raise ValueError('Source/sink resource differs from selected configuration')
    if report['raw_entry']:
        raw_bytes=read(report['raw_entry']);raw=json.loads(raw_bytes);request=read('analysis/selected-flow/request.json');req=json.loads(request)
        if hashlib.sha256(raw_bytes).hexdigest()!=report['raw_sha256'] or raw['request_sha256']!=hashlib.sha256(request).hexdigest() or raw['run_ref']!=facts.run.run_id or raw['apk_sha256']!=facts.run.apk_sha256 or raw['rules_sha256']!=hashlib.sha256(read('analysis/selected-flow/SourcesAndSinks.txt')).hexdigest() or raw['android_jar_sha256']!=req['android_jar_sha256']:
            raise ValueError('Flow raw output lacks current input binding')
        if report['mapped']!=map_flow(facts,config,raw) or report['state']!=raw['state']:raise ValueError('Flow endpoint/path mapping mismatch')
        if raw.get('callbacks',config.callbacks)!=config.callbacks:raise ValueError('Flow callback policy mismatch')
        if _explicit_entry(config):
            expected=[soot_signature(s) for s in config.entry_methods]
            if req.get('entry_methods')!=expected or raw.get('entry_methods')!=expected or req.get('entry_scope')!=config.entry_scope:
                raise ValueError('Explicit conditional method entry scope mismatch')
            if req.get('source_methods')!=[soot_signature(s) for s in config.sources] or req.get('sink_methods')!=[soot_signature(s) for s in config.sinks]:
                raise ValueError('Explicit method source/sink policy mismatch')
            if raw['state']=='complete' and (not raw.get('discovered_sources') or not raw.get('discovered_sinks')):
                raise ValueError('No-source/no-sink worker result cannot be accepted as completed flow validation')
    elif report['mapped'] or report['state'] in {'complete','partial'}:raise ValueError('Successful/mapped flows lack complete worker output')
    expected_nodes,expected_edges=_emit(facts,report)
    if nodes!={x.id:x for x in expected_nodes} or edges!={x.id:x for x in expected_edges}:raise ValueError('Forged selected information-flow facts')
    if isinstance(config,SummaryFlowConfig):
        from .flow_summaries import verify_summary_evidence
        verify_summary_evidence(facts,read)
