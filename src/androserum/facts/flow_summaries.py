"""Pinned native FlowDroid summary resources and current-call audit mapping.

The Java SummaryTaintWrapper performs propagation. This module verifies its
resources and maps reported wrapper observations; it does not replace a solver
with hand-authored library/JCA propagation rules.
"""
from copy import deepcopy
from io import BytesIO
import hashlib
import json
from pathlib import Path
import re
import zipfile
import xml.etree.ElementTree as ET

from .identity import canonical_json, fingerprint
from .models import Endpoint, InstructionRecord, MethodRecord

ROOT = Path(__file__).resolve().parents[3]
RESOURCE = ROOT/'.resources/flowdroid-summaries/2.15.1'
RESOURCE_ID = 'flowdroid-summaries:2.15.1:summariesManual'
JAR_NAME = 'soot-infoflow-summaries-2.15.1.jar'
JAR_SHA256 = '30c627520f0dee3d2612a662d48483eda43b8c80b4fd5153b6e24032ceb35c8f'
MANIFEST_SHA256 = 'cff96f874a21a62c425358c34c3d98843f5e4943823c14663ade87927cd8167f'
MANIFEST_ENTRY = 'analysis/flow-summaries/manifest.json'
JAR_ENTRY = 'analysis/flow-summaries/'+JAR_NAME
ENTRY = 'analysis/flow-summaries/report.json'
FLOW_ENTRY = 'analysis/selected-flow/report.json'


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _verify_bundle(manifest_raw, jar_raw):
    if _sha(manifest_raw)!=MANIFEST_SHA256 or _sha(jar_raw)!=JAR_SHA256:
        raise ValueError('Pinned FlowDroid summary resource identity differs')
    manifest=json.loads(manifest_raw)
    if manifest['resource_id']!=RESOURCE_ID:raise ValueError('Unknown native summary bundle')
    with zipfile.ZipFile(BytesIO(jar_raw)) as archive:
        entries=sorted(n for n in archive.namelist() if n.startswith('summariesManual/') and n.endswith('.xml'))
        if entries!=[x['jar_entry'] for x in manifest['xml_files']]:raise ValueError('Native summary XML inventory differs')
        for item in manifest['xml_files']:
            raw=archive.read(item['jar_entry'])
            if _sha(raw)!=item['sha256'] or len(raw)!=item['bytes']:raise ValueError('Native summary XML identity differs')
    return manifest


def summary_request(config):
    """Return the real worker policy and immutable assets; never download here."""
    policy={'mode':config.taint_wrapper,'resource_id':RESOURCE_ID,'manifest_sha256':MANIFEST_SHA256,
            'max_events':config.summary_max_events}
    if config.taint_wrapper=='none':return policy,{}
    manifest_raw=(RESOURCE/'manifest.json').read_bytes();jar_raw=(RESOURCE/JAR_NAME).read_bytes()
    manifest=_verify_bundle(manifest_raw,jar_raw)
    for item in manifest['xml_files']:
        if _sha((RESOURCE/item['jar_entry']).read_bytes())!=item['sha256']:
            raise ValueError('Local native summary XML differs: '+item['name'])
    directory=RESOURCE/'summariesManual'
    if {p.name for p in directory.iterdir() if p.is_file()}!={x['name'] for x in manifest['xml_files']}:
        raise ValueError('Local native summary directory inventory differs')
    policy.update(jar=str(RESOURCE/JAR_NAME),jar_sha256=JAR_SHA256,directory=str(directory),
                  xml_files=[{'name':x['name'],'sha256':x['sha256']} for x in manifest['xml_files']])
    assets={MANIFEST_ENTRY:manifest_raw,JAR_ENTRY:jar_raw}
    for item in manifest['files']:
        if item['name']==JAR_NAME:continue
        raw=(RESOURCE/item['name']).read_bytes()
        if _sha(raw)!=item['sha256']:raise ValueError('Pinned FlowDroid summary source/POM differs')
        assets['analysis/flow-summaries/'+item['name']]=raw
    return policy,assets


def validate_summary_worker(raw,config,request,read):
    """Actual load metadata is mandatory for successful v3 worker results."""
    audit=raw.get('summary_wrapper')
    if raw['state']=='failed':
        if not audit or audit.get('state') not in {'failed','loaded','disabled'}:
            raise ValueError('Failed summary worker omitted its loading state')
        return
    if not audit or audit.get('mode')!=config.taint_wrapper:
        raise ValueError('Summary worker omitted the explicit wrapper policy')
    if audit.get('resource_id')!=RESOURCE_ID or audit.get('manifest_sha256')!=MANIFEST_SHA256:
        raise ValueError('Summary worker resource identity differs')
    if config.taint_wrapper=='none':
        if audit['state']!='disabled' or audit.get('applications') or audit.get('loaded_classes'):
            raise ValueError('Disabled wrapper was reported as loaded or applied')
        return
    manifest=_verify_bundle(read(MANIFEST_ENTRY),read(JAR_ENTRY))
    expected={x['name'][:-4] for x in manifest['xml_files'] if x['name']!='SummaryMetaData.xml'}
    if (audit['state']!='loaded' or audit.get('provider_loading_errors') or audit.get('fallback_wrapper') is not None
        or audit.get('provider')!=manifest['provider'] or audit.get('wrapper')!=manifest['wrapper']
        or not expected<=set(audit.get('loaded_classes',[]))):
        raise ValueError('Real pinned summary provider/wrapper was not fully loaded')
    omitted=audit.get('omitted_event_count',0)
    if (len(audit.get('applications',[]))>config.summary_max_events or type(omitted) is not int or omitted<0
        or audit.get('event_capture_truncated',False)!=(omitted>0)
        or audit.get('supported_wrapper_calls',0)>audit.get('wrapper_calls',0)):
        raise ValueError('Wrapper observation budget/count/truncation metadata differs')
    policy=request['summary_config']
    if (policy.get('jar_sha256')!=JAR_SHA256 or policy.get('max_events')!=config.summary_max_events
        or policy.get('xml_files')!=[{'name':x['name'],'sha256':x['sha256']} for x in manifest['xml_files']]):
        raise ValueError('Worker summary resource/event policy differs')


def _locator(facts):
    methods={x.id:x for x in facts.elements if isinstance(x,MethodRecord)};calls={}
    for item in facts.elements:
        if isinstance(item,InstructionRecord) and item.operation=='invoke':
            key=(methods[item.position.method_ref].signature,item.position.offset_bytes,item.declared_target.signature)
            calls.setdefault(key,[]).append(item)
    def locate(stmt):
        if not stmt:return None,'missing_statement'
        offsets=stmt.get('offsets_code_units',[])
        if stmt.get('model_generated') or len(set(offsets))!=1 or not stmt.get('invoke_signature'):
            return None,'model_noninvoke_or_ambiguous_offset'
        found=calls.get((stmt.get('method_signature'),offsets[0]*2,stmt['invoke_signature']),[])
        return (found[0],None) if len(found)==1 else (None,'no_unique_current_offset_and_full_signature')
    return locate


def _path_roles(path,record):
    points=[];issues=[]
    for role in path['roles']:
        kind=role['role'];index=role['index'] if kind=='argument' else None
        if not record or not any(s.slot_kind==kind and s.slot_index==index for s in record.slots):
            issues.append({'role':role,'reason':'current_operation_slot_unavailable'});continue
        points.append(Endpoint(element_ref=record.id,slot_kind=kind,slot_index=index,
                               position_label=record.position.position_label).model_dump(mode='json'))
    return {'endpoint_candidates':points,'role_issues':issues,'solver_access_path':deepcopy(path),
            'abstract_state':{'kind':'flowdroid_access_path_state','fields':path['fields'],
                'taint_subfields':path['taint_subfields'],'array_taint_type':path['array_taint_type'],
                'is_concrete_APK_storage_identity':False},
            'role_ambiguity_retained':len(points)!=1}


def _norm(value):return re.sub(r'\s+','',str(value)).replace('<','').replace('>','')


def _same_end(native,xml):
    for key in ['sourceSinkType','ParameterIndex','AccessPath','gap']:
        a=native.get(key);b=xml.get(key)
        if key=='AccessPath':
            if _norm(a or '')!=_norm(b or ''):return False
        elif a!=b:return False
    return True


def _native_refs(native,archive,manifest):
    name='summariesManual/'+native['class_name']+'.xml'
    item=next((x for x in manifest['xml_files'] if x['jar_entry']==name),None)
    result=[]
    for rule in native['rules']:
        refs=[];reason=None
        if item:
            tree=ET.fromstring(archive.read(name))
            for method in tree.findall('./methods/method'):
                if method.attrib.get('id')!=rule['method']:continue
                for index,flow in enumerate(method.findall('./flows/flow')):
                    a,b=flow.find('from'),flow.find('to')
                    if a is not None and b is not None and _same_end(rule['from'],a.attrib) and _same_end(rule['to'],b.attrib):
                        refs.append({'jar_entry':name,'XML_sha256':item['sha256'],'method':rule['method'],'flow_index':index,
                                     'native_flow_attributes':dict(flow.attrib),'from':dict(a.attrib),'to':dict(b.attrib)})
        if not refs:reason='resolved_class_or_native_rule_not_uniquely_projected_to_original_XML; retained_without_fabricated_rule_ref'
        result.append({'native_rule':rule,'XML_rule_candidates':refs,'mapping_state':'mapped' if refs else 'unresolved','reason':reason,
                       'roles':{'from':_summary_role(rule['from']),'to':_summary_role(rule['to'])},
                       'individually_fired_rule_proven':False})
    return {'resolved_class':native['class_name'],'rules':result}


def _summary_role(end):
    kind=end.get('sourceSinkType')
    return {'role':{'Parameter':'parameter','Return':'return','Field':'receiver_state','GapBaseObject':'callback_gap_base'}.get(kind,'unknown'),
            'parameter_index':end.get('ParameterIndex'),'access_path':end.get('AccessPath'),
            'state_scope':'Native FlowDroid abstract state, not concrete bytes or successful runtime mutation' if kind=='Field' else None}


def make_summary_report(facts,flow_report,raw,read):
    config=flow_report['configuration'];mode=config['taint_wrapper'];audit=raw.get('summary_wrapper') if raw else None
    report={'schema_version':'flowdroid-summary-evidence.v1','run_ref':facts.run.run_id,'APK_sha256':facts.run.apk_sha256,
            'configuration':config,'resource_id':RESOURCE_ID,'resource_state':audit['state'] if audit else ('disabled' if mode=='none' else 'not_confirmed'),
            'worker_audit':deepcopy(audit),'applications':[],'issues':[],'execution_claim':'possible_only',
            'fine_grained_paths_claimed':False,'JCA_special_model_separate':True,
            'scope':'Real SummaryTaintWrapper observations and native XML candidates; solver effects and evidence mapping remain distinct.'}
    if mode=='none':return report
    if not audit or audit['state']!='loaded':
        report['issues'].append({'kind':'summary_loading_not_confirmed','reason':flow_report['reason']});return report
    manifest=_verify_bundle(read(MANIFEST_ENTRY),read(JAR_ENTRY));locate=_locator(facts)
    with zipfile.ZipFile(BytesIO(read(JAR_ENTRY))) as archive:
        for index,event in enumerate(audit['applications']):
            record,reason=locate(event['callsite'])
            row={'application_id':'flow-summary:'+fingerprint([facts.run.run_id,event])[:32],'raw_index':index,
                 'current_call_ref':record.id if record else None,'mapping_state':'mapped' if record else 'unresolved','mapping_reason':reason,
                 'callsite':event['callsite'],'input':_path_roles(event['input'],record),
                 'outputs':[{'roles':_path_roles(x['path'],record),'different_from_incoming':x['different_from_incoming']} for x in event['outputs']],
                 'native_summary_candidates':[_native_refs(x,archive,manifest) for x in event['resolved_summary_candidates']],
                 'source_context':event['source_context'],'solver_context_access_path':event['solver_context_access_path'],
                 'context_scope':event['context_scope'],'complete_call_frame_binding_asserted':False,
                 'execution_claim':'possible_only','individually_fired_rules_proven':False,
                 'input_output_abstractions_actually_returned_by_wrapper':True}
            report['applications'].append(row)
    if audit['event_capture_truncated']:report['issues'].append({'kind':'wrapper_event_capture_truncated','omitted_event_count':audit['omitted_event_count']})
    return report


def verify_summary_evidence(facts,read):
    flow=json.loads(read(FLOW_ENTRY));config=flow['configuration']
    if config.get('schema_version')!='selected-summary-flow-config.v3':return
    raw=json.loads(read(flow['raw_entry'])) if flow['raw_entry'] else None
    from .selected_flow import load_flow_config
    if raw:validate_summary_worker(raw,load_flow_config(config),json.loads(read('analysis/selected-flow/request.json')),read)
    expected=make_summary_report(facts,flow,raw,read)
    actual=json.loads(read(ENTRY))
    if actual!=expected:raise ValueError('FlowDroid summary resource/call/role/XML mapping differs from original solver audit')


def summary_evidence(facts,read,refs=()):
    selected=facts.run.configuration.options.get('selected_flow',{})
    if selected.get('schema_version')!='selected-summary-flow-config.v3':
        return {'schema_version':'flowdroid-summary-evidence.v1','resource_state':'not_started','applications':[],
                'reason':'This run has no configured native SummaryTaintWrapper; separate JCA models do not substitute for it.'}
    verify_summary_evidence(facts,read);report=json.loads(read(ENTRY));chosen=set(refs)
    if chosen:report['applications']=[x for x in report['applications'] if x['current_call_ref'] in chosen or x['application_id'] in chosen]
    return report
