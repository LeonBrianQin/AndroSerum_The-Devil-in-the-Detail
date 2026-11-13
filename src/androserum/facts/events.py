"""F7: versioned possible lifecycle/registration/ICC links, distinct from execution."""
from collections import Counter,defaultdict,deque
import hashlib,json
from pathlib import Path
from urllib.parse import urlparse
from androserum import __version__
from androserum.facts.control import extract_control
from androserum.facts.call_flow import _inputs
from androserum.facts.identity import canonical_json,fingerprint,parse_method_signature,record_id
from androserum.facts.io import loads_facts
from androserum.facts.models import (AnalysisNodeRecord,AnalysisScope,AnalysisStatus,BindingRecord,ClassRecord,ConfigurationRecord,Endpoint,InstructionRecord,
    MethodRecord,ModelPosition,ProgramSlot,Provenance,RelationRecord,ToolVersion,ValueInfo,VersionedArtifact)
from androserum.facts.operations import ENTRY as OP_ENTRY
from androserum.facts.operations import STATE_RULES
from androserum.facts.selected_flow import FlowConfig,ENTRY as FLOW_ENTRY

ENTRY='analysis/events/report.json';TOOL='tool:events';RULE='rule:events';MODEL='model:android-events-v1';A='{http://schemas.android.com/apk/res/android}'
LIFECYCLE={'activity':['onCreate(Landroid/os/Bundle;)V','onStart()V','onResume()V','onPause()V','onStop()V','onDestroy()V'],
    'service':['onCreate()V','onStartCommand(Landroid/content/Intent;II)I','onBind(Landroid/content/Intent;)Landroid/os/IBinder;','onDestroy()V'],
    'receiver':['onReceive(Landroid/content/Context;Landroid/content/Intent;)V'],'provider':['onCreate()Z']}
REGISTRATIONS={'Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V':('click',0,'onClick(Landroid/view/View;)V'),
    'Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z':('post',0,'run()V')}
MODELS={'version':'1','lifecycle':LIFECYCLE,'registration':REGISTRATIONS,'thread':'application Thread subclass.start -> run',
    'icc':'same allocation and dominating modeled Intent effects; static action/category/scheme/host/MIME subset',
    'registration_is_execution':False,'event_order_proven':False}


def analyze_events(facts,read):
    run=facts.run.run_id;records={x.id:x for x in facts.elements};methods={x.signature:x for x in facts.elements if isinstance(x,MethodRecord) and x.is_definition}
    classes={x.descriptor:x for x in facts.elements if isinstance(x,ClassRecord)}
    op=json.loads(read(OP_ENTRY));rows={x['operation_ref']:x for x in op['operations']};flow=json.loads(read(FLOW_ENTRY))
    flows,ir,cfgs,_=_inputs(facts,read)
    package=facts.run.apk_metadata.get('package_name') or facts.run.apk_metadata.get('package')
    if not package:
        package=next((x.value.value['attributes'].get('package') for x in facts.elements if isinstance(x,ConfigurationRecord) and x.name=='manifest'),None)
    def descriptor(name):
        if name.startswith('L') and name.endswith(';'):return name
        name=package+name if name.startswith('.') else package+'.'+name if '.' not in name else name
        return 'L'+name.replace('.','/')+';'
    def find_method(owner,suffix):
        seen=set()
        while owner and owner not in seen:
            seen.add(owner)
            if owner+'->'+suffix in methods:return methods[owner+'->'+suffix]
            owner=classes[owner].superclass if owner in classes else None
        return None
    def subtype(owner,parent):
        seen=set()
        while owner and owner not in seen:
            if owner==parent:return True
            seen.add(owner);owner=classes[owner].superclass if owner in classes else None
        return False
    components=[];roots=[];issues=[]
    for element in facts.elements:
        if not isinstance(element,ConfigurationRecord) or element.configuration_kind!='component':continue
        data=element.value.value;kind=data['tag'];name=data['attributes'].get(A+'name',element.name);owner=descriptor(name)
        component={'component_ref':element.id,'descriptor':owner,'kind':kind,'selector':element.position.selector,'filters':[],
            'enabled':data['attributes'].get(A+'enabled','true'),'exported':data['attributes'].get(A+'exported','unspecified')}
        for value in facts.elements:
            if isinstance(value,ConfigurationRecord) and value.configuration_kind=='intent_filter' and value.position.selector.startswith(element.position.selector+'/intent-filter'):
                component['filters'].append({'record_ref':value.id,**value.value.value})
        components.append(component)
        if kind not in LIFECYCLE:issues.append({'record_ref':element.id,'reason':'Unsupported component lifecycle model'});continue
        for suffix in LIFECYCLE[kind]:
            method=find_method(owner,suffix)
            if not method:
                issues.append({'record_ref':element.id,'rule':suffix,'reason':'No current APK implementation; framework/default inherited entry not materialized'});continue
            roots.append({'event_ref':record_id(run,'analysis',['lifecycle',element.id,method.id]),'kind':'lifecycle','source_ref':element.id,'target_method_ref':method.id,
                'component_ref':element.id,'object':None,'source_endpoint':None,'rule':kind+':'+suffix,'execution_asserted':False,
                'issues':[] if component['enabled']=='true' else ['Component disabled; runtime activation not established']})
    for ref,row in rows.items():
        instruction=records[ref]
        if instruction.operation!='invoke' or not instruction.declared_target:continue
        signature=instruction.declared_target.signature;spec=REGISTRATIONS.get(signature)
        owner,name,params,result=parse_method_signature(signature)
        if spec:
            kind,index,suffix=spec;value=next((x for x in row['arguments'] if x['index']==index),None)
        elif name=='start' and not params and result=='V' and subtype(owner,'Ljava/lang/Thread;'):
            kind,suffix='thread','run()V';value=row['receiver']
        else:continue
        objects=value.get('objects',[]) if value else []
        if not objects:issues.append({'record_ref':ref,'reason':'Registration object/target unresolved','kind':kind})
        elif value.get('truncated') or any(x['source_kind']!='allocation' for x in value.get('candidates',[])):
            issues.append({'record_ref':ref,'reason':'Additional registration object alternatives unresolved','kind':kind})
        for obj in objects:
            callback=find_method(obj['type_descriptor'],suffix)
            if not callback:issues.append({'record_ref':ref,'kind':kind,'reason':'Callback implementation not in APK/supported inheritance'});continue
            roots.append({'event_ref':record_id(run,'analysis',['registration',ref,callback.id,obj['object_key']]),'kind':kind,'source_ref':ref,'target_method_ref':callback.id,
                'component_ref':None,'object':obj,'source_endpoint':value['endpoint'],'rule':signature+' => '+suffix,'execution_asserted':False,'issues':[]})
    outgoing=defaultdict(list)
    for edge in facts.relations:
        if edge.relation_kind=='candidate_call' and edge.target:
            call=records[edge.source.element_ref];outgoing[call.position.method_ref].append((edge.target.element_ref,edge.id,edge.resolution))
    reach=[]
    for root in roots:
        q=deque([(root['target_method_ref'],[])]);seen=set()
        while q and len(seen)<1000:
            method,path=q.popleft()
            if method in seen:continue
            seen.add(method);reach.append({'event_ref':root['event_ref'],'method_ref':method,'call_path_refs':path,'possible_only':True})
            for target,edge,resolution in sorted(outgoing[method]):q.append((target,[*path,edge]))
        if q:issues.append({'event_ref':root['event_ref'],'reason':'Event background reachability budget exceeded'})
    # Normal CFG dominance gives explicit ordering, never source-code proximity.
    mapping=defaultdict(list)
    for edge in facts.relations:
        if edge.relation_kind=='dex_jimple_mapping' and edge.resolution=='resolved' and edge.target:
            node=records[edge.target.element_ref]
            mapping[edge.source.element_ref].append((node.method_ref,int(node.position.position_label.split(':')[1])))
    dominators={}
    for owner,cfg in cfgs.items():
        succ=defaultdict(set);pred=defaultdict(set)
        for a,b in cfg.normal_edges:succ[a].add(b);pred[b].add(a)
        reachable=set();q=deque([0] if ir[owner].units else [])
        while q:
            n=q.popleft()
            if n in reachable:continue
            reachable.add(n);q.extend(succ[n])
        dom={n:({0} if n==0 else set(reachable)) for n in reachable};changed=True
        while changed:
            changed=False
            for n in sorted(reachable-{0}):
                parents=pred[n]&reachable;new={n}|(set.intersection(*(dom[p] for p in parents)) if parents else set())
                if new!=dom[n]:dom[n]=new;changed=True
        dominators[owner]=dom
    def dominates(a,b):
        x,y=mapping.get(a,[]),mapping.get(b,[])
        return len(x)==len(y)==1 and x[0][0]==y[0][0] and x[0][1] in dominators[x[0][0]].get(y[0][1],set())
    def known(effect):
        if not effect['value'] or effect['value'].get('truncated') or any(x['value']['status']!='known' for x in effect['value']['candidates']):return []
        return [x['value']['value'] for x in effect['value']['candidates']]
    def last(effects):
        return next((x for x in effects if all(y['effect_ref']==x['effect_ref'] or dominates(y['operation_ref'],x['operation_ref']) for y in effects)),None)
    icc=[]
    for ref,row in rows.items():
        call=records[ref]
        if not call.declared_target or call.declared_target.signature not in {'Landroid/content/Context;->startActivity(Landroid/content/Intent;)V','Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V'}:continue
        argument=next((x for x in row['arguments'] if x['index']==0),None)
        objects=argument.get('objects',[]) if argument else []
        item={'callsite_ref':ref,'method_ref':row['method_ref'],'targets':[],'payloads':[],'issues':[],'object':None,'dominance_evidence':[],
            'condition_refs':list(dict.fromkeys(c for edge in facts.relations if edge.relation_kind=='control_dependency' and edge.target and edge.target.element_ref==ref for c in edge.condition_refs))}
        icc.append(item)
        if len(objects)!=1 or objects[0]['type_descriptor']!='Landroid/content/Intent;' or argument.get('truncated') or any(x['source_kind']!='allocation' for x in argument['candidates']):item['issues'].append('Intent object not uniquely within selected model');continue
        item['object']=objects[0]
        effects=[x for x in op['effects'] if x['object'] and x['object']['object_key']==objects[0]['object_key'] and records[x['operation_ref']].position.method_ref==row['method_ref']]
        eligible=[x for x in effects if dominates(x['operation_ref'],ref)]
        item['dominance_evidence']=[{'effect_ref':x['effect_ref'],'operation_ref':x['operation_ref'],'effect_unit':mapping[x['operation_ref']][0][1],
            'send_unit':mapping[ref][0][1],'cfg_sha256':flows[row['method_ref']].cfg_sha256} for x in eligible]
        if len(eligible)!=len(effects):item['issues'].append('Some effects do not dominate the send; state alternatives unresolved')
        unmodeled=[]
        for other_ref,other_row in rows.items():
            other=records[other_ref]
            if other_ref==ref or other_row['method_ref']!=row['method_ref'] or not other.declared_target or other.declared_target.signature in STATE_RULES:continue
            if dominates(other_ref,ref) and any(obj['object_key']==objects[0]['object_key'] for slot in [other_row['receiver'],*other_row['arguments']] for obj in slot.get('objects',[])):
                unmodeled.append(other_ref)
        def invalidated(effect):return effect is not None and any(not dominates(other,effect['operation_ref']) for other in unmodeled)
        if unmodeled:item['issues'].append('Unmodeled call may change Intent state; later dominating writes required to restore precision')
        target=last([x for x in eligible if x['property']=='target']);targets=known(target) if target else []
        if invalidated(target):targets=[]
        if len(targets)==1:
            found=[x for x in components if x['descriptor']==targets[0] and x['kind']=='activity']
            item['targets']=[{'component_ref':x['component_ref'],'basis':'explicit_class','effect_refs':[target['effect_ref']],'resolution':'resolved'} for x in found]
            if not found:item['issues'].append('Explicit target is outside current APK components')
        else:
            action=last([x for x in eligible if x['property']=='action']);actions=known(action) if action else []
            data=last([x for x in eligible if x['property']=='data']);uris=known(data) if data else []
            mime=last([x for x in eligible if x['property']=='mime']);mimes=known(mime) if mime else []
            categories={v for e in eligible if e['property']=='category' for v in known(e)}
            uncertain=(action and invalidated(action)) or (data and (invalidated(data) or len(uris)!=1)) or (mime and (invalidated(mime) or len(mimes)!=1)) or any(not known(e) for e in eligible if e['property']=='category')
            if len(actions)!=1 or uncertain:item['issues'].append('Implicit action/category/data/MIME unknown, ambiguous or affected by unmodeled calls')
            else:
                uri=urlparse(uris[0]['uri']) if len(uris)==1 and isinstance(uris[0],dict) and 'uri' in uris[0] else None
                for component in components:
                    if component['kind']!='activity':continue
                    for filter_ in component['filters']:
                        children=filter_['children'];filter_actions={x['attributes'].get(A+'name') for x in children if x['tag']=='action'}
                        filter_categories={x['attributes'].get(A+'name') for x in children if x['tag']=='category'}
                        if actions[0] not in filter_actions or 'android.intent.category.DEFAULT' not in filter_categories or not categories<=filter_categories:continue
                        data_rules=[x['attributes'] for x in children if x['tag']=='data'];supported=True
                        if len(data_rules)>1:
                            item['issues'].append('Multiple data entries outside selected static filter subset');continue
                        if (uri or mimes) and not data_rules:
                            item['issues'].append('Intent data/MIME has no corresponding filter data rule');continue
                        for rule in data_rules:
                            if any(k not in {A+'scheme',A+'host',A+'mimeType'} for k in rule):supported=False
                            if rule.get(A+'scheme') and (uri is None or uri.scheme!=rule[A+'scheme']):supported=False
                            if rule.get(A+'host') and (uri is None or uri.hostname!=rule[A+'host']):supported=False
                            expected=rule.get(A+'mimeType')
                            if expected and (len(mimes)!=1 or not (expected==mimes[0] or expected=='*/*' or expected.endswith('/*') and mimes[0].startswith(expected[:-1]))):supported=False
                        if supported:item['targets'].append({'component_ref':component['component_ref'],'basis':'static_intent_filter','filter_ref':filter_['record_ref'],
                            'effect_refs':[x['effect_ref'] for x in eligible if x['property'] in {'action','category','data','mime'}],'resolution':'partial'})
                        elif data_rules:item['issues'].append('Data constraint mismatch/unsupported or unknown; no resolved implicit target added')
        for key in sorted({x['key'] for x in eligible if x['property']=='extra' and x['key'] is not None}):
            effect=last([x for x in eligible if x['property']=='extra' and x['key']==key])
            if effect and not invalidated(effect):item['payloads'].append({'key':key,'effect_ref':effect['effect_ref'],'operation_ref':effect['operation_ref'],'value':effect['value'],'normal_completion_required':True})
        if any(x['property']=='extra' and x['key'] is None for x in eligible):item['issues'].append('Payload key unknown; target remains independently usable')
        item['payload_state']='bound_sources' if item['payloads'] else 'unknown' if any(x['property']=='extra' for x in eligible) else 'no_modeled_extra'
    joint={'callbacks_enabled':flow['configuration']['callbacks'],'selected_callback_class':'android.view.View$OnClickListener','state':'not_validated','flow_rows':[],'event_refs':[]}
    for index,row in enumerate(flow['mapped']):
        if row['issues']:continue
        source=row['source']['statement'];sink=row['sink']['statement']
        if source.get('invoke_signature')=='Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;' and '->jointSink(' in sink.get('invoke_signature',''):
            owner=records[row['source']['record_ref']].position.method_ref
            callback_events=[r['event_ref'] for r in roots if r['kind']=='click' and any(x['event_ref']==r['event_ref'] and x['method_ref']==owner for x in reach)]
            if callback_events and joint['callbacks_enabled']:
                joint['state']='selected_entry_callback_models_agree';joint['flow_rows'].append(index);joint['event_refs'].extend(callback_events)
    return {'schema_version':'event-evidence.v1','run_ref':run,'components':components,'roots':roots,'reachability':reach,'icc':icc,'issues':issues,
        'flow_joint_validation':joint,'execution_asserted':False,'event_order_proven':False,'unsupported':['dynamic registration/ICC targets','general async scheduling/order','unmodeled lifecycle/listener classes','full IntentFilter/permission semantics']}


def _emit(facts,report):
    run=facts.run.run_id;records={x.id:x for x in facts.elements};nodes=[];bindings=[];edges=[]
    prov=lambda *refs:Provenance(kind='model_assisted',tool_ref=TOOL,rule_ref=MODEL,support_refs=list(dict.fromkeys(refs)))
    for root in report['roots']:
        ref=root['event_ref'];nodes.append(AnalysisNodeRecord(id=ref,run_ref=run,kind='analysis_node',node_kind='event',position=ModelPosition(kind='model',model_ref=MODEL,position_label=ref),
            provenance=prov(root['source_ref'],root['target_method_ref'])))
        binding_refs=[]
        if root['object']:
            bound=record_id(run,'binding',['event-object',ref]);bindings.append(BindingRecord(id=bound,run_ref=run,provenance=prov(root['source_ref'],root['target_method_ref'],root['object']['object_key']),binding_kind='object',
                endpoints=[Endpoint(**root['source_endpoint']),Endpoint(**root['object']['allocation_endpoint']),Endpoint(element_ref=root['target_method_ref'],slot_kind='receiver')]))
            binding_refs=[bound]
        for index,reach in enumerate(report['reachability']):
            if reach['event_ref']!=ref:continue
            edges.append(RelationRecord(id=record_id(run,'relation',['event-reach',ref,reach['method_ref']]),run_ref=run,provenance=prov(ref,root['source_ref'],reach['method_ref'],*reach['call_path_refs']),
                relation_kind='event_trigger',source=Endpoint(element_ref=ref,slot_kind='element',position_label=ref),target=Endpoint(element_ref=reach['method_ref'],slot_kind='entry'),
                binding_refs=binding_refs,resolution='partial',unresolved_reason='Possible framework trigger/call reachability, not occurrence or immediate execution',source_selector=ENTRY+f'#/reachability/{index}'))
    for index,item in enumerate(report['icc']):
        call=records[item['callsite_ref']]
        for target in item['targets']:
            target_ref=target['component_ref'];delivery=record_id(run,'analysis',['icc-delivery',call.id,target_ref])
            nodes.append(AnalysisNodeRecord(id=delivery,run_ref=run,kind='analysis_node',node_kind='event',position=ModelPosition(kind='model',model_ref=MODEL,position_label=delivery),
                provenance=prov(call.id,target_ref),slots=[ProgramSlot(slot_kind='state',slot_label='extra:'+x['key'],value=ValueInfo(status='unknown',reason='Modeled possible Intent payload; not observed delivery')) for x in item['payloads']]))
            edges.append(RelationRecord(id=record_id(run,'relation',['icc-target',call.id,target_ref]),run_ref=run,provenance=prov(call.id,target_ref,*target['effect_refs']),
                relation_kind='icc_target',source=Endpoint(element_ref=call.id,slot_kind='element',position_label=call.position.position_label),target=Endpoint(element_ref=target_ref,slot_kind='element'),
                condition_refs=item['condition_refs'],resolution=target['resolution'],unresolved_reason=None if target['resolution']=='resolved' else 'Static subset Intent filter matching; runtime resolution not established',source_selector=ENTRY+f'#/icc/{index}'))
            for payload in item['payloads']:
                edges.append(RelationRecord(id=record_id(run,'relation',['icc-payload',delivery,payload['key']]),run_ref=run,provenance=prov(call.id,target_ref,payload['effect_ref'],payload['operation_ref']),
                    relation_kind='icc_data',source=Endpoint(**payload['value']['endpoint']),target=Endpoint(element_ref=delivery,slot_kind='state',slot_label='extra:'+payload['key'],position_label=delivery),
                    condition_refs=item['condition_refs'],resolution='partial',unresolved_reason='Modeled data binding; value, delivery and path constraints may remain unknown',source_selector=ENTRY+f'#/icc/{index}/payloads'))
    return nodes,bindings,edges


def extend_events(result):
    facts=result.facts;run=facts.run.run_id;read=lambda e:result.blobs[result.entry_digests[e]];report=analyze_events(facts,read)
    facts.run.configuration.options['events']={'model_version':'android-events-v1','flow_callback_scope':'OnClick only'};facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='selected Android event models',version=__version__))
    for path,raw,ref,kind in [('analysis/rules/events.py',Path(__file__).read_bytes(),RULE,'rule'),('analysis/rules/android-events.json',canonical_json(MODELS).encode(),MODEL,'framework_model'),(ENTRY,canonical_json(report).encode(),None,None)]:
        digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[path]=digest
        if ref:facts.run.artifacts.append(VersionedArtifact(artifact_id=ref,kind=kind,name='selected lifecycle/callback/ICC model',version='1',sha256=digest,location=path))
    nodes,bindings,edges=_emit(facts,report);facts.elements.extend(nodes);facts.bindings.extend(bindings);facts.relations.extend(edges)
    status=next(x for x in facts.statuses if x.capability=='events' and x.scope.kind=='run');status.state='partial';status.tool_ref=TOOL;status.reason='Selected possible lifecycle/registration/ICC models only; see model and dynamic gaps'
    result.facts=loads_facts(facts.model_dump_json());verify_events(result.facts,read)
    result.summary.update(stage='F7',events={'roots':len(report['roots']),'icc':len(report['icc']),'issues':len(report['issues']),'flow_joint_validation':report['flow_joint_validation']},
        coverage={x.capability:x.state for x in facts.statuses if x.scope.kind=='run'},element_counts=dict(Counter(x.kind for x in facts.elements)),relation_counts=dict(Counter(x.relation_kind for x in facts.relations)))
    return result


def extract_events(apk):return extend_events(extract_control(apk,flow_config=FlowConfig(callbacks=True)))


def verify_events(facts,read):
    own=lambda x:x.provenance.tool_ref==TOOL or x.provenance.rule_ref in {RULE,MODEL}
    actual=[{x.id:x for x in values if own(x)} for values in [facts.elements,facts.bindings,facts.relations]]
    if not any(x.tool_id==TOOL for x in facts.run.tools):
        if any(actual):raise ValueError('Event records lack versioned tool/model')
        return
    report=json.loads(read(ENTRY))
    if read('analysis/rules/android-events.json')!=canonical_json(MODELS).encode() or report!=analyze_events(facts,read):raise ValueError('Event model/target/payload/evidence mismatch')
    if actual!=[{x.id:x for x in values} for values in _emit(facts,report)]:raise ValueError('Forged event/ICC targets or data bindings')


def event_evidence(facts,read,refs):
    report=json.loads(read(ENTRY));records={x.id:x for x in facts.elements};result=[]
    for ref in refs:
        record=records[ref];owner=getattr(getattr(record,'position',None),'method_ref',None) or getattr(record,'method_ref',None)
        roots={x['event_ref']:x for x in report['roots']}
        background=[{'root':roots[x['event_ref']],'call_background':x} for x in report['reachability'] if x['method_ref']==owner]
        result.append({'operation_ref':ref,'background':background,'icc':[x for x in report['icc'] if x['callsite_ref']==ref],'execution_asserted':False,'registration_implies_immediate_execution':False})
    return {'schema_version':'event-query.v1','run_ref':facts.run.run_id,'operations':result,'flow_joint_validation':report['flow_joint_validation'],'issues':report['issues'],'unsupported':report['unsupported']}
