"""F5: evidence views and narrowly modeled normal-completion Intent effects."""
from collections import Counter,defaultdict
import hashlib,json
from pathlib import Path
from typing import Literal
from pydantic import Field
from androserum import __version__
from androserum.facts.context_heap import ContextHeapReport,entry_for,trace_context_sources
from androserum.facts.identity import canonical_json,fingerprint,record_id
from androserum.facts.io import loads_facts
from androserum.facts.models import (AnalysisNodeRecord,AnalysisPosition,AnalysisScope,AnalysisStatus,BindingRecord,Endpoint,
    InstructionRecord,ModelPosition,ProgramSlot,Provenance,RelationRecord,ResourceRecord,StrictModel,ToolVersion,ValueInfo,VersionedArtifact)
from androserum.facts.selected_flow import extract_selected_flow

ENTRY='analysis/operations/report.json';TOOL='tool:operations';RULE='rule:operations';MODEL='model:intent-state-v1'
# Exact pre-normalization policy. Old reports preserved the reader exception's
# display text for absent selected contexts; the underlying gap is unchanged.
LEGACY_CONTEXT_REASON_RULE='cd33b4dbe588ea5ee776734d64ab94a07d3f50dce7b6a8a2b3e2832d3f5e3417'
INTENT='Landroid/content/Intent;'
STATE_RULES={INTENT+'-><init>(Landroid/content/Context;Ljava/lang/Class;)V':('target',1,None),
    INTENT+'-><init>(Ljava/lang/String;)V':('action',0,None),
    INTENT+'->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;':('target',1,None),
    INTENT+'->setAction(Ljava/lang/String;)Landroid/content/Intent;':('action',0,None),
    INTENT+'->addCategory(Ljava/lang/String;)Landroid/content/Intent;':('category',0,None),
    INTENT+'->setData(Landroid/net/Uri;)Landroid/content/Intent;':('data',0,None),
    INTENT+'->setType(Ljava/lang/String;)Landroid/content/Intent;':('mime',0,None),
    INTENT+'->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;':('extra',1,0)}


def _missing_context_reason(error, entry):
    if ((isinstance(error, KeyError) and error.args == (entry,)) or
            (isinstance(error, ValueError) and str(error) in {
                'Structured IR evidence is missing: ' + entry, 'Evidence entry is absent: ' + entry})):
        return 'Selected context evidence is absent: ' + entry
    return None


def _legacy_context_issue_projection(report, facts, read):
    """Normalize only confirmed absent-context issue strings in old reports.

    Values, objects, candidates, ordered paths, bindings and all other strings
    remain exact. Invalid present artifacts and unrelated lookup errors are not
    accepted as missing evidence.
    """
    translations = {}
    for method in {x.position.method_ref for x in facts.elements if isinstance(x, InstructionRecord)}:
        entry = entry_for(method)
        try:
            read(entry)
        except (KeyError, ValueError) as error:
            canonical = _missing_context_reason(error, entry)
            if canonical:
                for old in [str(KeyError(entry)), 'Structured IR evidence is missing: ' + entry,
                            'Evidence entry is absent: ' + entry]:
                    translations[old] = canonical
    def visit(value, key=None):
        if isinstance(value, dict):
            return {k: visit(v, k) for k, v in value.items()}
        if isinstance(value, list):
            if key == 'issues':
                return [translations.get(v, v) if isinstance(v, str) else visit(v) for v in value]
            return [visit(v) for v in value]
        return value
    return visit(report)


class OperationConfig(StrictModel):
    schema_version:Literal['operation-view-config.v1']='operation-view-config.v1'
    max_operations:int=Field(default=5000,ge=1,le=100000)
    max_source_visits:int=Field(default=1000,ge=1,le=100000)
    max_candidates:int=Field(default=32,ge=1,le=1000)
    state_rules:Literal['intent-selected-v1']='intent-selected-v1'


def build_operations(facts,read,config):
    records={x.id:x for x in facts.elements};contexts={};cache={};ir_to_dex={};trace_cache={};resource_edges=defaultdict(list)
    for edge in facts.relations:
        if edge.relation_kind=='dex_jimple_mapping' and edge.target and edge.resolution=='resolved':ir_to_dex.setdefault(edge.target.element_ref,[]).append(edge.source.element_ref)
        if edge.relation_kind in {'resource_use','resource_reference'}:
            resource_edges[edge.source.element_ref].append(edge)
            if edge.target and edge.target.element_ref!=edge.source.element_ref:resource_edges[edge.target.element_ref].append(edge)
    operations=[x for x in facts.elements if isinstance(x,InstructionRecord)]
    issues=[]
    def context(ref):
        if ref not in contexts:
            try:contexts[ref]=ContextHeapReport.model_validate_json(read(entry_for(ref)))
            except (ValueError,KeyError):contexts[ref]=None
        return contexts[ref]
    def slot_view(operation,slot,active=frozenset()):
        point=Endpoint(element_ref=operation.id,position_label=operation.position.position_label,slot_kind=slot.slot_kind,slot_index=slot.slot_index,slot_label=slot.slot_label)
        key=canonical_json(point.model_dump(mode='json'))
        if key in cache:return cache[key]
        out={'endpoint':point.model_dump(mode='json'),'value_status':'unknown','candidates':[],'objects':[],'issues':[],'truncated':False}
        if key in active:out['issues'].append('Value-model recursion stopped');return out
        if slot.value.status=='known':
            out['candidates']=[{'value':slot.value.model_dump(mode='json'),'source_kind':'encoded_value','source_refs':[operation.id],'path':[],'metadata':{}}]
        else:
            try:
                traced=trace_context_sources(facts,read,operation.position.method_ref,point,limit=config.max_source_visits,_cache=trace_cache)
                out['truncated']=traced['truncated'];out['issues'].extend(x['reason'] for x in traced.get('unresolved_effects',[]))
                for item in traced['roots'][:config.max_candidates]:
                    root=item['root'];origin=item.get('origin',{});kind=root['kind'];meta=root['details']
                    refs=list(dict.fromkeys([operation.id,*([origin['origin_ref']] if origin.get('origin_ref') else []),root['endpoint']['element_ref']]))
                    if kind=='constant':
                        from androserum.facts.jimple import IRValue
                        from androserum.facts.local_flow import _constant_value
                        value=_constant_value(IRValue.model_validate(meta['operand'])).model_dump(mode='json')
                    else:value=ValueInfo(status='unknown',reason='Known '+kind+' origin; concrete value unresolved',source_refs=refs).model_dump(mode='json')
                    path=[{'relation_ref':x['relation']['id'],'source':x['relation']['source'],'target':x['relation']['target'],
                        'context_ref':x['relation']['context_ref'],'binding_refs':x['relation']['binding_refs'],'source_selector':x['relation']['source_selector']} for x in item['relations_to_target']]
                    candidate={'value':value,'source_kind':kind,'source_refs':refs,'path':path,'metadata':meta,'origin':origin}
                    out['candidates'].append(candidate)
                    if kind=='allocation':
                        report=context(operation.position.method_ref)
                        if report and report.projection:
                            nodes={x.node_ref:x for x in report.projection.nodes};node=nodes.get(root['endpoint']['element_ref'])
                            if node:
                                value=report.projection.method.units[node.index].right
                                out['objects'].append({'object_key':node.node_ref,'type_descriptor':value.type_descriptor,'origin_ref':node.origin_ref,
                                    'allocation_endpoint':root['endpoint'],'context_ref':node.frame_ref,'call_path':origin.get('call_path',[])})
                if len(traced['roots'])>config.max_candidates:out['truncated']=True;out['issues'].append('Candidate budget exceeded')
            except (ValueError,KeyError) as error:
                out['issues'].append(_missing_context_reason(error, entry_for(operation.position.method_ref)) or str(error))
        if not out['candidates']:out['candidates']=[{'value':slot.value.model_dump(mode='json'),'source_kind':'unresolved','source_refs':[operation.id],'path':[],'metadata':{}}]
        # A finite, explicit value rule for URI constants; no arbitrary API inference.
        modeled=[]
        for candidate in out['candidates']:
            if candidate['source_kind']=='call_result' and candidate['metadata'].get('signature')=='Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;':
                origin=candidate.get('origin',{}).get('origin_ref');found=ir_to_dex.get(origin,[])
                if len(found)==1:
                    call=records[found[0]];argument=next((x for x in call.slots if x.slot_kind=='argument' and x.slot_index==0),None)
                    if argument:
                        source=slot_view(call,argument,active|{key})
                        for value in source['candidates']:
                            if value['value']['status']=='known' and isinstance(value['value']['value'],str):
                                modeled.append({'value':ValueInfo(status='known',value={'uri':value['value']['value']}).model_dump(mode='json'),
                                    'source_kind':'modeled_uri','source_refs':list(dict.fromkeys([*value['source_refs'],call.id])),
                                    'path':value['path'],'metadata':{'rule':'Uri.parse(String)','normal_completion_required':True}})
                        if source['truncated'] or any(x['value']['status']!='known' for x in source['candidates']):modeled.append(candidate)
            else:modeled.append(candidate)
        if modeled:out['candidates']=modeled
        out['value_status']='known' if len(out['candidates'])==1 and out['candidates'][0]['value']['status']=='known' and not out['truncated'] else 'partial' if any(x['value']['status']=='known' for x in out['candidates']) else 'unknown'
        out['issues']=list(dict.fromkeys(out['issues']));cache[key]=out;return out
    rows=[];effects=[]
    for operation in operations[:config.max_operations]:
        slots=[{'kind':x.slot_kind,'index':x.slot_index,'label':x.slot_label,**slot_view(operation,x)} for x in operation.slots]
        receiver=next((x for x in slots if x['kind']=='receiver'),None);result=next((x for x in slots if x['kind']=='result'),None)
        not_app=lambda reason:{'value_status':'not_applicable','reason':reason,'candidates':[],'objects':[],'issues':[]}
        row={'operation_ref':operation.id,'method_ref':operation.position.method_ref,'position':operation.position.model_dump(mode='json'),'opcode':operation.opcode,
            'operation':operation.operation,'receiver':receiver or not_app('No receiver slot; static/non-object operation'),
            'arguments':[x for x in slots if x['kind']=='argument'],'result':result or not_app('No result slot, including void calls'),
            'other_slots':[x for x in slots if x['kind'] not in {'receiver','argument','result'}],
            'resources':[edge.id for edge in resource_edges[operation.id]],
            'resource_records':[records[ref].model_dump(mode='json') for ref in sorted({point.element_ref for edge in resource_edges[operation.id]
                for point in [edge.source,*([edge.target] if edge.target else [])] if isinstance(records.get(point.element_ref),ResourceRecord)})],
            'information_flows':[edge.id for edge in facts.relations if edge.relation_kind=='information_flow' and (edge.source.element_ref==operation.id or edge.target and edge.target.element_ref==operation.id)],
            'conditions':{'state':'deferred_until_F6','refs':[]},'effects':[],'slots_complete':operation.slots_complete}
        signature=operation.declared_target.signature if operation.declared_target else None
        if signature in STATE_RULES:
            property_,index,key_index=STATE_RULES[signature]
            values=next((x for x in row['arguments'] if x['index']==index),None)
            keys=next((x for x in row['arguments'] if x['index']==key_index),None) if key_index is not None else None
            known_keys=sorted({x['value']['value'] for x in keys['candidates'] if x['value']['status']=='known' and isinstance(x['value']['value'],str)}) if keys else []
            objects=receiver['objects'] if receiver else []
            for obj in objects or [None]:
                effect={'effect_ref':record_id(facts.run.run_id,'analysis',['operation-state',operation.id,len(effects)]),'operation_ref':operation.id,
                    'signature':signature,'property':property_,'key':known_keys[0] if len(known_keys)==1 else None,
                    'object':obj,'value':values,'key_candidates':keys,'normal_completion_required':True,'rule_ref':MODEL,
                    'issues':([] if obj else ['Receiver allocation unknown'])+(['Extra key unknown/ambiguous'] if keys and len(known_keys)!=1 else [])}
                effects.append(effect);row['effects'].append(effect['effect_ref'])
        rows.append(row)
    if len(operations)>config.max_operations:issues.append({'reason':'Operation budget exceeded','pending_refs':[x.id for x in operations[config.max_operations:]]})
    return {'schema_version':'operation-evidence.v1','run_ref':facts.run.run_id,'configuration':config.model_dump(mode='json'),
        'operations':rows,'effects':effects,'issues':issues,'conditions_policy':'Candidates preserve existing evidence; F6 association is a separate query overlay'}


def _emit(facts,report):
    run=facts.run.run_id;nodes=[];bindings=[];edges=[]
    support=[x['operation_ref'] for x in report['operations'][:1]]
    if support:nodes.append(AnalysisNodeRecord(id=record_id(run,'analysis',['operation-view']),run_ref=run,kind='analysis_node',node_kind='state',
        position=AnalysisPosition(kind='analysis',artifact_path=ENTRY,position_label='operation-view'),provenance=Provenance(kind='static_analysis',tool_ref=TOOL,rule_ref=RULE,support_refs=support)))
    for effect in report['effects']:
        operation=effect['operation_ref'];ref=effect['effect_ref'];label=effect['property']+(':'+effect['key'] if effect['key'] else '')
        provenance=Provenance(kind='model_assisted',tool_ref=TOOL,rule_ref=MODEL,support_refs=[operation])
        value=ValueInfo(status='unknown',reason='Potential normal-completion state; inspect candidates and conditions')
        nodes.append(AnalysisNodeRecord(id=ref,run_ref=run,kind='analysis_node',node_kind='state',position=ModelPosition(kind='model',model_ref=MODEL,position_label=ref),
            provenance=provenance,slots=[ProgramSlot(slot_kind='state',slot_label=label,value=value)]))
        binding_refs=[];context=None
        if effect['object']:
            obj=effect['object'];context=obj['context_ref'];bound=record_id(run,'binding',['operation-state',ref])
            operation_record=next(x for x in report['operations'] if x['operation_ref']==operation)
            bindings.append(BindingRecord(id=bound,run_ref=run,provenance=provenance,binding_kind='object',context_ref=context,
                endpoints=[Endpoint(**operation_record['receiver']['endpoint']),Endpoint(**obj['allocation_endpoint'])]));binding_refs.append(bound)
        if effect['value']:
            edges.append(RelationRecord(id=record_id(run,'relation',['operation-state',ref]),run_ref=run,provenance=provenance,relation_kind='state_dependency',
                source=Endpoint(**effect['value']['endpoint']),target=Endpoint(element_ref=ref,slot_kind='state',slot_label=label,position_label=ref),
                binding_refs=binding_refs,context_ref=context,resolution='partial',unresolved_reason='Finite API rule applies only on normal completion; conditions may be pending',source_selector=ENTRY+f"#/effects/{report['effects'].index(effect)}"))
    return nodes,bindings,edges


def extend_operations(result,config=None):
    config=OperationConfig.model_validate((config or OperationConfig()).model_dump());facts=result.facts;run=facts.run.run_id
    facts.run.configuration.options['operations']=config.model_dump(mode='json');facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    report=build_operations(facts,lambda e:result.blobs[result.entry_digests[e]],config)
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='operation evidence view',version=__version__))
    for ref,kind,name,path,data in [(RULE,'rule','operation evidence resolution','analysis/rules/operations.py',Path(__file__).read_bytes()),
        (MODEL,'summary','Intent/URI selected normal-completion rules','analysis/rules/intent-state.json',canonical_json({'version':'1','rules':STATE_RULES,'uri_parse':'literal String only'}).encode())]:
        digest=hashlib.sha256(data).hexdigest();result.blobs[digest]=data;result.entry_digests[path]=digest
        facts.run.artifacts.append(VersionedArtifact(artifact_id=ref,kind=kind,name=name,version='1',sha256=digest,location=path))
    raw=canonical_json(report).encode();digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[ENTRY]=digest
    nodes,bindings,edges=_emit(facts,report);facts.elements.extend(nodes);facts.bindings.extend(bindings);facts.relations.extend(edges)
    if nodes:facts.statuses.append(AnalysisStatus(id=record_id(run,'status',['operations']),run_ref=run,tool_ref=TOOL,capability='objects',scope=AnalysisScope(kind='element',element_ref=nodes[0].id),
        state='partial',reason='Operation candidates retain unknowns; finite state rules only; control association deferred'))
    result.facts=loads_facts(facts.model_dump_json());verify_operations(result.facts,lambda e:result.blobs[result.entry_digests[e]])
    result.summary.update(stage='F5',operations={'operations':len(report['operations']),'effects':len(report['effects']),'issues':report['issues']},
        element_counts=dict(Counter(x.kind for x in facts.elements)),relation_counts=dict(Counter(x.relation_kind for x in facts.relations)))
    return result


def extract_operations(apk,*,flow_config=None,config=None):return extend_operations(extract_selected_flow(apk,config=flow_config),config)


def verify_operations(facts,read):
    own=lambda x:x.provenance.tool_ref==TOOL or x.provenance.rule_ref in {RULE,MODEL}
    actual=[{x.id:x for x in values if own(x)} for values in [facts.elements,facts.bindings,facts.relations]]
    if not any(x.tool_id==TOOL for x in facts.run.tools):
        if any(actual):raise ValueError('Operation facts lack tool metadata')
        return
    report=json.loads(read(ENTRY));config=OperationConfig.model_validate(facts.run.configuration.options['operations'])
    if read('analysis/rules/intent-state.json')!=canonical_json({'version':'1','rules':STATE_RULES,'uri_parse':'literal String only'}).encode():raise ValueError('Operation finite-state model differs from fixed rules')
    expected_report=build_operations(facts,read,config)
    source_rule=next((x.sha256 for x in facts.run.artifacts if x.artifact_id==RULE),None)
    checked_report=_legacy_context_issue_projection(report,facts,read) if source_rule==LEGACY_CONTEXT_REASON_RULE else report
    if checked_report!=expected_report:raise ValueError('Operation values/objects/effects differ from current evidence')
    expected=[{x.id:x for x in values} for values in _emit(facts,report)]
    if actual!=expected:raise ValueError('Forged operation-state facts/bindings')


def operation_evidence(facts,read,refs):
    report=json.loads(read(ENTRY));rows={x['operation_ref']:x for x in report['operations']}
    result=[]
    for ref in refs:
        if ref not in rows:raise ValueError('Operation view not available; inspect operation budget/status')
        row=json.loads(json.dumps(rows[ref]))
        controls=[x for x in facts.relations if x.relation_kind=='control_dependency' and x.target and x.target.element_ref==ref]
        implemented=any(x.tool_id=='tool:control' for x in facts.run.tools)
        row['conditions']={'state':'available_normal_flow_scope' if implemented else 'not_started','refs':list(dict.fromkeys(c for x in controls for c in x.condition_refs)),
            'relation_refs':[x.id for x in controls],'absence_is_unconditional':False}
        statuses=[x for x in facts.statuses if x.tool_ref=='tool:control' and x.scope.element_ref==row['method_ref']]
        if implemented:row['conditions']['coverage_state']=statuses[-1].state if statuses else 'unavailable'
        for slot in [row['receiver'],*row['arguments'],row['result'],*row['other_slots']]:
            for candidate in slot.get('candidates',[]):
                scopes=[]
                for source in candidate['source_refs']:
                    if source==ref:continue
                    source_controls=[x for x in facts.relations if x.relation_kind=='control_dependency' and x.target and x.target.element_ref==source]
                    conds=list(dict.fromkeys(c for x in source_controls for c in x.condition_refs))
                    if conds:scopes.append({'source_ref':source,'condition_refs':conds})
                candidate['local_conditions']={'state':'available' if implemented else 'not_started','operation_condition_refs':row['conditions']['refs'],
                    'source_scopes':scopes,'combined_path_checked':False}
        row['effect_records']=[x for x in report['effects'] if x['operation_ref']==ref];result.append(row)
    return {'schema_version':'operation-evidence-query.v1','run_ref':facts.run.run_id,'operations':result,'issues':report['issues'],'path_feasibility_checked':False}
