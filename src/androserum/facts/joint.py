"""Explicit selected-operation evidence assembly; not a BU traversal algorithm."""
import json
from collections import deque
from androserum.facts.operations import operation_evidence
from androserum.facts.control import control_evidence
from androserum.facts.events import event_evidence,ENTRY as EVENT_ENTRY
from androserum.facts.selected_flow import ENTRY as FLOW_ENTRY
from androserum.facts.sapi import match_sapi


def joint_evidence(view,refs,catalog,*,limit=5000):
    facts=view.export_bundle();read=view.read_evidence
    selected=set(refs);operations=operation_evidence(facts,read,refs);controls=control_evidence(facts,read,refs);events=event_evidence(facts,read,refs)
    matches=match_sapi(facts,catalog);matches['matches']=[x for x in matches['matches'] if x['callsite_ref'] in selected]
    raw_flow=json.loads(read(FLOW_ENTRY));flows=[x for x in raw_flow['mapped'] if x['source'].get('record_ref') in selected or x['sink'].get('record_ref') in selected]
    event_report=json.loads(read(EVENT_ENTRY));seeds=set(refs);required_effects=set()
    for op in operations['operations']:
        seeds.update(op['resources']);seeds.update(op['information_flows']);seeds.update(op['effects']);seeds.update(op['conditions']['refs']);seeds.update(op['conditions']['relation_refs'])
        for slot in [op['receiver'],*op['arguments'],op['result'],*op['other_slots']]:
            for candidate in slot.get('candidates',[]):
                seeds.update(candidate['source_refs']);seeds.update(x['relation_ref'] for x in candidate['path'])
                for scope in candidate.get('local_conditions',{}).get('source_scopes',[]):seeds.update(scope['condition_refs'])
    for op in events['operations']:
        for background in op['background']:
            root=background['root'];seeds.update([root['event_ref'],root['source_ref'],root['target_method_ref']]);seeds.update(background['call_background']['call_path_refs'])
        for item in op['icc']:
            seeds.update(x['effect_ref'] for x in item['dominance_evidence']);seeds.update(x['operation_ref'] for x in item['payloads']);seeds.update(x['effect_ref'] for x in item['payloads'])
            required_effects.update(x['effect_ref'] for x in item['dominance_evidence'])
            seeds.update(x['component_ref'] for x in item['targets'])
            for payload in item['payloads']:
                for candidate in payload['value']['candidates']:
                    seeds.update(candidate['source_refs']);seeds.update(x['relation_ref'] for x in candidate['path'])
    icc_indices={i for i,x in enumerate(event_report['icc']) if x['callsite_ref'] in selected}
    for edge in facts.relations:
        if edge.relation_kind=='event_trigger' and edge.target and edge.target.element_ref in {x['method_ref'] for x in operations['operations']}:seeds.add(edge.id)
        if edge.relation_kind in {'icc_target','icc_data'} and edge.source_selector and '#/icc/' in edge.source_selector:
            index=int(edge.source_selector.split('#/icc/')[1].split('/')[0])
            if index in icc_indices:seeds.add(edge.id)
        if edge.relation_kind=='information_flow' and (edge.source.element_ref in selected or edge.target and edge.target.element_ref in selected):seeds.add(edge.id)
        if edge.relation_kind=='state_dependency' and edge.target and edge.target.element_ref in required_effects:seeds.add(edge.id)
    present_artifacts={x.artifact_id for x in facts.run.artifacts}
    seeds.update(present_artifacts&{'rule:selected-flow','rule:selected-source-sink','rule:flow-worker','rule:operations','model:intent-state-v1','rule:control','rule:events','model:android-events-v1'})
    support=view.collect_support(sorted(seeds),limit=limit)
    support_data=support.to_dict()
    # Close typed artifact references inside sealed reports, without interpreting
    # program strings or expanding operation consumers. A report can cover a run.
    manifest={x.archive_entry:x for x in view.manifest.files}
    queue=deque([x.archive_entry for x in support.files]+['analysis/selected-flow/report.json','analysis/operations/report.json','analysis/control/report.json','analysis/events/report.json'])
    queue.extend(p for p in ['analysis/selected-flow/request.json','analysis/selected-flow/build.json','analysis/selected-flow/SourcesAndSinks.txt'] if p in manifest)
    seen=set();missing_files=[]
    path_keys={'artifact_path','ir_entry','cfg_entry','input_flow_entry','raw_entry','source_selector','location'}
    def references(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key=='input_flow_sha256' and isinstance(item,dict):queue.extend(item)
                if key in path_keys and isinstance(item,str):
                    path=item.split('#',1)[0]
                    if path.startswith('analysis/'):queue.append(path)
                references(item)
        elif isinstance(value,list):
            for item in value:references(item)
    for record in support_data['records']:references(record)
    while queue and len(seen)<limit:
        path=queue.popleft()
        if path in seen:continue
        seen.add(path)
        if path not in manifest:missing_files.append(path);continue
        raw=view.read_evidence(path)
        if path.startswith(('analysis/java/methods/','analysis/java/cfg/')) and path.endswith('.json') and not path.endswith('.commit.json'):
            queue.append(path.replace('.json','.commit.json'))
            queue.extend(p for p in ['analysis/java/request.json','analysis/java/start.json','analysis/java/end.json'] if p in manifest)
        if path.endswith('.json'):
            try:references(json.loads(raw))
            except (ValueError,UnicodeDecodeError):missing_files.append(path+':invalid-json')
    support_data['analysis_files']=[manifest[p].model_dump(mode='json') for p in sorted(seen) if p in manifest]
    support_data['pending_files']=sorted(set(queue)-seen);support_data['missing_files']=missing_files
    support_data['file_closure_complete']=not support_data['pending_files'] and not missing_files
    support_data['file_scope']='Typed references of sealed reports; does not expand selected operation rows'
    support_data['truncated']=support_data['truncated'] or bool(support_data['pending_files'])
    return {'schema_version':'joint-evidence.v1','run_ref':view.run_ref,'snapshot_id':view.snapshot_id,'apk_sha256':facts.run.apk_sha256,
        'selected_refs':refs,'operations':operations['operations'],'control':controls,'events':events,'sapi':matches,
        'selected_flows':flows,'support':support_data,'coverage':view.manifest.coverage,
        'remaining_gaps':{'sapi_sources':catalog['pending_sources'],'events':events['unsupported'],'event_model_issues':events['issues'],
            'flow_intermediate_mappings':sum(x['state']=='unresolved' for f in flows for x in f['path']),
            'path_feasibility_checked':False,'precise_exceptional_heap':False,'full_program_coverage':False},
        'selection_policy':'Explicit operations plus referenced evidence closure only; no shared-source consumers or same-entry expansion',
        'is_bu_extraction':False,'engineering_scope':'Selected first-version evidence mechanisms; runtime execution not asserted'}
