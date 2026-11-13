"""F6: explicit if-branch control dependencies under normal-completion semantics."""
from collections import Counter,defaultdict,deque
import hashlib,json
from pathlib import Path
from typing import Literal
from pydantic import Field
from androserum import __version__
from androserum.facts.call_flow import _inputs
from androserum.facts.context_heap import trace_context_sources,entry_for
from androserum.facts.identity import canonical_json,fingerprint,record_id
from androserum.facts.io import loads_facts
from androserum.facts.models import (AnalysisNodeRecord,AnalysisPosition,AnalysisScope,AnalysisStatus,ConditionRecord,Endpoint,
    ProgramSlot,Provenance,RelationRecord,StrictModel,ToolVersion,ValueInfo,VersionedArtifact)
from androserum.facts.operations import extract_operations,_missing_context_reason

ENTRY='analysis/control/report.json';TOOL='tool:control';RULE='rule:control'
LEGACY_CONTEXT_REASON_RULE='7aba3c347b2e562923913cc51e3f6cec85bb7e31e81306d2af19758fea7d4be9'


def _legacy_context_source_projection(report,read):
    """Legacy reader wording only; predicates, paths and endpoints stay exact."""
    from copy import deepcopy
    result=deepcopy(report)
    for method in result['methods']:
        entry=entry_for(method['method_ref']);canonical=None
        try:read(entry)
        except (KeyError,ValueError) as error:canonical=_missing_context_reason(error,entry)
        if canonical is None:continue
        previous={str(KeyError(entry)),'Structured IR evidence is missing: '+entry,'Evidence entry is absent: '+entry}
        for condition in method['conditions']:
            for source in condition['source_evidence']:
                if source.get('state')=='unknown' and source.get('reason') in previous:
                    source['reason']=canonical
    return result


class ControlConfig(StrictModel):
    schema_version:Literal['control-config.v1']='control-config.v1'
    scope:Literal['explicit_if_normal_completion']='explicit_if_normal_completion'
    max_visits:int=Field(default=100000,ge=1,le=10000000)
    max_controls:int=Field(default=100000,ge=1,le=1000000)


def analyze_control(facts,read,config):
    flows,methods,cfgs,hashes=_inputs(facts,read);run=facts.run.run_id;reports=[];trace_cache={}
    raw_mapping=defaultdict(list)
    for edge in facts.relations:
        if edge.relation_kind=='dex_jimple_mapping' and edge.target and edge.resolution=='resolved':raw_mapping[edge.target.element_ref].append(edge.source)
    for owner,flow in sorted(flows.items()):
        method,cfg=methods[owner],cfgs[owner]
        result={'method_ref':owner,'state':'complete','reason':None,'conditions':[],'controls':[],'predicate_nodes':[],'predicate_inputs':[],
            'issues':[],'visits':0,'scope':config.scope,'input_cfg_sha256':flow.cfg_sha256}
        reports.append(result)
        if flow.state!='complete':result.update(state='unavailable',reason='Local CFG/analysis incomplete');continue
        succ=defaultdict(set);pred=defaultdict(set)
        for a,b in cfg.normal_edges:succ[a].add(b);pred[b].add(a)
        reachable=set();q=deque([0] if method.units else [])
        while q:
            n=q.popleft()
            if n in reachable:continue
            reachable.add(n);q.extend(succ[n])
        exits={n for n in reachable if not succ[n]};can_exit=set();q=deque(exits)
        while q:
            n=q.popleft()
            if n in can_exit:continue
            can_exit.add(n);q.extend(pred[n])
        if reachable-can_exit:
            result.update(state='unavailable',reason='Non-exiting CFG region; ordinary postdominance scope incomplete');continue
        if cfg.exception_edges:result['issues'].append('Exceptional constraints excluded; method-local explicit normal branches only')
        universe=reachable|{-1};post={n:set(universe) for n in reachable};post[-1]={-1}
        try:
            changed=True
            while changed:
                changed=False
                for n in sorted(reachable,reverse=True):
                    result['visits']+=1
                    if result['visits']>config.max_visits:raise OverflowError('Postdominator budget exceeded')
                    successors=succ[n] or {-1};common=set.intersection(*(post[x] for x in successors));value={n}|common
                    if value!=post[n]:post[n]=value;changed=True
            direct=defaultdict(set);by_condition={}
            for unit in method.units:
                if unit.index not in reachable or unit.condition is None:continue
                if unit.switch_keys or len(succ[unit.index])!=2:
                    result['issues'].append('Switch/degenerate branch not in first-version if scope');continue
                branch_ref=flow.node_refs[unit.index]
                for successor in sorted(succ[unit.index]):
                    taken=successor in unit.targets;label='taken' if taken else 'fallthrough'
                    ref=record_id(run,'condition',['control',owner,unit.index,successor]);value_point=None;expected=taken;normalization='predicate_truth'
                    children=unit.condition.children
                    local=next((x for x in children if x.local_index is not None and x.type_descriptor=='Z'),None)
                    literal=next((x for x in children if x.constant_kind=='int' and x.constant in [0,1]),None)
                    if local and literal and unit.condition.kind in {'JEqExpr','JNeExpr'}:
                        expected=bool(literal.constant)
                        if unit.condition.kind=='JNeExpr':expected=not expected
                        if not taken:expected=not expected
                        value_point=Endpoint(element_ref=branch_ref,slot_kind='local',slot_index=local.local_index,position_label=f'unit:{unit.index}')
                        normalization='boolean_local'
                    else:
                        node_ref=record_id(run,'analysis',['control-predicate',owner,unit.index])
                        value_point=Endpoint(element_ref=node_ref,slot_kind='value',position_label=f'predicate:{owner}:{unit.index}')
                        if not any(x['id']==node_ref for x in result['predicate_nodes']):
                            result['predicate_nodes'].append({'id':node_ref,'unit':unit.index,'position_label':value_point.position_label})
                            locals_=sorted({x.local_index for x in unit.uses if x.local_index is not None})
                            result['predicate_inputs'].extend({'source':Endpoint(element_ref=branch_ref,slot_kind='local',slot_index=i,position_label=f'unit:{unit.index}').model_dump(mode='json'),
                                'target':value_point.model_dump(mode='json'),'unit':unit.index} for i in locals_)
                    source_points=[value_point] if normalization=='boolean_local' else [Endpoint(**x['source']) for x in result['predicate_inputs'] if x['unit']==unit.index]
                    sources=[]
                    for point in source_points:
                        try:sources.append(trace_context_sources(facts,read,owner,point,limit=1000,_cache=trace_cache))
                        except (ValueError,KeyError) as error:sources.append({'state':'unknown',
                            'reason':_missing_context_reason(error,entry_for(owner)) or str(error),'endpoint':point.model_dump(mode='json')})
                    condition={'condition_ref':ref,'branch_ref':branch_ref,'branch_unit':unit.index,'successor':successor,'label':label,
                        'value_endpoint':value_point.model_dump(mode='json'),'expected_value':expected,'normalization':normalization,
                        'expression':unit.condition.model_dump(mode='json'),'source_evidence':sources}
                    result['conditions'].append(condition);by_condition[ref]=condition
                    for target in sorted(post[successor]-post[unit.index]-{-1}):
                        if target!=unit.index:direct[target].add(ref)
            # Nested branch controllers apply locally through the direct CD graph.
            for target in sorted(direct):
                q=deque((c,[c]) for c in sorted(direct[target]));seen=set()
                while q:
                    condition,path=q.popleft()
                    if condition in seen:continue
                    seen.add(condition)
                    if len(result['controls'])>=config.max_controls:raise OverflowError('Control relation budget exceeded')
                    result['controls'].append({'target_unit':target,'condition_ref':condition,'via_conditions':path})
                    for parent in sorted(direct[by_condition[condition]['branch_unit']]):
                        if parent not in seen:q.append((parent,[*path,parent]))
            if result['issues']:result['state']='partial';result['reason']='Some control semantics remain outside supported normal-if scope'
        except OverflowError as error:
            result.update(state='truncated',reason=str(error),conditions=[],controls=[],predicate_nodes=[],predicate_inputs=[])
    return {'schema_version':'control-evidence.v1','run_ref':run,'configuration':config.model_dump(mode='json'),'methods':reports,
        'raw_mapping':{key:[p.model_dump(mode='json') for p in value] for key,value in raw_mapping.items()},'path_feasibility_checked':False}


def _emit(facts,report):
    run=facts.run.run_id;nodes=[];edges=[];records={x.id:x for x in facts.elements}
    for method in report['methods']:
        owner=method['method_ref'];flow_cfg=record_id(run,'analysis',[owner,'local-cfg'])
        prov=lambda *refs:Provenance(kind='static_analysis',tool_ref=TOOL,rule_ref=RULE,support_refs=list(dict.fromkeys([owner,flow_cfg,*refs])))
        for predicate in method['predicate_nodes']:
            nodes.append(AnalysisNodeRecord(id=predicate['id'],run_ref=run,kind='analysis_node',node_kind='state',method_ref=owner,
                position=AnalysisPosition(kind='analysis',artifact_path=ENTRY,position_label=predicate['position_label']),provenance=prov(),
                slots=[ProgramSlot(slot_kind='value',type_descriptor='Z',value=ValueInfo(status='unknown',reason='Truth of recorded local predicate'))]))
        by_cond={x['condition_ref']:x for x in method['conditions']}
        for condition in method['conditions']:
            nodes.append(ConditionRecord(id=condition['condition_ref'],run_ref=run,kind='condition',provenance=prov(condition['branch_ref']),
                branch_ref=condition['branch_ref'],branch_label=condition['label'],value_endpoint=Endpoint(**condition['value_endpoint']),
                expected_value=ValueInfo(status='known',value=condition['expected_value'])))
        for index,entry in enumerate(method['predicate_inputs']):
            edges.append(RelationRecord(id=record_id(run,'relation',['predicate-input',owner,index]),run_ref=run,provenance=prov(entry['source']['element_ref'],entry['target']['element_ref']),
                relation_kind='data_dependency',source=Endpoint(**entry['source']),target=Endpoint(**entry['target']),resolution='resolved',source_selector=ENTRY+f'#/methods/{report["methods"].index(method)}/predicate_inputs/{index}'))
        flows=[x for x in facts.elements if isinstance(x,AnalysisNodeRecord) and x.node_kind=='jimple' and x.method_ref==owner]
        by_unit={int(x.position.position_label.split(':')[1]):x for x in flows}
        for index,entry in enumerate(method['controls']):
            condition=by_cond[entry['condition_ref']];target=by_unit[entry['target_unit']]
            endpoints=[Endpoint(element_ref=target.id,slot_kind='element',position_label=target.position.position_label)]
            endpoints += [Endpoint(**{**p,'slot_kind':'element','slot_index':None,'slot_label':None}) for p in report['raw_mapping'].get(target.id,[])]
            for point in endpoints:
                edges.append(RelationRecord(id=record_id(run,'relation',['control',owner,index,point.element_ref]),run_ref=run,
                    provenance=prov(condition['branch_ref'],point.element_ref,entry['condition_ref'],*entry['via_conditions']),relation_kind='control_dependency',
                    source=Endpoint(element_ref=condition['branch_ref'],slot_kind='element',position_label=f"unit:{condition['branch_unit']}"),
                    target=point,condition_refs=[entry['condition_ref']],resolution='resolved',source_selector=ENTRY+f'#/methods/{report["methods"].index(method)}/controls/{index}'))
    return nodes,edges


def extend_control(result,config=None):
    config=ControlConfig.model_validate((config or ControlConfig()).model_dump());facts=result.facts;run=facts.run.run_id
    facts.run.configuration.options['control']=config.model_dump(mode='json');facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    report=analyze_control(facts,lambda e:result.blobs[result.entry_digests[e]],config)
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='local control constraints',version=__version__))
    for entry,raw,ref in [('analysis/rules/control.py',Path(__file__).read_bytes(),RULE),(ENTRY,canonical_json(report).encode(),None)]:
        digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[entry]=digest
        if ref:facts.run.artifacts.append(VersionedArtifact(artifact_id=ref,kind='rule',name='explicit normal-if postdominance',version='1',sha256=digest,location=entry))
    nodes,edges=_emit(facts,report);facts.elements.extend(nodes);facts.relations.extend(edges)
    status=next(x for x in facts.statuses if x.capability=='control' and x.scope.kind=='run');status.tool_ref=TOOL;status.state='partial';status.reason='Explicit normal-completion if scope only; exceptional/global paths and unsupported regions remain unknown'
    for method in report['methods']:
        facts.statuses.append(AnalysisStatus(id=record_id(run,'status',['control',method['method_ref']]),run_ref=run,tool_ref=TOOL,capability='control',scope=AnalysisScope(kind='element',element_ref=method['method_ref']),
            state=method['state'],reason=method['reason'],issue_code=None if method['state']=='complete' else 'control_'+method['state']))
    result.facts=loads_facts(facts.model_dump_json());verify_control(result.facts,lambda e:result.blobs[result.entry_digests[e]])
    result.summary.update(stage='F6',control={'methods':len(report['methods']),'conditions':sum(len(x['conditions']) for x in report['methods'])},
        coverage={x.capability:x.state for x in facts.statuses if x.scope.kind=='run'},element_counts=dict(Counter(x.kind for x in facts.elements)),relation_counts=dict(Counter(x.relation_kind for x in facts.relations)))
    return result


def extract_control(apk,*,flow_config=None,config=None):return extend_control(extract_operations(apk,flow_config=flow_config),config)


def verify_control(facts,read):
    own=lambda x:x.provenance.tool_ref==TOOL or x.provenance.rule_ref==RULE
    actual=[{x.id:x for x in values if own(x)} for values in [facts.elements,facts.relations]]
    if not any(x.tool_id==TOOL for x in facts.run.tools):
        if any(actual):raise ValueError('Control facts lack analysis tool')
        return
    report=json.loads(read(ENTRY));config=ControlConfig.model_validate(facts.run.configuration.options['control'])
    source_rule=next((x.sha256 for x in facts.run.artifacts if x.artifact_id==RULE),None)
    checked_report=_legacy_context_source_projection(report,read) if source_rule==LEGACY_CONTEXT_REASON_RULE else report
    if checked_report!=analyze_control(facts,read,config):raise ValueError('Control conditions or local scope disagree with CFG')
    if actual!=[{x.id:x for x in values} for values in _emit(facts,report)]:raise ValueError('Forged control facts/conditions')


def control_evidence(facts,read,refs):
    report=json.loads(read(ENTRY));conditions={x['condition_ref']:x for m in report['methods'] for x in m['conditions']};records={x.id:x for x in facts.elements};methods={m['method_ref']:m for m in report['methods']}
    result=[]
    for ref in refs:
        original=records[ref];owner=getattr(getattr(original,'position',None),'method_ref',None) or getattr(original,'method_ref',None)
        edges=[x for x in facts.relations if x.relation_kind=='control_dependency' and x.target and x.target.element_ref==ref]
        refs_=sorted({c for edge in edges for c in edge.condition_refs})
        result.append({'operation_ref':ref,'method_ref':owner,'state':methods.get(owner,{}).get('state','unavailable'),'scope':'method_normal_completion',
            'conditions':[{'record':records[c].model_dump(mode='json'),'analysis':conditions[c]} for c in refs_],
            'relation_refs':[x.id for x in edges],'absence_is_unconditional':False,'issues':methods.get(owner,{}).get('issues',[])})
    return {'schema_version':'control-query.v1','run_ref':facts.run.run_id,'operations':result,'path_feasibility_checked':False}
