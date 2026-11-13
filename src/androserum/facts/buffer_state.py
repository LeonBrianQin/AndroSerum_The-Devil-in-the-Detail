"""Selected AudioRecord short-buffer effects over existing contextual graphs.

This is an explicit conditional API model, not a FlowDroid result or a new
points-to analysis. Only unique allocation identities and constant accesses
are linked. Normal CFG witnesses are not proofs of whole-path feasibility.
"""
from collections import defaultdict,deque
import hashlib,json
from pathlib import Path
from typing import Literal
from pydantic import Field
from types import SimpleNamespace
from androserum import __version__
from androserum.facts.call_flow import _inputs
from androserum.facts.context_heap import ContextHeapReport,entry_for
from androserum.facts.identity import canonical_json,fingerprint,record_id
from androserum.facts.io import loads_facts
from androserum.facts.models import (AnalysisNodeRecord,ModelPosition,AnalysisPosition,AnalysisScope,AnalysisStatus,
    BindingRecord,ConditionRecord,Endpoint,ProgramSlot,Provenance,RelationRecord,StrictModel,ToolVersion,ValueInfo,VersionedArtifact)

TOOL='tool:buffer-state';RULE='rule:buffer-state';MODEL='model:audiorecord-short-buffer-v1'
ENTRY='analysis/buffer-state/report.json'
SIGNATURE='Landroid/media/AudioRecord;->read([SII)I'
UPSTREAM_ENTRY='analysis/models/AudioRecord.android-9.0.0_r1.java'
UPSTREAM_SHA256='de4511ccf952f4a9de5a554617843935b0f7d8dc0a90af174131bf26ca57f9cc'
MODEL_SPEC={'version':'1','signature':SIGNATURE,'buffer_argument':0,'offset_argument':1,'count_argument':2,
    'upstream_url':'https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-9.0.0_r1/media/java/android/media/AudioRecord.java',
    'upstream_sha256':UPSTREAM_SHA256,'upstream_entry':UPSTREAM_ENTRY,'platform_contract':'Android 9/API 28; three-argument short[] read delegates to READ_BLOCKING',
    'normal_write_condition':'Framework implementation applies; normal return n > 0; valid offset/count; actual written interval [offset,offset+n)',
    'failure':'n <= 0 or exceptional completion supplies no new audio contents; prior contents are not erased',
    'scope':'unique finite allocation in existing context projection; constant offset/count/read index; sequential normal CFG',
    'excluded':['other overloads','async/concurrent mutation','general aliasing','dynamic ranges','complete exception heap','whole path feasibility']}


class BufferConfig(StrictModel):
    schema_version:Literal['buffer-state-config.v1']='buffer-state-config.v1'
    max_writers:int=Field(default=256,ge=1,le=10000)
    max_candidates:int=Field(default=4096,ge=1,le=100000)
    max_visits:int=Field(default=100000,ge=1,le=10000000)


def _key(point):return canonical_json(point.model_dump(mode='json'))


def analyze_buffers(facts,read,config):
    run=facts.run.run_id;effects=[];decisions=[];issues=[];visits=0
    if not any(x.tool_id=='tool:context-heap' for x in facts.run.tools):
        return {'schema_version':'buffer-state-evidence.v1','run_ref':run,'configuration':config.model_dump(mode='json'),
            'effects':[],'read_decisions':[],'issues':[{'state':'unavailable','reason':'Context heap stage not present'}],'visits':0,
            'execution_claim':'possible_only','path_feasibility_checked':False,'exception_policy':'normal CFG only; exceptional writes are not inferred',
            'failed_read_erases_prior_contents':False,'complete_array_coverage_claimed':False}
    flows,methods,_,_=_inputs(facts,read)
    original_units={ref:methods[owner].units[i] for owner,flow in flows.items() for i,ref in enumerate(flow.node_refs)}
    roots=sorted({x.method_ref for x in facts.elements if getattr(x,'node_kind',None)=='state' and
        x.provenance.tool_ref=='tool:context-heap' and getattr(x.position,'position_label',None)=='context-heap'})
    def use_budget():
        nonlocal visits
        visits+=1
        if visits>config.max_visits:raise OverflowError('Buffer origin/CFG visit budget exhausted')
    for root in roots:
        report=ContextHeapReport.model_validate_json(read(entry_for(root)))
        if report.state!='complete':
            issues.append({'root_ref':root,'state':report.state,'reason':'Context projection unavailable: '+str(report.reason)});continue
        p=report.projection;nodes=p.nodes;units=p.method.units;by_ref={x.node_ref:x for x in nodes}
        incoming=defaultdict(list);root_map=defaultdict(list);succ=defaultdict(list)
        for edge in report.scalar.links:incoming[_key(edge.target)].append(edge.source)
        for item in report.scalar.roots:root_map[_key(item.endpoint)].append(item)
        for a,b in p.cfg.normal_edges:succ[a].append(b)
        point=lambda i,kind,index=None:Endpoint(element_ref=nodes[i].node_ref,position_label=f'unit:{i}',slot_kind=kind,slot_index=index)
        cache={}
        def origins(endpoint):
            key=_key(endpoint)
            if key not in cache:
                q=deque([endpoint]);seen=set();found=[]
                while q:
                    use_budget();current=q.popleft();k=_key(current)
                    if k in seen:continue
                    seen.add(k);found.extend(root_map[k]);q.extend(incoming[k])
                cache[key]=found
            return cache[key]
        def literal(value,unit):
            if value is None:return None
            if value.constant_kind=='int':return value.constant
            if value.local_index is None:return None
            values=origins(point(unit,'local',value.local_index))
            if len(values)!=1 or values[0].kind!='constant':return None
            operand=values[0].details.get('operand',{})
            return operand.get('constant') if operand.get('constant_kind')=='int' else None
        def result_of(value,unit,writer):
            if value.local_index is None:return False
            values=origins(point(unit,'local',value.local_index))
            return bool(values) and all(v.kind=='call_result' and v.endpoint.element_ref==nodes[writer].node_ref for v in values)
        def refine(lo,hi,unit,target,writer):
            cond=unit.condition
            if not cond or len(cond.children)!=2:return lo,hi,None
            a,b=cond.children;op=cond.kind;constant=literal(b,unit.index)
            if not result_of(a,unit.index,writer):
                if result_of(b,unit.index,writer):
                    constant=literal(a,unit.index);op={'JGtExpr':'JLtExpr','JGeExpr':'JLeExpr','JLtExpr':'JGtExpr','JLeExpr':'JGeExpr'}.get(op,op)
                else:return lo,hi,None
            if constant is None:return lo,hi,None
            # Projection targets include *both* normal successors, so their
            # membership is not the original predicate truth. Recover that
            # label from original Jimple, keeping the projected local indices.
            original=original_units.get(nodes[unit.index].origin_ref)
            successor=original_units.get(nodes[target].origin_ref)
            if original is None or successor is None:return lo,hi,None
            taken=successor.index in original.targets
            if not taken:op={'JGtExpr':'JLeExpr','JGeExpr':'JLtExpr','JLtExpr':'JGeExpr','JLeExpr':'JGtExpr','JEqExpr':'JNeExpr','JNeExpr':'JEqExpr'}.get(op,op)
            if op=='JGtExpr':lo=max(lo,constant+1)
            elif op=='JGeExpr':lo=max(lo,constant)
            elif op=='JLtExpr':hi=min(hi,constant-1)
            elif op=='JLeExpr':hi=min(hi,constant)
            elif op=='JEqExpr':lo=max(lo,constant);hi=min(hi,constant)
            elif op=='JNeExpr' and lo==hi==constant:lo=hi+1
            return lo,hi,{'branch_ref':nodes[unit.index].node_ref,'target_unit':target,'taken':taken,
                'predicate':cond.model_dump(mode='json'),'constraint_operator':op,'constant':constant}
        objects={x.allocation_unit:x for x in report.heap.objects};accesses={x.unit:x for x in report.heap.accesses}
        try:
            for writer,unit in enumerate(units):
                if not unit.invoke or unit.invoke.signature!=SIGNATURE or nodes[writer].role=='exception_effect':continue
                if len(effects)>=config.max_writers:raise OverflowError('Buffer writer budget exhausted')
                refs=origins(point(writer,'argument',0));allocation=[by_ref[x.endpoint.element_ref].index for x in refs if x.kind=='allocation' and x.endpoint.element_ref in by_ref]
                obj=objects.get(allocation[0]) if len(refs)==len(allocation)==1 else None
                if not obj and len(refs)==len(allocation)==1:
                    # Heap analysis materializes objects lazily at actual
                    # field/array accesses. An API-only allocation still has
                    # a verified projected allocation identity.
                    index=allocation[0];q=deque(succ[index]);seen=set();repeated=False
                    while q:
                        use_budget();n=q.popleft()
                        if n==index:repeated=True;break
                        if n not in seen:seen.add(n);q.extend(succ[n])
                    obj=SimpleNamespace(object_ref=nodes[index].node_ref,allocation_unit=index,single_allocation_per_invocation=not repeated)
                if obj and not obj.single_allocation_per_invocation:obj=None
                offset=literal(unit.invoke.arguments[1],writer);count=literal(unit.invoke.arguments[2],writer)
                allocated=units[obj.allocation_unit].right if obj else None
                length=literal(allocated.children[0],obj.allocation_unit) if allocated and allocated.kind=='JNewArrayExpr' and len(allocated.children)==1 else None
                invalid=(offset is not None and offset<0 or count is not None and count<=0 or
                    offset is not None and count is not None and (offset+count>2147483647 or length is not None and offset+count>length))
                effect={'effect_ref':record_id(run,'analysis',['buffer-state',root,writer]),'root_ref':root,'writer_ref':nodes[writer].node_ref,
                    'original_writer_ref':nodes[writer].origin_ref,'context_ref':nodes[writer].frame_ref,
                    'call_path':[x.model_dump(mode='json') for x in next(f for f in p.frames if f.context_ref==nodes[writer].frame_ref).call_path],
                    'signature':SIGNATURE,'buffer_endpoint':point(writer,'argument',0).model_dump(mode='json'),
                    'object_ref':obj.object_ref if obj else None,'allocation_endpoint':point(obj.allocation_unit,'result').model_dump(mode='json') if obj else None,
                    'offset':offset,'requested_count':count,'allocation_length':length,'known_invalid_request':bool(invalid),
                    'actual_interval':'[offset,offset+n), only on normal return n>0',
                    'result_endpoint':point(writer,'result').model_dump(mode='json') if unit.definitions else None,
                    'success_proven':False,'rule_ref':MODEL,'issues':[],
                    'condition_ref':record_id(run,'condition',['buffer-success',root,writer]),'reads':[]}
                effects.append(effect)
                if obj is None:effect['issues'].append('Buffer allocation is unknown, ambiguous or repeated')
                if offset is None or count is None:effect['issues'].append('Nonconstant offset/count outside v1 propagation scope')
                if invalid:effect['issues'].append('Known invalid or empty request supplies no successful buffer-write dependency')
                if not unit.definitions:effect['issues'].append('Return status not mapped in projection; write remains explicitly conditional')
                for access in report.heap.accesses:
                    if access.operation!='array_read':continue
                    if len(decisions)>=config.max_candidates:raise OverflowError('Buffer candidate budget exhausted')
                    row={'effect_ref':effect['effect_ref'],'root_ref':root,'read_ref':access.unit_ref,'read_unit':access.unit,
                        'read_index':access.index,'objects':access.objects,'unknown_base':access.unknown_base,
                        'state':'not_adapted','reason':None,'witness':[],'guards':[]}
                    decisions.append(row)
                    if not obj or offset is None or count is None:row['reason']='writer_object_or_range_unknown';continue
                    if access.unknown_base or len(access.objects)!=1:row['reason']='read_object_unknown_or_ambiguous';continue
                    if access.objects!=[obj.object_ref]:row.update(state='rejected',reason='different_buffer_allocation');continue
                    if access.unknown_index or access.index is None:row['reason']='read_index_unknown';continue
                    if invalid:row.update(state='rejected',reason='invalid_or_empty_request');continue
                    if access.index<offset or access.index>=offset+count:row.update(state='rejected',reason='outside_requested_interval');continue
                    # Existential sequential witness. Propagate the *actual*
                    # count bound, reject failed/zero/short-read branches, and
                    # stop on overlapping overwrites or unknown buffer calls.
                    q=deque((n,max(1,access.index-offset+1),count,[writer,n],[]) for n in succ[writer]);seen=set();blocked=set();found=None
                    while q:
                        use_budget();current,lo,hi,path,guards=q.popleft();key=(current,lo,hi)
                        if key in seen:continue
                        seen.add(key)
                        if current==writer:blocked.add('repeated_writer_cycle');continue
                        if lo>hi:blocked.add('nonpositive_or_short_read_branch');continue
                        if current==access.unit:found=(path,guards,lo,hi);break
                        current_access=accesses.get(current)
                        if current_access and current_access.operation=='array_write' and (current_access.unknown_base or obj.object_ref in current_access.objects):
                            if current_access.unknown_index or current_access.index==access.index:blocked.add('intervening_buffer_overwrite');continue
                        other=units[current]
                        if other.invoke and nodes[current].role!='call_entry':
                            maybe=False
                            for arg in range(len(other.invoke.arguments)):
                                for origin in origins(point(current,'argument',arg)):
                                    if origin.kind=='allocation' and origin.endpoint.element_ref==nodes[obj.allocation_unit].node_ref:maybe=True
                            # An opaque call can also affect an escaped array
                            # through fields/globals, without an array argument.
                            # V1 has no escape/summary proof to exempt it.
                            blocked.add('intervening_opaque_buffer_call' if maybe else 'intervening_opaque_call_effect_unknown');continue
                        for target in succ[current]:
                            lower,upper,guard=refine(lo,hi,other,target,writer)
                            q.append((target,lower,upper,[*path,target],[*guards,*([guard] if guard else [])]))
                    if not found:
                        row.update(state='rejected',reason=','.join(sorted(blocked)) or 'no_normal_cfg_path');continue
                    path,guards,lo,hi=found
                    row.update(state='included_conditional',reason='Same allocated array, actual count interval and normal CFG witness; success is a model precondition',
                        witness=path,guards=guards,actual_count_bounds=[lo,hi],read_endpoint=point(access.unit,'result').model_dump(mode='json'),
                        read_context_ref=nodes[access.unit].frame_ref,base_endpoint=access.base_endpoint.model_dump(mode='json'),
                        support_refs=list(dict.fromkeys([nodes[i].node_ref for i in path]+access.binding_refs)))
                    effect['reads'].append(len(decisions)-1)
        except OverflowError as error:issues.append({'root_ref':root,'state':'truncated','reason':str(error)});break
    return {'schema_version':'buffer-state-evidence.v1','run_ref':run,'configuration':config.model_dump(mode='json'),
        'effects':effects,'read_decisions':decisions,'issues':issues,'visits':visits,
        'execution_claim':'possible_only','path_feasibility_checked':False,'exception_policy':'normal CFG only; exceptional writes are not inferred',
        'failed_read_erases_prior_contents':False,'complete_array_coverage_claimed':False}


def _emit(facts,report):
    run=facts.run.run_id;nodes=[];bindings=[];edges=[]
    for index,effect in enumerate(report['effects']):
        writer=effect['writer_ref'];ref=effect['effect_ref'];condition=effect['condition_ref']
        support=[writer,*([effect['original_writer_ref']] if effect['original_writer_ref'] else [])]
        if effect['object_ref']:support.append(effect['object_ref'])
        prov=lambda refs:Provenance(kind='model_assisted',tool_ref=TOOL,rule_ref=MODEL,support_refs=list(dict.fromkeys(refs)))
        state=Endpoint(element_ref=ref,position_label=ref,slot_kind='state',slot_label='written_buffer_content')
        precondition=Endpoint(element_ref=ref,position_label=ref,slot_kind='value')
        nodes.append(AnalysisNodeRecord(id=ref,run_ref=run,kind='analysis_node',node_kind='state',method_ref=effect['root_ref'],
            position=ModelPosition(kind='model',model_ref=MODEL,position_label=ref),provenance=prov(support),
            text='Potential AudioRecord FRAMEWORK implementation buffer write; normal return n>0 and valid request required; only [offset,offset+n) is written; success and dispatch NOT established. '+
                canonical_json({k:effect[k] for k in ['offset','requested_count','allocation_length','known_invalid_request','result_endpoint','issues']}),
            slots=[ProgramSlot(slot_kind='state',slot_label='written_buffer_content',value=ValueInfo(status='unknown',reason='Conditional modeled audio contents')),
                ProgramSlot(slot_kind='value',value=ValueInfo(status='unknown',reason='Model precondition, not a recognized execution branch'))]))
        nodes.append(ConditionRecord(id=condition,run_ref=run,kind='condition',branch_ref=writer,
            branch_label='MODEL PRECONDITION: framework implementation, valid request and normal return n>0; not proof of a taken branch',value_endpoint=precondition,
            expected_value=ValueInfo(status='known',value=True),provenance=prov(support)))
        obj_binding=[]
        if effect['allocation_endpoint']:
            bound=record_id(run,'binding',['buffer-object',ref]);obj_binding=[bound]
            bindings.append(BindingRecord(id=bound,run_ref=run,binding_kind='object',context_ref=effect['context_ref'],
                endpoints=[Endpoint(**effect['buffer_endpoint']),Endpoint(**effect['allocation_endpoint'])],condition_refs=[condition],provenance=prov(support)))
        if not effect['known_invalid_request']:
            edges.append(RelationRecord(id=record_id(run,'relation',['buffer-effect',ref]),run_ref=run,relation_kind='state_dependency',
                source=Endpoint(**effect['buffer_endpoint']),target=state,context_ref=effect['context_ref'],binding_refs=obj_binding,condition_refs=[condition],
                resolution='partial',unresolved_reason='Conditional API effect; buffer reference is not audio contents; inspect model precondition and actual count interval',
                provenance=prov(support),source_selector=ENTRY+f'#/effects/{index}'))
        for d in effect['reads']:
            row=report['read_decisions'][d];bound=record_id(run,'binding',['buffer-read',ref,d])
            bindings.append(BindingRecord(id=bound,run_ref=run,binding_kind='state',context_ref=effect['context_ref'],condition_refs=[condition],
                endpoints=[Endpoint(**effect['buffer_endpoint']),Endpoint(**row['base_endpoint'])],provenance=prov([*support,*row['support_refs']])))
            edges.append(RelationRecord(id=record_id(run,'relation',['buffer-read',ref,d]),run_ref=run,relation_kind='state_dependency',
                source=state,target=Endpoint(**row['read_endpoint']),context_ref=effect['context_ref'],binding_refs=[*obj_binding,bound],condition_refs=[condition],
                resolution='partial',unresolved_reason='Selected conditional same-buffer state witness; actual n bounds retained; no guaranteed execution, full path feasibility or exception propagation',
                provenance=prov([*support,*row['support_refs']]),source_selector=ENTRY+f'#/read_decisions/{d}'))
    return nodes,bindings,edges


def extend_buffer_state(result,config=None):
    config=config or BufferConfig();facts=result.facts
    if any(x.tool_id==TOOL for x in facts.run.tools):raise ValueError('Buffer model must be added to a fresh run, not applied twice')
    facts.run.configuration.options['buffer_state']=config.model_dump(mode='json')
    facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    report=analyze_buffers(facts,lambda e:result.blobs[result.entry_digests[e]],config)
    upstream=(Path(__file__).resolve().parents[3]/'.resources/buffer-state/AudioRecord.android-9.0.0_r1.java').read_bytes()
    if hashlib.sha256(upstream).hexdigest()!=UPSTREAM_SHA256:raise ValueError('Pinned AudioRecord upstream contract changed')
    for entry,raw,ref,kind in [(ENTRY,canonical_json(report).encode(),None,None),
        (UPSTREAM_ENTRY,upstream,'model:audiorecord-aosp28','summary'),
        ('analysis/rules/buffer_state.py',Path(__file__).read_bytes(),RULE,'rule'),
        ('analysis/rules/buffer-state.json',canonical_json(MODEL_SPEC).encode(),MODEL,'summary')]:
        digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[entry]=digest
        if ref:facts.run.artifacts.append(VersionedArtifact(artifact_id=ref,kind=kind,name='selected AudioRecord buffer state',version='1',sha256=digest,location=entry))
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='conditional AudioRecord buffer state',version=__version__))
    nodes,bindings,edges=_emit(facts,report);facts.elements.extend(nodes);facts.bindings.extend(bindings);facts.relations.extend(edges)
    for effect in report['effects']:
        facts.statuses.append(AnalysisStatus(id=record_id(facts.run.run_id,'status',['buffer-state',effect['effect_ref']]),run_ref=facts.run.run_id,
            tool_ref=TOOL,capability='objects',scope=AnalysisScope(kind='element',element_ref=effect['effect_ref']),state='partial',
            reason='Conditional finite model; success/runtime/concurrency unknown; constant intervals and unique allocation only'))
    result.facts=loads_facts(facts.model_dump_json())
    verify_buffer_state(result.facts,lambda e:result.blobs[result.entry_digests[e]])
    result.summary.update(buffer_state={'effects':len(report['effects']),'included_reads':sum(x['state']=='included_conditional' for x in report['read_decisions']),
        'issues':report['issues'],'conditional_only':True})
    return result


def verify_buffer_state(facts,read):
    own=lambda x:x.provenance.tool_ref==TOOL
    actual=[{x.id:x for x in values if own(x)} for values in [facts.elements,facts.bindings,facts.relations]]
    if not any(x.tool_id==TOOL for x in facts.run.tools):
        if any(actual):raise ValueError('Buffer state facts lack tool metadata')
        return
    if read('analysis/rules/buffer-state.json')!=canonical_json(MODEL_SPEC).encode():raise ValueError('Buffer model differs from fixed rules')
    if hashlib.sha256(read(UPSTREAM_ENTRY)).hexdigest()!=UPSTREAM_SHA256:raise ValueError('Pinned AudioRecord upstream contract changed')
    config=BufferConfig.model_validate(facts.run.configuration.options['buffer_state']);report=json.loads(read(ENTRY))
    if report!=analyze_buffers(facts,read,config):raise ValueError('Buffer state report differs from source projection/model')
    if actual!=[{x.id:x for x in values} for values in _emit(facts,report)]:raise ValueError('Forged buffer state endpoints, conditions or object bindings')


def buffer_evidence(facts,read,refs):
    if not any(x.tool_id==TOOL for x in facts.run.tools):return {'schema_version':'buffer-state-query.v1','state':'not_started','effects':[],'read_decisions':[]}
    report=json.loads(read(ENTRY));selected=set(refs)
    return {**report,'schema_version':'buffer-state-query.v1','state':'partial',
        'effects':[x for x in report['effects'] if not selected or selected & {x['writer_ref'],x['original_writer_ref'],x['effect_ref'],x['root_ref']}],
        'read_decisions':[x for x in report['read_decisions'] if not selected or selected & {x['read_ref'],x['root_ref'],x['effect_ref']}]}
