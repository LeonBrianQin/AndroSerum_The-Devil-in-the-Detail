"""Selected short-buffer loop reads; finite patterns, explicit per-element conditions.

Only configured physical sites are considered. This adapter proves identity,
recorded expression/loop structure and a conditional normal-flow connection;
it does not solve arbitrary symbolic ranges or assert a successful recording.
"""
from collections import defaultdict,deque
from pathlib import Path
from typing import Literal
import hashlib,json
from pydantic import Field
from androserum import __version__
from androserum.facts.call_flow import _inputs
from androserum.facts.context_heap import ContextHeapReport,entry_for
from androserum.facts.identity import canonical_json,fingerprint,record_id
from androserum.facts.io import loads_facts
from androserum.facts.models import (StrictModel,MethodSignature,SHA256,Endpoint,AnalysisNodeRecord,ModelPosition,
    ConditionRecord,ProgramSlot,ValueInfo,Provenance,BindingRecord,RelationRecord,AnalysisStatus,
    AnalysisScope,ToolVersion,VersionedArtifact)
from androserum.facts.buffer_state import ENTRY as BUFFER_ENTRY

TOOL='tool:audio-read-sites';RULE='rule:audio-read-sites';MODEL='model:audio-read-sites-v1'
ENTRY='analysis/audio-read-sites/report.json'
DOUBLE_ENTRY='analysis/models/Double.android-9.0.0_r1.java'
DOUBLE_SHA256='f344309ad72e4f0ae647b0f70c82bca711687e7f2e51ac393a923f01eb8d4223'
FOOTPRINTS={
    'Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;':'new Double(d); constructor only assigns its private primitive value field',
    'Ljava/lang/Double;->doubleValue()D':'returns its private primitive value field',
    'Ljava/lang/Double;->isNaN(D)Z':'primitive v!=v predicate; D8 may insert its unused call around numeric conversion in the controlled fixture'}
SPEC={'version':'1','patterns':['recorded constant/field/parameter and one int subtraction','unique short-array allocation',
    'zero-initialized unit-step index with strict same-array length guard','exact existing application call frames'],
    'footprints':FOOTPRINTS,'footprint_source':'https://android.googlesource.com/platform/libcore/+/android-9.0.0_r1/ojluni/src/main/java/java/lang/Double.java',
    'footprint_sha256':DOUBLE_SHA256,'written_element_condition':'framework AudioRecord call valid and normal; 0<n<=C; offset+C<=L; offset<=i<offset+n',
    'loop_condition':'0<=i<L is not evidence that i<n','field_reads_equal_assumed':False,
    'excluded':['general dynamic ranges','arbitrary loop induction','concurrent mutations','unlisted opaque calls',
        'full exception semantics','all array contents fresh','complete RMS/calibration behavior']}


class ReadSelection(StrictModel):
    root_signature:MethodSignature
    writer_offset_code_units:int=Field(ge=0)
    reader_signature:MethodSignature
    reader_offsets_code_units:list[int]=Field(min_length=1,max_length=2)


class AudioReadConfig(StrictModel):
    schema_version:Literal['selected-audio-read-config.v1']='selected-audio-read-config.v1'
    apk_sha256:SHA256
    selections:list[ReadSelection]=Field(min_length=1,max_length=16)
    max_visits:int=Field(default=20000,ge=1,le=1000000)


class ScopeGap(ValueError):pass
def _key(point):return canonical_json(point.model_dump(mode='json'))


def analyze_audio_reads(facts,read,config):
    if config.apk_sha256!=facts.run.apk_sha256:raise ValueError('Selected audio sites belong to a different APK')
    records={x.id:x for x in facts.elements};flows,methods,_,_=_inputs(facts,read)
    originals={ref:methods[owner].units[i] for owner,flow in flows.items() for i,ref in enumerate(flow.node_refs)}
    definitions={x.signature:x.id for x in facts.elements if getattr(x,'is_definition',False) and x.kind=='method'}
    raw_map=defaultdict(list);mapping_refs=defaultdict(list)
    for edge in facts.relations:
        if edge.relation_kind=='dex_jimple_mapping' and edge.resolution=='resolved' and edge.target:
            raw_map[edge.target.element_ref].append(edge.source.element_ref);mapping_refs[edge.target.element_ref].append(edge.id)
    buffer=json.loads(read(BUFFER_ENTRY));rows=[];visits=0
    def tick():
        nonlocal visits
        visits+=1
        if visits>config.max_visits:raise ScopeGap('analysis_visit_budget_exhausted')
    for selection in config.selections:
        root=definitions.get(selection.root_signature)
        try:
            if root is None:raise ScopeGap('selected_root_definition_missing')
            h=ContextHeapReport.model_validate_json(read(entry_for(root)))
            if h.state!='complete' or not h.projection:raise ScopeGap('selected_context_projection_'+h.state)
            p=h.projection;nodes=p.nodes;units=p.method.units
            succ=defaultdict(list);pred=defaultdict(list)
            for a,b in p.cfg.normal_edges:succ[a].append(b);pred[b].append(a)
            point=lambda i,k,index=None:Endpoint(element_ref=nodes[i].node_ref,position_label=f'unit:{i}',slot_kind=k,slot_index=index)
            uses={(x.unit,x.local_index):x for x in h.scalar.uses}
            incoming=defaultdict(list);outgoing=defaultdict(list);scalar_roots=defaultdict(list)
            for edge in facts.relations:
                if edge.provenance.tool_ref=='tool:context-heap' and edge.target and (edge.source_selector or '').startswith(entry_for(root)+'#'):
                    incoming[_key(edge.target)].append(edge);outgoing[_key(edge.source)].append(edge)
            for item in h.scalar.roots:scalar_roots[_key(item.endpoint)].append(item)
            def reached(start,graph,avoid=frozenset()):
                q=deque([start]);seen=set()
                while q:
                    tick();i=q.popleft()
                    if i in seen or i in avoid:continue
                    seen.add(i);q.extend(graph[i])
                return seen
            def origins(endpoint):
                q=deque([endpoint]);seen=set();found=[]
                while q:
                    tick();cur=q.popleft();key=_key(cur)
                    if key in seen:continue
                    seen.add(key);found.extend(scalar_roots[key]);q.extend(e.source for e in incoming[key])
                return found
            def path(a,b):
                q=deque([(a,[])]);seen=set()
                while q:
                    tick();cur,edges=q.popleft();key=_key(cur)
                    if key==_key(b):return [e.id for e in edges]
                    if key in seen:continue
                    seen.add(key);q.extend((e.target,[*edges,e]) for e in outgoing[key])
                raise ScopeGap('array_identity_path_not_recorded')
            def symbolic(value,at,depth=0):
                tick()
                if value is None or value.truncated or depth>4:raise ScopeGap('expression_outside_selected_depth')
                if value.constant_kind=='int':return {'kind':'constant','value':value.constant,'support_refs':[nodes[at].node_ref]}
                if value.local_index is not None:
                    u=uses.get((at,value.local_index))
                    if not u or u.undefined or len(u.definitions)!=1:raise ScopeGap('expression_has_ambiguous_reaching_definitions')
                    index=u.definitions[0];unit=units[index]
                    if unit.operation in {'field_read','identity'}:
                        return {'kind':'recorded_symbol','endpoint':point(index,'result').model_dump(mode='json'),
                            'field_signature':unit.right.field_signature if unit.right else None,
                            'origin_kind':'field_read' if unit.operation=='field_read' else 'parameter_or_receiver',
                            'support_refs':[nodes[index].node_ref,nodes[at].node_ref]}
                    result=symbolic(unit.right,index,depth+1)
                    result['support_refs']=sorted(set(result['support_refs'])|{nodes[index].node_ref,nodes[at].node_ref});return result
                if len(value.children)==2 and value.children[1].constant_kind=='int' and (
                    value.kind=='JSubExpr' and value.children[1].constant==1 or value.kind=='JAddExpr' and value.children[1].constant==-1):
                    child=symbolic(value.children[0],at,depth+1)
                    return {'kind':'java_int_subtract_one','input':child,'overflow_semantics':'signed int32 wrap; no numeric simplification assumed',
                        'support_refs':sorted(set(child['support_refs'])|{nodes[at].node_ref})}
                raise ScopeGap('expression_outside_constant_symbol_subtract_one')
            def physical(signature,offset):
                return [x for x in facts.elements if x.kind=='instruction' and
                    records[x.position.method_ref].signature==signature and x.position.offset_bytes==2*offset]
            raw_writer=physical(selection.root_signature,selection.writer_offset_code_units)
            if len(raw_writer)!=1:raise ScopeGap('writer_physical_location_not_unique')
            raw_writer=raw_writer[0]
            effects=[e for e in buffer['effects'] if e['root_ref']==root and raw_writer.id in raw_map[e['original_writer_ref']]]
            if len(effects)!=1:raise ScopeGap('writer_projected_invocation_not_unique')
            effect=effects[0];writer=next(n.index for n in nodes if n.node_ref==effect['writer_ref'])
        except (ValueError,KeyError) as error:
            for offset in selection.reader_offsets_code_units:
                rows.append({'selection':selection.model_dump(mode='json'),'reader_offset_code_units':offset,'state':'unresolved',
                    'reason':str(error),'support_refs':[],'root_ref':root})
            continue
        for offset in selection.reader_offsets_code_units:
            row={'selection':selection.model_dump(mode='json'),'reader_offset_code_units':offset,'root_ref':root,
                'state':'unresolved','reason':None,'support_refs':[],'effect_ref':effect['effect_ref'],
                'writer_ref':effect['writer_ref'],'writer_context_ref':effect['context_ref'],'api_condition_ref':effect['condition_ref']}
            rows.append(row)
            try:
                candidates=physical(selection.reader_signature,offset)
                if len(candidates)!=1 or candidates[0].operation!='array_read':raise ScopeGap('reader_physical_location_not_unique_array_read')
                raw=candidates[0];selected=[n for n in nodes if raw.id in raw_map[n.origin_ref] and n.role=='original']
                if len(selected)!=1:raise ScopeGap('reader_call_frame_not_unique')
                meta=selected[0];ix=meta.index;unit=units[ix]
                row.update(read_ref=meta.node_ref,original_reader_ref=meta.origin_ref,raw_reader_ref=raw.id,
                    read_context_ref=meta.frame_ref,read_endpoint=point(ix,'result').model_dump(mode='json'),
                    positions={'writer':raw_writer.position.model_dump(mode='json'),'reader':raw.position.model_dump(mode='json'),
                        'jimple':records[meta.origin_ref].position.model_dump(mode='json')},
                    call_path=[x.model_dump(mode='json') for x in next(f for f in p.frames if f.context_ref==meta.frame_ref).call_path])
                access=next(a for a in h.heap.accesses if a.unit==ix)
                row.update(writer_object_ref=effect['object_ref'],reader_object_refs=access.objects,
                    unknown_reader_base=access.unknown_base,base_endpoint=access.base_endpoint.model_dump(mode='json') if access.base_endpoint else None)
                if not effect['object_ref'] or access.unknown_base or access.objects!=[effect['object_ref']]:raise ScopeGap('array_identity_different_or_unresolved')
                obj=next((o for o in h.heap.objects if o.object_ref==effect['object_ref']),None)
                if not obj or not obj.single_allocation_per_invocation:raise ScopeGap('array_allocation_missing_or_repeated')
                if effect['known_invalid_request']:raise ScopeGap('writer_request_known_invalid_or_empty')
                allocation=units[obj.allocation_unit].right
                if not allocation or allocation.kind!='JNewArrayExpr' or allocation.type_descriptor!='[S' or len(allocation.children)!=1:
                    raise ScopeGap('selected_short_array_allocation_shape_missing')
                if effect['offset']!=0:raise ScopeGap('selected_pattern_requires_zero_offset')
                length=symbolic(allocation.children[0],obj.allocation_unit)
                count=symbolic(units[writer].invoke.arguments[2],writer)
                if count['kind']=='constant' and count['value']<=0:raise ScopeGap('writer_request_nonpositive')
                row['ranges']={'allocation_length':{'symbol':'L','expression':length},'requested_count':{'symbol':'C','expression':count},
                    'offset':0,'actual_written':'[0,n)','loop_reads':'[0,L)','eligible_written_subset':'[0,min(n,L))',
                    'element_preconditions':['framework AudioRecord implementation and normal return','valid request: 0<C<=L',
                        'actual result: 0<n<=C','selected element: 0<=i<n'],
                    'all_iterations_written_claimed':False,'separate_field_reads_equal_assumed':False}
                index=unit.right.index_value.local_index if unit.right and unit.right.index_value else None
                if index is None:raise ScopeGap('selected_pattern_requires_local_loop_index')
                index_use=uses.get((ix,index))
                if not index_use or index_use.undefined or len(index_use.definitions)!=2:raise ScopeGap('index_reaching_definitions_not_init_and_step')
                initial=[i for i in index_use.definitions if units[i].right and units[i].right.constant_kind=='int' and units[i].right.constant==0]
                increments=[i for i in index_use.definitions if units[i].right and units[i].right.kind=='JAddExpr' and
                    len(units[i].right.children)==2 and units[i].right.children[0].local_index==index and
                    units[i].right.children[1].constant_kind=='int' and units[i].right.children[1].constant==1]
                if len(initial)!=1 or len(increments)!=1:raise ScopeGap('index_not_zero_then_unit_increment')
                init,step=initial[0],increments[0];guards=[]
                for n in nodes:
                    cond=units[n.index].condition
                    if n.frame_ref!=meta.frame_ref or not cond or len(cond.children)!=2:continue
                    a,b=cond.children
                    if a.local_index!=index or b.local_index is None or cond.kind not in {'JLtExpr','JGeExpr'}:continue
                    use=uses.get((n.index,b.local_index))
                    if not use or use.undefined or len(use.definitions)!=1:continue
                    ld=use.definitions[0];value=units[ld].right
                    if not value or value.kind!='JLengthExpr' or len(value.children)!=1:continue
                    roots=origins(point(ld,'local',value.children[0].local_index))
                    if not roots or any(r.kind!='allocation' or r.endpoint.element_ref!=nodes[obj.allocation_unit].node_ref for r in roots):continue
                    guard_edges=[e for e in facts.relations if e.relation_kind=='control_dependency' and e.target and
                        e.target.element_ref==meta.origin_ref and e.source.element_ref==n.origin_ref]
                    cond_refs={c for e in guard_edges for c in e.condition_refs if records[c].expected_value.value==(cond.kind=='JLtExpr')}
                    if cond_refs:guards.append((n.index,ld,sorted(cond_refs),[e.id for e in guard_edges]))
                if len(guards)!=1:raise ScopeGap('strict_same_array_length_guard_not_uniquely_supported')
                guard,ld,guard_refs,guard_edges=guards[0]
                loop=reached(guard,succ)&reached(guard,pred)
                if not {guard,ld,step,ix}<=loop or init in loop:raise ScopeGap('selected_natural_loop_structure_not_supported')
                if any(units[i].condition is not None for i in loop-{guard}):raise ScopeGap('additional_loop_branch_outside_selected_pattern')
                if ix in reached(writer,succ,{init,guard}):raise ScopeGap('read_can_bypass_selected_index_initialization_and_guard')
                if ix in reached(writer,succ,{guard}):raise ScopeGap('read_can_bypass_selected_loop_guard')
                if ix in reached(writer,succ,{init}):raise ScopeGap('read_can_bypass_zero_initialization')
                # Every complete loop cycle must pass the sole unit increment.
                if guard in set().union(*(reached(s,succ,{step}) for s in succ[guard] if s in loop)):
                    raise ScopeGap('loop_cycle_can_bypass_unit_increment')
                loop_writes=[a for a in h.heap.accesses if a.unit in loop and a.operation=='array_write' and
                    (a.unknown_base or effect['object_ref'] in a.objects)]
                if loop_writes:raise ScopeGap('loop_contains_array_overwrite')
                if any(u.left and u.left.local_index==index and u.index!=step for u in (units[i] for i in loop)):
                    raise ScopeGap('loop_index_has_other_definition')
                row['loop_proof']={'initial_ref':nodes[init].node_ref,'step_ref':nodes[step].node_ref,'guard_ref':nodes[guard].node_ref,
                    'length_ref':nodes[ld].node_ref,'index_local':index,'condition_refs':guard_refs,
                    'normal_loop_units':sorted(loop),'induction':'i starts at 0, every cycle increments 1, body requires i<L; array length <= int32 max prevents increment overflow',
                    'not_an_actual_count_guard':True}
                raw_return=records.get(raw_writer.result_receiver_ref)
                if not raw_return or not any(s.slot_kind=='result' for s in raw_writer.slots):raise ScopeGap('current_call_dex_return_endpoint_missing')
                row['return_evidence']={'raw_call_ref':raw_writer.id,'move_result_ref':raw_return.id,
                    'endpoint':Endpoint(element_ref=raw_writer.id,position_label=raw_writer.position.position_label,slot_kind='result').model_dump(mode='json'),
                    'move_result_position':raw_return.position.model_dump(mode='json'),
                    'projected_result_available':bool(units[writer].definitions),'runtime_value_known':False}
                def footprint(i):
                    call=units[i].invoke
                    if not call or nodes[i].role=='call_entry':return None
                    if call.signature not in FOOTPRINTS:raise ScopeGap('unmodeled_call_can_affect_buffer:'+call.signature)
                    if call.signature in definitions:raise ScopeGap('framework_footprint_shadowed_by_apk_definition')
                    return {'unit_ref':nodes[i].node_ref,'signature':call.signature,'rule_ref':MODEL,
                        'short_array_write':False,'normal_framework_implementation_required':True,'source_sha256':DOUBLE_SHA256}
                loop_footprints=[v for i in sorted(loop) if (v:=footprint(i))]
                def returned(value,at):
                    if value.local_index is None:return False
                    roots=origins(point(at,'local',value.local_index))
                    return bool(roots) and all(r.kind=='call_result' and r.endpoint.element_ref==nodes[writer].node_ref for r in roots)
                def narrow(i,target,lo,hi):
                    cond=units[i].condition
                    if not cond or len(cond.children)!=2:return lo,hi,None
                    a,b=cond.children
                    if not returned(a,i):
                        if i==guard:return lo,hi,None
                        raise ScopeGap('path_branch_outside_selected_return_and_loop_guards')
                    if b.constant_kind!='int':raise ScopeGap('return_guard_requires_literal_integer')
                    old=originals.get(nodes[i].origin_ref);dst=originals.get(nodes[target].origin_ref)
                    if old is None or dst is None:raise ScopeGap('return_guard_branch_label_unresolved')
                    op=cond.kind;constant=b.constant
                    taken=dst.index in old.targets
                    if not taken:op={'JGtExpr':'JLeExpr','JGeExpr':'JLtExpr','JLtExpr':'JGeExpr','JLeExpr':'JGtExpr','JEqExpr':'JNeExpr','JNeExpr':'JEqExpr'}.get(op,op)
                    refs=[r.id for r in facts.elements if r.kind=='condition' and r.branch_ref==nodes[i].origin_ref and r.expected_value.value==taken]
                    if not refs:raise ScopeGap('recorded_return_guard_condition_missing')
                    if op=='JGtExpr':lo=max(lo,constant+1)
                    elif op=='JGeExpr':lo=max(lo,constant)
                    elif op=='JLtExpr':hi=min(hi,constant-1)
                    elif op=='JLeExpr':hi=min(hi,constant)
                    elif op=='JEqExpr':lo=max(lo,constant);hi=min(hi,constant)
                    elif op=='JNeExpr' and lo==hi==constant:lo=hi+1
                    return lo,hi,{'branch_ref':nodes[i].node_ref,'original_branch_ref':nodes[i].origin_ref,
                        'context_ref':nodes[i].frame_ref,'successor_ref':nodes[target].node_ref,'taken':taken,
                        'expression':cond.model_dump(mode='json'),'normalized_operator':op,'constant':constant,'condition_refs':refs}
                q=deque((s,[writer,s],1,count['value'] if count['kind']=='constant' else 2147483647,[],[]) for s in succ[writer]);seen=set();found=None;blocked=[]
                while q:
                    tick();i,witness,lo,hi,models,predicates=q.popleft();key=(i,lo,hi)
                    if key in seen:continue
                    seen.add(key)
                    if i==writer:blocked.append('writer_reentered');continue
                    if lo>hi:blocked.append('path_requires_nonpositive_read_result');continue
                    if i==ix:found=(witness,models,lo,hi,predicates);break
                    access_at=next((a for a in h.heap.accesses if a.unit==i),None)
                    if access_at and access_at.operation=='array_write' and (access_at.unknown_base or effect['object_ref'] in access_at.objects):
                        blocked.append('intervening_array_overwrite');continue
                    try:fm=footprint(i)
                    except ScopeGap as error:blocked.append(str(error));continue
                    for target in succ[i]:
                        lower,upper,predicate=narrow(i,target,lo,hi)
                        q.append((target,[*witness,target],lower,upper,[*models,*([fm] if fm else [])],
                            [*predicates,*([predicate] if predicate else [])]))
                if not found:raise ScopeGap(';'.join(sorted(set(blocked))) or 'no_supported_normal_path_from_writer')
                witness,models,lo,hi,predicates=found
                allocation_endpoint=Endpoint(**effect['allocation_endpoint'])
                write_path=path(allocation_endpoint,Endpoint(**effect['buffer_endpoint']))
                read_path=path(allocation_endpoint,access.base_endpoint)
                footprints={f['unit_ref']:f for f in [*loop_footprints,*models]}
                support=set(write_path+read_path+guard_edges+access.binding_refs+mapping_refs[meta.origin_ref]+mapping_refs[effect['original_writer_ref']])
                support.update([raw_writer.id,raw_return.id,raw.id,meta.node_ref,meta.origin_ref,effect['writer_ref'],effect['effect_ref'],effect['object_ref'],
                    nodes[obj.allocation_unit].node_ref,nodes[init].node_ref,nodes[step].node_ref,nodes[guard].node_ref,nodes[ld].node_ref,*guard_refs])
                support.update(length['support_refs']+count['support_refs']);support.update(f['unit_ref'] for f in footprints.values())
                for node in nodes:
                    if node.index in witness or node.index in loop:support.update(node.support_refs)
                if predicates:
                    row['witness_return_constraints']=predicates
                    row['ranges']['element_preconditions'].append('Returned n must also satisfy the saved normal-witness predicates; these are not dropped at a call boundary')
                    for predicate in predicates:
                        support.update([predicate['branch_ref'],predicate['original_branch_ref'],predicate['successor_ref'],*predicate['condition_refs']])
                row.update(state='conditional_connection',reason='Same array through recorded call frame; selected loop and normal path proven; only elements satisfying i<n may originate from this successful read',
                    witness=[nodes[i].node_ref for i in witness],normal_witness_units=witness,footprint_models=list(footprints.values()),
                    return_bounds_on_witness=[lo,hi],identity_paths={'allocation_to_writer':write_path,'allocation_to_reader':read_path},
                    loop_condition_refs=guard_refs,support_refs=sorted(support),
                    relation_ref=record_id(facts.run.run_id,'relation',['selected-audio-read',root,raw.id]),
                    range_node_ref=record_id(facts.run.run_id,'analysis',['selected-audio-range',root,raw.id]),
                    range_condition_ref=record_id(facts.run.run_id,'condition',['selected-audio-range',root,raw.id]),
                    limitation_notes=['Actual n, valid call and framework footprint applicability are not proven runtime facts',
                        'The loop uses L, not n; tail [n,L) is not attributed to this AudioRecord write',
                        'Numeric field values and equality of separate field reads are not inferred',
                        'No complete RMS result or subsequent preference write is established by these two links'])
            except (ValueError,KeyError,StopIteration) as error:
                row['reason']=str(error) or type(error).__name__
    return {'schema_version':'selected-audio-read-evidence.v1','run_ref':facts.run.run_id,'configuration':config.model_dump(mode='json'),
        'reads':rows,'visits':visits,'execution_claim':'possible_only','general_dynamic_range_solver':False,'full_behavior_coverage':False}


def _emit(facts,report):
    nodes=[];bindings=[];relations=[];run=facts.run.run_id;records={x.id:x for x in facts.elements}
    for i,row in enumerate(report['reads']):
        if row['state']!='conditional_connection':continue
        ref=row['range_node_ref'];condition=row['range_condition_ref'];support=row['support_refs']
        prov=Provenance(kind='model_assisted',tool_ref=TOOL,rule_ref=MODEL,support_refs=support)
        value=Endpoint(element_ref=ref,slot_kind='value',position_label=ref)
        nodes.append(AnalysisNodeRecord(id=ref,run_ref=run,kind='analysis_node',node_kind='mapping',method_ref=row['root_ref'],
            position=ModelPosition(kind='model',model_ref=MODEL,position_label=ref),provenance=prov,
            text='SELECTED ELEMENT PRECONDITION, not an execution guard: valid framework call normal return, 0<n<=C<=L, 0<=i<L and i<n. '+
                canonical_json({'ranges':row['ranges'],'return_evidence':row['return_evidence'],'limitations':row['limitation_notes'],
                    **({'normal_witness_return_predicates':row['witness_return_constraints']} if row.get('witness_return_constraints') else {})}),
            slots=[ProgramSlot(slot_kind='value',value=ValueInfo(status='unknown',reason='Conditional predicate; actual n and selected iteration not observed'))]))
        nodes.append(ConditionRecord(id=condition,run_ref=run,kind='condition',branch_ref=row['read_ref'],
            branch_label='MODEL PRECONDITION: this selected loop element satisfies i<n; i<L alone is insufficient'+
                ('; retain all saved normal-witness return predicates' if row.get('witness_return_constraints') else ''),value_endpoint=value,
            expected_value=ValueInfo(status='known',value=True),provenance=prov))
        bound=record_id(run,'binding',['selected-audio-read',ref]);conditions=[row['api_condition_ref'],condition,*row['loop_condition_refs']]
        source=Endpoint(element_ref=row['effect_ref'],position_label=row['effect_ref'],slot_kind='state',slot_label='written_buffer_content')
        bindings.append(BindingRecord(id=bound,run_ref=run,binding_kind='state',context_ref=row['writer_context_ref'],
            endpoints=[source,Endpoint(**row['base_endpoint'])],condition_refs=conditions,provenance=prov))
        relations.append(RelationRecord(id=row['relation_ref'],run_ref=run,relation_kind='state_dependency',source=source,
            target=Endpoint(**row['read_endpoint']),context_ref=row['writer_context_ref'],binding_refs=[bound],condition_refs=conditions,
            resolution='partial',unresolved_reason='Per-element conditional state link: 0<n<=C<=L and i<n; does not cover the tail or prove recording success',
            source_selector=ENTRY+f'#/reads/{i}',provenance=prov))
    return nodes,bindings,relations


def extend_audio_read_sites(result,config):
    facts=result.facts
    if any(t.tool_id==TOOL for t in facts.run.tools):raise ValueError('Selected read analysis requires a fresh stage')
    facts.run.configuration.options['audio_read_sites']=config.model_dump(mode='json')
    facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    report=analyze_audio_reads(facts,lambda e:result.blobs[result.entry_digests[e]],config)
    source=(Path(__file__).resolve().parents[3]/'.resources/audio-read-sites/Double.android-9.0.0_r1.java').read_bytes()
    if hashlib.sha256(source).hexdigest()!=DOUBLE_SHA256:raise ValueError('Selected Double footprint source changed')
    for entry,raw,ref,kind in [(ENTRY,canonical_json(report).encode(),None,None),
        ('analysis/rules/audio_read_sites.py',Path(__file__).read_bytes(),RULE,'rule'),
        ('analysis/rules/audio-read-sites.json',canonical_json(SPEC).encode(),MODEL,'summary'),
        (DOUBLE_ENTRY,source,'model:double-aosp28','summary')]:
        digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[entry]=digest
        if ref:facts.run.artifacts.append(VersionedArtifact(artifact_id=ref,kind=kind,name='selected audio read patterns and footprint',version='1',sha256=digest,location=entry))
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='selected audio buffer loop reads',version=__version__))
    nodes,bindings,relations=_emit(facts,report);facts.elements.extend(nodes);facts.bindings.extend(bindings);facts.relations.extend(relations)
    for i,row in enumerate(report['reads']):
        target=row.get('read_ref') or row.get('root_ref')
        if target:facts.statuses.append(AnalysisStatus(id=record_id(facts.run.run_id,'status',['selected-audio-read',i]),run_ref=facts.run.run_id,
            tool_ref=TOOL,capability='objects',scope=AnalysisScope(kind='element',element_ref=target),state='partial',reason=row['reason']))
    result.facts=loads_facts(facts.model_dump_json());verify_audio_read_sites(result.facts,lambda e:result.blobs[result.entry_digests[e]])
    result.summary['selected_audio_reads']={'selected':len(report['reads']),'conditional':sum(r['state']=='conditional_connection' for r in report['reads']),
        'unresolved':sum(r['state']=='unresolved' for r in report['reads']),'general_dynamic_solver':False}
    return result


def verify_audio_read_sites(facts,read):
    groups=[facts.elements,facts.bindings,facts.relations];actual=[{x.id:x for x in g if x.provenance.tool_ref==TOOL} for g in groups]
    if not any(t.tool_id==TOOL for t in facts.run.tools):
        if any(actual):raise ValueError('Selected read facts lack tool metadata')
        return
    if read('analysis/rules/audio-read-sites.json')!=canonical_json(SPEC).encode() or hashlib.sha256(read(DOUBLE_ENTRY)).hexdigest()!=DOUBLE_SHA256:
        raise ValueError('Selected pattern/footprint source differs from fixed model')
    config=AudioReadConfig.model_validate(facts.run.configuration.options['audio_read_sites']);report=json.loads(read(ENTRY))
    if report!=analyze_audio_reads(facts,read,config):raise ValueError('Selected read decisions differ from current evidence')
    if actual!=[{x.id:x for x in g} for g in _emit(facts,report)]:raise ValueError('Forged selected read range, context, condition or binding')


def audio_read_evidence(facts,read,refs=()):
    if not any(t.tool_id==TOOL for t in facts.run.tools):return {'schema_version':'selected-audio-read-query.v1','state':'not_started','reads':[]}
    report=json.loads(read(ENTRY));refs=set(refs)
    return {**report,'schema_version':'selected-audio-read-query.v1','state':'partial',
        'model_basis':[a.model_dump(mode='json') for a in facts.run.artifacts if a.artifact_id in
            {MODEL,RULE,'model:double-aosp28','model:audiorecord-aosp28'}],
        'reads':[r for r in report['reads'] if not refs or refs & {r.get('root_ref'),r.get('read_ref'),r.get('raw_reader_ref'),r.get('relation_ref')}]}
