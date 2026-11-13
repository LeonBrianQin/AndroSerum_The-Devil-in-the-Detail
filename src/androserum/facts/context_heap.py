"""F4-C2: frame-separated normal-call projections using the local solvers.

Projection units are derived analysis nodes, never replacements for original IR.
Cross-method exceptional effects are opaque; only explicit normal returns bind.
"""
from collections import Counter, defaultdict, deque
import hashlib
from pathlib import Path
from typing import Literal

from pydantic import Field

from androserum import __version__
from androserum.facts.call_flow import CallFrame, CallReport, ENTRY as CALL_ENTRY, _inputs
from androserum.facts.heap_flow import HeapConfig, HeapMethod, analyze_heap, extract_heap
from androserum.facts.identity import canonical_json, fingerprint, record_id
from androserum.facts.io import loads_facts, strict_json_syntax
from androserum.facts.java_backend import _slots
from androserum.facts.jimple import IRLocal, IRTrap, IRUnit, JimpleMethod
from androserum.facts.local_flow import (ExceptionalEdge, LocalFlowConfig, MethodCFG, MethodFlow,
    _constant_value, analyze_method)
from androserum.facts.models import (AnalysisNodeRecord, AnalysisPosition, AnalysisScope, AnalysisStatus,
    ContextRecord, Endpoint, MethodSignature, ProgramSlot, Provenance, Ref, RelationRecord,
    SHA256, StrictModel, ToolVersion, ValueInfo, VersionedArtifact)

TOOL, RULE, PREFIX = "tool:context-heap", "rule:context-heap", "analysis/context-heap/"


class ContextHeapConfig(StrictModel):
    schema_version: Literal["context-heap-config.v1"] = "context-heap-config.v1"
    root_signatures: list[MethodSignature] = Field(default_factory=list)
    max_depth: int = Field(default=4, ge=1, le=16)
    max_nodes: int = Field(default=5000, ge=1, le=50000)
    max_frames: int = Field(default=256, ge=1, le=4096)
    scalar: LocalFlowConfig = Field(default_factory=LocalFlowConfig)
    heap: HeapConfig = Field(default_factory=HeapConfig)


class ProjectionFrame(StrictModel):
    context_ref: Ref
    method_ref: Ref
    parent_ref: Ref | None
    call_path: list[CallFrame]
    local_offset: int


class ProjectionNode(StrictModel):
    index: int
    node_ref: Ref
    origin_ref: Ref | None
    origin_method_ref: Ref
    frame_ref: Ref
    role: Literal["original", "argument_binding", "return_binding", "call_entry", "call_result", "exception_effect", "exit"]
    support_refs: list[Ref]


class Projection(StrictModel):
    schema_version: Literal["context-projection.v1"] = "context-projection.v1"
    frames: list[ProjectionFrame]
    nodes: list[ProjectionNode]
    method: JimpleMethod
    cfg: MethodCFG
    issues: list[dict]
    interpretation: Literal["derived_graph_not_original_jimple"] = "derived_graph_not_original_jimple"


class ContextHeapReport(StrictModel):
    schema_version: Literal["context-heap-method.v1"] = "context-heap-method.v1"
    run_ref: Ref
    root_method_ref: Ref
    configuration: ContextHeapConfig
    input_flow_sha256: dict[str, SHA256]
    call_report_sha256: SHA256
    state: Literal["complete", "truncated", "unavailable"]
    reason: str | None
    projection: Projection | None
    scalar: MethodFlow | None
    heap: HeapMethod | None
    path_feasibility_checked: Literal[False] = False
    exceptional_heap_precision: Literal["unknown_cross_method_effects"] = "unknown_cross_method_effects"


def entry_for(root): return PREFIX + fingerprint(root)[:32] + ".json"
def _scalar_id(run, root, index): return record_id(run, "relation", ["context-scalar", root, index])
def _heap_id(run, root, index): return record_id(run, "relation", ["context-storage", root, index])
def _key(point): return canonical_json(point.model_dump(mode="json"))


def build_projection(facts, read, root, config, *, prepared=None, calls=None):
    flows, methods, cfgs, _ = prepared if prepared is not None else _inputs(facts, read)
    calls = calls if calls is not None else CallReport.model_validate_json(read(CALL_ENTRY))
    sites = {site.unit_ref: site for site in calls.calls}
    run = facts.run.run_id
    actual_relations = [edge for edge in facts.relations if edge.provenance.tool_ref == "tool:call-flow"]
    units, locals_, metadata, frames, adjacency, exceptional, issues = [], [], [], [], {}, [], []

    def append(unit, origin, owner, frame, role="original", support=()):
        if len(units) >= config.max_nodes: raise OverflowError("Context projection node budget exceeded")
        index = len(units); unit = unit.model_copy(deep=True); unit.index = index
        units.append(unit)
        metadata.append(ProjectionNode(index=index, node_ref=record_id(run,"analysis",["context-unit",root,index]),
            origin_ref=origin, origin_method_ref=owner, frame_ref=frame, role=role, support_refs=list(support)))
        adjacency[index] = []
        return index

    def move(value, offset):
        if value is None: return None
        value = value.model_copy(deep=True)
        if value.local_index is not None: value.local_index += offset
        value.base = move(value.base, offset); value.index_value = move(value.index_value, offset)
        value.children = [move(child, offset) for child in value.children]
        return value

    def instance(owner, path, parent=None, actuals=None, receiver=None, result=None, continuation=(), return_support=()):
        if len(frames) >= config.max_frames: raise OverflowError("Context projection frame budget exceeded")
        frame = record_id(run,"context",["context-heap",root,[x.model_dump(mode="json") for x in path]])
        frames.append(ProjectionFrame(context_ref=frame,method_ref=owner,parent_ref=parent,call_path=path,local_offset=len(locals_)))
        method, flow, cfg = methods[owner], flows[owner], cfgs[owner]
        offset = len(locals_)
        locals_.extend(IRLocal(index=offset+x.index,name=f"frame{len(frames)}:{x.name}",type_descriptor=x.type_descriptor) for x in method.locals)
        mapping = {}
        for unit in method.units:
            clone = unit.model_copy(deep=True)
            clone.left, clone.right, clone.condition = move(unit.left,offset),move(unit.right,offset),move(unit.condition,offset)
            clone.definitions = [move(x,offset) for x in unit.definitions];clone.uses = [move(x,offset) for x in unit.uses]
            if clone.invoke:
                clone.invoke.arguments = [move(x,offset) for x in unit.invoke.arguments]
                clone.invoke.receiver = move(unit.invoke.receiver,offset)
            clone.offsets_code_units,clone.tag_names = [],["derived-context-projection"]
            index = append(clone,flow.node_refs[unit.index],owner,frame)
            mapping[unit.index] = index
            if actuals is not None and unit.operation == "identity" and unit.right and unit.right.identity_kind in {"parameter","this"}:
                value = receiver if unit.right.identity_kind == "this" else actuals[unit.right.parameter_index]
                clone = units[index];clone.operation="assignment";clone.right=value.model_copy(deep=True)
                clone.uses=[clone.right];metadata[index].role="argument_binding"
                source_frame=path[-1]
                metadata[index].support_refs=[edge.id for edge in actual_relations if edge.callsite_ref==source_frame.callsite_ref
                    and edge.context_ref==source_frame.context_ref and edge.target and edge.target.element_ref==owner and
                    ((unit.right.identity_kind=="parameter" and edge.relation_kind=="argument_to_parameter" and edge.target.slot_index==unit.right.parameter_index)
                     or (unit.right.identity_kind=="this" and edge.binding_refs and edge.target.slot_kind=="receiver"))]
                if not metadata[index].support_refs: raise ValueError("Context formal copy lacks the concrete call binding")
            if parent is not None and unit.operation == "return":
                clone=units[index];metadata[index].role="return_binding";metadata[index].support_refs=list(return_support)
                if result is not None and unit.uses:
                    clone.operation="assignment";clone.left=result.model_copy(deep=True);clone.definitions=[clone.left]
                    clone.right=move(unit.uses[0],offset);clone.uses=[clone.right]
                else:
                    clone.operation="nop";clone.left=clone.right=None;clone.definitions=[];clone.uses=[]
                adjacency[index]=list(continuation)
        for source,target in cfg.normal_edges:
            if parent is None or method.units[source].operation != "return":adjacency[mapping[source]].append(mapping[target])
        exceptions_by_source=defaultdict(list)
        for edge in cfg.exception_edges: exceptions_by_source[edge.source].append(edge)
        for unit in method.units:
            index=mapping[unit.index]
            site=sites.get(flow.node_refs[unit.index])
            chosen=None
            if site and site.invoke_kind in {"static","special"} and len(site.candidates)==1:
                candidate=site.candidates[0]
                if candidate.body_available and candidate.rule in {"exact_static","exact_special"}: chosen=candidate
            choices=[chosen] if chosen else []
            if site and site.invoke_kind in {'virtual','interface'} and site.candidates and all(
                    c.body_available and c.rule=='spark_points_to' for c in site.candidates):
                choices=list(site.candidates)
            if site and choices and len(path)<config.max_depth:
                clone=units[index];original=clone.model_copy(deep=True)
                normal=list(adjacency[index])
                returned=original.left if original.definitions else None
                support=[edge.id for edge in actual_relations if edge.relation_kind=="return_to_result" and
                    edge.callsite_ref==site.callsite_ref and any(edge.context_ref==c.context_ref and edge.source.element_ref==c.method_ref for c in choices)]
                if returned is not None:
                    probe=original.model_copy(deep=True);probe.operation='assignment';probe.invoke=None
                    probe.right=returned.model_copy(deep=True);probe.uses=[probe.right]
                    probe_index=append(probe,site.unit_ref,owner,frame,'call_result',support)
                    adjacency[probe_index]=normal;normal=[probe_index]
                children=[]
                for target in choices:
                    frame_value=CallFrame(callsite_ref=site.callsite_ref,callee_ref=target.method_ref,context_ref=target.context_ref)
                    target_support=[edge.id for edge in actual_relations if edge.relation_kind=='return_to_result' and
                        edge.callsite_ref==site.callsite_ref and edge.context_ref==target.context_ref and edge.source.element_ref==target.method_ref]
                    children.append(instance(target.method_ref,[*path,frame_value],frame,original.invoke.arguments,original.invoke.receiver,returned,normal,target_support))
                clone.operation="invoke";clone.left=clone.right=None;clone.definitions=[]
                metadata[index].role="call_entry";adjacency[index]=children
                if any(c.rule=='spark_points_to' for c in choices):
                    dispatch_edges=[edge for edge in actual_relations if edge.relation_kind=='candidate_call' and
                        edge.callsite_ref==site.callsite_ref and any(edge.context_ref==c.context_ref for c in choices)]
                    metadata[index].support_refs=list(dict.fromkeys([ref for edge in dispatch_edges
                        for ref in [edge.id,*edge.provenance.support_refs,*edge.binding_refs]]))
                    issues.append({'unit_ref':site.unit_ref,'context_ref':frame,
                        'reason':'Spark receiver allocations select may-dispatch branches, each with distinct candidate context; branch feasibility and actual target execution are not established',
                        'candidate_context_refs':[c.context_ref for c in choices],
                        'candidate_relation_refs':[edge.id for edge in dispatch_edges]})
                if exceptions_by_source[unit.index]:
                    effect=original.model_copy(deep=True);effect.definitions=[];effect.left=effect.right=None
                    effect_index=append(effect,site.unit_ref,owner,frame,"exception_effect")
                    adjacency[effect_index]=sorted({mapping[e.target] for e in exceptions_by_source[unit.index]})
                    for edge in exceptions_by_source[unit.index]:exceptional.append((index,effect_index,edge))
                    issues.append({"unit_ref":site.unit_ref,"context_ref":frame,"reason":"Cross-method exceptional heap effects are opaque; no normal return copied"})
            else:
                for edge in exceptions_by_source[unit.index]:exceptional.append((index,mapping[edge.target],edge))
                if site:
                    issues.append({"unit_ref":site.unit_ref,"context_ref":frame,"reason":"Depth budget: call remains opaque" if choices else
                        site.reason or "No uniquely supported static/special implementation; call effects remain unknown"})
        return mapping[0]

    instance(root,[])
    # A final auxiliary node keeps synthetic one-unit trap ranges within bounds.
    dummy=units[0].model_copy(deep=True);dummy.operation="nop";dummy.invoke=None;dummy.left=dummy.right=dummy.condition=None
    dummy.definitions=[];dummy.uses=[]
    append(dummy,None,root,frames[0].context_ref,"exit")
    traps=[];exception_edges=[]
    for source,target,edge in exceptional:
        trap=len(traps);traps.append(IRTrap(exception_type=edge.exception_type,begin=source,end=source+1,handler=target))
        exception_edges.append(ExceptionalEdge(source=source,target=target,trap_index=trap,exception_type=edge.exception_type,
            transfer="before_unit",included_types=edge.included_types,excluded_types=edge.excluded_types))
    for unit in units:
        unit.targets=sorted(set(adjacency[unit.index]));unit.falls_through=False;unit.branches=bool(unit.targets)
    method=JimpleMethod(signature=methods[root].signature,soot_signature="DERIVED context projection; original Soot IR retained separately",
        modifiers=methods[root].modifiers,state="complete",reason=None,declared_unit_count=len(units),locals=locals_,units=units,traps=traps)
    raw=canonical_json(method.model_dump(mode="json")).encode()
    cfg=MethodCFG(method_signature=method.signature,method_sha256=hashlib.sha256(raw).hexdigest(),unit_count=len(units),
        exception_model="soot-4.7.1-unit-throw-analysis",normal_edges=[(u.index,t) for u in units for t in u.targets],
        exception_edges=exception_edges,escaping_exceptions=[],normal_defs_oracle=[])
    return Projection(frames=frames,nodes=metadata,method=method,cfg=cfg,issues=issues)


def analyze_context(facts,read,root,config,*,prepared=None,calls=None):
    prepared=prepared if prepared is not None else _inputs(facts,read)
    flows,_,_,hashes=prepared
    report=ContextHeapReport(run_ref=facts.run.run_id,root_method_ref=root,configuration=config,input_flow_sha256=hashes,
        call_report_sha256=hashlib.sha256(read(CALL_ENTRY)).hexdigest(),state="complete",reason=None,projection=None,scalar=None,heap=None)
    if flows[root].state!="complete":report.state="unavailable";report.reason="Root local analysis incomplete";return report
    try:
        projection=build_projection(facts,read,root,config,prepared=prepared,calls=calls)
        entry=entry_for(root);ir_entry=entry.replace('.json','.ir.json');cfg_entry=entry.replace('.json','.cfg.json')
        ir_raw=canonical_json(projection.method.model_dump(mode="json")).encode();cfg_raw=canonical_json(projection.cfg.model_dump(mode="json")).encode()
        scope="context:"+root
        scalar=analyze_method(projection.method,projection.cfg,run_ref=facts.run.run_id,method_ref=root,
            node_refs=[x.node_ref for x in projection.nodes],ir_entry=ir_entry,ir_sha256=hashlib.sha256(ir_raw).hexdigest(),
            cfg_entry=cfg_entry,cfg_sha256=hashlib.sha256(cfg_raw).hexdigest(),config=config.scalar,identity_scope=scope)
        if scalar.state!="complete":raise OverflowError(scalar.reason)
        ids=[_scalar_id(facts.run.run_id,root,i) for i in range(len(scalar.links))]
        scalar_entry=entry.replace('.json','.scalar.json');scalar_raw=canonical_json(scalar.model_dump(mode='json')).encode()
        heap=analyze_heap(facts,scalar,projection.method,projection.cfg,scalar_entry,hashlib.sha256(scalar_raw).hexdigest(),config.heap,
            identity_scope=scope,entry_override=entry,tool=TOOL,rule=RULE,scalar_relation_ids=ids,
            transparent_call_units={x.index for x in projection.nodes if x.role=='call_entry'})
        if heap.state!="complete":raise OverflowError(heap.reason)
        report.projection,report.scalar,report.heap=projection,scalar,heap
    except OverflowError as error:report.state,report.reason="truncated",str(error)
    return report


def _emit(facts,report):
    run,root=facts.run.run_id,report.root_method_ref;entry=entry_for(root)
    prov=lambda *refs:Provenance(kind="static_analysis",tool_ref=TOOL,rule_ref=RULE,support_refs=list(dict.fromkeys([root,*refs])))
    anchor=AnalysisNodeRecord(id=record_id(run,"analysis",["context-report",root]),run_ref=run,kind="analysis_node",node_kind="state",
        method_ref=root,position=AnalysisPosition(kind="analysis",artifact_path=entry,position_label="context-heap"),provenance=prov(root))
    nodes,contexts,bindings,edges=[anchor],[],[],[]
    if report.state!="complete":return nodes,contexts,bindings,edges
    projection,scalar,heap=report.projection,report.scalar,report.heap
    root_context=projection.frames[0].context_ref
    for frame in projection.frames:
        contexts.append(ContextRecord(id=frame.context_ref,run_ref=run,provenance=prov(frame.method_ref,*[x.context_ref for x in frame.call_path]),
            abstraction="Full call-path projection; no frame merging",callsite_refs=[x.callsite_ref for x in frame.call_path],parent_ref=frame.parent_ref))
    for meta,unit in zip(projection.nodes,projection.method.units):
        nodes.append(AnalysisNodeRecord(id=meta.node_ref,run_ref=run,kind="analysis_node",node_kind="state",method_ref=root,
            position=AnalysisPosition(kind="analysis",artifact_path=entry,position_label=f"unit:{meta.index}"),
            text="Derived "+meta.role+": "+unit.text,provenance=prov(*([meta.origin_ref] if meta.origin_ref else []),meta.frame_ref,*meta.support_refs),slots=_slots(unit)))
    for operand in scalar.operand_nodes:
        nodes.append(AnalysisNodeRecord(id=operand.node_ref,run_ref=run,kind="analysis_node",node_kind="state",method_ref=root,
            position=AnalysisPosition(kind="analysis",artifact_path=entry,position_label=f"operand:{operand.unit}:{operand.role}"),
            provenance=prov(projection.nodes[operand.unit].node_ref),slots=[ProgramSlot(slot_kind="value",value=_constant_value(operand.value),
                type_descriptor=operand.value.type_descriptor if operand.value.type_descriptor!='V' else None)]))
    nodes.extend(heap.nodes)
    bindings=[x.model_copy(update={"context_ref":root_context}) for x in heap.bindings]
    metadata={x.node_ref:x for x in projection.nodes}
    for i,link in enumerate(scalar.links):
        refs=[link.source.element_ref,link.target.element_ref]
        selected=sorted((metadata[ref] for ref in set(refs) if ref in metadata),key=lambda x:x.index)
        for meta in selected:refs.extend(meta.support_refs)
        edges.append(RelationRecord(id=_scalar_id(run,root,i),run_ref=run,provenance=prov(*refs),relation_kind="data_dependency",
            source=link.source,target=link.target,context_ref=root_context,resolution=link.resolution,unresolved_reason=link.reason,
            source_selector=entry+f"#/scalar/links/{i}"))
    for i,link in enumerate(heap.links):
        refs=[link.source.element_ref,link.target.element_ref]
        if link.location_ref:refs.append(link.location_ref)
        if link.object_ref:refs.append(link.object_ref)
        edges.append(RelationRecord(id=_heap_id(run,root,i),run_ref=run,provenance=prov(*refs),relation_kind=link.relation_kind,
            source=link.source,target=link.target,context_ref=root_context,binding_refs=link.binding_refs,resolution=link.resolution,
            unresolved_reason=link.reason,source_selector=entry+f"#/heap/links/{i}"))
    return nodes,contexts,bindings,edges


def _reports(facts,read,config):
    prepared=_inputs(facts,read);flows,methods,_,_=prepared
    calls=CallReport.model_validate_json(read(CALL_ENTRY))
    selected=[ref for ref in flows if not config.root_signatures or methods[ref].signature in config.root_signatures]
    missing=set(config.root_signatures)-{methods[x].signature for x in selected}
    definitions={e.id:e for e in facts.elements if e.kind=='method' and e.is_definition}
    absent=missing-{e.signature for e in definitions.values()}
    if absent:raise ValueError('Requested context root is absent from APK definitions: '+', '.join(sorted(absent)))
    # A declared root without usable IR is still part of the discovered scope.
    # Publish its individual failure and continue the other roots; never invent
    # a projection, erase the root, or confuse non-analysis with a negative fact.
    for ref,method in sorted(definitions.items()):
        if method.signature not in missing:continue
        support=sorted(({'status_ref':s.id,'tool_ref':s.tool_ref,'state':s.state,
            'issue_code':s.issue_code,'reason':s.reason} for s in facts.statuses
            if s.scope.kind=='element' and s.scope.element_ref==ref
            and s.tool_ref in {'tool:extractor','tool:java-adapter','tool:soot','tool:local-flow','tool:call-flow','tool:heap-flow'}),key=lambda s:s['status_ref'])
        reason=canonical_json({'issue_code':'context_root_ir_unavailable','signature':method.signature,
            'body_status':method.body_status,'analysis_started':False,'upstream_statuses':support})
        yield ContextHeapReport(run_ref=facts.run.run_id,root_method_ref=ref,configuration=config,
            input_flow_sha256=prepared[3],call_report_sha256=hashlib.sha256(read(CALL_ENTRY)).hexdigest(),
            state='unavailable',reason=reason,projection=None,scalar=None,heap=None)
    for ref in sorted(selected):yield analyze_context(facts,read,ref,config,prepared=prepared,calls=calls)


def extend_context_heap(result,config=None):
    config=ContextHeapConfig.model_validate((config or ContextHeapConfig()).model_dump())
    facts,run=result.facts,result.facts.run.run_id
    facts.run.configuration.options['context_heap']=config.model_dump(mode='json')
    facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    read=lambda e:result.blobs[result.entry_digests[e]]
    reports=_reports(facts,read,config)
    report_summaries=[]; storage_dependencies=0
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name="androserum-frame-separated-heap",version=__version__))
    raw=Path(__file__).read_bytes();digest=hashlib.sha256(raw).hexdigest();rule_entry='analysis/rules/context_heap.py'
    result.blobs[digest],result.entry_digests[rule_entry]=raw,digest
    facts.run.artifacts.append(VersionedArtifact(artifact_id=RULE,kind='rule',name='bounded-normal-call-heap',version='1',sha256=digest,location=rule_entry))
    for report in reports:
        report_summaries.append({'method_ref':report.root_method_ref,'entry':entry_for(report.root_method_ref),'state':report.state,
            **({'reason':report.reason} if report.state!='complete' else {})})
        if report.heap:storage_dependencies+=sum(y.role=='storage_read' for y in report.heap.links)
        entry=entry_for(report.root_method_ref)
        data={entry:report.model_dump(mode='json')}
        if report.projection:
            data[entry.replace('.json','.ir.json')]=report.projection.method.model_dump(mode='json')
            data[entry.replace('.json','.cfg.json')]=report.projection.cfg.model_dump(mode='json')
            data[entry.replace('.json','.scalar.json')]=report.scalar.model_dump(mode='json')
        for path,value in data.items():
            raw=canonical_json(value).encode();digest=hashlib.sha256(raw).hexdigest();result.blobs[digest],result.entry_digests[path]=raw,digest
        nodes,contexts,bindings,edges=_emit(facts,report)
        facts.elements.extend(nodes);facts.contexts.extend(contexts);facts.bindings.extend(bindings);facts.relations.extend(edges)
        facts.statuses.append(AnalysisStatus(id=record_id(run,'status',['context-heap',report.root_method_ref]),run_ref=run,tool_ref=TOOL,
            capability='data_flow',scope=AnalysisScope(kind='element',element_ref=report.root_method_ref),state='partial' if report.state=='complete' else report.state,
            reason='Bounded normal-call heap; exceptional effects, unknown calls and path feasibility remain unresolved' if report.state=='complete' else report.reason))
    for capability in ['data_flow','objects']:
        status=next(x for x in facts.statuses if x.scope.kind=='run' and x.capability==capability)
        status.tool_ref,status.state=TOOL,'partial'
        status.reason='F4-C2 bounded exact-call object/storage projections only; complete points-to/exceptional heap/FlowDroid remain incomplete'
        if facts.run.configuration.options.get('call_flow',{}).get('dispatch')=='cha_spark_points_to':
            status.reason='Exact and actual Spark receiver may-dispatch call frames consume allocation/type/context evidence; exceptional heap, path feasibility and external effects retain explicit gaps'
    result.facts=loads_facts(facts.model_dump_json());verify_context_heap(result.facts,read)
    summary={'methods':report_summaries,
        'counts':dict(Counter(x['state'] for x in report_summaries)),'storage_dependencies':storage_dependencies}
    result.summary.update(stage='F4-C2',context_heap=summary,outcome='failed' if result.summary['outcome']=='failed' else 'partial',
        coverage={x.capability:x.state for x in facts.statuses if x.scope.kind=='run'},
        element_counts=dict(Counter(x.kind for x in facts.elements)),relation_counts=dict(Counter(x.relation_kind for x in facts.relations)),
        limits=['Frame-separated exact normal calls only; opaque unknown/exceptional effects preserved','No FlowDroid, complete object/control/event analysis or BU'])
    if facts.run.configuration.options.get('call_flow',{}).get('dispatch')=='cha_spark_points_to':
        result.summary['context_heap']['spark_may_dispatch_consumed']=True
        result.summary['limits']=['Distinct normal-call frames/branches for exact and Spark allocation-supported dispatch; receiver bindings retain sources.',
            'Spark global may sets do not prove contextual/path feasibility; opaque unknown and exceptional effects remain visible.']
    return result


def extract_context_heap(apk,*,config=None,java_config=None,flow_config=None,call_config=None,heap_config=None):
    return extend_context_heap(extract_heap(apk,java_config=java_config,flow_config=flow_config,call_config=call_config,config=heap_config),config)


def verify_context_heap(facts,read):
    own=lambda x:x.provenance.tool_ref==TOOL or x.provenance.rule_ref==RULE
    groups=[facts.elements,facts.contexts,facts.bindings,facts.relations]
    actual=[{x.id:x for x in group if own(x) or isinstance(x,RelationRecord) and x.source_selector and x.source_selector.startswith(PREFIX)} for group in groups]
    if not any(x.tool_id==TOOL for x in facts.run.tools):
        if any(actual):raise ValueError('Context heap records lack tool metadata')
        return {'relations':0}
    config=ContextHeapConfig.model_validate(facts.run.configuration.options.get('context_heap',{}))
    expected=[{}, {}, {}, {}]
    for report in _reports(facts,read,config):
        data=read(entry_for(report.root_method_ref));strict_json_syntax(data.decode('utf-8'))
        if ContextHeapReport.model_validate_json(data)!=report:raise ValueError('Context frame/object/storage/coverage replay mismatch')
        if report.projection:
            for suffix,value in [('.ir.json',report.projection.method),('.cfg.json',report.projection.cfg),('.scalar.json',report.scalar)]:
                if read(entry_for(report.root_method_ref).replace('.json',suffix))!=canonical_json(value.model_dump(mode='json')).encode():
                    raise ValueError('Derived context graph artifact mismatch')
        for destination,values in zip(expected,_emit(facts,report)):destination.update({x.id:x for x in values})
    if actual!=expected:raise ValueError('Forged/missing contextual heap facts, call frames, bindings or dependencies')
    return {'relations':len(expected[-1])}


def trace_context_sources(facts,read,root,endpoint,*,call_path=None,limit=1000,_cache=None):
    # This cache belongs to one immutable analysis invocation, never a global
    # cache or a cross-run evidence grant. Query traversal remains unchanged.
    cache={} if _cache is None else _cache
    identity=(id(facts),facts.run.run_id,len(facts.elements),len(facts.relations))
    if cache and cache.get('identity')!=identity:raise ValueError('Context query cache belongs to another or changed fact bundle')
    if not cache:
        mappings=defaultdict(set);by_entry=defaultdict(list)
        for edge in facts.relations:
            if edge.relation_kind=='dex_jimple_mapping' and edge.resolution=='resolved' and edge.target:
                mappings[edge.source.element_ref].add(edge.target.element_ref)
            if edge.provenance.tool_ref==TOOL and edge.source_selector and '#' in edge.source_selector and edge.target:
                by_entry[edge.source_selector.split('#',1)[0]].append(edge)
        cache.update(identity=identity,records={x.id:x for x in facts.elements},mappings=mappings,
            by_entry=by_entry,reports={},indexes={})
    if root not in cache['reports']:cache['reports'][root]=ContextHeapReport.model_validate_json(read(entry_for(root)))
    report=cache['reports'][root]
    if report.state!='complete':return {'schema_version':'context-sources.v1','state':report.state,'reason':report.reason,'roots':[],'truncated':True}
    projection,scalar,heap=report.projection,report.scalar,report.heap
    frames={x.context_ref:x for x in projection.frames};meta={x.node_ref:x for x in projection.nodes}
    records=cache['records'];original=records.get(endpoint.element_ref)
    if original is None or endpoint.position_label!=getattr(original.position,'position_label',None):raise ValueError('Invalid original endpoint position')
    if endpoint.slot_kind!='element' and not any((x.slot_kind,x.slot_index,x.slot_label)==(endpoint.slot_kind,endpoint.slot_index,endpoint.slot_label) for x in getattr(original,'slots',[])):
        raise ValueError('Invalid original endpoint slot')
    origins={endpoint.element_ref}
    origins.update(cache['mappings'].get(endpoint.element_ref,()))
    if call_path is not None:call_path=[CallFrame.model_validate(x).model_dump(mode='json') for x in call_path]
    selected=[x for x in projection.nodes if x.origin_ref in origins and x.role not in {'exception_effect','exit'} and
        ((endpoint.slot_kind=='result' and x.role=='call_result') or (x.role!='call_result' and not(endpoint.slot_kind=='result' and x.role=='call_entry'))) and
        (call_path is None and not frames[x.frame_ref].call_path or call_path is not None and [v.model_dump(mode='json') for v in frames[x.frame_ref].call_path]==call_path)]
    if len(selected)!=1:raise ValueError('Select exactly one projected operation using root and full call path')
    target=endpoint.model_copy(update={'element_ref':selected[0].node_ref,'position_label':f'unit:{selected[0].index}'})
    if target.slot_kind=='local':target.slot_index+=frames[selected[0].frame_ref].local_offset
    if root not in cache['indexes']:
        incoming,roots=defaultdict(list),defaultdict(list)
        for edge in cache['by_entry'].get(entry_for(root),()):incoming[_key(edge.target)].append(edge)
        replaced={_key(x.target) for x in heap.links if x.role=='storage_read'}|{_key(x.endpoint) for x in heap.roots if x.kind=='heap_read'}
        for item in scalar.roots:
            if item.kind=='heap_read' and _key(item.endpoint) in replaced:continue
            roots[_key(item.endpoint)].append(item)
        for item in heap.roots:roots[_key(item.endpoint)].append(item)
        auxiliary_units={x.node_ref:x.unit for x in scalar.operand_nodes}
        auxiliary_units.update({x.write_value.element_ref:x.unit for x in heap.accesses if x.write_value})
        storage_links={_heap_id(facts.run.run_id,root,i):x for i,x in enumerate(heap.links) if x.role=='storage_read'}
        cache['indexes'][root]=(incoming,roots,auxiliary_units,storage_links)
    incoming,roots,auxiliary_units,storage_links=cache['indexes'][root]
    def describe(point):
        node=meta.get(point.element_ref)
        if node is None and point.element_ref in auxiliary_units:node=projection.nodes[auxiliary_units[point.element_ref]]
        if node is None:return {'endpoint':point.model_dump(mode='json')}
        frame=frames[node.frame_ref]
        return {'endpoint':point.model_dump(mode='json'),'origin_ref':node.origin_ref,'method_ref':node.origin_method_ref,
            'method_signature':records[node.origin_method_ref].signature,'role':node.role,
            'context_ref':node.frame_ref,'call_path':[x.model_dump(mode='json') for x in frame.call_path],'support_refs':node.support_refs}
    start=_key(target)
    if start not in incoming and start not in roots:raise ValueError('Selected endpoint has no supported normal-flow source; inspect projection/coverage')
    queue=deque([(target,[],frozenset())]);seen=set();found=[];cycles=[]
    while queue and len(seen)<limit:
        point,path,ancestors=queue.popleft();key=_key(point)
        if key in ancestors:cycles.append(describe(point));continue
        if key in seen:continue
        seen.add(key)
        for value in roots[key]:found.append({'root':value.model_dump(mode='json'),'origin':describe(value.endpoint),'relations_to_target':list(reversed(path))})
        for edge in incoming[key]:
            step={'relation':edge.model_dump(mode='json'),'source':describe(edge.source),'target':describe(edge.target)}
            if edge.id in storage_links:
                link=storage_links[edge.id]
                step['storage_evidence']={'dependency':link.model_dump(mode='json'),
                    'location':next(x.model_dump(mode='json') for x in heap.locations if x.location_ref==link.location_ref),
                    'write_access':next(x.model_dump(mode='json') for x in heap.accesses if x.unit==link.write_unit),
                    'read_state':heap.read_states[str(link.read_unit)][link.location_ref]}
            queue.append((edge.source,[*path,step],ancestors|{key}))
    return {'schema_version':'context-sources.v1','run_ref':facts.run.run_id,'root_method_ref':root,'target':describe(target),'roots':found,
        'truncated':bool(queue or any('Depth budget' in x['reason'] for x in projection.issues)),
        'pending':[describe(p) for p,_,_ in queue],'cycles':cycles,'unresolved_effects':projection.issues,
        'path_feasibility_checked':False,'exceptional_heap_precision':report.exceptional_heap_precision}
