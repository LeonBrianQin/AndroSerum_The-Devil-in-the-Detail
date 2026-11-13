"""F4-B v1: application CHA candidates and balanced, bounded call/return bindings.

Candidate enumeration is not points-to analysis or Android reachability. Exception
destinations remain in F4-A; only explicit normal return operands produce values.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import hashlib
from pathlib import Path
from typing import Literal

from pydantic import Field

from androserum import __version__
from androserum.facts.identity import canonical_json, fingerprint, parse_method_signature, record_id
from androserum.facts.io import loads_facts, strict_json_syntax
from androserum.facts.jimple import JimpleMethod
from androserum.facts.local_flow import FlowRoot, MethodCFG, MethodFlow, _constant_value, extract_local
from androserum.facts.models import (AnalysisNodeRecord, AnalysisPosition, AnalysisScope, AnalysisStatus,
    ArchivePath, BindingRecord, ClassRecord, ContextRecord, Endpoint, MethodRecord, MethodSignature,
    NonNegative, ProgramSlot, Provenance, Ref, RelationRecord, SHA256, StrictModel, ToolVersion, VersionedArtifact)

ENTRY = "analysis/call-flow/run.json"
TOOL = "tool:call-flow"
RULE = "rule:call-flow"


class CallConfig(StrictModel):
    schema_version: Literal["call-flow-config.v1"] = "call-flow-config.v1"
    dispatch: Literal["application_cha", "cha_spark_points_to"] = "application_cha"
    context_policy: Literal["balanced_stack_no_merge"] = "balanced_stack_no_merge"
    max_calls: int = Field(default=100000, ge=1, le=1000000)
    max_candidates_per_call: int = Field(default=128, ge=1, le=10000)
    max_trace_depth: int = Field(default=8, ge=1, le=128)


class CallFrame(StrictModel):
    callsite_ref: Ref
    callee_ref: Ref
    context_ref: Ref


class Candidate(StrictModel):
    method_ref: Ref
    signature: MethodSignature
    context_ref: Ref
    rule: Literal["exact_static", "exact_special", "application_cha", "spark_points_to"]
    body_available: bool
    normal_return_units: list[NonNegative]
    escaping_exception_units: list[NonNegative]
    cross_method_exception_objects_resolved: Literal[False] = False


class CallSite(StrictModel):
    caller_ref: Ref
    unit_ref: Ref
    unit: NonNegative
    declared_signature: MethodSignature
    invoke_kind: Literal["static", "special", "virtual", "interface", "dynamic"]
    callsite_ref: Ref | None
    candidates: list[Candidate]
    state: Literal["complete", "partial", "unavailable", "truncated"]
    reason: str | None


class CallLink(StrictModel):
    role: Literal["candidate", "argument_bridge", "result_bridge", "receiver_bridge", "formal_input",
                  "receiver_binding", "argument_binding", "normal_return_operand", "normal_return_binding"]
    relation_kind: Literal["candidate_call", "data_dependency", "argument_to_parameter", "return_to_result"]
    source: Endpoint
    target: Endpoint
    support_refs: list[Ref]
    callsite_ref: Ref | None = None
    context_ref: Ref | None = None
    binding_kind: Literal["object", "value"] | None = None
    resolution: Literal["resolved", "partial"] = "resolved"
    reason: str | None = None
    normal_return_only: bool = False


class CallReport(StrictModel):
    schema_version: Literal["call-flow-run.v1"] = "call-flow-run.v1"
    run_ref: Ref
    configuration: CallConfig
    input_flow_sha256: dict[ArchivePath, SHA256]
    calls: list[CallSite]
    links: list[CallLink]
    nodes: list[AnalysisNodeRecord]
    roots: list[FlowRoot]
    truncated: bool
    pending_methods: list[Ref]
    unavailable_methods: dict[Ref, str]
    path_feasibility_checked: Literal[False] = False
    points_to_analysis_performed: bool = False
    control_conditions_resolved: Literal[False] = False


def _key(endpoint):
    return canonical_json(endpoint.model_dump(mode="json"))


def _inputs(facts, read):
    flows, methods, cfgs, hashes = {}, {}, {}, {}
    for node in facts.elements:
        if (isinstance(node, AnalysisNodeRecord) and node.node_kind == "cfg" and node.position.kind == "analysis"
                and node.position.artifact_path.startswith("analysis/local-flow/")):
            data = read(node.position.artifact_path)
            flow = MethodFlow.model_validate_json(data)
            if flow.method_ref in flows:
                raise ValueError("Duplicate local-flow method in call analysis")
            flows[flow.method_ref] = flow
            methods[flow.method_ref] = JimpleMethod.model_validate_json(read(flow.ir_entry))
            cfgs[flow.method_ref] = MethodCFG.model_validate_json(read(flow.cfg_entry))
            hashes[node.position.artifact_path] = hashlib.sha256(data).hexdigest()
    return flows, methods, cfgs, hashes


def analyze_calls(facts, read, config):
    """Pure replayable analysis, based only on this run's declared classes and IR."""
    flows, methods, cfgs, hashes = _inputs(facts, read)
    run = facts.run.run_id
    report = CallReport(run_ref=run, configuration=config, input_flow_sha256=hashes,
        calls=[], links=[], nodes=[], roots=[], truncated=False, pending_methods=[], unavailable_methods={})
    pointer_calls={}
    if config.dispatch=="cha_spark_points_to":
        import json
        from .points_to import ENTRY as POINTER_ENTRY,verify_points_to
        verify_points_to(facts,read)
        pointer_report=json.loads(read(POINTER_ENTRY))
        pointer_calls={row['unit_ref']:row for row in pointer_report['calls']}
        report.points_to_analysis_performed=pointer_report['state'] in {'complete','partial'}
        report.input_flow_sha256[POINTER_ENTRY]=hashlib.sha256(read(POINTER_ENTRY)).hexdigest()
    definitions, classes = defaultdict(list), defaultdict(list)
    elements = {item.id: item for item in facts.elements}
    for item in facts.elements:
        if isinstance(item, MethodRecord) and item.is_definition: definitions[item.signature].append(item)
        if isinstance(item, ClassRecord): classes[item.descriptor].append(item)
    for values in definitions.values():
        for value in values:
            if value.id not in flows or flows[value.id].state != "complete":
                report.unavailable_methods[value.id] = ("Local analysis " + flows[value.id].state + ": " + str(flows[value.id].reason)) if value.id in flows else "No supported complete local IR; body status=" + value.body_status
    mapping = defaultdict(set)
    for edge in facts.relations:
        if edge.relation_kind == "dex_jimple_mapping" and edge.resolution == "resolved" and edge.target:
            mapping[edge.target.element_ref].add(edge.source.element_ref)

    def point(flow, index, slot, ordinal=None):
        return Endpoint(element_ref=flow.node_refs[index], position_label=f"unit:{index}", slot_kind=slot, slot_index=ordinal)

    def dexpoint(ref, slot, ordinal=None):
        return Endpoint(element_ref=ref, position_label=elements[ref].position.position_label, slot_kind=slot, slot_index=ordinal)

    def link(role, source, target, refs, **kwargs):
        report.links.append(CallLink(role=role, source=source, target=target, support_refs=list(dict.fromkeys(refs)), **kwargs))

    def subtype(child, parent, seen=None):
        if child == parent: return True
        seen = set() if seen is None else seen
        if child in seen or len(classes[child]) != 1: return False
        seen.add(child)
        cls = classes[child][0]
        return any(subtype(value, parent, seen.copy()) for value in [cls.superclass, *cls.interfaces] if value)

    def dispatch(owner, suffix, seen=None):
        seen = set() if seen is None else seen
        if owner in seen: return None
        seen.add(owner)
        matching = definitions[owner + "->" + suffix]
        if matching:
            if len(matching) != 1: return None
            method = matching[0]
            return method if not method.is_static and not ((method.access_flags or 0) & (0x400 | 0x2)) else None
        if len(classes[owner]) == 1 and classes[owner][0].superclass:
            return dispatch(classes[owner][0].superclass, suffix, seen)
        return None

    # Context-free bridges retain their method; the query supplies the balanced stack.
    for method_ref, flow in sorted(flows.items()):
        if flow.state != "complete": continue
        method = methods[method_ref]
        for root in flow.roots:
            if root.kind in {"parameter", "receiver"}:
                ordinal = root.details.get("parameter_index")
                source = Endpoint(element_ref=method_ref, slot_kind="parameter" if root.kind == "parameter" else "receiver",
                                  slot_index=ordinal if root.kind == "parameter" else None)
                link("formal_input", source, root.endpoint, [method_ref, root.endpoint.element_ref], relation_kind="data_dependency")
                report.roots.append(FlowRoot(endpoint=source, kind=root.kind, details={**root.details, "method_ref": method_ref}))
        if parse_method_signature(method.signature)[3] == "V": continue
        for unit in method.units:
            if unit.operation != "return" or unit.index not in flow.reachable: continue
            target = Endpoint(element_ref=method_ref, slot_kind="return")
            # Jimple ReturnStmt has exactly one local or literal operand; nested boxes
            # are not used as a substitute for a supported return expression.
            if len(unit.uses) != 1:
                report.roots.append(FlowRoot(endpoint=target, kind="incomplete_operand", details={"unit": unit.index}))
                continue
            value = unit.uses[0]
            if value.local_index is not None:
                source = point(flow, unit.index, "local", value.local_index)
            else:
                ref = record_id(run, "analysis", ["call-return-operand", method_ref, unit.index])
                label = f"normal-return:{unit.index}"
                source = Endpoint(element_ref=ref, position_label=label, slot_kind="value")
                report.nodes.append(AnalysisNodeRecord(id=ref, run_ref=run, kind="analysis_node", node_kind="state", method_ref=method_ref,
                    position=AnalysisPosition(kind="analysis", artifact_path=ENTRY, position_label=label + ":" + method_ref),
                    provenance=Provenance(kind="static_analysis", tool_ref=TOOL, rule_ref=RULE, support_refs=[method_ref, flow.node_refs[unit.index]]),
                    slots=[ProgramSlot(slot_kind="value", type_descriptor=value.type_descriptor if value.type_descriptor != "V" else None,
                                       value=_constant_value(value))]))
                source.position_label = label + ":" + method_ref
                report.roots.append(FlowRoot(endpoint=source, kind="constant" if value.constant_kind is not None else "unsupported_expression",
                    details={"operand": value.model_dump(mode="json")}))
            link("normal_return_operand", source, target, [method_ref, flow.node_refs[unit.index]],
                 relation_kind="data_dependency", normal_return_only=True)

    for method_ref, flow in sorted(flows.items()):
        if flow.state != "complete": continue
        for unit in methods[method_ref].units:
            if unit.invoke is None or unit.index not in flow.reachable: continue
            if len(report.calls) >= config.max_calls:
                report.truncated = True
                report.pending_methods = sorted(set(report.pending_methods + [method_ref]))
                continue
            invoke = unit.invoke
            refs = sorted(mapping[flow.node_refs[unit.index]])
            dex_ref = refs[0] if len(refs) == 1 else None
            site = CallSite(caller_ref=method_ref, unit_ref=flow.node_refs[unit.index], unit=unit.index,
                declared_signature=invoke.signature, invoke_kind=invoke.kind, callsite_ref=dex_ref,
                candidates=[], state="partial", reason=None)
            report.calls.append(site)
            if dex_ref is None:
                site.state, site.reason = "unavailable", "No unique verified DEX callsite; no call bindings published"
                continue
            owner, _, parameters, _ = parse_method_signature(invoke.signature)
            targets = []
            if invoke.kind in {"static", "special"}:
                matching = definitions[invoke.signature]
                if len(matching) == 1 and matching[0].is_static == (invoke.kind == "static"):
                    targets = matching
                else:
                    site.reason = "Missing/ambiguous exact application definition; library/native/dynamic propagation unresolved"
            elif invoke.kind in {"virtual", "interface"}:
                suffix = invoke.signature.split("->", 1)[1]
                for descriptor, records in sorted(list(classes.items())):
                    if len(records) != 1 or records[0].access_flags & (0x400 | 0x200): continue
                    if subtype(descriptor, owner):
                        found = dispatch(descriptor, suffix)
                        if found and found not in targets: targets.append(found)
                site.reason = "Application CHA may-candidates only; points-to, default-interface/library dispatch and dynamic classes unresolved"
                if config.dispatch=="cha_spark_points_to":
                    pointer=pointer_calls.get(site.unit_ref)
                    supported={t['signature'] for t in pointer['targets'] if t['allocation_ids']} if pointer else set()
                    targets=[target for target in targets if target.signature in supported]
                    site.reason=("Actual Spark receiver allocation sets and class hierarchy yield may-targets; "
                                 "flow/context-insensitive pointer sets and normal-call bindings do not establish runtime dispatch or Android reachability"
                                 if targets else "No mapped Spark receiver/allocation dispatch witness for this call; no positive CHA target substituted")
                    if pointer_report['state']=='failed':site.reason='Pointer solver failed: '+str(pointer_report.get('reason'))
            else:
                site.state, site.reason = "unavailable", "Dynamic/polymorphic/reflective dispatch is outside v1"
            if len(targets) > config.max_candidates_per_call:
                site.state, site.reason = "truncated", "Candidate budget exceeded; no partial target set published"
                targets = []
            uncertain = invoke.kind in {"virtual", "interface"}
            for target in sorted(targets, key=lambda item: item.id):
                context = record_id(run, "context", ["call-flow", dex_ref, target.id])
                available = target.id in flows and flows[target.id].state == "complete"
                returns = [value.index for value in methods[target.id].units if value.operation == "return" and value.index in flows[target.id].reachable] if available else []
                candidate = Candidate(method_ref=target.id, signature=target.signature, context_ref=context,
                    rule=("spark_points_to" if config.dispatch=="cha_spark_points_to" else "application_cha") if uncertain else "exact_static" if invoke.kind == "static" else "exact_special",
                    body_available=available, normal_return_units=returns,
                    escaping_exception_units=sorted({value.unit for value in cfgs[target.id].escaping_exceptions}) if available else [])
                site.candidates.append(candidate)
                status = {"resolution": "partial", "reason": site.reason} if uncertain else {}
                pointer_support=[]
                if uncertain and config.dispatch=="cha_spark_points_to":
                    pointer=pointer_calls[site.unit_ref]
                    witness=next(t for t in pointer['targets'] if t['signature']==target.signature)
                    pointer_support=[pointer['evidence_ref'],*witness['object_refs'],*witness['binding_refs']]
                    pointer_support.extend(ref for allocation in pointer_report['allocations'] if allocation['object_ref'] in witness['object_refs']
                                           for ref in allocation['source_support_refs'])
                link("candidate", dexpoint(dex_ref, "element"), Endpoint(element_ref=target.id, slot_kind="entry"),
                    [dex_ref, site.unit_ref, target.id,*pointer_support], relation_kind="candidate_call", callsite_ref=dex_ref, context_ref=context, **status)
                if not available: continue
                if len(parameters) != len(invoke.arguments): raise ValueError("IR call arity disagrees with signature")
                for ordinal in range(len(parameters)):
                    link("argument_binding", dexpoint(dex_ref, "argument", ordinal),
                        Endpoint(element_ref=target.id, slot_kind="parameter", slot_index=ordinal), [dex_ref, site.unit_ref, target.id,*pointer_support],
                        relation_kind="argument_to_parameter", callsite_ref=dex_ref, context_ref=context, binding_kind="value", **status)
                if invoke.receiver is not None:
                    link("receiver_binding", dexpoint(dex_ref, "receiver"), Endpoint(element_ref=target.id, slot_kind="receiver"),
                        [dex_ref, site.unit_ref, target.id,*pointer_support], relation_kind="data_dependency", callsite_ref=dex_ref,
                        context_ref=context, binding_kind="object", **status)
                if unit.definitions and returns:
                    link("normal_return_binding", Endpoint(element_ref=target.id, slot_kind="return"), dexpoint(dex_ref, "result"),
                        [dex_ref, site.unit_ref, target.id, *(flows[target.id].node_refs[i] for i in returns),*pointer_support],
                        relation_kind="return_to_result", callsite_ref=dex_ref, context_ref=context, binding_kind="value", normal_return_only=True, **status)
            for ordinal in range(len(invoke.arguments)):
                link("argument_bridge", point(flow, unit.index, "argument", ordinal), dexpoint(dex_ref, "argument", ordinal),
                    [site.unit_ref, dex_ref], relation_kind="data_dependency")
            if invoke.receiver:
                link("receiver_bridge", point(flow, unit.index, "receiver"), dexpoint(dex_ref, "receiver"),
                    [site.unit_ref, dex_ref], relation_kind="data_dependency")
            if unit.definitions:
                output = dexpoint(dex_ref, "result")
                link("result_bridge", output, point(flow, unit.index, "result"), [site.unit_ref, dex_ref], relation_kind="data_dependency", normal_return_only=True)
                if uncertain or not site.candidates or any(not value.body_available for value in site.candidates):
                    report.roots.append(FlowRoot(endpoint=output, kind="call_result", details={"signature": invoke.signature,
                        "reason": site.reason or "Candidate body unavailable", "callsite_ref": dex_ref, "analysis_state": site.state}))
                elif not any(value.normal_return_units for value in site.candidates):
                    report.roots.append(FlowRoot(endpoint=output, kind="call_result", details={"signature": invoke.signature,
                        "reason": "No explicit reachable normal return; no return value propagated", "callsite_ref": dex_ref}))
            if not uncertain and site.candidates and all(value.body_available for value in site.candidates):
                site.state, site.reason = "complete", None
            elif site.reason is None: site.reason = "Candidate implementation/local analysis unavailable"
    return report


def _relation_id(run, index):
    return record_id(run, "relation", ["call-flow", index])


def _emit(facts, report):
    run = facts.run.run_id
    anchor = record_id(run, "analysis", ["call-flow-report"])
    contexts, bindings, edges = {}, [], []
    for index, link in enumerate(report.links):
        support = list(dict.fromkeys([anchor, *link.support_refs, link.source.element_ref, link.target.element_ref]))
        provenance = Provenance(kind="static_analysis", tool_ref=TOOL, rule_ref=RULE, support_refs=support)
        if link.context_ref:
            contexts[link.context_ref] = ContextRecord(id=link.context_ref, run_ref=run, provenance=provenance,
                abstraction="call-edge-template; query uses balanced full stack without merging",
                callsite_refs=[link.callsite_ref])
        bound = []
        if report.configuration.dispatch=='cha_spark_points_to':
            bound=[b.id for b in facts.bindings if b.id in link.support_refs and b.provenance.tool_ref=='tool:spark-points-to']
        if link.binding_kind:
            ref = record_id(run, "binding", ["call-flow", index])
            bindings.append(BindingRecord(id=ref, run_ref=run, provenance=provenance, binding_kind=link.binding_kind,
                endpoints=[link.source, link.target], context_ref=link.context_ref))
            bound.append(ref)
        edges.append(RelationRecord(id=_relation_id(run, index), run_ref=run, provenance=provenance,
            relation_kind=link.relation_kind, source=link.source, target=link.target, callsite_ref=link.callsite_ref,
            context_ref=link.context_ref, binding_refs=bound, resolution=link.resolution, unresolved_reason=link.reason,
            source_selector=ENTRY + f"#/links/{index}"))
    return list(contexts.values()), bindings, edges


def extend_calls(result, config=None):
    config = CallConfig.model_validate((config or CallConfig()).model_dump())
    facts, run = result.facts, result.facts.run.run_id
    facts.run.configuration.options["call_flow"] = config.model_dump(mode="json")
    facts.run.config_fingerprint = fingerprint(facts.run.configuration.model_dump(mode="json"))
    report = analyze_calls(facts, lambda entry: result.blobs[result.entry_digests[entry]], config)
    facts.run.tools.append(ToolVersion(tool_id=TOOL, name="androserum-balanced-call-flow", version=__version__))
    rule_entry = "analysis/rules/call_flow.py"
    source = Path(__file__).read_bytes(); digest = hashlib.sha256(source).hexdigest()
    result.blobs[digest], result.entry_digests[rule_entry] = source, digest
    facts.run.artifacts.append(VersionedArtifact(artifact_id=RULE, kind="rule", name="application-call-bindings", version="1", sha256=digest, location=rule_entry))
    data = canonical_json(report.model_dump(mode="json")).encode("utf-8"); digest = hashlib.sha256(data).hexdigest()
    result.blobs[digest], result.entry_digests[ENTRY] = data, digest
    facts.elements.append(AnalysisNodeRecord(id=record_id(run, "analysis", ["call-flow-report"]), run_ref=run, kind="analysis_node",
        node_kind="state", position=AnalysisPosition(kind="analysis", artifact_path=ENTRY, position_label="call-flow"),
        provenance=Provenance(kind="static_analysis", tool_ref=TOOL, rule_ref=RULE, support_refs=list(sorted(report_method_refs(report))))))
    facts.elements.extend(report.nodes)
    contexts, bindings, edges = _emit(facts, report)
    facts.contexts.extend(contexts); facts.bindings.extend(bindings); facts.relations.extend(edges)
    for capability in ["calls", "data_flow"]:
        status = next(value for value in facts.statuses if value.capability == capability and value.scope.kind == "run")
        status.tool_ref, status.state = TOOL, "partial" if report.input_flow_sha256 else "unavailable"
        status.reason = "F4-B v1 exact application calls/application CHA and normal-return bindings only; heap, exception objects, Android events and full path feasibility unresolved"
        if config.dispatch=='cha_spark_points_to':
            status.reason='Actual Spark allocation/type receiver witnesses filter CHA may targets with explicit call contexts and normal-return bindings; runtime reachability, exceptional objects and path feasibility are not established'
    for site in report.calls:
        facts.statuses.append(AnalysisStatus(id=record_id(run, "status", ["call-flow", site.unit_ref]), run_ref=run,
            tool_ref=TOOL, capability="calls", scope=AnalysisScope(kind="element", element_ref=site.unit_ref), state=site.state,
            reason=site.reason, issue_code=None if site.state == "complete" else "call_flow_" + site.state))
    for ref, reason in report.unavailable_methods.items():
        facts.statuses.append(AnalysisStatus(id=record_id(run, "status", ["call-flow-unavailable", ref]), run_ref=run,
            tool_ref=TOOL, capability="calls", scope=AnalysisScope(kind="element", element_ref=ref), state="unavailable",
            reason=reason, issue_code="call_flow_method_unavailable"))
    if report.truncated:
        facts.statuses.append(AnalysisStatus(id=record_id(run, "status", ["call-flow-budget"]), run_ref=run, tool_ref=TOOL,
            capability="calls", scope=AnalysisScope(kind="element", element_ref=record_id(run, "analysis", ["call-flow-report"])),
            state="truncated", reason="Call enumeration budget exceeded", issue_code="call_flow_budget"))
    result.facts = loads_facts(facts.model_dump_json())
    verify_call_evidence(result.facts, lambda entry: result.blobs[result.entry_digests[entry]])
    result.summary.update(stage="F4-B", outcome="failed" if result.summary["outcome"] == "failed" else "partial",
        call_flow={"entry": ENTRY, "counts": dict(Counter(value.state for value in report.calls)), "calls": len(report.calls),
                   "links": len(report.links), "truncated": report.truncated},
        element_counts=dict(Counter(value.kind for value in facts.elements)), relation_counts=dict(Counter(value.relation_kind for value in facts.relations)),
        coverage={value.capability: value.state for value in facts.statuses if value.scope.kind == "run"},
        limits=["Application exact/static/special and CHA may-candidates; balanced scalar call/normal-return bindings only",
                "Heap/points-to, cross-method exception objects, path feasibility, control conditions, Android events and selected FlowDroid remain incomplete"])
    if config.dispatch=='cha_spark_points_to':
        result.summary['call_flow']['points_to_analysis_performed']=report.points_to_analysis_performed
        result.summary['limits']=['Actual allocation-site Spark may points-to filters CHA; distinct targets/objects/callsite bindings are retained.',
            'Flow/context-insensitive solver; external entry objects, reflection, exceptional object transfer and Android runtime reachability require separate analysis.']
    return result


def report_method_refs(report):
    return {site.caller_ref for site in report.calls} | {candidate.method_ref for site in report.calls for candidate in site.candidates}


def extract_calls(apk, *, java_config=None, flow_config=None, config=None, points_config=None):
    config=config or CallConfig()
    base=extract_local(apk, java_config=java_config, config=flow_config)
    if config.dispatch=='cha_spark_points_to':
        from .points_to import extend_points_to
        base=extend_points_to(base,apk,points_config)
    elif points_config is not None:raise ValueError('Pointer configuration requires cha_spark_points_to dispatch')
    return extend_calls(base, config)


def verify_call_evidence(facts, read):
    own = lambda value: value.provenance.tool_ref == TOOL or value.provenance.rule_ref == RULE
    active = any(value.tool_id == TOOL for value in facts.run.tools)
    if not active:
        if any(own(value) for group in [facts.elements, facts.relations, facts.contexts, facts.bindings] for value in group):
            raise ValueError("Call-flow records lack their analysis tool")
        return {"relations": 0}
    anchors = [value for value in facts.elements if isinstance(value, AnalysisNodeRecord) and own(value) and value.position.kind == "analysis"
               and value.position.artifact_path == ENTRY and value.position.position_label == "call-flow"]
    if len(anchors) != 1 or anchors[0].id != record_id(facts.run.run_id, "analysis", ["call-flow-report"]):
        raise ValueError("Missing/forged call-flow report identity")
    data = read(ENTRY); strict_json_syntax(data.decode("utf-8"))
    report = CallReport.model_validate_json(data)
    configured = CallConfig.model_validate(facts.run.configuration.options.get("call_flow", {}))
    if report.run_ref != facts.run.run_id or report.configuration != configured:
        raise ValueError("Call-flow configuration/run mismatch")
    expected = analyze_calls(facts, read, configured)
    if expected != report: raise ValueError("Call candidates, exits or bindings disagree with fixed IR/hierarchy/mappings")
    contexts, bindings, edges = _emit(facts, report)
    for name, expected_values, actual_values in [("contexts", contexts, facts.contexts), ("bindings", bindings, facts.bindings), ("relations", edges, facts.relations)]:
        actual = {value.id: value for value in actual_values if own(value) or (name == "relations" and value.source_selector and value.source_selector.startswith("analysis/call-flow/"))}
        if actual != {value.id: value for value in expected_values}: raise ValueError("Forged/missing call-flow " + name)
    nodes = {value.id: value for value in facts.elements if own(value) and value.id != anchors[0].id}
    if nodes != {value.id: value for value in report.nodes}: raise ValueError("Call return operands disagree with IR")
    return {"relations": len(edges), "calls": len(report.calls)}


def trace_sources(facts, read, endpoint, *, limit=1000, initial_call_path=()):
    """Backward scalar traversal; formal inputs pop only their exact pending frame."""
    report = CallReport.model_validate_json(read(ENTRY))
    frames = tuple(CallFrame.model_validate(value.model_dump() if isinstance(value, CallFrame) else value) for value in initial_call_path)
    candidates = {(site.callsite_ref, value.method_ref, value.context_ref): site for site in report.calls for value in site.candidates if value.body_available}
    for index, frame in enumerate(frames):
        site = candidates.get((frame.callsite_ref, frame.callee_ref, frame.context_ref))
        if site is None or (index and site.caller_ref != frames[index-1].callee_ref):
            raise ValueError("Initial call path is not a nested sequence of supported call frames")
    if len(frames) > report.configuration.max_trace_depth: raise ValueError("Initial call path exceeds depth budget")
    elements = {value.id: value for value in facts.elements}
    owner = getattr(elements.get(endpoint.element_ref), "method_ref", None)
    if isinstance(elements.get(endpoint.element_ref), MethodRecord): owner = endpoint.element_ref
    if frames and owner != frames[-1].callee_ref: raise ValueError("Initial call path does not enter the selected endpoint's method")
    flows, _, _, _ = _inputs(facts, read)
    incoming, roots = defaultdict(list), defaultdict(list)
    role_by_id = {_relation_id(facts.run.run_id, i): value.role for i, value in enumerate(report.links)}
    for edge in facts.relations:
        if edge.provenance.tool_ref in {TOOL, "tool:local-flow"} and edge.relation_kind != "candidate_call" and edge.target:
            incoming[_key(edge.target)].append(edge)
    for flow in flows.values():
        for root in flow.roots: roots[_key(root.endpoint)].append(root)
    for root in report.roots: roots[_key(root.endpoint)].append(root)
    start = _key(endpoint)
    if start not in incoming and start not in roots and not any(start == _key(value.source) for edges in incoming.values() for value in edges):
        if owner in flows and flows[owner].state != "complete":
            return {"schema_version": "call-sources.v1", "state": flows[owner].state, "reason": flows[owner].reason,
                    "roots": [], "truncated": True, "run_ref": facts.run.run_id}
        raise ValueError("Endpoint is not in the supported scalar call graph")
    queue = deque([(endpoint, frames, [], frozenset())])
    seen, found, cycles, cut = set(), [], [], []
    while queue and len(seen) < limit:
        point, stack, path, ancestors = queue.popleft()
        key = (_key(point), tuple((v.callsite_ref, v.callee_ref, v.context_ref) for v in stack))
        if key in ancestors:
            cycles.append({"endpoint": point.model_dump(mode="json"), "call_path": [v.model_dump(mode="json") for v in stack]}); continue
        if key in seen: continue
        seen.add(key)
        choices = incoming[_key(point)]
        for root in roots[_key(point)]:
            bridged = root.kind in {"parameter", "receiver"} and any(role_by_id.get(e.id) == "formal_input" for e in choices)
            bridged |= root.kind == "call_result" and any(role_by_id.get(e.id) == "result_bridge" for e in choices)
            bridged |= root.kind in {"parameter", "receiver"} and isinstance(elements.get(point.element_ref), MethodRecord) and bool(stack)
            if not bridged:
                found.append({"root": root.model_dump(mode="json"), "call_path": [v.model_dump(mode="json") for v in stack],
                              "relations_to_target": list(reversed(path))})
        for edge in choices:
            role = role_by_id.get(edge.id)
            next_stack = stack
            if role == "normal_return_binding":
                frame = CallFrame(callsite_ref=edge.callsite_ref, callee_ref=edge.source.element_ref, context_ref=edge.context_ref)
                if len(stack) >= report.configuration.max_trace_depth:
                    cut.append({"reason": "Call depth budget exceeded", "endpoint": point.model_dump(mode="json"), "frame": frame.model_dump(mode="json")})
                    continue
                next_stack = (*stack, frame)
            elif role in {"argument_binding", "receiver_binding"}:
                if not stack: continue
                frame = stack[-1]
                if (frame.callsite_ref, frame.callee_ref, frame.context_ref) != (edge.callsite_ref, edge.target.element_ref, edge.context_ref): continue
                next_stack = stack[:-1]
            queue.append((edge.source, next_stack, [*path, edge.model_dump(mode="json")], ancestors | {key}))
    return {"schema_version": "call-sources.v1", "run_ref": facts.run.run_id, "target": endpoint.model_dump(mode="json"),
            "scope": "scalar_application_calls", "roots": found, "cycles": cycles, "truncated": bool(queue or cut or report.truncated or any(x["root"]["details"].get("analysis_state")=="truncated" for x in found)),
            "pending": [{"endpoint": p.model_dump(mode="json"), "call_path": [v.model_dump(mode="json") for v in s]} for p,s,_,_ in queue],
            "stops": cut, "enumeration_truncated": report.truncated, "pending_methods": report.pending_methods, "path_feasibility_checked": False,
            "heap_resolved": False, "cross_method_exception_objects_resolved": False}
