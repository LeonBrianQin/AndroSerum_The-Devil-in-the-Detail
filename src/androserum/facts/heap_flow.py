"""F4-C1: bounded method-local storage reaching writes, with allocation identities.

Unknown bases/indices/call effects stay explicit. No interprocedural heap, default
initialization, general points-to, FlowDroid, control or event analysis is claimed.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import hashlib
from pathlib import Path
from typing import Literal

from pydantic import Field

from androserum import __version__
from androserum.facts.call_flow import _inputs, extract_calls
from androserum.facts.identity import canonical_json, fingerprint, record_id
from androserum.facts.io import loads_facts, strict_json_syntax
from androserum.facts.local_flow import FlowRoot, _constant_value, cfg_edges
from androserum.facts.models import (AnalysisNodeRecord, AnalysisPosition, AnalysisScope, AnalysisStatus,
    ArchivePath, BindingRecord, Endpoint, FieldSignature, NonNegative, ProgramSlot, Provenance,
    Ref, RelationRecord, SHA256, StrictModel, ToolVersion, ValueInfo, VersionedArtifact)

TOOL = "tool:heap-flow"
RULE = "rule:heap-flow"
PREFIX = "analysis/heap-flow/"


class HeapConfig(StrictModel):
    schema_version: Literal["heap-flow-config.v1"] = "heap-flow-config.v1"
    scope: Literal["method_local_allocation_storage"] = "method_local_allocation_storage"
    call_effect: Literal["unknown_on_normal_and_exceptional_exit"] = "unknown_on_normal_and_exceptional_exit"
    max_locations: int = Field(default=10000, ge=1, le=100000)
    max_worklist_visits: int = Field(default=100000, ge=1, le=10000000)
    max_origin_visits: int = Field(default=500000, ge=1, le=10000000)
    max_witness_visits: int = Field(default=2000000, ge=1, le=100000000)


class HeapObject(StrictModel):
    object_ref: Ref
    allocation_unit: NonNegative
    type_descriptor: str | None
    single_allocation_per_invocation: bool


class StorageLocation(StrictModel):
    location_ref: Ref
    kind: Literal["instance_field", "static_field", "array"]
    object_ref: Ref | None
    field_signature: FieldSignature | None = None
    index: int | None = None


class HeapAccess(StrictModel):
    unit: NonNegative
    unit_ref: Ref
    operation: Literal["field_write", "field_read", "array_write", "array_read"]
    storage_kind: Literal["instance_field", "static_field", "array"]
    field_signature: FieldSignature | None
    index: int | None
    unknown_index: bool
    objects: list[Ref]
    unknown_base: bool
    base_endpoint: Endpoint | None
    origin_paths: list[list[Ref]]
    location_refs: list[Ref]
    binding_refs: list[Ref]
    write_value: Endpoint | None
    strong_update: bool
    issues: list[str]


class HeapLink(StrictModel):
    role: Literal["write_operand", "storage_read"]
    relation_kind: Literal["data_dependency", "field_dependency", "array_dependency"]
    source: Endpoint
    target: Endpoint
    write_unit: NonNegative
    read_unit: NonNegative | None = None
    location_ref: Ref | None = None
    object_ref: Ref | None = None
    binding_refs: list[Ref]
    witness: list[str]
    resolution: Literal["resolved", "partial"]
    reason: str | None
    requires_successful_write: bool


class HeapMethod(StrictModel):
    schema_version: Literal["heap-flow-method.v1"] = "heap-flow-method.v1"
    method_ref: Ref
    configuration: HeapConfig
    input_flow_entry: ArchivePath
    input_flow_sha256: SHA256
    ir_entry: ArchivePath
    cfg_entry: ArchivePath
    state: Literal["complete", "truncated", "unavailable"]
    reason: str | None
    visits: NonNegative
    objects: list[HeapObject]
    locations: list[StorageLocation]
    accesses: list[HeapAccess]
    links: list[HeapLink]
    nodes: list[AnalysisNodeRecord]
    bindings: list[BindingRecord]
    roots: list[FlowRoot]
    read_states: dict[str, dict[str, list[str]]]
    path_feasibility_checked: Literal[False] = False
    interprocedural_heap_resolved: Literal[False] = False
    default_initialization_resolved: Literal[False] = False


def _key(point):
    return canonical_json(point.model_dump(mode="json"))


def method_entry(method_ref):
    return PREFIX + fingerprint(method_ref)[:32] + ".json"


def _point(flow, unit, kind, index=None):
    return Endpoint(element_ref=flow.node_refs[unit], position_label=f"unit:{unit}", slot_kind=kind, slot_index=index)


def _overlap(left, right):
    if left.kind != right.kind or left.object_ref != right.object_ref: return False
    if left.kind != "array": return left.field_signature == right.field_signature
    return left.index is None or right.index is None or left.index == right.index


def analyze_heap(facts, flow, method, cfg, flow_entry, flow_digest, config, *, identity_scope=None, entry_override=None,
                 tool=TOOL, rule=RULE, scalar_relation_ids=None, transparent_call_units=()):
    run, owner = facts.run.run_id, flow.method_ref
    report = HeapMethod(method_ref=owner, configuration=config, input_flow_entry=flow_entry, input_flow_sha256=flow_digest,
        ir_entry=flow.ir_entry, cfg_entry=flow.cfg_entry, state="complete", reason=None, visits=0,
        objects=[], locations=[], accesses=[], links=[], nodes=[], bindings=[], roots=[], read_states={})
    if flow.state != "complete":
        report.state, report.reason = "unavailable", "Required local scalar analysis is " + flow.state
        return report
    entry = entry_override or method_entry(owner)
    identity = identity_scope or owner
    proof = lambda *refs: Provenance(kind="static_analysis", tool_ref=tool, rule_ref=rule, support_refs=list(dict.fromkeys([owner, *refs])))
    edges = cfg_edges(cfg, flow.configuration)
    successors, predecessors = defaultdict(list), defaultdict(list)
    for edge in edges:
        successors[edge[1]].append(edge); predecessors[edge[2]].append(edge)
    incoming = defaultdict(list)
    root_map = defaultdict(list)
    for index, link in enumerate(flow.links): incoming[_key(link.target)].append((index, link))
    for root in flow.roots: root_map[_key(root.endpoint)].append(root)
    node_units = {ref: i for i, ref in enumerate(flow.node_refs)}
    remaining_origins = config.max_origin_visits
    origins_cache = {}

    def origins(point):
        nonlocal remaining_origins
        if _key(point) in origins_cache: return origins_cache[_key(point)]
        queue, seen, values = deque([(point, [])]), set(), []
        while queue:
            if remaining_origins <= 0: raise OverflowError("Object/index origin budget exceeded")
            endpoint, path = queue.popleft(); remaining_origins -= 1
            key = _key(endpoint)
            if key in seen: continue
            seen.add(key)
            values.extend((root, path) for root in root_map[key])
            for index, link in incoming[key]:
                queue.append((link.source, [*path, scalar_relation_ids[index] if scalar_relation_ids else record_id(run, "relation", ["local-flow", owner, index])]))
        origins_cache[_key(point)] = values
        return values

    def value_origins(value, unit):
        if value is None or value.truncated: return []
        if value.local_index is not None: return origins(_point(flow, unit, "local", value.local_index))
        if value.constant_kind is not None:
            return [(FlowRoot(endpoint=_point(flow, unit, "element"), kind="constant", details={"operand": value.model_dump(mode="json")}), [])]
        return []

    def is_repeated(unit):
        nonlocal remaining_origins
        queue, seen = deque(edge[2] for edge in successors[unit]), set()
        while queue:
            if remaining_origins <= 0: raise OverflowError("Allocation-cycle budget exceeded")
            current = queue.popleft(); remaining_origins -= 1
            if current == unit: return True
            if current in seen: continue
            seen.add(current); queue.extend(edge[2] for edge in successors[current])
        return False

    objects, locations = {}, {}

    def object_for(root):
        unit = node_units.get(root.endpoint.element_ref)
        if root.kind != "allocation" or unit is None or method.units[unit].operation != "allocation": return None
        ref = record_id(run, "analysis", ["heap-object", identity, unit])
        if ref not in objects:
            obj = HeapObject(object_ref=ref, allocation_unit=unit, type_descriptor=method.units[unit].right.type_descriptor,
                             single_allocation_per_invocation=not is_repeated(unit))
            objects[ref] = obj
            report.nodes.append(AnalysisNodeRecord(id=ref, run_ref=run, kind="analysis_node", node_kind="object", method_ref=owner,
                position=AnalysisPosition(kind="analysis", artifact_path=entry, position_label=f"object:{unit}"),
                provenance=proof(flow.node_refs[unit]), slots=[ProgramSlot(slot_kind="value", value=ValueInfo(status="unknown",
                    reason="Allocation-site object identity; heap contents and concrete instance not materialized"))]))
        return ref

    def location_for(kind, obj, signature, index):
        identity = [kind, obj, signature, index]
        ref = record_id(run, "analysis", ["heap-location", identity_scope or owner, identity])
        if ref not in locations:
            if len(locations) >= config.max_locations: raise OverflowError("Heap location budget exceeded")
            locations[ref] = StorageLocation(location_ref=ref, kind=kind, object_ref=obj, field_signature=signature, index=index)
            label = "location:" + ref
            slot_kind, slot_label = ("array_element", "index:" + str(index)) if kind == "array" else ("field", signature)
            report.nodes.append(AnalysisNodeRecord(id=ref, run_ref=run, kind="analysis_node", node_kind="state", method_ref=owner,
                position=AnalysisPosition(kind="analysis", artifact_path=entry, position_label=label), provenance=proof(*([obj] if obj else [])),
                slots=[ProgramSlot(slot_kind=slot_kind, slot_label=slot_label, value=ValueInfo(status="unknown", reason="Abstract storage location, contents depend on CFG position"))]))
        return ref

    try:
        for unit in method.units:
            if unit.index not in flow.reachable or unit.operation not in {"field_read", "field_write", "array_read", "array_write"}: continue
            write = unit.operation.endswith("write")
            value = unit.left if write else unit.right
            if value is None: continue
            kind = "array" if unit.operation.startswith("array") else "static_field" if "StaticFieldRef" in value.kind else "instance_field"
            base = value.base
            refs, unknown, paths, issues = set(), False, [], []
            base_point = _point(flow, unit.index, "local", base.local_index) if base and base.local_index is not None else None
            if kind != "static_field":
                sources = value_origins(base, unit.index)
                if not sources: unknown = True
                for root, path in sources:
                    ref = object_for(root)
                    if ref is None: unknown = True
                    else: refs.add(ref); paths.append(path)
                if unknown: issues.append("Base object not fully resolved to local allocation sites; no disjointness assumed for unknown references")
            index, unknown_index = None, False
            if kind == "array":
                sources = value_origins(value.index_value, unit.index)
                indices = {root.details["operand"]["constant"] for root, _ in sources if root.kind == "constant"
                           and root.details.get("operand", {}).get("constant_kind") == "int"}
                known = bool(sources) and all(root.kind == "constant" and root.details.get("operand", {}).get("constant_kind") == "int" for root, _ in sources)
                if known and len(indices) == 1: index = next(iter(indices))
                else: unknown_index = True; issues.append("Array index is unknown or has alternatives")
            signature = value.field_signature
            invalid = value.truncated or (kind != "array" and signature is None) or (index is not None and index < 0)
            if invalid: issues.append("Unsupported/truncated storage expression or negative index; no normal access inferred")
            loc_refs = [] if invalid else [location_for(kind, obj, signature, index) for obj in sorted(refs)] if kind != "static_field" else [location_for(kind, None, signature, None)]
            bindings = []
            for obj in sorted(refs):
                if base_point:
                    ref = record_id(run, "binding", ["heap-base", identity, unit.index, obj])
                    allocation = objects[obj]
                    report.bindings.append(BindingRecord(id=ref, run_ref=run, provenance=proof(obj, flow.node_refs[unit.index]), binding_kind="object",
                        endpoints=[base_point, Endpoint(element_ref=obj, slot_kind="value", position_label=f"object:{allocation.allocation_unit}")]))
                    bindings.append(ref)
            access = HeapAccess(unit=unit.index, unit_ref=flow.node_refs[unit.index], operation=unit.operation, storage_kind=kind,
                field_signature=signature, index=index, unknown_index=unknown_index, objects=sorted(refs), unknown_base=unknown,
                base_endpoint=base_point, origin_paths=paths, location_refs=loc_refs, binding_refs=bindings,
                write_value=None, strong_update=False, issues=issues)
            access.strong_update = write and bool(loc_refs) and not unknown and not unknown_index and (
                kind == "static_field" or len(refs) == 1 and objects[next(iter(refs))].single_allocation_per_invocation)
            report.accesses.append(access)
            if write:
                ref = record_id(run, "analysis", ["heap-write-value", identity, unit.index])
                label = f"write:{unit.index}"
                access.write_value = Endpoint(element_ref=ref, slot_kind="value", position_label=label)
                right = unit.right
                report.nodes.append(AnalysisNodeRecord(id=ref, run_ref=run, kind="analysis_node", node_kind="state", method_ref=owner,
                    position=AnalysisPosition(kind="analysis", artifact_path=entry, position_label=label), provenance=proof(flow.node_refs[unit.index]),
                    slots=[ProgramSlot(slot_kind="value", type_descriptor=right.type_descriptor if right and right.type_descriptor != "V" else None,
                                       value=_constant_value(right) if right else ValueInfo(status="unknown", reason="Missing write operand"))]))
                if right and right.local_index is not None:
                    report.links.append(HeapLink(role="write_operand", relation_kind="data_dependency",
                        source=_point(flow, unit.index, "local", right.local_index), target=access.write_value, write_unit=unit.index,
                        binding_refs=[], witness=[], resolution="resolved", reason=None, requires_successful_write=False))
                else:
                    report.roots.append(FlowRoot(endpoint=access.write_value, kind="constant" if right and right.constant_kind else "incomplete_operand",
                        details={"operand": right.model_dump(mode="json") if right else None}))
        report.objects, report.locations = list(objects.values()), list(locations.values())
        by_unit = {value.unit: value for value in report.accesses}
        # State tokens are program writes or explicit unknown origins, never values.
        token_bits={}; token_names=[]
        def token_bit(name):
            if name not in token_bits:
                token_bits[name]=1 << len(token_names); token_names.append(name)
            return token_bits[name]
        def decode_tokens(bits):
            names=[]
            while bits:
                bit=bits & -bits; names.append(token_names[bit.bit_length()-1]); bits^=bit
            return sorted(names)
        initial_bit=token_bit('u:initial')
        def targets(access, loc):
            if not access.location_refs: return False
            return any(_overlap(locations[ref], loc) for ref in access.location_refs)
        def unknown_alias(access, loc):
            if not access.unknown_base: return False
            if access.storage_kind != loc.kind: return False
            return access.field_signature == loc.field_signature if loc.kind != "array" else (access.index is None or loc.index is None or access.index == loc.index)
        def transfer(unit, state, normal):
            result = state.copy()
            if method.units[unit].invoke and unit not in transparent_call_units:
                call_bit=token_bit(f"u:call:{unit}")
                for key in result: result[key] |= call_bit
            access = by_unit.get(unit)
            if access and access.write_value and normal:
                for ref, loc in locations.items():
                    if targets(access, loc):
                        strong = access.strong_update and ref in access.location_refs
                        write_bit=token_bit(f"w:{unit}")
                        result[ref] = write_bit if strong else result[ref] | write_bit
                    if unknown_alias(access, loc): result[ref] |= token_bit(f"u:base:{unit}")
            return result
        empty = lambda: {ref: 0 for ref in locations}
        inside = {unit: empty() for unit in flow.reachable}
        outside = {unit: empty() for unit in flow.reachable}
        exceptional = {unit: empty() for unit in flow.reachable}
        queue, queued = deque(sorted(flow.reachable)), set(flow.reachable)
        while queue:
            if report.visits >= config.max_worklist_visits: raise OverflowError("Heap reaching-write worklist budget exceeded")
            unit = queue.popleft(); queued.remove(unit); report.visits += 1
            merged = {ref: initial_bit if unit == 0 else 0 for ref in locations}
            for edge in predecessors[unit]:
                if edge[1] not in inside: continue
                state = outside[edge[1]] if edge[3] == "after" else exceptional[edge[1]]
                for ref in merged: merged[ref] |= state[ref]
            normal, failed = transfer(unit, merged, True), transfer(unit, merged, False)
            if merged != inside[unit] or normal != outside[unit] or failed != exceptional[unit]:
                inside[unit], outside[unit], exceptional[unit] = merged, normal, failed
                for edge in successors[unit]:
                    if edge[2] in inside and edge[2] not in queued: queue.append(edge[2]); queued.add(edge[2])

        witness_budget = config.max_witness_visits
        def witness(write, read, ref):
            nonlocal witness_budget
            queue = deque((edge[2], [edge[0]]) for edge in successors[write] if edge[3] == "after")
            seen = set()
            while queue:
                if witness_budget <= 0: raise OverflowError("Heap dependency witness budget exceeded")
                current, path = queue.popleft(); witness_budget -= 1
                if current == read: return path
                if current in seen: continue
                seen.add(current)
                access = by_unit.get(current)
                killed = access and access.write_value and access.strong_update and ref in access.location_refs and current != write
                for edge in successors[current]:
                    if not killed or edge[3] == "before": queue.append((edge[2], [*path, edge[0]]))
            raise ValueError("Heap write/read claim has no storage-preserving CFG witness")

        for access in report.accesses:
            if access.write_value: continue
            target = _point(flow, access.unit, "result")
            states = {ref: decode_tokens(inside[access.unit][ref]) for ref in access.location_refs}
            report.read_states[str(access.unit)] = states
            unknowns = sorted({token for tokens in states.values() for token in tokens if token.startswith("u:")})
            if access.issues or unknowns or not states:
                report.roots.append(FlowRoot(endpoint=target, kind="heap_read", details={"issues": access.issues,
                    "unknown_origins": unknowns, "reason": "Heap read retains unresolved base/index/default/call effects"}))
            alternatives = set(token for tokens in states.values() for token in tokens)
            partial = bool(access.issues or unknowns or len(access.location_refs) != 1 or len(alternatives) != 1)
            for ref, tokens in states.items():
                for token in tokens:
                    if not token.startswith("w:"): continue
                    written = by_unit[int(token[2:])]
                    loc = locations[ref]
                    report.links.append(HeapLink(role="storage_read", relation_kind="array_dependency" if access.storage_kind == "array" else "field_dependency",
                        source=written.write_value, target=target, write_unit=written.unit, read_unit=access.unit,
                        location_ref=ref, object_ref=loc.object_ref,
                        binding_refs=[binding.id for binding in report.bindings if binding.id in [*written.binding_refs, *access.binding_refs]
                                      and any(point.element_ref == loc.object_ref for point in binding.endpoints)],
                        witness=witness(written.unit, access.unit, ref), resolution="partial" if partial or not written.strong_update else "resolved",
                        reason="May locations/writes or unresolved effects remain" if partial or not written.strong_update else None,
                        requires_successful_write=True))
    except OverflowError as error:
        report.state, report.reason = "truncated", str(error)
        report.objects, report.locations, report.accesses, report.links = [], [], [], []
        report.nodes, report.bindings, report.roots, report.read_states = [], [], [], {}
    return report


def _emit(facts, report):
    run, owner = facts.run.run_id, report.method_ref
    anchor = record_id(run, "analysis", ["heap-report", owner])
    entry = method_entry(owner)
    node = AnalysisNodeRecord(id=anchor, run_ref=run, kind="analysis_node", node_kind="state", method_ref=owner,
        position=AnalysisPosition(kind="analysis", artifact_path=entry, position_label="heap-flow"),
        provenance=Provenance(kind="static_analysis", tool_ref=TOOL, rule_ref=RULE, support_refs=[owner]))
    edges = []
    for index, value in enumerate(report.links):
        support = [anchor, owner, value.source.element_ref, value.target.element_ref]
        if value.location_ref: support.append(value.location_ref)
        if value.object_ref: support.append(value.object_ref)
        edges.append(RelationRecord(id=record_id(run, "relation", ["heap-flow", owner, index]), run_ref=run,
            provenance=Provenance(kind="static_analysis", tool_ref=TOOL, rule_ref=RULE, support_refs=list(dict.fromkeys(support))),
            relation_kind=value.relation_kind, source=value.source, target=value.target, binding_refs=value.binding_refs,
            resolution=value.resolution, unresolved_reason=value.reason, source_selector=entry + f"#/links/{index}"))
    return [node, *report.nodes], report.bindings, edges


def _all_reports(facts, read, config):
    flows, methods, cfgs, hashes = _inputs(facts, read)
    entries = {node.method_ref: node.position.artifact_path for node in facts.elements if isinstance(node, AnalysisNodeRecord)
               and node.node_kind == "cfg" and node.position.kind == "analysis" and node.position.artifact_path.startswith("analysis/local-flow/")}
    for ref, flow in sorted(flows.items()):
        if any(unit.operation in {"field_read", "field_write", "array_read", "array_write"} for unit in methods[ref].units):
            yield analyze_heap(facts, flow, methods[ref], cfgs[ref], entries[ref], hashes[entries[ref]], config)


def extend_heap(result, config=None):
    config = HeapConfig.model_validate((config or HeapConfig()).model_dump())
    facts, run = result.facts, result.facts.run.run_id
    facts.run.configuration.options["heap_flow"] = config.model_dump(mode="json")
    facts.run.config_fingerprint = fingerprint(facts.run.configuration.model_dump(mode="json"))
    read = lambda entry: result.blobs[result.entry_digests[entry]]
    reports = list(_all_reports(facts, read, config))
    facts.run.tools.append(ToolVersion(tool_id=TOOL, name="androserum-local-storage-flow", version=__version__))
    raw = Path(__file__).read_bytes(); digest = hashlib.sha256(raw).hexdigest(); entry = "analysis/rules/heap_flow.py"
    result.blobs[digest], result.entry_digests[entry] = raw, digest
    facts.run.artifacts.append(VersionedArtifact(artifact_id=RULE, kind="rule", name="local-allocation-storage", version="1", sha256=digest, location=entry))
    for report in reports:
        raw = canonical_json(report.model_dump(mode="json")).encode("utf-8"); digest = hashlib.sha256(raw).hexdigest()
        result.blobs[digest], result.entry_digests[method_entry(report.method_ref)] = raw, digest
        nodes, bindings, edges = _emit(facts, report)
        facts.elements.extend(nodes); facts.bindings.extend(bindings); facts.relations.extend(edges)
        for capability in ["objects", "data_flow"]:
            unresolved = report.state == "complete" and (any(root.kind == "heap_read" for root in report.roots) or any(access.issues for access in report.accesses))
            scope_state = "partial" if unresolved else report.state
            facts.statuses.append(AnalysisStatus(id=record_id(run, "status", ["heap-flow", report.method_ref, capability]), run_ref=run,
                tool_ref=TOOL, capability=capability, scope=AnalysisScope(kind="element", element_ref=report.method_ref), state=scope_state,
                reason="Unresolved storage/base/index/default or call effects remain" if unresolved else report.reason,
                issue_code=None if scope_state == "complete" else "heap_flow_" + scope_state))
    for capability in ["objects", "data_flow"]:
        status = next(value for value in facts.statuses if value.capability == capability and value.scope.kind == "run")
        status.tool_ref, status.state = TOOL, "partial" if reports else "unavailable"
        status.reason = "Only F4-C1 method-local allocation/storage analysis; interprocedural heap, full object precision, defaults and call effects unresolved"
    result.facts = loads_facts(facts.model_dump_json())
    verify_heap_evidence(result.facts, read)
    summary = {"methods": [{"method_ref": report.method_ref, "entry": method_entry(report.method_ref), "state": report.state} for report in reports],
               "counts": dict(Counter(report.state for report in reports)), "dependencies": sum(value.role == "storage_read" for report in reports for value in report.links)}
    result.summary.update(stage="F4-C1", heap_flow=summary, outcome="failed" if result.summary["outcome"] == "failed" else "partial",
        element_counts=dict(Counter(value.kind for value in facts.elements)), relation_counts=dict(Counter(value.relation_kind for value in facts.relations)),
        coverage={value.capability: value.state for value in facts.statuses if value.scope.kind == "run"},
        limits=["Method-local allocation objects and field/array reaching writes only", "Unknown/default/call effects retained; no interprocedural heap, full points-to, control/events, FlowDroid or BU"])
    return result


def extract_heap(apk, *, java_config=None, flow_config=None, call_config=None, config=None):
    return extend_heap(extract_calls(apk, java_config=java_config, flow_config=flow_config, config=call_config), config)


def verify_heap_evidence(facts, read):
    own = lambda value: value.provenance.tool_ref == TOOL or value.provenance.rule_ref == RULE
    active = any(tool.tool_id == TOOL for tool in facts.run.tools)
    actual_nodes = {value.id: value for value in facts.elements if own(value)}
    actual_edges = {value.id: value for value in facts.relations if own(value) or value.source_selector and value.source_selector.startswith(PREFIX)}
    actual_bindings = {value.id: value for value in facts.bindings if own(value)}
    if not active:
        if actual_nodes or actual_edges or actual_bindings: raise ValueError("Heap records lack analysis tool")
        return {"relations": 0}
    config = HeapConfig.model_validate(facts.run.configuration.options.get("heap_flow", {}))
    nodes, bindings, edges = {}, {}, {}
    for expected in _all_reports(facts, read, config):
        data = read(method_entry(expected.method_ref)); strict_json_syntax(data.decode("utf-8"))
        actual = HeapMethod.model_validate_json(data)
        if actual != expected: raise ValueError("Heap objects/locations/write-read witnesses disagree with local IR and CFG")
        new_nodes, new_bindings, new_edges = _emit(facts, expected)
        nodes.update({value.id: value for value in new_nodes}); bindings.update({value.id: value for value in new_bindings}); edges.update({value.id: value for value in new_edges})
    if nodes != actual_nodes or bindings != actual_bindings or edges != actual_edges:
        raise ValueError("Heap facts have forged/missing object, binding, storage or dependency records")
    return {"relations": len(edges), "bindings": len(bindings)}


def trace_heap_sources(facts, read, endpoint, *, limit=1000):
    elements = {value.id: value for value in facts.elements}
    owner = getattr(elements.get(endpoint.element_ref), "method_ref", None)
    if owner is None: raise ValueError("Endpoint has no method-local heap scope")
    report = HeapMethod.model_validate_json(read(method_entry(owner)))
    if report.state != "complete":
        return {"schema_version": "heap-sources.v1", "run_ref": facts.run.run_id, "method_ref": owner, "state": report.state,
                "reason": report.reason, "roots": [], "truncated": True}
    flows, _, _, _ = _inputs(facts, read); flow = flows[owner]
    incoming, roots = defaultdict(list), defaultdict(list)
    for edge in facts.relations:
        if edge.provenance.tool_ref in {TOOL, "tool:local-flow"} and edge.target and getattr(elements.get(edge.source.element_ref), "method_ref", None) == owner:
            incoming[_key(edge.target)].append(edge)
    read_results = {_key(_point(flow, access.unit, "result")) for access in report.accesses if not access.write_value}
    for root in flow.roots:
        if root.kind == "heap_read" and _key(root.endpoint) in read_results: continue
        roots[_key(root.endpoint)].append(root)
    for root in report.roots: roots[_key(root.endpoint)].append(root)
    start = _key(endpoint)
    if start not in roots and start not in incoming: raise ValueError("Endpoint is not a supported heap/scalar use or result")
    queue, seen, found, cycles = deque([(endpoint, [], frozenset())]), set(), [], []
    while queue and len(seen) < limit:
        point, path, ancestors = queue.popleft(); key = _key(point)
        if key in ancestors: cycles.append(point.model_dump(mode="json")); continue
        if key in seen: continue
        seen.add(key)
        for root in roots[key]: found.append({"root": root.model_dump(mode="json"), "relations_to_target": list(reversed(path))})
        for edge in incoming[key]: queue.append((edge.source, [*path, edge.model_dump(mode="json")], ancestors | {key}))
    return {"schema_version": "heap-sources.v1", "run_ref": facts.run.run_id, "method_ref": owner,
            "scope": report.configuration.scope, "target": endpoint.model_dump(mode="json"), "roots": found,
            "truncated": bool(queue), "pending": [point.model_dump(mode="json") for point, _, _ in queue], "cycles": cycles,
            "path_feasibility_checked": False, "interprocedural_heap_resolved": False, "default_initialization_resolved": False}
