"""F4-A: method-local scalar may-definitions, with pre-statement exceptional transfer.

No heap alias, call-return summary, branch feasibility or control-dependence inference.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
import hashlib
import json
import re
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from androserum import __version__
from androserum.facts.identity import canonical_json, fingerprint, record_id
from androserum.facts.io import loads_facts, strict_json_syntax
from androserum.facts.java_backend import JavaConfig, extract_java
from androserum.facts.jimple import IRValue, JimpleMethod
from androserum.facts.models import (AnalysisNodeRecord, AnalysisPosition, AnalysisScope, AnalysisStatus,
    ArchivePath, Endpoint, FactBundle, MethodSignature, NonNegative, ProgramSlot, Provenance, Ref,
    RelationRecord, SHA256, StrictModel, ToolVersion, ValueInfo, VersionedArtifact)


class ExceptionalEdge(StrictModel):
    source: NonNegative
    target: NonNegative
    trap_index: NonNegative
    exception_type: str
    transfer: Literal["before_unit"]
    included_types: list[str]
    excluded_types: list[str]


class EscapingException(StrictModel):
    unit: NonNegative
    included_types: list[str]
    excluded_types: list[str]


class DefOracle(StrictModel):
    unit: NonNegative
    local_index: NonNegative
    definitions: list[NonNegative]


class MethodCFG(StrictModel):
    schema_version: Literal["jimple-cfg.v1"] = "jimple-cfg.v1"
    method_signature: MethodSignature
    method_sha256: SHA256
    unit_count: NonNegative
    exception_model: Literal["soot-4.7.1-unit-throw-analysis"]
    normal_edges: list[tuple[NonNegative, NonNegative]]
    exception_edges: list[ExceptionalEdge]
    escaping_exceptions: list[EscapingException]
    normal_defs_oracle: list[DefOracle]


class CFGCommit(StrictModel):
    schema_version: Literal["jimple-cfg-commit.v1"]
    request_sha256: SHA256
    apk_sha256: SHA256
    path: ArchivePath
    sha256: SHA256
    method_path: ArchivePath
    method_sha256: SHA256
    signature: MethodSignature


class LocalFlowConfig(StrictModel):
    schema_version: Literal["local-flow-config.v1"] = "local-flow-config.v1"
    exception_policy: Literal["soot_direct_pre_state", "normal_only"] = "soot_direct_pre_state"
    max_worklist_visits: int = Field(default=100000, ge=1, le=10000000)
    max_cfg_edges: int = Field(default=200000, ge=1, le=10000000)
    max_witness_visits: int = Field(default=2000000, ge=1, le=100000000)


class ReachingUse(StrictModel):
    unit: NonNegative
    local_index: NonNegative
    definitions: list[NonNegative]
    undefined: bool


class FlowLink(StrictModel):
    kind: Literal["reaching_definition", "value_copy", "expression_input", "argument_input", "receiver_input"]
    source: Endpoint
    target: Endpoint
    local_index: NonNegative | None = None
    witness: list[str] = Field(default_factory=list)
    alternatives: list[int] = Field(default_factory=list)
    resolution: Literal["resolved", "partial"] = "resolved"
    reason: str | None = None
    # Reaching links require the source definition to complete; expression links
    # require the target result. Argument/receiver reads do not require call return.
    requires_normal_completion: bool = True


class FlowRoot(StrictModel):
    endpoint: Endpoint
    kind: Literal["parameter", "receiver", "caught_exception", "constant", "call_result", "heap_read", "allocation",
                  "undefined_local", "unsupported_expression", "incomplete_operand", "opaque_result"]
    details: dict[str, JsonValue] = Field(default_factory=dict)


class OperandNode(StrictModel):
    node_ref: Ref
    unit: NonNegative
    role: str
    value: IRValue


class MethodFlow(StrictModel):
    schema_version: Literal["local-flow-method.v1"] = "local-flow-method.v1"
    scope: Literal["method_scalar_locals"] = "method_scalar_locals"
    method_ref: Ref
    method_signature: MethodSignature
    ir_entry: ArchivePath
    ir_sha256: SHA256
    cfg_entry: ArchivePath
    cfg_sha256: SHA256
    node_refs: list[Ref]
    configuration: LocalFlowConfig
    state: Literal["complete", "truncated", "unavailable"]
    reason: str | None
    visits: NonNegative
    reachable: list[NonNegative]
    pending_units: list[NonNegative]
    uses: list[ReachingUse]
    links: list[FlowLink]
    roots: list[FlowRoot]
    operand_nodes: list[OperandNode]
    path_feasibility_checked: Literal[False] = False
    heap_and_callee_resolved: Literal[False] = False


def validate_cfg(method, cfg):
    if method.state != "complete" or cfg.method_signature != method.signature or cfg.unit_count != len(method.units):
        raise ValueError("CFG does not describe this complete Jimple method")
    expected = set()
    for unit in method.units:
        expected.update((unit.index, target) for target in unit.targets)
        if unit.falls_through and unit.index + 1 < len(method.units): expected.add((unit.index, unit.index + 1))
    if set(cfg.normal_edges) != expected or len(cfg.normal_edges) != len(expected):
        raise ValueError("CFG normal edges disagree with structured IR branches/fallthrough")
    exception_keys = [(edge.source, edge.target, edge.trap_index) for edge in cfg.exception_edges]
    if len(set(exception_keys)) != len(exception_keys): raise ValueError("Duplicate exceptional CFG edges")
    for edge in cfg.exception_edges:
        if max(edge.source, edge.target) >= len(method.units) or edge.trap_index >= len(method.traps):
            raise ValueError("Exceptional CFG edge is outside the method/traps")
        trap = method.traps[edge.trap_index]
        if not trap.begin <= edge.source < trap.end or edge.target != trap.handler or edge.exception_type != trap.exception_type:
            raise ValueError("Exceptional edge lacks its claimed protected range/handler")
    for value in cfg.normal_defs_oracle:
        if value.unit >= len(method.units) or value.local_index >= len(method.locals) or any(i >= len(method.units) for i in value.definitions):
            raise ValueError("Independent normal-flow oracle contains invalid positions")


def _locals(value):
    if value is None: return set()
    result = {value.local_index} if value.local_index is not None else set()
    for child in value.children: result.update(_locals(child))
    result.update(_locals(value.base)); result.update(_locals(value.index_value))
    return result


def unit_definition(unit):
    definitions = {value.local_index for value in unit.definitions if value.local_index is not None}
    if len(definitions) > 1: raise ValueError("Expected a single Jimple scalar definition")
    local = next(iter(definitions), None)
    if local is not None and (unit.left is None or unit.left.local_index != local):
        raise ValueError("IR definition boxes and assignment left side disagree")
    return local


def cfg_edges(cfg, config):
    edges = [(f"n:{source}:{target}", source, target, "after") for source, target in cfg.normal_edges]
    if config.exception_policy == "soot_direct_pre_state":
        edges += [(f"x:{edge.source}:{edge.target}:{edge.trap_index}", edge.source, edge.target, "before") for edge in cfg.exception_edges]
    return edges


class _DefinitionRow:
    """Decode only queried locals; bit zero is the original unknown definition -1."""
    def __init__(self, values): self.values = values
    def __len__(self): return len(self.values)
    def __getitem__(self, index):
        if isinstance(index, slice):return [self[i] for i in range(*index.indices(len(self)))]
        bits = self.values[index]; result = set()
        while bits:
            bit = bits & -bits
            result.add(bit.bit_length() - 2); bits ^= bit
        return result
    def __iter__(self):
        for i in range(len(self)):yield self[i]


def solve_reaching(method, cfg, config):
    validate_cfg(method, cfg)
    edges = cfg_edges(cfg, config)
    if len(edges) > config.max_cfg_edges:
        return {"state": "truncated", "reason": "CFG edge budget exceeded", "visits": 0, "reachable": [], "pending": [0] if method.units else [], "in": []}
    count, locals_count = len(method.units), len(method.locals)
    successors, predecessors = defaultdict(list), defaultdict(list)
    for _, source, target, phase in edges:
        successors[source].append(target); predecessors[target].append((source, phase))
    reachable, queue = set(), deque([0] if count else [])
    while queue:
        unit = queue.popleft()
        if unit in reachable: continue
        reachable.add(unit); queue.extend(successors[unit])
    incoming = [[0] * locals_count for _ in range(count)]
    outgoing = [[0] * locals_count for _ in range(count)]
    definitions = [unit_definition(unit) for unit in method.units]
    queue, queued, visits = deque(sorted(reachable)), set(reachable), 0
    while queue:
        if visits >= config.max_worklist_visits:
            return {"state": "truncated", "reason": "Reaching-definition worklist budget exceeded", "visits": visits,
                    "reachable": sorted(reachable), "pending": list(queue), "in": [_DefinitionRow(row) for row in incoming]}
        unit = queue.popleft(); queued.remove(unit); visits += 1
        current = [1 if unit == 0 else 0] * locals_count
        for source, phase in predecessors[unit]:
            if source in reachable:
                values = incoming[source] if phase == "before" else outgoing[source]
                for local in range(locals_count): current[local] |= values[local]
        after = current.copy()
        if definitions[unit] is not None: after[definitions[unit]] = 1 << (unit + 1)
        if current != incoming[unit] or after != outgoing[unit]:
            incoming[unit], outgoing[unit] = current, after
            for target in successors[unit]:
                if target in reachable and target not in queued: queue.append(target); queued.add(target)
    return {"state": "complete", "reason": None, "visits": visits, "reachable": sorted(reachable), "pending": [], "in": [_DefinitionRow(row) for row in incoming]}


def _witness(definition, target, local, definitions, edges, allowance):
    successors = defaultdict(list)
    for edge in edges: successors[edge[1]].append(edge)
    queue = deque((edge[2], [edge[0]]) for edge in successors[definition] if edge[3] == "after")
    seen, visits = set(), 0
    while queue:
        if visits >= allowance: raise OverflowError("Definition witness budget exceeded")
        unit, path = queue.popleft(); visits += 1
        if unit == target: return path, visits
        if unit in seen: continue
        seen.add(unit)
        for edge in successors[unit]:
            if edge[3] == "before" or definitions[unit] != local or unit == definition:
                queue.append((edge[2], path + [edge[0]]))
    raise ValueError("A claimed reaching definition has no kill-free CFG witness")


PURE = {"JAddExpr", "JSubExpr", "JMulExpr", "JDivExpr", "JRemExpr", "JAndExpr", "JOrExpr", "JXorExpr", "JShlExpr",
        "JShrExpr", "JUshrExpr", "JNegExpr", "JCastExpr", "JInstanceOfExpr", "JCmpExpr", "JCmplExpr", "JCmpgExpr",
        "JEqExpr", "JNeExpr", "JGtExpr", "JGeExpr", "JLtExpr", "JLeExpr"}


def value_terms(value, path):
    if value.truncated: return None
    if value.local_index is not None: return [("local", value.local_index, path)]
    if value.constant_kind is not None: return [("literal", value, path)]
    if value.kind not in PURE or value.field_signature is not None or value.base is not None: return None
    terms = []
    for i, child in enumerate(value.children):
        part = value_terms(child, path + f".children[{i}]")
        if part is None: return None
        terms.extend(part)
    return terms if terms else None


def analyze_method(method, cfg, *, run_ref, method_ref, node_refs, ir_entry, ir_sha256, cfg_entry, cfg_sha256, config, identity_scope=None):
    if len(node_refs) != len(method.units) or len(set(node_refs)) != len(node_refs):
        raise ValueError("Flow analysis needs exactly one positioned node per IR unit")
    solved = solve_reaching(method, cfg, config)
    report = MethodFlow(method_ref=method_ref, method_signature=method.signature, node_refs=node_refs,
        ir_entry=ir_entry, ir_sha256=ir_sha256, cfg_entry=cfg_entry, cfg_sha256=cfg_sha256, configuration=config,
        state=solved["state"], reason=solved["reason"], visits=solved["visits"], reachable=solved["reachable"],
        pending_units=solved["pending"], uses=[], links=[], roots=[], operand_nodes=[])
    if solved["state"] != "complete": return report
    def point(unit, kind, index=None):
        return Endpoint(element_ref=node_refs[unit], slot_kind=kind, slot_index=index, position_label=f"unit:{unit}")
    root_keys, link_keys, operand_keys = set(), set(), {}
    def root(endpoint, kind, details):
        key = canonical_json([endpoint.model_dump(mode="json"), kind, details])
        if key not in root_keys: report.roots.append(FlowRoot(endpoint=endpoint, kind=kind, details=details)); root_keys.add(key)
    def link(kind, source, target, **kwargs):
        key = canonical_json([kind, source.model_dump(mode="json"), target.model_dump(mode="json")])
        kwargs.setdefault("requires_normal_completion", kind in {"reaching_definition", "value_copy", "expression_input"})
        if key not in link_keys: report.links.append(FlowLink(kind=kind, source=source, target=target, **kwargs)); link_keys.add(key)
    def operand(unit, value, role):
        key = (unit, role)
        if key not in operand_keys:
            ref = record_id(run_ref, "analysis", [identity_scope or method_ref, "operand", unit, role])
            label = f"operand:{unit}:{role}"
            endpoint = Endpoint(element_ref=ref, slot_kind="value", position_label=label)
            report.operand_nodes.append(OperandNode(node_ref=ref, unit=unit, role=role, value=value))
            operand_keys[key] = endpoint
            root(endpoint, "constant" if value.constant_kind is not None else "incomplete_operand" if value.truncated else "unsupported_expression",
                 {"operand": value.model_dump(mode="json")})
        return operand_keys[key]
    def term_links(unit, value, role, target, kind):
        terms = value_terms(value, role)
        if terms is None:
            root(target, "incomplete_operand" if value.truncated else "unsupported_expression", {"operand": value.model_dump(mode="json")})
            return
        for term_kind, value_or_local, path in terms:
            source = point(unit, "local", value_or_local) if term_kind == "local" else operand(unit, value_or_local, path)
            link(kind, source, target)
    definitions = [unit_definition(unit) for unit in method.units]
    edges, witness_visits = cfg_edges(cfg, config), 0
    try:
        for index in solved["reachable"]:
            unit = method.units[index]
            used = set().union(*(_locals(value) for value in unit.uses)) if unit.uses else set()
            for local in sorted(used):
                reached = solved["in"][index][local]
                defs, undefined = sorted(value for value in reached if value >= 0), -1 in reached
                report.uses.append(ReachingUse(unit=index, local_index=local, definitions=defs, undefined=undefined))
                if undefined or not defs:
                    root(point(index, "local", local), "undefined_local", {"local_index": local, "reason": "Undefined on at least one modeled path"})
                alternatives = sorted(reached)
                for definition in defs:
                    witness, visits = _witness(definition, index, local, definitions, edges, config.max_witness_visits - witness_visits)
                    witness_visits += visits
                    multiple = len(reached) > 1
                    link("reaching_definition", point(definition, "result"), point(index, "local", local), local_index=local,
                         witness=witness, alternatives=alternatives, resolution="partial" if multiple else "resolved",
                         reason="Alternative may-definitions/undefined paths remain" if multiple else None)
            if definitions[index] is not None:
                target = point(index, "result")
                if unit.operation == "identity" and unit.right:
                    root(target, {"this": "receiver", "parameter": "parameter", "caught_exception": "caught_exception"}.get(unit.right.identity_kind, "opaque_result"),
                         {"parameter_index": unit.right.parameter_index, "type_descriptor": unit.right.type_descriptor})
                elif unit.invoke:
                    root(target, "call_result", {"signature": unit.invoke.signature, "reason": "Callee/heap summary deferred to F4-B/C"})
                elif unit.operation in {"field_read", "array_read"}:
                    root(target, "heap_read", {"reason": "Object/heap relation not resolved in F4-A"})
                elif unit.operation == "allocation":
                    root(target, "allocation", {"reason": "Allocation identity; no heap-content inference"})
                elif unit.right and unit.right.constant_kind is not None:
                    root(target, "constant", {"operand": unit.right.model_dump(mode="json")})
                elif unit.right:
                    term_links(index, unit.right, "right", target, "value_copy" if unit.right.local_index is not None else "expression_input")
                else: root(target, "opaque_result", {"reason": "No supported scalar expression"})
            if unit.invoke:
                for argument, value in enumerate(unit.invoke.arguments):
                    term_links(index, value, f"invoke.arguments[{argument}]", point(index, "argument", argument), "argument_input")
                if unit.invoke.receiver:
                    term_links(index, unit.invoke.receiver, "invoke.receiver", point(index, "receiver"), "receiver_input")
    except OverflowError as error:
        report.state, report.reason = "truncated", str(error)
        report.links, report.roots, report.operand_nodes, report.uses = [], [], [], []
        report.pending_units = list(solved["reachable"])
    return report


def _constant_value(value):
    if value.constant_kind is None: return ValueInfo(status="unknown", reason="Unsupported/opaque IR operand")
    constant = value.constant
    if value.constant_kind in {"float_bits", "double_bits"}:
        constant = {"encoding": "ieee754-bits", "bits": 32 if value.constant_kind == "float_bits" else 64, "hex": constant}
    elif value.constant_kind == "utf16_units": constant = {"encoding": "utf16-code-units", "hex": constant}
    return ValueInfo(status="known", value=constant)


def _emit_method(facts, report, entry, cfg_node_ref):
    run = facts.run.run_id
    provenance = lambda *refs: Provenance(kind="static_analysis", tool_ref="tool:local-flow", rule_ref="rule:local-flow", support_refs=list(dict.fromkeys(refs)))
    nodes = []
    for operand in report.operand_nodes:
        nodes.append(AnalysisNodeRecord(id=operand.node_ref, run_ref=run, kind="analysis_node", node_kind="state", method_ref=report.method_ref,
            position=AnalysisPosition(kind="analysis", artifact_path=entry, position_label=f"operand:{operand.unit}:{operand.role}"),
            text="IR operand " + operand.role, provenance=provenance(report.method_ref, report.node_refs[operand.unit]),
            slots=[ProgramSlot(slot_kind="value", type_descriptor=operand.value.type_descriptor if operand.value.type_descriptor != "V" else None,
                               value=_constant_value(operand.value))]))
    relations = []
    for index, value in enumerate(report.links):
        relations.append(RelationRecord(id=record_id(run, "relation", ["local-flow", report.method_ref, index]), run_ref=run,
            provenance=provenance(report.method_ref, cfg_node_ref, value.source.element_ref, value.target.element_ref),
            relation_kind="data_dependency", source=value.source, target=value.target,
            resolution=value.resolution, unresolved_reason=value.reason, source_selector=entry + f"#/links/{index}"))
    return nodes, relations


def extend_local_flow(result, config: LocalFlowConfig | None = None):
    config = config or LocalFlowConfig()
    config = LocalFlowConfig.model_validate(config.model_dump())
    facts, run = result.facts, result.facts.run.run_id
    facts.run.configuration.options["local_flow"] = config.model_dump(mode="json")
    facts.run.config_fingerprint = fingerprint(facts.run.configuration.model_dump(mode="json"))
    facts.run.tools.append(ToolVersion(tool_id="tool:local-flow", name="androserum-method-local-flow", version=__version__))
    rule_entry = "analysis/rules/local_flow.py"
    rule = Path(__file__).read_bytes(); digest = hashlib.sha256(rule).hexdigest()
    result.blobs[digest], result.entry_digests[rule_entry] = rule, digest
    facts.run.artifacts.append(VersionedArtifact(artifact_id="rule:local-flow", kind="rule", name="method-local-scalar-flow", version="1", sha256=digest, location=rule_entry))
    cfg_source = Path(__file__).resolve().parents[3] / "java/fact-backend/src/main/java/org/androserum/backend/CfgExporter.java"
    cfg_source_data = cfg_source.read_bytes(); digest = hashlib.sha256(cfg_source_data).hexdigest()
    entry = "analysis/rules/CfgExporter.java"
    result.blobs[digest], result.entry_digests[entry] = cfg_source_data, digest
    facts.run.artifacts.append(VersionedArtifact(artifact_id="rule:local-cfg-export", kind="rule", name="Soot direct exception destination export", version="1", sha256=digest, location=entry))
    elements = {record.id: record for record in facts.elements}
    groups = defaultdict(dict)
    for record in facts.elements:
        if isinstance(record, AnalysisNodeRecord) and record.node_kind == "jimple" and record.position.kind == "analysis":
            groups[(record.method_ref, record.position.artifact_path)][int(record.position.position_label.split(":")[1])] = record.id
    counts, reports, issues = Counter(), [], []
    def add_issue(method_ref, state, reason):
        issues.append(AnalysisStatus(id=record_id(run, "status", ["local-flow", method_ref, state]), run_ref=run,
            tool_ref="tool:local-flow", capability="data_flow", scope=AnalysisScope(kind="element", element_ref=method_ref),
            state=state, reason=reason, issue_code=None if state == "complete" else "local_flow_" + state))
    for (method_ref, ir_entry), node_map in sorted(groups.items(), key=lambda item: item[0][1]):
        try:
            ir_bytes = result.blobs[result.entry_digests[ir_entry]]
            method = JimpleMethod.model_validate_json(ir_bytes)
            filename = ir_entry.removeprefix("analysis/java/")
            commit_entry = "analysis/java/" + filename.replace("methods/", "cfg/").replace(".json", ".commit.json")
            cfg_commit = CFGCommit.model_validate_json(result.blobs[result.entry_digests[commit_entry]])
            request_bytes = result.blobs[result.entry_digests["analysis/java/request.json"]]
            if (cfg_commit.request_sha256 != hashlib.sha256(request_bytes).hexdigest() or cfg_commit.apk_sha256 != facts.run.apk_sha256 or
                    cfg_commit.method_path != filename or cfg_commit.method_sha256 != hashlib.sha256(ir_bytes).hexdigest() or
                    cfg_commit.signature != elements[method_ref].signature or not re.fullmatch(r"cfg/[0-9]+\.json", cfg_commit.path)):
                raise ValueError("CFG commit identity disagrees with this method/request")
            cfg_entry = "analysis/java/" + cfg_commit.path
            cfg_bytes = result.blobs[result.entry_digests[cfg_entry]]
            if hashlib.sha256(cfg_bytes).hexdigest() != cfg_commit.sha256: raise ValueError("CFG checksum mismatch")
            cfg = MethodCFG.model_validate_json(cfg_bytes)
            if cfg.method_sha256 != cfg_commit.method_sha256: raise ValueError("CFG belongs to another IR artifact")
            report = analyze_method(method, cfg, run_ref=run, method_ref=method_ref, node_refs=[node_map[i] for i in range(len(method.units))],
                ir_entry=ir_entry, ir_sha256=cfg.method_sha256, cfg_entry=cfg_entry, cfg_sha256=cfg_commit.sha256, config=config)
            entry = "analysis/local-flow/" + fingerprint(method_ref)[:32] + ".json"
            data = canonical_json(report.model_dump(mode="json")).encode("utf-8"); digest = hashlib.sha256(data).hexdigest()
            result.blobs[digest], result.entry_digests[entry] = data, digest
            cfg_id = record_id(run, "analysis", [method_ref, "local-cfg"])
            facts.elements.append(AnalysisNodeRecord(id=cfg_id, run_ref=run, kind="analysis_node", node_kind="cfg", method_ref=method_ref,
                position=AnalysisPosition(kind="analysis", artifact_path=entry, position_label="cfg"),
                text="Method-local scalar CFG and reaching definitions; exceptions use pre-state", provenance=Provenance(kind="static_analysis",
                    tool_ref="tool:local-flow", rule_ref="rule:local-flow", support_refs=[method_ref, *report.node_refs])))
            nodes, relations = _emit_method(facts, report, entry, cfg_id)
            facts.elements.extend(nodes); facts.relations.extend(relations)
            counts[report.state] += 1
            counts["data_links"] += len(report.links)
            reports.append({"method_ref": method_ref, "signature": method.signature, "entry": entry, "state": report.state})
            add_issue(method_ref, report.state, "F4-A method scalar locals only; callee/heap/path feasibility remain unresolved" if report.state == "complete" else report.reason)
        except (KeyError, ValueError) as error:
            counts["unavailable"] += 1
            add_issue(method_ref, "unavailable", str(error))
    scope = next(value for value in facts.statuses if value.capability == "data_flow" and value.scope.kind == "run")
    scope.tool_ref, scope.state = "tool:local-flow", "partial" if reports else "unavailable"
    scope.reason = "Only F4-A method-local scalar dependencies implemented; F4-B/C and object/control/event analyses remain incomplete"
    facts.statuses.extend(issues)
    summary = {"schema_version": "local-flow-run.v1", "scope": "F4-A", "configuration": config.model_dump(mode="json"), "counts": dict(counts),
               "methods": reports, "not_implemented": ["cross_method_bindings", "heap_alias_dependence", "FlowDroid_selected_flows", "control_dependence", "events"]}
    data = canonical_json(summary).encode("utf-8"); digest = hashlib.sha256(data).hexdigest()
    result.blobs[digest], result.entry_digests["analysis/local-flow/run.json"] = data, digest
    result.facts = loads_facts(facts.model_dump_json())
    verify_local_flow_evidence(result.facts, lambda entry: result.blobs[result.entry_digests[entry]])
    previous_outcome = result.summary["outcome"]
    result.summary.update(stage="F4-A", local_flow=summary, outcome="failed" if previous_outcome == "failed" else "partial",
        element_counts=dict(Counter(record.kind for record in facts.elements)), relation_counts=dict(Counter(value.relation_kind for value in facts.relations)),
        coverage={value.capability: value.state for value in facts.statuses if value.scope.kind == "run"})
    return result


def extract_local(apk, *, java_config=None, config=None):
    java_config = (java_config or JavaConfig()).model_copy(update={"export_cfg": True})
    return extend_local_flow(extract_java(apk, config=java_config), config)


def verify_local_flow_evidence(facts, read_entry):
    elements = {record.id: record for record in facts.elements}
    expected_relations, expected_operands = {}, {}
    for node in facts.elements:
        if not isinstance(node, AnalysisNodeRecord) or node.node_kind != "cfg" or node.position.kind != "analysis" or not node.position.artifact_path.startswith("analysis/local-flow/"):
            continue
        entry = node.position.artifact_path
        data = read_entry(entry); strict_json_syntax(data.decode("utf-8"))
        report = MethodFlow.model_validate_json(data)
        if (report.method_ref != node.method_ref or node.id != record_id(facts.run.run_id, "analysis", [report.method_ref, "local-cfg"]) or
                node.position.position_label != "cfg" or node.provenance.tool_ref != "tool:local-flow" or node.provenance.rule_ref != "rule:local-flow" or
                not {report.method_ref, *report.node_refs}.issubset(node.provenance.support_refs)):
            raise ValueError("Local-flow method/CFG identity mismatch")
        method_data, cfg_data = read_entry(report.ir_entry), read_entry(report.cfg_entry)
        if hashlib.sha256(method_data).hexdigest() != report.ir_sha256 or hashlib.sha256(cfg_data).hexdigest() != report.cfg_sha256:
            raise ValueError("Local-flow input artifact hash mismatch")
        method = JimpleMethod.model_validate_json(method_data); cfg = MethodCFG.model_validate_json(cfg_data)
        if cfg.method_sha256 != report.ir_sha256: raise ValueError("CFG does not bind its IR artifact")
        commit = CFGCommit.model_validate_json(read_entry(report.cfg_entry.replace(".json", ".commit.json")))
        request_data = read_entry("analysis/java/request.json")
        strict_json_syntax(request_data.decode("utf-8")); request = json.loads(request_data)
        if (request.get("export_cfg") is not True or request.get("run_ref") != facts.run.run_id or request.get("apk_sha256") != facts.run.apk_sha256 or
                commit.request_sha256 != hashlib.sha256(request_data).hexdigest() or commit.apk_sha256 != facts.run.apk_sha256 or
                commit.path != report.cfg_entry.removeprefix("analysis/java/") or commit.sha256 != report.cfg_sha256 or
                commit.method_path != report.ir_entry.removeprefix("analysis/java/") or commit.method_sha256 != report.ir_sha256 or
                commit.signature != report.method_signature):
            raise ValueError("Local CFG lacks a method/request-bound complete commit")
        for i, ref in enumerate(report.node_refs):
            unit = elements.get(ref)
            if (not isinstance(unit, AnalysisNodeRecord) or unit.node_kind != "jimple" or unit.method_ref != node.method_ref or
                    unit.position.kind != "analysis" or unit.position.artifact_path != report.ir_entry or unit.position.position_label != f"unit:{i}"):
                raise ValueError("Local flow crosses method/IR positions")
        expected = analyze_method(method, cfg, run_ref=facts.run.run_id, method_ref=report.method_ref, node_refs=report.node_refs,
            ir_entry=report.ir_entry, ir_sha256=report.ir_sha256, cfg_entry=report.cfg_entry, cfg_sha256=report.cfg_sha256, config=report.configuration)
        if expected != report: raise ValueError("Local-flow definitions/links disagree with CFG and structured IR")
        operands, relations = _emit_method(facts, report, entry, node.id)
        expected_operands.update({value.id: value for value in operands}); expected_relations.update({value.id: value for value in relations})
    actual_relations = {value.id: value for value in facts.relations if value.provenance.tool_ref == "tool:local-flow" or
                        value.provenance.rule_ref == "rule:local-flow" or (value.source_selector and value.source_selector.startswith("analysis/local-flow/"))}
    if actual_relations != expected_relations: raise ValueError("Local dependency relations are missing, forged, or semantically altered")
    for ref, value in expected_operands.items():
        if elements.get(ref) != value: raise ValueError("Scalar operand fact disagrees with structured IR")
    return {"relations": len(expected_relations), "operands": len(expected_operands)}
