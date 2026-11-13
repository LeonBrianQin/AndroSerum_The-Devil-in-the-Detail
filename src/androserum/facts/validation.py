"""Cross-record integrity checks; this does not prove analysis or path semantics."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterator

from pydantic import BaseModel, Field

from androserum.facts.identity import parse_method_signature
from androserum.facts.models import (
    AnalysisNodeRecord, AnalysisPosition, AnalysisStatus, ArchivePosition, BindingRecord,
    ClassRecord, ConditionRecord, ConfigurationRecord, ContextRecord, DexDeclarationPosition,
    DexRecord, Endpoint, FactBundle, FieldRecord, InstructionPosition, InstructionRecord,
    MethodRecord, ModelPosition, ParameterRecord, Provenance, Record, RelationRecord,
    ResourceRecord, StrictModel, ToolVersion, TypeReferenceRecord, ValueInfo, VersionedArtifact,
)

ELEMENT_TYPES = (DexRecord, ClassRecord, TypeReferenceRecord, MethodRecord, ParameterRecord, FieldRecord,
                 InstructionRecord, ConfigurationRecord, ResourceRecord, AnalysisNodeRecord, ConditionRecord)
DATA_RELATIONS = {"data_dependency", "argument_to_parameter", "return_to_result", "field_dependency",
                  "array_dependency", "state_dependency", "icc_data", "information_flow"}
VALUE_SLOTS = {"receiver", "argument", "result", "parameter", "return", "value", "local", "field", "array_element", "state", "condition"}


class CheckIssue(StrictModel):
    code: str
    path: str
    message: str


class CheckReport(StrictModel):
    schema_version: str = "fact-check.v1"
    valid: bool
    errors: list[CheckIssue] = Field(default_factory=list)
    checked: list[str] = Field(default_factory=lambda: [
        "schema_and_field_constraints", "unique_ids_and_program_positions", "reference_existence_and_run_ownership",
        "provenance_and_versioned_basis", "endpoint_slots_and_parameter_indices", "basic_relation_kinds_and_call_bindings",
        "explicit_analysis_statuses",
    ])
    unchecked: list[str] = Field(default_factory=lambda: [
        "truth_or_completeness_of_extracted_program_content", "correctness_of_static_analysis",
        "multi_edge_path_context_object_and_branch_compatibility", "natural_language_behavior_semantics",
    ])


def walk_models(value: Any, path: str) -> Iterator[tuple[BaseModel, str]]:
    if isinstance(value, BaseModel):
        yield value, path
        for field in type(value).model_fields:
            yield from walk_models(getattr(value, field), f"{path}.{field}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_models(item, f"{path}[{index}]")


def slot_key(value: Any) -> tuple:
    return value.slot_kind, value.slot_index, value.slot_label


class _Checker:
    def __init__(self, facts: FactBundle):
        self.facts = facts
        self.errors: list[CheckIssue] = []
        self.index: dict[str, tuple[Any, str]] = {}
        self.records: list[tuple[Any, str]] = []

    def error(self, code: str, path: str, message: str) -> None:
        self.errors.append(CheckIssue(code=code, path=path, message=message))

    def add(self, identifier: str, record: Any, path: str) -> None:
        if identifier in self.index:
            self.error("duplicate_id", path, f"ID {identifier} already occurs at {self.index[identifier][1]}")
        else:
            self.index[identifier] = record, path

    def ref(self, identifier: str | None, path: str, expected: tuple[type, ...]) -> Any:
        if identifier is None:
            return None
        item = self.index.get(identifier)
        if item is None:
            self.error("dangling_reference", path, f"Reference {identifier} is absent from this bundle")
            return None
        record = item[0]
        if not isinstance(record, expected):
            self.error("reference_kind", path, f"Reference {identifier} has an incompatible record kind")
            return None
        return record

    def run(self) -> CheckReport:
        self.add(self.facts.run.run_id, self.facts.run, "run.run_id")
        for index, tool in enumerate(self.facts.run.tools):
            self.add(tool.tool_id, tool, f"run.tools[{index}].tool_id")
        for index, artifact in enumerate(self.facts.run.artifacts):
            self.add(artifact.artifact_id, artifact, f"run.artifacts[{index}].artifact_id")
        for section in ("elements", "relations", "contexts", "bindings", "statuses"):
            for index, record in enumerate(getattr(self.facts, section)):
                path = f"{section}[{index}]"
                self.records.append((record, path))
                self.add(record.id, record, path + ".id")
                if record.run_ref != self.facts.run.run_id:
                    self.error("cross_run_record", path + ".run_ref", "Every record must belong to this bundle's run/APK")
        self.nested_references()
        self.elements()
        self.contexts_and_bindings()
        self.relations()
        self.statuses()
        return CheckReport(valid=not self.errors, errors=self.errors)

    def nested_references(self) -> None:
        for record, path in self.records:
            for value, nested in walk_models(record, path):
                if isinstance(value, Provenance):
                    self.ref(value.tool_ref, nested + ".tool_ref", (ToolVersion,))
                    self.ref(value.rule_ref, nested + ".rule_ref", (VersionedArtifact,))
                    for index, support in enumerate(value.support_refs):
                        self.ref(support, f"{nested}.support_refs[{index}]", (Record,))
                        if support == record.id:
                            self.error("self_support", nested + ".support_refs", "A record cannot support itself")
                elif isinstance(value, ValueInfo):
                    for index, source in enumerate(value.source_refs):
                        self.ref(source, f"{nested}.source_refs[{index}]", (Record,))
                elif isinstance(value, (DexDeclarationPosition, InstructionPosition)):
                    self.ref(value.dex_ref, nested + ".dex_ref", (DexRecord,))
                    if isinstance(value, InstructionPosition):
                        self.ref(value.method_ref, nested + ".method_ref", (MethodRecord,))
                elif isinstance(value, ModelPosition):
                    self.ref(value.model_ref, nested + ".model_ref", (VersionedArtifact,))
                elif isinstance(value, Endpoint):
                    self.endpoint(value, nested)
            if isinstance(record, Record):
                direct = isinstance(record, (DexRecord, ClassRecord, TypeReferenceRecord, MethodRecord, ParameterRecord,
                                            FieldRecord, InstructionRecord, ConfigurationRecord, ResourceRecord))
                if direct and record.provenance.kind != "direct":
                    self.error("provenance_kind", path + ".provenance.kind", "Direct program records require direct provenance")
                if isinstance(record, (AnalysisNodeRecord, ConditionRecord, ContextRecord, BindingRecord)) and record.provenance.kind == "direct":
                    self.error("provenance_kind", path + ".provenance.kind", "Analysis/model records must distinguish their derived provenance")
                if isinstance(record, AnalysisNodeRecord) and isinstance(record.position, ModelPosition):
                    if record.provenance.kind != "model_assisted" or record.provenance.rule_ref != record.position.model_ref:
                        self.error("model_basis", path, "Model nodes must reference the same versioned basis in position and provenance")

    def endpoint(self, endpoint: Endpoint, path: str) -> Any:
        element = self.ref(endpoint.element_ref, path + ".element_ref", ELEMENT_TYPES)
        if element is None:
            return None
        position = getattr(element, "position", None)
        expected_label = getattr(position, "position_label", None)
        needs_label = isinstance(element, (InstructionRecord, AnalysisNodeRecord))
        if (needs_label or endpoint.position_label is not None) and endpoint.position_label != expected_label:
            self.error("endpoint_position", path + ".position_label", "Endpoint label must match the referenced program/analysis position")
        kind = endpoint.slot_kind
        if kind == "element":
            return element
        if isinstance(element, MethodRecord):
            _, _, parameters, result = parse_method_signature(element.signature)
            if kind == "parameter":
                if endpoint.slot_index >= len(parameters):
                    self.error("parameter_index", path, "Parameter index exceeds the method's declared parameter list")
            elif kind == "receiver":
                if element.is_static is not False:
                    self.error("receiver_slot", path, "A receiver requires a method known to be non-static")
            elif kind == "return":
                if result == "V":
                    self.error("void_result", path, "Void methods have no return value endpoint")
            elif kind != "entry":
                self.error("endpoint_slot", path, "This slot is not available on a method")
        elif isinstance(element, ParameterRecord):
            if kind != "value":
                self.error("endpoint_slot", path, "A parameter record exposes its value slot; indexed parameters use the method endpoint")
        elif isinstance(element, (ConfigurationRecord, ResourceRecord)):
            if kind != "value":
                self.error("endpoint_slot", path, "Configuration/resources expose value endpoints")
        elif isinstance(element, FieldRecord):
            if kind != "value":
                self.error("endpoint_slot", path, "Field declarations expose value endpoints")
        elif isinstance(element, ConditionRecord):
            if kind not in {"value", "condition"}:
                self.error("endpoint_slot", path, "Conditions expose condition/value endpoints")
        elif isinstance(element, (InstructionRecord, AnalysisNodeRecord)):
            if kind == "entry" and isinstance(element, AnalysisNodeRecord) and element.node_kind == "entry":
                return element
            if slot_key(endpoint) not in {slot_key(slot) for slot in element.slots}:
                self.error("endpoint_slot", path, "Endpoint must select an explicitly recorded operation slot")
        else:
            self.error("endpoint_slot", path, "This element has no value/operation slot of the requested kind")
        return element

    def elements(self) -> None:
        seen: dict[tuple, str] = {}
        for element, path in self.records:
            if not isinstance(element, ELEMENT_TYPES):
                continue
            key = None
            if isinstance(element, DexRecord):
                key = ("dex", element.position.path)
            elif isinstance(element, (ClassRecord, TypeReferenceRecord, MethodRecord, FieldRecord)):
                table = {ClassRecord: "class_def", TypeReferenceRecord: "type_id", MethodRecord: "method_id", FieldRecord: "field_id"}[type(element)]
                if element.position.table != table:
                    self.error("dex_table", path + ".position.table", f"Expected {table}")
                key = (element.kind, element.position.dex_ref, element.position.index)
                if isinstance(element, (MethodRecord, FieldRecord)):
                    klass = self.ref(element.class_ref, path + ".class_ref", (ClassRecord,))
                    if element.is_definition and klass is None and element.class_ref is None:
                        self.error("missing_owner", path + ".class_ref", "Definitions require an owning class")
                    owner = element.signature.partition("->")[0]
                    if klass is not None and (klass.descriptor != owner or (element.is_definition and klass.position.dex_ref != element.position.dex_ref)):
                        self.error("method_field_owner", path + ".class_ref", "Declaring class/DEX disagrees with the definition")
            elif isinstance(element, ParameterRecord):
                key = ("parameter", element.method_ref, element.index)
                method = self.ref(element.method_ref, path + ".method_ref", (MethodRecord,))
                if method is not None:
                    parameters = parse_method_signature(method.signature)[2]
                    if element.index >= len(parameters):
                        self.error("parameter_index", path + ".index", "Parameter index is outside the declared signature")
                    elif element.type_descriptor != parameters[element.index]:
                        self.error("parameter_type", path + ".type_descriptor", "Parameter type disagrees with the declared signature")
            elif isinstance(element, InstructionRecord):
                key = ("instruction", element.position.method_ref, element.position.offset_bytes)
                method = self.ref(element.position.method_ref, path + ".position.method_ref", (MethodRecord,))
                if method is not None:
                    if method.position.dex_ref != element.position.dex_ref:
                        self.error("instruction_dex", path + ".position.dex_ref", "Instruction and owning method must have the same DEX")
                    if method.body_status != "available":
                        self.error("method_body", path, "Instructions require an available owning method body")
                target = element.declared_target
                if target is not None and target.method_ref is not None:
                    method_target = self.ref(target.method_ref, path + ".declared_target.method_ref", (MethodRecord,))
                    if method_target is not None and method_target.signature != target.signature:
                        self.error("declared_target", path + ".declared_target", "Declared method reference and signature disagree")
                    if (method_target is not None and method_target.is_static is not None
                            and element.invoke_kind not in {"custom", "polymorphic"}
                            and method_target.is_static != (element.invoke_kind == "static")):
                        self.error("invocation_staticness", path + ".invoke_kind", "Invocation kind disagrees with the target's known staticness")
                operand_indices = [operand.index for operand in element.operands]
                receiver = self.ref(element.result_receiver_ref, path + ".result_receiver_ref", (InstructionRecord,))
                if receiver is not None and (not receiver.opcode.startswith("move-result") or
                        receiver.position.method_ref != element.position.method_ref or
                        element.length_bytes is None or receiver.position.offset_bytes != element.position.offset_bytes + element.length_bytes):
                    self.error("result_receiver", path + ".result_receiver_ref", "Result receiver must be the next move-result in this method")
                if len(set(operand_indices)) != len(operand_indices):
                    self.error("duplicate_operand", path + ".operands", "Operand indices must be unique within an instruction")
                for index, operand in enumerate(element.operands):
                    if operand.reference_ref is not None:
                        expected = {"method": (MethodRecord,), "field": (FieldRecord,), "resource": (ResourceRecord,)}.get(operand.kind, ELEMENT_TYPES)
                        referenced = self.ref(operand.reference_ref, f"{path}.operands[{index}].reference_ref", expected)
                        if referenced is not None and operand.kind in {"method", "field"} and operand.value.status == "known":
                            if operand.value.value != referenced.signature:
                                self.error("operand_reference", f"{path}.operands[{index}]", "Encoded reference disagrees with the referenced signature")
            elif isinstance(element, AnalysisNodeRecord):
                self.ref(element.method_ref, path + ".method_ref", (MethodRecord,))
            elif isinstance(element, ConditionRecord):
                branch = self.ref(element.branch_ref, path + ".branch_ref", (InstructionRecord, AnalysisNodeRecord))
                if isinstance(branch, InstructionRecord) and branch.operation != "branch":
                    self.error("condition_branch", path + ".branch_ref", "Condition must reference an actual branch operation")
            if key is not None:
                if key in seen:
                    self.error("duplicate_position", path, f"Program identity already recorded at {seen[key]}")
                else:
                    seen[key] = path
            if isinstance(element, (ClassRecord, MethodRecord, FieldRecord)):
                identity = element.descriptor if isinstance(element, ClassRecord) else element.signature
                identity_key = ("declaration", element.kind, element.position.dex_ref, identity)
                if identity_key in seen:
                    self.error("duplicate_program_identity", path, f"DEX declaration already recorded at {seen[identity_key]}")
                else:
                    seen[identity_key] = path
            if isinstance(element, (InstructionRecord, AnalysisNodeRecord)):
                keys = [slot_key(slot) for slot in element.slots]
                if len(set(keys)) != len(keys):
                    self.error("duplicate_slot", path + ".slots", "An operation cannot declare the same slot twice")

    def contexts_and_bindings(self) -> None:
        checked_contexts: set[str] = set()
        for record, path in self.records:
            if isinstance(record, ContextRecord):
                self.ref(record.parent_ref, path + ".parent_ref", (ContextRecord,))
                for index, callsite in enumerate(record.callsite_refs):
                    call = self.ref(callsite, f"{path}.callsite_refs[{index}]", (InstructionRecord,))
                    if call is not None and call.operation != "invoke":
                        self.error("context_callsite", path, "Call contexts must refer to invocation instructions")
                for index, issue in enumerate(record.issue_refs):
                    self.ref(issue, f"{path}.issue_refs[{index}]", (AnalysisStatus,))
                if record.truncated and not record.issue_refs:
                    self.error("context_truncation", path, "A truncated context requires an explicit analysis-status reference")
                if record.truncated and record.issue_refs:
                    issues = [self.index.get(ref, (None,))[0] for ref in record.issue_refs]
                    if not any(isinstance(issue, AnalysisStatus) and issue.state == "truncated" for issue in issues):
                        self.error("context_truncation", path, "A truncated context requires a status explicitly marked truncated")
                visited = {record.id}
                parent = record.parent_ref
                while parent in self.index and parent not in checked_contexts:
                    if parent in visited:
                        self.error("context_cycle", path + ".parent_ref", "Context parent links must be acyclic")
                        break
                    visited.add(parent)
                    ancestor = self.index[parent][0]
                    parent = ancestor.parent_ref if isinstance(ancestor, ContextRecord) else None
                checked_contexts.update(visited)
            elif isinstance(record, BindingRecord):
                self.ref(record.context_ref, path + ".context_ref", (ContextRecord,))
                for index, condition in enumerate(record.condition_refs):
                    self.ref(condition, f"{path}.condition_refs[{index}]", (ConditionRecord,))
                endpoints = [tuple(endpoint.model_dump().values()) for endpoint in record.endpoints]
                if len(set(endpoints)) != len(endpoints):
                    self.error("duplicate_binding_endpoint", path + ".endpoints", "Bindings must connect distinct endpoints")

    def relations(self) -> None:
        candidates = {
            (edge.source.element_ref, edge.target.element_ref, edge.context_ref)
            for edge in self.facts.relations if edge.relation_kind == "candidate_call" and edge.target is not None
        }
        for relation, path in self.records:
            if not isinstance(relation, RelationRecord):
                continue
            source = self.index.get(relation.source.element_ref, (None,))[0]
            target = self.index.get(relation.target.element_ref, (None,))[0] if relation.target else None
            context = self.ref(relation.context_ref, path + ".context_ref", (ContextRecord,))
            callsite = self.ref(relation.callsite_ref, path + ".callsite_ref", (InstructionRecord,))
            if callsite is not None and callsite.operation != "invoke":
                self.error("callsite_kind", path + ".callsite_ref", "Callsite references must select an invocation")
            for index, condition in enumerate(relation.condition_refs):
                self.ref(condition, f"{path}.condition_refs[{index}]", (ConditionRecord,))
            for index, binding_ref in enumerate(relation.binding_refs):
                binding = self.ref(binding_ref, f"{path}.binding_refs[{index}]", (BindingRecord,))
                if binding is not None:
                    if binding.context_ref is not None and binding.context_ref != relation.context_ref:
                        self.error("binding_context", path + ".binding_refs", "A relation must retain the binding's call context")
                    if not set(binding.condition_refs).issubset(relation.condition_refs):
                        self.error("binding_conditions", path + ".condition_refs", "A relation must retain the binding's conditions")
                    if binding.binding_kind == "value" and relation.relation_kind in {"argument_to_parameter", "return_to_result"}:
                        keys = {tuple(endpoint.model_dump().values()) for endpoint in binding.endpoints}
                        required = [relation.source] + ([relation.target] if relation.target else [])
                        if any(tuple(endpoint.model_dump().values()) not in keys for endpoint in required):
                            self.error("binding_endpoints", path + ".binding_refs", "Call value bindings must retain the declared mapping endpoints")
            kind = relation.relation_kind
            if kind in DATA_RELATIONS:
                if relation.source.slot_kind not in VALUE_SLOTS or (relation.target is not None and relation.target.slot_kind not in VALUE_SLOTS):
                    self.error("data_endpoint_kind", path, "Data relations require value endpoints, not whole elements or entries")
                if relation.provenance.kind == "direct":
                    self.error("data_provenance", path + ".provenance", "Data dependencies must identify their analysis/model producer")
            if kind in {"declared_call", "candidate_call"}:
                if not isinstance(source, InstructionRecord) or source.operation != "invoke" or relation.source.slot_kind != "element":
                    self.error("call_relation_source", path + ".source", "Call edges start at an invocation instruction")
                if relation.target is not None and (not isinstance(target, MethodRecord) or relation.target.slot_kind != "entry"):
                    self.error("call_relation_target", path + ".target", "Call edges end at method entries")
                if kind == "declared_call" and isinstance(source, InstructionRecord) and isinstance(target, MethodRecord):
                    if source.declared_target is None or source.declared_target.signature != target.signature:
                        self.error("declared_call_signature", path, "Declared call edge disagrees with its encoded method signature")
                if kind == "candidate_call" and relation.provenance.kind == "direct":
                    self.error("candidate_provenance", path, "Candidate targets must identify their analysis/model basis")
            elif kind in {"argument_to_parameter", "return_to_result"}:
                if context is not None and callsite is not None and (not context.callsite_refs or context.callsite_refs[-1] != callsite.id):
                    self.error("call_context", path + ".context_ref", "Context must end at this exact callsite")
                if kind == "argument_to_parameter":
                    if relation.source.slot_kind != "argument" or relation.source.element_ref != relation.callsite_ref:
                        self.error("argument_binding", path + ".source", "Argument mapping starts at this callsite's argument")
                    if relation.target is not None and (not isinstance(target, MethodRecord) or relation.target.slot_kind != "parameter"):
                        self.error("argument_binding", path + ".target", "Argument mapping ends at a method parameter")
                    if relation.target is not None and relation.source.slot_index != relation.target.slot_index:
                        self.error("argument_binding", path, "Argument and formal parameter ordinals must agree")
                else:
                    if not isinstance(source, MethodRecord) or relation.source.slot_kind != "return":
                        self.error("return_binding", path + ".source", "Return mapping starts at a method return value")
                    if relation.target is not None and (relation.target.slot_kind != "result" or relation.target.element_ref != relation.callsite_ref):
                        self.error("return_binding", path + ".target", "Return mapping ends at this callsite's result")
                callee = target if kind == "argument_to_parameter" else source
                if callsite is not None and isinstance(callee, MethodRecord):
                    declared = callsite.declared_target.signature if callsite.declared_target else None
                    candidate_key = (callsite.id, callee.id, relation.context_ref)
                    if declared != callee.signature and candidate_key not in candidates:
                        self.error("call_binding_target", path, "Callee must be the declared target or a recorded candidate in this context")
            elif kind == "control_dependency":
                branch_ok = isinstance(source, InstructionRecord) and source.operation == "branch"
                branch_ok |= isinstance(source, AnalysisNodeRecord) and source.node_kind in {"cfg", "jimple"}
                if not branch_ok or relation.source.slot_kind not in {"element", "condition"}:
                    self.error("control_relation_source", path, "Control dependencies require a branch/CFG source")
                if relation.target is not None and (not isinstance(target, (InstructionRecord, AnalysisNodeRecord)) or relation.target.slot_kind != "element"):
                    self.error("control_relation_target", path, "Control dependencies constrain operation records")
            elif kind == "dex_jimple_mapping":
                if (not isinstance(source, InstructionRecord) or relation.source.slot_kind != "element"
                        or (relation.target is not None and (not isinstance(target, AnalysisNodeRecord) or relation.target.slot_kind != "element"))):
                    self.error("mapping_endpoints", path, "DEX/Jimple mappings connect instructions to analysis nodes")
                if isinstance(source, InstructionRecord) and isinstance(target, AnalysisNodeRecord):
                    if target.node_kind != "jimple" or target.method_ref != source.position.method_ref:
                        self.error("mapping_method", path, "DEX/Jimple mappings must retain the same owning method")
            elif kind == "event_trigger":
                source_ok = (isinstance(source, ConfigurationRecord) and source.configuration_kind in {"component", "intent_filter"}) or (
                    isinstance(source, InstructionRecord) and source.operation == "invoke") or (
                    isinstance(source, AnalysisNodeRecord) and source.node_kind in {"entry", "event"})
                target_ok = isinstance(target, MethodRecord) and relation.target.slot_kind == "entry" if relation.target else True
                target_ok |= isinstance(target, AnalysisNodeRecord) and target.node_kind in {"entry", "event"}
                if not source_ok or not target_ok or relation.provenance.rule_ref is None or relation.provenance.kind == "direct":
                    self.error("event_endpoints", path, "Events require configuration/model sources, entry targets and a versioned model basis")
            elif kind == "icc_target":
                source_ok = isinstance(source, InstructionRecord) and source.operation == "invoke"
                source_ok |= isinstance(source, AnalysisNodeRecord) and source.node_kind == "event"
                target_ok = target is None or (isinstance(target, ConfigurationRecord) and target.configuration_kind == "component") or (
                    isinstance(target, AnalysisNodeRecord) and target.node_kind in {"entry", "event"})
                if not source_ok or not target_ok:
                    self.error("icc_endpoints", path, "ICC target links connect send operations to component/model targets")
            elif kind == "resource_use":
                if not isinstance(source, ResourceRecord) or (target is not None and not isinstance(target, (InstructionRecord, AnalysisNodeRecord))):
                    self.error("resource_endpoints", path, "Resource-use links connect resource records to operations")
            elif kind == "reference_resolution":
                same = isinstance(source, MethodRecord) and isinstance(target, MethodRecord) and source.signature == target.signature
                same |= isinstance(source, FieldRecord) and isinstance(target, FieldRecord) and source.signature == target.signature
                same |= isinstance(source, TypeReferenceRecord) and isinstance(target, ClassRecord) and source.descriptor == target.descriptor
                if not same or relation.provenance.kind == "direct":
                    self.error("reference_resolution", path, "Reference resolution needs matching declarations and an explicit analysis basis")
            elif kind == "call_result_assignment":
                if not isinstance(source, InstructionRecord) or source.result_receiver_ref != getattr(target, "id", None):
                    self.error("call_result_assignment", path, "Result assignment must reference the recorded move-result receiver")
            elif kind == "resource_reference":
                if not isinstance(source, (ConfigurationRecord, ResourceRecord, FieldRecord)) or not isinstance(target, ResourceRecord):
                    self.error("resource_reference", path, "Resource references require a configuration/resource/field source and a resource target")

    def statuses(self) -> None:
        run_statuses: Counter = Counter()
        for status, path in self.records:
            if not isinstance(status, AnalysisStatus):
                continue
            self.ref(status.tool_ref, path + ".tool_ref", (ToolVersion,))
            self.ref(status.scope.element_ref, path + ".scope.element_ref", (Record,))
            if status.scope.kind == "run":
                run_statuses[status.capability] += 1
        for capability in self.facts.run.configuration.requested_capabilities:
            if run_statuses[capability] != 1:
                self.error("capability_status", "statuses", f"Expected exactly one run-scope status for requested capability {capability}")


def check_facts(facts: FactBundle) -> CheckReport:
    """Check references and declared structure after schema validation."""
    return _Checker(facts).run()
