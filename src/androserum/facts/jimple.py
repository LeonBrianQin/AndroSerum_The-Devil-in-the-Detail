"""Versioned structured IR artifacts linked by existing program-facts.v2 analysis positions."""

from typing import Literal

from pydantic import Field, JsonValue, model_validator

from androserum.facts.models import AnyTypeDescriptor, ArchivePath, FieldSignature, MethodSignature, NonNegative, SHA256, StrictModel, TypeDescriptor


class BackendStart(StrictModel):
    schema_version: Literal["jimple-run.v1"]
    request_sha256: SHA256
    apk_sha256: SHA256
    android_jar_sha256: SHA256
    java_version: str
    soot_version: Literal["4.7.1"]


class MethodCommit(StrictModel):
    schema_version: Literal["jimple-commit.v1"]
    request_sha256: SHA256
    apk_sha256: SHA256
    path: ArchivePath
    sha256: SHA256
    signature: MethodSignature


class BackendEnd(StrictModel):
    schema_version: Literal["jimple-end.v1"]
    request_sha256: SHA256
    apk_sha256: SHA256
    state: Literal["complete", "partial", "failed"]
    reason: str | None
    commits: list[ArchivePath]
    method_budget_exhausted: bool
    phantom_classes: list[str]


class IRValue(StrictModel):
    kind: str
    type_descriptor: AnyTypeDescriptor | None
    text: str
    local_index: NonNegative | None
    parameter_index: NonNegative | None = None
    identity_kind: Literal["this", "parameter", "caught_exception"] | None = None
    base: "IRValue | None" = None
    index_value: "IRValue | None" = None
    constant_kind: Literal["int", "long", "float_bits", "double_bits", "string", "utf16_units", "null", "class"] | None
    constant: JsonValue
    field_signature: FieldSignature | None
    children: list["IRValue"]
    truncated: bool

    @model_validator(mode="after")
    def constant_encoding(self):
        import re
        if self.constant_kind in {"int", "long"} and type(self.constant) is not int:
            raise ValueError("Integer IR constants must retain integer precision")
        if self.constant_kind in {"float_bits", "double_bits"}:
            width = 8 if self.constant_kind == "float_bits" else 16
            if not isinstance(self.constant, str) or not re.fullmatch("[0-9a-f]{" + str(width) + "}", self.constant):
                raise ValueError("Floating constants require exact IEEE bit strings")
        if self.constant_kind in {None, "null"} and self.constant is not None:
            raise ValueError("Nonconstant/null values cannot carry a constant payload")
        return self


class IRLocal(StrictModel):
    index: NonNegative
    name: str
    type_descriptor: TypeDescriptor | None


class IRInvoke(StrictModel):
    signature: MethodSignature
    kind: Literal["static", "interface", "special", "dynamic", "virtual"]
    arguments: list[IRValue]
    receiver: IRValue | None
    phantom_owner: bool


class IRUnit(StrictModel):
    index: NonNegative
    text: str
    operation: Literal["identity", "invoke", "return", "branch", "field_write", "field_read", "array_write", "array_read",
                       "allocation", "constant", "assignment", "throw", "monitor", "nop", "other"]
    definitions: list[IRValue]
    uses: list[IRValue]
    invoke: IRInvoke | None
    targets: list[NonNegative]
    switch_keys: list[int]
    condition: IRValue | None
    falls_through: bool
    branches: bool
    left: IRValue | None
    right: IRValue | None
    offsets_code_units: list[int]
    tag_names: list[str]
    line_number: int


class IRTrap(StrictModel):
    exception_type: TypeDescriptor
    begin: NonNegative
    end: NonNegative
    handler: NonNegative


class JimpleMethod(StrictModel):
    schema_version: Literal["jimple-method.v1"] = "jimple-method.v1"
    signature: MethodSignature
    soot_signature: str
    modifiers: NonNegative
    state: Literal["complete", "abstract", "native", "unavailable", "truncated", "failed"]
    reason: str | None
    declared_unit_count: NonNegative
    locals: list[IRLocal]
    units: list[IRUnit]
    traps: list[IRTrap]

    @model_validator(mode="after")
    def references_and_budget(self):
        if [unit.index for unit in self.units] != list(range(len(self.units))):
            raise ValueError("IR unit indexes must be contiguous")
        if [local.index for local in self.locals] != list(range(len(self.locals))):
            raise ValueError("IR local indexes must be contiguous")
        if self.state == "complete" and len(self.units) != self.declared_unit_count:
            raise ValueError("Complete method unit count does not match declaration")
        if self.state != "complete" and (self.units or self.locals or self.traps):
            raise ValueError("Incomplete methods cannot masquerade as complete IR bodies")
        for unit in self.units:
            if any(target >= len(self.units) for target in unit.targets):
                raise ValueError("IR branch target is outside this method")
        for trap in self.traps:
            if max(trap.begin, trap.end, trap.handler) >= len(self.units) or trap.begin > trap.end:
                raise ValueError("Invalid IR exception range")
        def walk(value):
            if isinstance(value, IRValue) and value.local_index is not None and value.local_index >= len(self.locals):
                raise ValueError("IR value refers to an absent local")
            if isinstance(value, StrictModel):
                for name in type(value).model_fields:
                    walk(getattr(value, name))
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        for unit in self.units:
            walk(unit)
        return self


def compatible_origin(instruction, unit):
    """Offset tags are origin candidates, checked against operation/signature evidence."""
    if unit.operation == "identity":
        return unit.right is not None and unit.right.identity_kind == "caught_exception" and instruction.opcode == "move-exception"
    if unit.invoke is not None:
        kinds = {"static": {"static"}, "interface": {"interface"}, "virtual": {"virtual"},
                 "special": {"direct", "super"}, "dynamic": {"custom", "polymorphic"}}
        return (instruction.operation == "invoke" and instruction.declared_target is not None and
                instruction.declared_target.signature == unit.invoke.signature and instruction.invoke_kind in kinds[unit.invoke.kind])
    if unit.operation in {"field_read", "field_write"}:
        value = unit.right if unit.operation == "field_read" else unit.left
        return instruction.operation == unit.operation and value is not None and any(
            operand.kind == "field" and operand.value.value == value.field_signature for operand in instruction.operands)
    if unit.operation == "constant" and unit.right is not None:
        value = unit.right
        expected = {"string": "string", "class": "type"}.get(value.constant_kind, "literal")
        candidates = [operand.value.value for operand in instruction.operands if operand.kind == expected]
        constant = value.constant
        if value.constant_kind in {"float_bits", "double_bits"}:
            width = 32 if value.constant_kind == "float_bits" else 64
            candidates = [number & ((1 << width) - 1) for number in candidates if type(number) is int]
            constant = int(constant, 16)
        if value.constant_kind == "null":
            constant = 0
        return instruction.operation == "constant" and constant in candidates
    if unit.operation == instruction.operation:
        return True
    if unit.operation == "array_write" and instruction.opcode.startswith("filled-new-array"):
        return True
    return unit.operation == "assignment" and instruction.operation in {"assignment", "constant"}


def verify_jimple_evidence(facts, read_entry):
    """Check cross-artifact bindings before publication; do not validate execution paths."""
    from androserum.facts.io import strict_json_syntax
    from androserum.facts.models import AnalysisNodeRecord, InstructionRecord, MethodRecord
    elements = {record.id: record for record in facts.elements}
    methods, units = {}, {}
    for node in facts.elements:
        if (not isinstance(node, AnalysisNodeRecord) or node.node_kind != "jimple" or node.position.kind != "analysis" or
                not node.position.artifact_path.startswith("analysis/java/methods/")):
            continue
        path = node.position.artifact_path
        if path not in methods:
            text = read_entry(path).decode("utf-8")
            strict_json_syntax(text)
            methods[path] = JimpleMethod.model_validate_json(text)
        method = methods[path]
        owner = elements.get(node.method_ref)
        label = node.position.position_label
        if not label.startswith("unit:") or not label[5:].isdigit() or not isinstance(owner, MethodRecord):
            raise ValueError("Invalid IR unit/method reference")
        index = int(label[5:])
        if method.signature != owner.signature or index >= len(method.units) or method.units[index].text != node.text:
            raise ValueError("IR artifact disagrees with its fact record")
        unit = method.units[index]
        local_types = {local.index: local.type_descriptor for local in method.locals}
        for slot in node.slots:
            if slot.slot_kind == "local" and (slot.slot_index not in local_types or slot.type_descriptor != local_types[slot.slot_index]):
                raise ValueError("Jimple local slot disagrees with its structured artifact")
        arguments = sorted(slot.slot_index for slot in node.slots if slot.slot_kind == "argument")
        if arguments != list(range(len(unit.invoke.arguments) if unit.invoke else 0)):
            raise ValueError("Jimple argument slots disagree with IR")
        if any(slot.slot_kind == "receiver" for slot in node.slots) != bool(unit.invoke and unit.invoke.receiver):
            raise ValueError("Jimple receiver disagrees with IR")
        units[node.id] = unit
    for relation in facts.relations:
        if relation.relation_kind != "dex_jimple_mapping" or not relation.target or relation.target.element_ref not in units:
            continue
        unit = units[relation.target.element_ref]
        source, target = elements.get(relation.source.element_ref), elements[relation.target.element_ref]
        if (not isinstance(source, InstructionRecord) or source.position.method_ref != target.method_ref or
                source.position.offset_bytes not in {offset * 2 for offset in unit.offsets_code_units} or not compatible_origin(source, unit)):
            raise ValueError("DEX/Jimple mapping lacks matching offset/operation/signature evidence")
        if len(set(unit.offsets_code_units)) != 1 and relation.resolution == "resolved":
            raise ValueError("Multiple origin tags must remain candidate mappings")
        if not {source.id, target.id, target.method_ref}.issubset(relation.provenance.support_refs):
            raise ValueError("DEX/Jimple mapping lost necessary support references")
        if relation.source_selector != target.position.artifact_path + f"#/units/{unit.index}/offsets_code_units":
            raise ValueError("DEX/Jimple mapping points to unrelated structured support")
    return {"methods": len(methods), "units": len(units)}
