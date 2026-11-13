"""Executable v1 representation of Method table A and its evidence endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Union

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

from androserum.facts.identity import (
    ID_VERSION, archive_path, class_descriptor, field_signature, fingerprint,
    method_signature, new_run_id, parse_method_signature, sha256_file, type_descriptor,
)

SCHEMA_VERSION = "program-facts.v2"
Text = Annotated[str, StringConstraints(min_length=1, pattern=r"\S")]
Ref = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]*:[A-Za-z0-9._-]+$")]
SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonNegative = Annotated[int, Field(ge=0)]
ClassDescriptor = Annotated[Text, AfterValidator(class_descriptor)]
TypeDescriptor = Annotated[Text, AfterValidator(type_descriptor)]
AnyTypeDescriptor = Annotated[Text, AfterValidator(lambda value: type_descriptor(value, allow_void=True))]
MethodSignature = Annotated[Text, AfterValidator(method_signature)]
FieldSignature = Annotated[Text, AfterValidator(field_signature)]
ArchivePath = Annotated[Text, AfterValidator(archive_path)]
Capability = Literal["dex", "manifest", "resources", "dex_jimple_mapping", "data_flow", "calls", "objects", "control", "events"]
SlotKind = Literal["element", "receiver", "argument", "result", "parameter", "return", "value", "local", "field", "array_element", "state", "condition", "entry"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True, allow_inf_nan=False)


class FactConfig(StrictModel):
    schema_version: Literal["facts-config.v1"] = "facts-config.v1"
    requested_capabilities: list[Capability] = Field(min_length=1)
    options: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_capabilities(self) -> FactConfig:
        if len(set(self.requested_capabilities)) != len(self.requested_capabilities):
            raise ValueError("requested_capabilities must be unique")
        return self


class ToolVersion(StrictModel):
    tool_id: Ref
    name: Text
    version: Text


class VersionedArtifact(StrictModel):
    artifact_id: Ref
    kind: Literal["platform", "rule", "summary", "framework_model"]
    name: Text
    version: Text
    sha256: SHA256 | None = None
    location: Text | None = None


class AnalysisRun(StrictModel):
    run_id: Ref
    schema_version: Literal["program-facts.v2"] = SCHEMA_VERSION
    id_version: Literal["program-id.v1"] = ID_VERSION
    input_kind: Literal["apk", "synthetic"]
    apk_sha256: SHA256
    apk_size_bytes: NonNegative
    input_name: Text
    created_at: datetime
    tools: list[ToolVersion] = Field(min_length=1)
    artifacts: list[VersionedArtifact] = Field(default_factory=list)
    configuration: FactConfig
    config_fingerprint: SHA256
    apk_metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def run_contract(self) -> AnalysisRun:
        if not self.run_id.startswith("run:"):
            raise ValueError("run_id must use the run: namespace")
        if self.created_at.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        if self.config_fingerprint != fingerprint(self.configuration.model_dump(mode="json")):
            raise ValueError("config_fingerprint does not match configuration")
        return self

    @classmethod
    def for_apk(cls, path: str | Path, *, tools: list[ToolVersion], configuration: FactConfig,
                artifacts: list[VersionedArtifact] | None = None) -> AnalysisRun:
        path = Path(path)
        return cls(run_id=new_run_id(), input_kind="apk", apk_sha256=sha256_file(path),
                   apk_size_bytes=path.stat().st_size, input_name=path.name,
                   created_at=datetime.now(timezone.utc), tools=tools, artifacts=artifacts or [],
                   configuration=configuration,
                   config_fingerprint=fingerprint(configuration.model_dump(mode="json")))


class Provenance(StrictModel):
    kind: Literal["direct", "static_analysis", "model_assisted"]
    tool_ref: Ref
    support_refs: list[Ref] = Field(default_factory=list)
    rule_ref: Ref | None = None

    @model_validator(mode="after")
    def support_contract(self) -> Provenance:
        if self.kind == "static_analysis" and not self.support_refs:
            raise ValueError("static_analysis requires support_refs")
        if self.kind == "model_assisted" and self.rule_ref is None:
            raise ValueError("model_assisted requires a versioned rule/model reference")
        return self


class ValueInfo(StrictModel):
    status: Literal["known", "partial", "unknown", "not_applicable"]
    value: JsonValue = None
    source_refs: list[Ref] = Field(default_factory=list)
    reason: Text | None = None

    @model_validator(mode="after")
    def value_contract(self) -> ValueInfo:
        if self.status == "known" and "value" not in self.model_fields_set:
            raise ValueError("known values must explicitly provide value (including known null)")
        if self.status != "known" and self.reason is None:
            raise ValueError("partial/unknown/not_applicable requires reason")
        if self.status in {"unknown", "not_applicable"} and self.value is not None:
            raise ValueError("unknown/not_applicable cannot contain a known value")
        if self.status == "not_applicable" and self.source_refs:
            raise ValueError("not_applicable cannot have value sources")
        if self.status == "partial" and self.value is None and not self.source_refs:
            raise ValueError("partial requires a known portion or source_refs")
        return self


class ArchivePosition(StrictModel):
    kind: Literal["archive"]
    path: ArchivePath
    selector: Text | None = None


class DexDeclarationPosition(StrictModel):
    kind: Literal["dex_declaration"]
    dex_ref: Ref
    table: Literal["class_def", "method_id", "field_id", "type_id"]
    index: NonNegative


class InstructionPosition(StrictModel):
    kind: Literal["dex_instruction"]
    dex_ref: Ref
    method_ref: Ref
    offset_bytes: Annotated[int, Field(ge=0, multiple_of=2)]
    position_label: Text

    @model_validator(mode="after")
    def consistent_label(self) -> InstructionPosition:
        if self.position_label != f"code+0x{self.offset_bytes:x}":
            raise ValueError("position_label must encode the method-relative instruction byte offset")
        return self

    @classmethod
    def at(cls, dex_ref: str, method_ref: str, offset_bytes: int) -> InstructionPosition:
        return cls(kind="dex_instruction", dex_ref=dex_ref, method_ref=method_ref,
                   offset_bytes=offset_bytes, position_label=f"code+0x{offset_bytes:x}")


class AnalysisPosition(StrictModel):
    kind: Literal["analysis"]
    artifact_path: Text
    position_label: Text


class ModelPosition(StrictModel):
    kind: Literal["model"]
    model_ref: Ref
    position_label: Text


Position = Annotated[Union[ArchivePosition, DexDeclarationPosition, InstructionPosition, AnalysisPosition, ModelPosition], Field(discriminator="kind")]


class Endpoint(StrictModel):
    element_ref: Ref
    slot_kind: SlotKind
    slot_index: NonNegative | None = None
    slot_label: Text | None = None
    position_label: Text | None = None

    @model_validator(mode="after")
    def slot_shape(self) -> Endpoint:
        indexed = self.slot_kind in {"argument", "parameter", "local"}
        if indexed != (self.slot_index is not None):
            raise ValueError("Only argument/parameter/local endpoints require slot_index")
        if self.slot_kind in {"state", "field", "array_element"} and self.slot_label is None:
            raise ValueError("state/field/array_element endpoints require slot_label")
        if self.slot_kind not in {"state", "field", "array_element"} and self.slot_label is not None:
            raise ValueError("This endpoint kind does not accept slot_label")
        return self


class ProgramSlot(StrictModel):
    slot_kind: SlotKind
    slot_index: NonNegative | None = None
    slot_label: Text | None = None
    value: ValueInfo
    type_descriptor: TypeDescriptor | None = None
    registers: list[NonNegative] = Field(default_factory=list)

    @model_validator(mode="after")
    def slot_shape(self) -> ProgramSlot:
        Endpoint(element_ref="slot:shape", slot_kind=self.slot_kind,
                 slot_index=self.slot_index, slot_label=self.slot_label)
        if self.slot_kind in {"element", "entry", "parameter", "return"}:
            raise ValueError("These slots are represented by their owning element/method")
        return self


class Operand(StrictModel):
    index: NonNegative
    kind: Literal["register", "literal", "string", "method", "field", "type", "resource", "branch", "unknown"]
    value: ValueInfo
    reference_ref: Ref | None = None
    encoded_kind: NonNegative | None = None

    @model_validator(mode="after")
    def encoded_value(self) -> Operand:
        if self.value.status == "known":
            value = self.value.value
            if self.kind == "register" and (type(value) is not int or value < 0):
                raise ValueError("Known register operands contain a non-negative encoded register number")
            if self.kind in {"method", "field", "type"}:
                if not isinstance(value, str):
                    raise ValueError("Known reference operands contain descriptor/signature text")
                {"method": method_signature, "field": field_signature, "type": type_descriptor}[self.kind](value)
        return self


class MethodTarget(StrictModel):
    signature: MethodSignature | None
    method_ref: Ref | None = None
    unknown_reason: Text | None = None

    @model_validator(mode="after")
    def target_contract(self) -> MethodTarget:
        if self.signature is None and (self.unknown_reason is None or self.method_ref is not None):
            raise ValueError("An unknown target requires a reason and cannot name a method_ref")
        if self.signature is not None and self.unknown_reason is not None:
            raise ValueError("A known declared signature must not carry unknown_reason")
        return self


class Record(StrictModel):
    id: Ref
    run_ref: Ref
    provenance: Provenance


class DexRecord(Record):
    kind: Literal["dex"]
    position: ArchivePosition
    sha256: SHA256
    size_bytes: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def dex_entry(self) -> DexRecord:
        if not self.position.path.endswith(".dex"):
            raise ValueError("DEX records must locate an APK .dex entry")
        return self


class ClassRecord(Record):
    kind: Literal["class"]
    position: DexDeclarationPosition
    descriptor: ClassDescriptor
    superclass: ClassDescriptor | None
    interfaces: list[ClassDescriptor] = Field(default_factory=list)
    access_flags: NonNegative = 0


class TypeReferenceRecord(Record):
    kind: Literal["type_reference"]
    position: DexDeclarationPosition
    descriptor: AnyTypeDescriptor


class MethodRecord(Record):
    kind: Literal["method"]
    position: DexDeclarationPosition
    signature: MethodSignature
    is_definition: bool
    class_ref: Ref | None = None
    is_static: bool | None
    body_status: Literal["available", "abstract", "native", "external", "unavailable"]
    access_flags: NonNegative | None = None
    code_offset_bytes: NonNegative | None = None
    code_size_bytes: NonNegative | None = None
    registers_size: NonNegative | None = None
    input_registers_size: NonNegative | None = None
    exception_handlers_count: NonNegative | None = None

    @model_validator(mode="after")
    def method_contract(self) -> MethodRecord:
        if self.is_definition and (self.class_ref is None or self.is_static is None or self.body_status == "external"):
            raise ValueError("Method definitions require a class_ref, staticness and non-external body status")
        if not self.is_definition and self.body_status != "external":
            raise ValueError("Non-definitions must use body_status=external")
        return self


class ParameterRecord(Record):
    kind: Literal["parameter"]
    method_ref: Ref
    index: NonNegative
    type_descriptor: TypeDescriptor
    register_index: NonNegative | None = None


class FieldRecord(Record):
    kind: Literal["field"]
    position: DexDeclarationPosition
    signature: FieldSignature
    is_definition: bool
    class_ref: Ref | None = None
    is_static: bool | None
    initial_value: ValueInfo | None = None
    access_flags: NonNegative | None = None


class InstructionRecord(Record):
    kind: Literal["instruction"]
    position: InstructionPosition
    opcode: Text
    operation: Literal["assignment", "invoke", "field_read", "field_write", "array_read", "array_write", "constant", "branch", "return", "allocation", "other"]
    operands: list[Operand]
    slots: list[ProgramSlot] = Field(default_factory=list)
    slots_complete: bool
    invoke_kind: Literal["static", "direct", "virtual", "interface", "super", "custom", "polymorphic"] | None = None
    declared_target: MethodTarget | None = None
    raw_hex: Annotated[str, StringConstraints(pattern=r"^(?:[0-9a-f]{2})+$")] | None = None
    length_bytes: Annotated[int, Field(gt=0)] | None = None
    result_receiver_ref: Ref | None = None

    @model_validator(mode="after")
    def call_contract(self) -> InstructionRecord:
        if self.raw_hex is not None and (self.length_bytes is None or len(self.raw_hex) != self.length_bytes * 2):
            raise ValueError("Raw instruction bytes must match length_bytes")
        if self.operation == "invoke":
            if self.invoke_kind is None or self.declared_target is None:
                raise ValueError("Invocations require invoke_kind and a known/explicitly unknown declared_target")
            if self.slots_complete and self.declared_target.signature is not None and self.invoke_kind not in {"custom", "polymorphic"}:
                _, _, parameters, result = parse_method_signature(self.declared_target.signature)
                indices = sorted(s.slot_index for s in self.slots if s.slot_kind == "argument")
                if indices != list(range(len(parameters))):
                    raise ValueError("Complete argument slots must match the declared parameter list")
                receivers = [s for s in self.slots if s.slot_kind == "receiver"]
                if bool(receivers) != (self.invoke_kind != "static"):
                    raise ValueError("Receiver slot disagrees with invocation kind")
                if result == "V" and any(s.slot_kind == "result" for s in self.slots):
                    raise ValueError("Void invocations have no result value slot")
        elif self.invoke_kind is not None or self.declared_target is not None:
            raise ValueError("Only invocations can have invocation metadata")
        return self


class ConfigurationRecord(Record):
    kind: Literal["configuration"]
    position: ArchivePosition
    configuration_kind: Literal["component", "permission", "intent_filter", "manifest_attribute"]
    name: Text
    value: ValueInfo


class ResourceRecord(Record):
    kind: Literal["resource"]
    position: ArchivePosition
    resource_id: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    resource_type: Text
    name: Text
    qualifiers: str = ""
    value: ValueInfo
    package_name: Text | None = None
    raw_value: JsonValue = None


class AnalysisNodeRecord(Record):
    kind: Literal["analysis_node"]
    position: Annotated[Union[AnalysisPosition, ModelPosition], Field(discriminator="kind")]
    node_kind: Literal["jimple", "cfg", "object", "state", "entry", "event", "mapping"]
    method_ref: Ref | None = None
    text: Text | None = None
    slots: list[ProgramSlot] = Field(default_factory=list)


class ConditionRecord(Record):
    kind: Literal["condition"]
    branch_ref: Ref
    branch_label: Text
    value_endpoint: Endpoint
    expected_value: ValueInfo


Element = Annotated[Union[DexRecord, ClassRecord, TypeReferenceRecord, MethodRecord, ParameterRecord, FieldRecord, InstructionRecord,
                          ConfigurationRecord, ResourceRecord, AnalysisNodeRecord, ConditionRecord], Field(discriminator="kind")]


class ContextRecord(Record):
    abstraction: Text
    callsite_refs: list[Ref]
    parent_ref: Ref | None = None
    truncated: bool = False
    issue_refs: list[Ref] = Field(default_factory=list)


class BindingRecord(Record):
    binding_kind: Literal["object", "value", "state"]
    endpoints: list[Endpoint] = Field(min_length=2)
    context_ref: Ref | None = None
    condition_refs: list[Ref] = Field(default_factory=list)


RelationKind = Literal["declared_call", "candidate_call", "data_dependency", "argument_to_parameter", "return_to_result",
                       "field_dependency", "array_dependency", "state_dependency", "control_dependency", "event_trigger",
                       "icc_target", "icc_data", "dex_jimple_mapping", "resource_use", "information_flow"]
RelationKind = Union[RelationKind, Literal["reference_resolution", "call_result_assignment", "resource_reference"]]


class RelationRecord(Record):
    relation_kind: RelationKind
    source: Endpoint
    target: Endpoint | None
    context_ref: Ref | None = None
    callsite_ref: Ref | None = None
    binding_refs: list[Ref] = Field(default_factory=list)
    condition_refs: list[Ref] = Field(default_factory=list)
    resolution: Literal["resolved", "partial", "unresolved"]
    unresolved_reason: Text | None = None
    source_selector: Text | None = None

    @model_validator(mode="after")
    def resolution_contract(self) -> RelationRecord:
        if self.resolution == "unresolved" and self.target is not None:
            raise ValueError("unresolved targets must remain absent; use partial for a known endpoint")
        if self.resolution != "unresolved" and self.target is None:
            raise ValueError("resolved/partial relations require a target")
        if self.resolution != "resolved" and self.unresolved_reason is None:
            raise ValueError("partial/unresolved relations require unresolved_reason")
        if self.resolution == "resolved" and self.unresolved_reason is not None:
            raise ValueError("Resolved relations cannot carry unresolved_reason")
        if not self.provenance.support_refs:
            raise ValueError("Relations require support_refs")
        if self.relation_kind in {"argument_to_parameter", "return_to_result"} and (self.callsite_ref is None or self.context_ref is None):
            raise ValueError("Cross-method call bindings require a callsite and context")
        return self


class AnalysisScope(StrictModel):
    kind: Literal["run", "element", "location"]
    element_ref: Ref | None = None
    location: Position | None = None

    @model_validator(mode="after")
    def scope_contract(self) -> AnalysisScope:
        if self.kind == "run" and (self.element_ref is not None or self.location is not None):
            raise ValueError("Run scopes do not select an element/location")
        if self.kind == "element" and (self.element_ref is None or self.location is not None):
            raise ValueError("Element scopes require only element_ref")
        if self.kind == "location" and (self.location is None or self.element_ref is not None):
            raise ValueError("Location scopes require only location")
        return self


class AnalysisStatus(StrictModel):
    id: Ref
    run_ref: Ref
    tool_ref: Ref
    capability: Capability
    scope: AnalysisScope
    state: Literal["complete", "partial", "not_started", "unavailable", "failed", "truncated"]
    reason: Text | None = None
    unknowns: list[Text] = Field(default_factory=list)
    issue_code: Text | None = None

    @model_validator(mode="after")
    def status_contract(self) -> AnalysisStatus:
        if self.state != "complete" and self.reason is None:
            raise ValueError("Incomplete analysis states require a reason")
        if self.state == "complete" and self.unknowns:
            raise ValueError("Analysis with unresolved contents must use an incomplete state")
        return self


class FactBundle(StrictModel):
    schema_version: Literal["program-facts.v2"] = SCHEMA_VERSION
    source_schema_version: Literal["program-facts.v1"] | None = None
    run: AnalysisRun
    elements: list[Element] = Field(default_factory=list)
    relations: list[RelationRecord] = Field(default_factory=list)
    contexts: list[ContextRecord] = Field(default_factory=list)
    bindings: list[BindingRecord] = Field(default_factory=list)
    statuses: list[AnalysisStatus] = Field(default_factory=list)
