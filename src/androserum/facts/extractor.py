"""F1: directly locatable Android facts with explicit limited normalization rules."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import importlib.metadata as metadata
import json
import math
from pathlib import Path
import re
import struct
from typing import Any
import zipfile

from lxml import etree
from loguru import logger
from pydantic import Field

from androserum import __version__
from androserum.facts.identity import filesystem_path, parse_method_signature, record_id, sha256_file
from androserum.facts.io import dump_facts, loads_facts
from androserum.facts.models import (
    AnalysisRun, AnalysisScope, AnalysisStatus, ArchivePosition, ClassRecord, ConfigurationRecord,
    DexDeclarationPosition, DexRecord, Endpoint, FactBundle, FactConfig, FieldRecord,
    InstructionPosition, InstructionRecord, MethodRecord, MethodTarget, Operand, ParameterRecord,
    ProgramSlot, Provenance, RelationRecord, ResourceRecord, StrictModel, ToolVersion,
    TypeReferenceRecord, ValueInfo, VersionedArtifact,
)

BASE = ("dex", "manifest", "resources")
ALL = (*BASE, "dex_jimple_mapping", "data_flow", "calls", "objects", "control", "events")
ANDROID = "{http://schemas.android.com/apk/res/android}"


class ExtractionOptions(StrictModel):
    max_entry_bytes: int = Field(default=256 * 1024 * 1024, gt=0)
    max_total_uncompressed_bytes: int = Field(default=1024 * 1024 * 1024, gt=0)
    max_instructions_per_method: int = Field(default=1000000, gt=0)


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"encoding": "bytes", "hex": value.hex()}
    if isinstance(value, float) and not math.isfinite(value):
        import struct
        return {"encoding": "ieee754-bits", "bits": 64, "hex": struct.pack(">d", value).hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                return {"encoding": "utf16-le", "hex": value.encode("utf-16-le", errors="surrogatepass").hex()}
        return value
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if hasattr(value, "get_value"):
        return _json_value(value.get_value())
    raise TypeError(f"Unsupported encoded value type {type(value).__name__}")


def _method_signature(item) -> str:
    return f"{item.get_class_name()}->{item.get_name()}{item.get_descriptor().replace(' ', '')}"


def _field_signature(item) -> str:
    return f"{item.get_class_name()}->{item.get_name()}:{item.get_descriptor()}"


def _initial_value(value) -> ValueInfo:
    if value is None:
        return ValueInfo(status="unknown", reason="No explicit encoded static value; runtime/default initialization is not inferred")
    kind, raw = value.value_type, getattr(value, "raw_value", b"")
    if kind in {16, 17} and isinstance(raw, bytes):
        width = 4 if kind == 16 else 8
        bits = int.from_bytes(raw, "little") << ((width - len(raw)) * 8)
        return ValueInfo(status="known", value={"encoding": "ieee754-bits", "bits": width * 8,
                         "hex": f"{bits:0{width * 2}x}", "encoded_hex": raw.hex()})
    return ValueInfo(status="known", value=_json_value(value.get_value()))


@dataclass
class ExtractionResult:
    facts: FactBundle
    summary: dict
    blobs: dict[str, bytes]
    entry_digests: dict[str, str]


class Extractor:
    def __init__(self, path: str | Path, configuration: FactConfig | None = None):
        self.path = Path(path)
        self.configuration = configuration or FactConfig(requested_capabilities=list(ALL))
        self.options = ExtractionOptions.model_validate(self.configuration.options)
        self.run = AnalysisRun.for_apk(self.path, configuration=self.configuration, tools=[
            ToolVersion(tool_id="tool:androguard", name="androguard", version=metadata.version("androguard")),
            ToolVersion(tool_id="tool:extractor", name="androserum-extractor", version=__version__),
        ], artifacts=[VersionedArtifact(artifact_id="rule:direct-normalization", kind="rule",
              name="declaration-reference-and-local-resource-rules", version="1",
              sha256=sha256_file(__file__), location="src/androserum/facts/extractor.py")])
        self.elements: dict[str, Any] = {}
        self.relations: list[RelationRecord] = []
        self.issues: list[AnalysisStatus] = []
        self.blobs: dict[str, bytes] = {}
        self.entry_digests: dict[str, str] = {}
        self.counts = Counter()
        self.dex_stats: list[dict] = []
        self.config_records: list[ConfigurationRecord] = []
        self.resources: dict[int, list[ResourceRecord]] = defaultdict(list)
        self.method_code: dict[str, list[InstructionRecord]] = {}
        self._total_bytes = 0
        self._seen_issues: set[str] = set()

    def identity(self, namespace: str, identity: Any) -> str:
        return record_id(self.run.run_id, namespace, identity)

    def direct(self) -> Provenance:
        return Provenance(kind="direct", tool_ref="tool:androguard")

    def derived(self, *support: str) -> Provenance:
        return Provenance(kind="static_analysis", tool_ref="tool:extractor",
                          support_refs=list(dict.fromkeys(support)), rule_ref="rule:direct-normalization")

    def issue(self, capability: str, code: str, reason: str, *, element_ref: str | None = None,
              path: str | None = None, selector: str | None = None, state: str = "partial") -> None:
        scope = AnalysisScope(kind="element", element_ref=element_ref) if element_ref else (
            AnalysisScope(kind="location", location=ArchivePosition(kind="archive", path=path, selector=selector))
            if path else AnalysisScope(kind="run"))
        key = self.identity("status", [capability, code, scope.model_dump(mode="json"), reason])
        if key in self._seen_issues:
            return
        self._seen_issues.add(key)
        self.issues.append(AnalysisStatus(id=key, run_ref=self.run.run_id, tool_ref="tool:extractor",
            capability=capability, scope=scope, state=state, reason=reason, issue_code=code))

    def emit(self, record) -> None:
        if record.id in self.elements:
            raise ValueError("Duplicate generated identity")
        self.elements[record.id] = record

    def read_entry(self, archive: zipfile.ZipFile, name: str) -> bytes:
        infos = [entry for entry in archive.infolist() if entry.filename == name]
        if len(infos) != 1:
            raise ValueError("APK entry is missing or ambiguous (duplicate ZIP names)")
        if name in self.entry_digests:
            return self.blobs[self.entry_digests[name]]
        info = infos[0]
        if info.file_size > self.options.max_entry_bytes or self._total_bytes + info.file_size > self.options.max_total_uncompressed_bytes:
            raise ValueError("Configured uncompressed-entry budget exceeded")
        data = archive.read(info)
        self._total_bytes += len(data)
        digest = hashlib.sha256(data).hexdigest()
        self.blobs[digest] = data
        self.entry_digests[name] = digest
        return data

    def extract(self) -> ExtractionResult:
        logger.disable("androguard")
        failed: set[str] = set()
        try:
            with zipfile.ZipFile(self.path) as archive:
                names = sorted(set(entry.filename for entry in archive.infolist() if not entry.is_dir()))
                if "manifest" in self.configuration.requested_capabilities:
                    try:
                        self.manifest(self.read_entry(archive, "AndroidManifest.xml"))
                    except Exception as error:
                        failed.add("manifest")
                        self.issue("manifest", "manifest_parse_error", self.error(error), path="AndroidManifest.xml", state="failed")
                if "resources" in self.configuration.requested_capabilities:
                    if "resources.arsc" in names:
                        try:
                            self.resource_table(self.read_entry(archive, "resources.arsc"))
                        except Exception as error:
                            failed.add("resources")
                            self.issue("resources", "resource_parse_error", self.error(error), path="resources.arsc", state="failed")
                    for name in names:
                        if name.startswith("res/"):
                            try:
                                self.read_entry(archive, name)
                            except Exception as error:
                                self.issue("resources", "resource_file_error", self.error(error), path=name)
                if "dex" in self.configuration.requested_capabilities:
                    dex_names = [name for name in names if name.endswith(".dex")]
                    if not dex_names:
                        failed.add("dex")
                        self.issue("dex", "no_dex", "No DEX entry present", path="AndroidManifest.xml", state="failed")
                    for name in dex_names:
                        try:
                            self.dex(name, self.read_entry(archive, name))
                        except Exception as error:
                            self.issue("dex", "dex_parse_error", self.error(error), path=name, state="failed")
                    if dex_names and not any(isinstance(record, DexRecord) for record in self.elements.values()):
                        failed.add("dex")
                self.resolve_references()
                if "resources" in self.configuration.requested_capabilities:
                    self.resource_references()
        except (zipfile.BadZipFile, OSError) as error:
            failed.update(BASE)
            for capability in BASE:
                self.issue(capability, "apk_container_error", self.error(error), state="failed")
        if self.path.stat().st_size != self.run.apk_size_bytes or sha256_file(self.path) != self.run.apk_sha256:
            raise OSError("APK changed during extraction; no result is published")
        statuses = []
        for capability in ALL:
            local = [issue for issue in self.issues if issue.capability == capability]
            if capability not in self.configuration.requested_capabilities:
                state, reason = "not_started", "Capability was not requested"
            elif capability not in BASE:
                state, reason = "not_started", "F1 provides direct records only; this analysis belongs to F3-F7"
            elif capability in failed:
                state, reason = "failed", "This capability could not extract its primary input; see scoped issues"
            elif local:
                state, reason = "partial", "Known local gaps are preserved in scoped analysis statuses"
            else:
                state, reason = "complete", None
            run_issues = [issue for issue in local if issue.scope.kind == "run"]
            if run_issues:
                reason = "; ".join(issue.reason for issue in run_issues)
            statuses.append(AnalysisStatus(id=self.identity("status", ["coverage", capability]), run_ref=self.run.run_id,
                tool_ref="tool:extractor", capability=capability, scope=AnalysisScope(kind="run"), state=state, reason=reason,
                issue_code=run_issues[0].issue_code if run_issues else None))
        facts = FactBundle(run=self.run, elements=list(self.elements.values()), relations=self.relations,
                           statuses=statuses + [issue for issue in self.issues if issue.scope.kind != "run"])
        # The public loader checks both local schemas and complete cross-record integrity.
        facts = loads_facts(facts.model_dump_json())
        selected = [status.state for status in statuses if status.capability in BASE and status.capability in self.configuration.requested_capabilities]
        outcome = "failed" if not selected or all(state == "failed" for state in selected) else (
            "complete" if all(state == "complete" for state in selected) else "partial")
        summary = {"stage": "F1", "extractor_version": __version__, "outcome": outcome,
            "run_id": self.run.run_id, "apk_sha256": self.run.apk_sha256, "schema_version": facts.schema_version,
            "element_counts": dict(Counter(record.kind for record in facts.elements)),
            "relation_counts": dict(Counter(record.relation_kind for record in facts.relations)),
            "operation_counts": dict(Counter(record.operation for record in facts.elements if isinstance(record, InstructionRecord))),
            "body_status_counts": dict(Counter(record.body_status for record in facts.elements if isinstance(record, MethodRecord))),
            "coverage": {status.capability: status.state for status in statuses}, "issues": len(self.issues),
            "observed_counts": dict(self.counts), "dex": self.dex_stats,
            "limits": ["No general reaching definitions, points-to, control or event analysis is performed",
                       "Runtime argument values remain unknown; only encoded registers and limited explicit resource rules are recorded"]}
        return ExtractionResult(facts, summary, self.blobs, self.entry_digests)

    @staticmethod
    def error(error: Exception) -> str:
        return f"{type(error).__name__}: {str(error)[:1200]}"

    def manifest(self, data: bytes) -> None:
        from androguard.core.axml import AXMLPrinter
        printer = AXMLPrinter(data)
        root = printer.get_xml_obj()
        if not printer.is_valid() or root is None or etree.QName(root).localname != "manifest":
            raise ValueError("Manifest is not readable binary Android XML")
        tree = root.getroottree()
        sdk = root.find("uses-sdk")
        self.run.apk_metadata = {"package": root.get("package"), "version_code": root.get(ANDROID + "versionCode"),
            "version_name": root.get(ANDROID + "versionName"),
            "min_sdk": sdk.get(ANDROID + "minSdkVersion") if sdk is not None else None,
            "target_sdk": sdk.get(ANDROID + "targetSdkVersion") if sdk is not None else None}
        for node in root.iter():
            if not isinstance(node.tag, str):
                continue
            tag = etree.QName(node).localname
            category = "component" if tag in {"activity", "activity-alias", "service", "receiver", "provider"} else (
                "permission" if "permission" in tag else "intent_filter" if tag == "intent-filter" else "manifest_attribute")
            selector = tree.getpath(node)
            attributes = {str(key): value for key, value in node.attrib.items()}
            value = {"tag": tag, "attributes": attributes,
                     "children": [{"tag": etree.QName(child).localname, "attributes": dict(child.attrib)}
                                  for child in node if isinstance(child.tag, str)]}
            record = ConfigurationRecord(id=self.identity("configuration", ["AndroidManifest.xml", selector]),
                run_ref=self.run.run_id, provenance=self.direct(), kind="configuration",
                position=ArchivePosition(kind="archive", path="AndroidManifest.xml", selector=selector),
                configuration_kind=category, name=node.get(ANDROID + "name") or tag,
                value=ValueInfo(status="known", value=value))
            self.emit(record)
            self.config_records.append(record)

    def resource_table(self, data: bytes) -> None:
        from androguard.core.axml import ARSCParser
        if len(data) < 12:
            raise ValueError("Truncated resource table header")
        chunk_type, header_size, declared_size, package_count = struct.unpack_from("<HHII", data)
        if chunk_type != 2 or not 12 <= header_size <= declared_size <= len(data):
            raise ValueError("Invalid resource table header or size")
        table = ARSCParser(data)
        packages = table.get_packages_names()
        if not packages:
            if package_count == 0:
                return  # A valid APK can contain an empty resource table.
            raise ValueError("Declared resource packages could not be read")
        table._analyse()
        for rid, variants in sorted(table.resource_values.items()):
            for config, entry in variants.items():
                try:
                    xml_name = table.get_resource_xml_name(rid)
                    match = re.fullmatch(r"@([^:]+):([^/]+)/(.+)", xml_name or "")
                    if match is None:
                        raise ValueError("Resource name could not be identified")
                    package, resource_type, name = match.groups()
                    qualifier = config.get_qualifier()
                    if entry.is_complex():
                        raw_value = {"complex": True, "parent": entry.item.id_parent,
                                     "items": [{"name": key, "data_type": item.data_type, "data": item.data,
                                                "formatted": item.format_value()} for key, item in entry.item.items]}
                        value = [{"name": key, "value": item.format_value(), "data_type": item.data_type, "data": item.data}
                                 for key, item in entry.item.items]
                    else:
                        item = entry.key
                        raw_value = {"complex": False, "data_type": item.data_type, "data": item.data}
                        if item.data_type == 18:
                            value = bool(item.data)
                        elif item.data_type in {16, 17}:
                            value = item.data - 2**32 if item.data_type == 16 and item.data >= 2**31 else item.data
                        else:
                            value = item.format_value()
                    record = ResourceRecord(id=self.identity("resource", [rid, qualifier]), run_ref=self.run.run_id,
                        provenance=self.direct(), kind="resource", position=ArchivePosition(kind="archive", path="resources.arsc",
                            selector=f"resource:0x{rid:08x};config={qualifier};offset={entry.start}"),
                        resource_id=rid, resource_type=resource_type, name=name, qualifiers=qualifier,
                        value=ValueInfo(status="known", value=_json_value(value)), package_name=package, raw_value=raw_value)
                    self.emit(record)
                    self.resources[rid].append(record)
                except Exception as error:
                    self.issue("resources", "resource_entry_error", self.error(error), path="resources.arsc", selector=f"resource:0x{rid:08x}")

    def dex(self, name: str, data: bytes) -> None:
        from androguard.core.dex import DEX
        dex = DEX(data)
        dex_id = self.identity("dex", name)
        self.emit(DexRecord(id=dex_id, run_ref=self.run.run_id, provenance=self.direct(), kind="dex",
            position=ArchivePosition(kind="archive", path=name), sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data)))
        stats = {"entry": name, "class_definitions": len(dex.get_classes()), "method_references": len(dex.get_methods()),
                 "field_references": len(dex.get_fields()), "type_references": dex.header.type_ids_size,
                 "method_definitions": 0, "decoded_method_bodies": 0, "partial_method_bodies": 0,
                 "decoded_instructions": 0, "decoded_bytes": 0}
        self.dex_stats.append(stats)
        for index in range(dex.header.type_ids_size):
            try:
                self.emit(TypeReferenceRecord(id=self.identity("type", [name, index]), run_ref=self.run.run_id,
                    provenance=self.direct(), kind="type_reference", position=DexDeclarationPosition(kind="dex_declaration",
                    dex_ref=dex_id, table="type_id", index=index), descriptor=dex.CM.get_type(index)))
            except Exception as error:
                self.issue("dex", "type_record_error", self.error(error), path=name, selector=f"type_id:{index}")
        class_ids, methods, fields = {}, {}, {}
        for index, klass in enumerate(dex.get_classes()):
            try:
                identifier = self.identity("class", [name, index])
                self.emit(ClassRecord(id=identifier, run_ref=self.run.run_id, provenance=self.direct(), kind="class",
                    position=DexDeclarationPosition(kind="dex_declaration", dex_ref=dex_id, table="class_def", index=index),
                    descriptor=klass.get_name(), superclass=klass.get_superclassname() or None,
                    interfaces=klass.get_interfaces(), access_flags=klass.get_access_flags()))
                class_ids[klass.get_name()] = identifier
                for method in klass.get_methods():
                    methods[method.get_method_idx()] = method
                for field in klass.get_fields():
                    fields[field.get_field_idx()] = field
            except Exception as error:
                self.issue("dex", "class_record_error", self.error(error), path=name, selector=f"class_def:{index}")
        method_ids = {}
        for index, item in enumerate(dex.get_methods()):
            try:
                encoded = methods.get(index)
                flags = encoded.get_access_flags() if encoded else None
                status = "external" if encoded is None else "abstract" if flags & 0x400 else "native" if flags & 0x100 else "available"
                record = MethodRecord(id=self.identity("method", [name, index]), run_ref=self.run.run_id,
                    provenance=self.direct(), kind="method", position=DexDeclarationPosition(kind="dex_declaration",
                    dex_ref=dex_id, table="method_id", index=index), signature=_method_signature(item),
                    is_definition=encoded is not None, class_ref=class_ids.get(item.get_class_name()) if encoded else None,
                    is_static=bool(flags & 8) if flags is not None else None, body_status=status,
                    access_flags=flags, code_offset_bytes=encoded.get_code_off() if encoded else None)
                self.emit(record)
                method_ids[index] = record.id
                if encoded:
                    stats["method_definitions"] += 1
            except Exception as error:
                self.issue("dex", "method_record_error", self.error(error), path=name, selector=f"method_id:{index}")
        field_ids = {}
        for index, item in enumerate(dex.get_fields()):
            try:
                encoded = fields.get(index)
                flags = encoded.get_access_flags() if encoded else None
                record = FieldRecord(id=self.identity("field", [name, index]), run_ref=self.run.run_id,
                    provenance=self.direct(), kind="field", position=DexDeclarationPosition(kind="dex_declaration",
                    dex_ref=dex_id, table="field_id", index=index), signature=_field_signature(item),
                    is_definition=encoded is not None, class_ref=class_ids.get(item.get_class_name()) if encoded else None,
                    is_static=bool(flags & 8) if flags is not None else None, access_flags=flags,
                    initial_value=_initial_value(encoded.get_init_value()) if encoded else None)
                self.emit(record)
                field_ids[index] = record.id
            except Exception as error:
                self.issue("dex", "field_record_error", self.error(error), path=name, selector=f"field_id:{index}")
        for index, encoded in sorted(methods.items()):
            if index not in method_ids:
                continue
            method = self.elements[method_ids[index]]
            code = None
            if method.body_status == "available":
                try:
                    code = encoded.get_code()
                    if code is None:
                        raise ValueError("Concrete definition has no code item")
                    method.registers_size = code.get_registers_size()
                    method.input_registers_size = code.get_ins_size()
                    method.code_size_bytes = code.get_insns_size() * 2
                    method.exception_handlers_count = code.get_tries_size()
                except Exception as error:
                    method.body_status = "unavailable"
                    self.issue("dex", "method_body_error", self.error(error), element_ref=method.id, state="failed")
            self.parameters(method)
            if code is not None:
                try:
                    complete = self.instructions(dex, encoded, method, method_ids, field_ids, stats)
                    stats["decoded_method_bodies" if complete else "partial_method_bodies"] += 1
                except Exception as error:
                    stats["partial_method_bodies"] += 1
                    self.issue("dex", "method_decode_error", self.error(error), element_ref=method.id, state="failed")
        self.counts.update({key: value for key, value in stats.items() if isinstance(value, int)})

    def parameters(self, method: MethodRecord) -> None:
        parameters = parse_method_signature(method.signature)[2]
        register = None
        if method.registers_size is not None and method.input_registers_size is not None:
            register = method.registers_size - method.input_registers_size + (0 if method.is_static else 1)
        for index, descriptor in enumerate(parameters):
            self.emit(ParameterRecord(id=self.identity("parameter", [method.id, index]), run_ref=self.run.run_id,
                provenance=self.direct(), kind="parameter", method_ref=method.id, index=index,
                type_descriptor=descriptor, register_index=register))
            if register is not None:
                register += 2 if descriptor in {"J", "D"} else 1

    def instructions(self, dex, encoded, method: MethodRecord, method_ids: dict, field_ids: dict, stats: dict) -> bool:
        instructions = []
        # Keep a committed prefix if a later instruction is unreadable.
        self.method_code[method.id] = instructions
        for index, (offset, raw) in enumerate(encoded.get_instructions_idx()):
            if index >= self.options.max_instructions_per_method:
                self.issue("dex", "instruction_budget", "Configured instruction budget exceeded", element_ref=method.id, state="truncated")
                return False
            record = self.instruction(dex, raw, offset, method, method_ids, field_ids)
            self.emit(record)
            instructions.append(record)
            # Commit result reception with the decoded adjacent pair. A later
            # unsupported instruction or budget stop must not discard evidence
            # already read from this method's valid prefix.
            if len(instructions) > 1:
                self.link_result_receiver(instructions[-2], record)
            stats["decoded_instructions"] += 1
            stats["decoded_bytes"] += record.length_bytes
        if sum(item.length_bytes for item in instructions) != method.code_size_bytes:
            self.issue("dex", "code_size_mismatch", "Decoded instruction lengths do not cover the declared code size", element_ref=method.id)
            return False
        return True

    @staticmethod
    def link_result_receiver(call, following):
        result_type = parse_method_signature(call.declared_target.signature)[3] if call.declared_target and call.declared_target.signature else None
        adjacent = call.position.offset_bytes + call.length_bytes == following.position.offset_bytes
        if (adjacent and (call.operation == "invoke" or call.opcode.startswith("filled-new-array"))
                and following.opcode.startswith("move-result") and result_type != "V"):
            call.result_receiver_ref = following.id
            registers = next(slot.registers for slot in following.slots if slot.slot_kind == "result")
            existing = next((slot for slot in call.slots if slot.slot_kind == "result"), None)
            if existing is None:
                call.slots.append(ProgramSlot(slot_kind="result", registers=registers,
                    type_descriptor=result_type if result_type not in {None, "V"} else None,
                    value=ValueInfo(status="unknown", reason="Runtime invocation result", source_refs=[following.id])))
            else:
                existing.registers = registers
                existing.value = ValueInfo(status="unknown", reason="Runtime result received by the recorded instruction", source_refs=[following.id])

    def instruction(self, dex, raw, offset: int, method: MethodRecord, method_ids: dict, field_ids: dict) -> InstructionRecord:
        name = raw.get_name()
        operands, registers = [], []
        for index, item in enumerate(raw.get_operands(offset)):
            tag, value = int(item[0]), item[1]
            kind, reference = "unknown", None
            if tag == 0:
                kind = "register"
                registers.append(int(value))
            elif tag == 1:
                kind = "literal"
            elif tag == 3:
                kind = "branch"
                value = {"relative_code_units": int(value), "target_offset_bytes": offset + int(value) * 2}
            elif tag == 256:
                kind = "method"
                value = _method_signature(dex.get_methods()[int(value)])
                reference = method_ids.get(int(item[1]))
            elif tag == 257:
                kind, value = "string", item[2]
            elif tag == 258:
                kind = "field"
                value = _field_signature(dex.get_fields()[int(value)])
                reference = field_ids.get(int(item[1]))
            elif tag == 259:
                kind, value = "type", dex.CM.get_type(int(value))
            else:
                value = list(item[1:])
            operands.append(Operand(index=index, kind=kind, reference_ref=reference, encoded_kind=tag,
                                    value=ValueInfo(status="known", value=_json_value(value))))
        operation = "invoke" if name.startswith("invoke-") else "constant" if name.startswith("const") else (
            "assignment" if name.startswith("move") else "field_read" if name.startswith(("iget", "sget")) else
            "field_write" if name.startswith(("iput", "sput")) else "array_read" if name.startswith("aget") else
            "array_write" if name.startswith("aput") else "branch" if name.startswith(("if-", "goto", "packed-switch", "sparse-switch")) and "payload" not in name else
            "return" if name.startswith("return") else "allocation" if name.startswith(("new-", "filled-new-array")) else "other")
        slots, target, invoke_kind = [], None, None
        complete = True
        if operation == "invoke":
            invoke_kind = name.removeprefix("invoke-").split("/")[0]
            known = next((operand for operand in operands if operand.kind == "method"), None)
            if invoke_kind not in {"static", "direct", "virtual", "interface", "super", "custom", "polymorphic"}:
                invoke_kind = "custom"
            target = MethodTarget(signature=known.value.value, method_ref=known.reference_ref) if known else MethodTarget(
                signature=None, unknown_reason="Dynamic/unsupported encoded call target; raw bytes and operands preserved")
            complete = known is not None and invoke_kind not in {"custom", "polymorphic"}
            used = 0
            if invoke_kind not in {"static", "custom"} and registers:
                slots.append(ProgramSlot(slot_kind="receiver", registers=[registers[0]], value=ValueInfo(status="unknown", reason="Runtime receiver object")))
                used = 1
            if complete:
                for index, descriptor in enumerate(parse_method_signature(target.signature)[2]):
                    width = 2 if descriptor in {"J", "D"} else 1
                    selected = registers[used:used + width]
                    if len(selected) != width:
                        raise ValueError("Encoded argument register count disagrees with descriptor")
                    slots.append(ProgramSlot(slot_kind="argument", slot_index=index, registers=selected,
                        type_descriptor=descriptor, value=ValueInfo(status="unknown", reason="Runtime argument value; encoded registers are preserved")))
                    used += width
                if used != len(registers):
                    raise ValueError("Unconsumed invocation registers")
        elif registers:
            is_result = operation in {"assignment", "constant", "allocation", "field_read", "array_read"}
            if is_result:
                value = next((operand.value for operand in operands if operand.kind in {"literal", "string"}), None) if operation == "constant" else None
                slots.append(ProgramSlot(slot_kind="result", registers=[registers[0], registers[0] + 1] if "wide" in name else registers[:1],
                    value=value or ValueInfo(status="unknown", reason="Operation result needs analysis")))
            for register in sorted(set(registers)):
                slots.append(ProgramSlot(slot_kind="local", slot_index=register, registers=[register],
                    value=ValueInfo(status="unknown", reason="Runtime register value")))
        return InstructionRecord(id=self.identity("instruction", [method.id, offset]), run_ref=self.run.run_id,
            provenance=self.direct(), kind="instruction", position=InstructionPosition.at(method.position.dex_ref, method.id, offset),
            opcode=name, operation=operation, operands=operands, slots=slots, slots_complete=complete,
            invoke_kind=invoke_kind, declared_target=target, raw_hex=bytes(raw.get_raw()).hex(), length_bytes=raw.get_length())

    def resolve_references(self) -> None:
        definitions = defaultdict(list)
        classes = defaultdict(list)
        for record in self.elements.values():
            if isinstance(record, (MethodRecord, FieldRecord)) and record.is_definition:
                definitions[(record.kind, record.signature)].append(record)
            if isinstance(record, ClassRecord):
                classes[record.descriptor].append(record)
        for record in list(self.elements.values()):
            targets = []
            if isinstance(record, (MethodRecord, FieldRecord)) and not record.is_definition:
                targets = definitions[(record.kind, record.signature)]
            elif isinstance(record, TypeReferenceRecord):
                targets = classes[record.descriptor]
            for target in targets:
                self.relations.append(RelationRecord(id=self.identity("relation", ["reference_resolution", record.id, target.id]),
                    run_ref=self.run.run_id, provenance=self.derived(record.id, target.id), relation_kind="reference_resolution",
                    source=Endpoint(element_ref=record.id, slot_kind="element"), target=Endpoint(element_ref=target.id, slot_kind="element"),
                    resolution="resolved" if len(targets) == 1 else "partial",
                    unresolved_reason=None if len(targets) == 1 else "Multiple matching definitions; no unique target inferred"))
            if isinstance(record, InstructionRecord) and record.declared_target and record.declared_target.method_ref:
                self.relations.append(RelationRecord(id=self.identity("relation", ["declared_call", record.id]),
                    run_ref=self.run.run_id, provenance=Provenance(kind="direct", tool_ref="tool:androguard", support_refs=[record.id, record.declared_target.method_ref]),
                    relation_kind="declared_call", source=self.endpoint(record, "element"),
                    target=Endpoint(element_ref=record.declared_target.method_ref, slot_kind="entry"), resolution="resolved"))
            if isinstance(record, InstructionRecord) and record.result_receiver_ref:
                receiver = self.elements[record.result_receiver_ref]
                if record.operation == "invoke":
                    self.relations.append(RelationRecord(id=self.identity("relation", ["call_result_assignment", record.id]),
                        run_ref=self.run.run_id, provenance=self.derived(record.id, receiver.id), relation_kind="call_result_assignment",
                        source=self.endpoint(record, "result"), target=self.endpoint(receiver, "result"), resolution="resolved"))

    @staticmethod
    def endpoint(record: InstructionRecord, kind: str, index: int | None = None) -> Endpoint:
        return Endpoint(element_ref=record.id, slot_kind=kind, slot_index=index, position_label=record.position.position_label)

    def resource_references(self) -> None:
        # Typed AXML resource references are explicit, not coincidentally equal integer constants.
        for config in self.config_records:
            for name, value in config.value.value["attributes"].items():
                match = re.fullmatch(r"@(?:0x)?([0-9a-fA-F]{8})", value)
                if match:
                    rid = int(match[1], 16)
                    for target in self.resources.get(rid, []):
                        self.relations.append(RelationRecord(id=self.identity("relation", ["resource_reference", config.id, name, target.id]),
                            run_ref=self.run.run_id, provenance=self.derived(config.id, target.id), relation_kind="resource_reference",
                            source=Endpoint(element_ref=config.id, slot_kind="value"), target=Endpoint(element_ref=target.id, slot_kind="value"),
                            source_selector=config.position.selector + "/@" + name,
                            resolution="resolved" if len(self.resources[rid]) == 1 else "partial",
                            unresolved_reason=None if len(self.resources[rid]) == 1 else "Resource qualifier selection depends on runtime configuration"))
        class_parents = {record.descriptor: record.superclass for record in self.elements.values() if isinstance(record, ClassRecord)}
        framework = {"Landroid/content/Context;", "Landroid/app/Activity;", "Landroid/app/Application;", "Landroid/app/Service;", "Landroid/content/res/Resources;"}
        for instructions in self.method_code.values():
            method = self.elements[instructions[0].position.method_ref] if instructions else None
            simple = method is not None and not method.exception_handlers_count and not any(item.operation == "branch" for item in instructions)
            for previous, call in zip(instructions, instructions[1:]):
                if call.declared_target is None or call.declared_target.signature is None:
                    continue
                owner, name, parameters, _ = parse_method_signature(call.declared_target.signature)
                visited = set()
                while owner in class_parents and owner not in visited:
                    visited.add(owner)
                    owner = class_parents[owner]
                if owner not in framework or name not in {"getString", "getText", "getDrawable", "getColor", "getInteger", "getBoolean", "getDimension"} or not parameters or parameters[0] != "I":
                    continue
                argument = next((slot for slot in call.slots if slot.slot_kind == "argument" and slot.slot_index == 0), None)
                result = next((slot for slot in previous.slots if slot.slot_kind == "result"), None)
                if (simple and previous.operation == "constant" and argument is not None and result is not None
                        and result.registers == argument.registers and type(result.value.value) is int):
                    for resource in self.resources.get(result.value.value, []):
                        self.relations.append(RelationRecord(id=self.identity("relation", ["resource_use", resource.id, call.id]),
                            run_ref=self.run.run_id, provenance=self.derived(resource.id, previous.id, call.id), relation_kind="resource_use",
                            source=Endpoint(element_ref=resource.id, slot_kind="value"), target=self.endpoint(call, "argument", 0),
                            resolution="resolved" if len(self.resources[result.value.value]) == 1 else "partial",
                            unresolved_reason=None if len(self.resources[result.value.value]) == 1 else "Resource qualifier selection depends on runtime configuration"))
                else:
                    self.issue("resources", "resource_argument_unresolved", "Resource API argument requires analysis beyond the straight-line adjacent-constant rule", element_ref=call.id)


def extract_apk(path: str | Path, configuration: FactConfig | None = None) -> ExtractionResult:
    return Extractor(path, configuration).extract()


def write_extraction(result: ExtractionResult, output_root: str | Path) -> Path:
    # Validate before making a new result directory; previous runs are never overwritten.
    loads_facts(result.facts.model_dump_json())
    for digest, data in result.blobs.items():
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Evidence content does not match its SHA-256 identity")
    if any(digest not in result.blobs for digest in result.entry_digests.values()):
        raise ValueError("Evidence manifest refers to an absent blob")
    run_key = result.facts.run.run_id.replace(":", "_")
    base = filesystem_path(output_root)
    final = base / result.facts.run.apk_sha256 / run_key
    output = final.with_name(".building_" + run_key)
    final.resolve().relative_to(base)
    output.resolve().relative_to(base)
    if final.exists():
        raise FileExistsError(f"Accepted run already exists: {final}")
    output.mkdir(parents=True, exist_ok=False)
    evidence = output / "evidence"
    evidence.mkdir()
    files = []
    for digest, data in sorted(result.blobs.items()):
        (evidence / digest).write_bytes(data)
    for entry, digest in sorted(result.entry_digests.items()):
        files.append({"archive_entry": entry, "sha256": digest, "path": f"evidence/{digest}", "bytes": len(result.blobs[digest])})
    dump_facts(result.facts, output / "facts.json")
    for filename, value in [("summary.json", result.summary), ("run.json", result.facts.run.model_dump(mode="json")),
                            ("manifest.json", {"schema_version": "fact-evidence.v1", "run_ref": result.facts.run.run_id, "files": files,
                                               "facts_sha256": sha256_file(output / "facts.json")})]:
        (output / filename).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    # Both directory paths are verified under the explicitly selected output root.
    output.rename(final)
    return final
