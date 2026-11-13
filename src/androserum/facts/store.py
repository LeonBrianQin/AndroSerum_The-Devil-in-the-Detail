"""F2 immutable SQLite snapshots; projections are derived from one typed payload per record."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import binascii
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import zipfile
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, TypeAdapter, model_validator

from androserum import __version__
from androserum.facts.exchange import ADAPTERS, SECTIONS, assemble, export_jsonl, iter_records, load_jsonl, metadata_for, record_identity
from androserum.facts.identity import archive_path, canonical_json, filesystem_path, fingerprint, method_signature, parse_method_signature, sha256_file
from androserum.facts.io import dump_facts, load_facts, loads_facts, strict_json_syntax
from androserum.facts.models import (
    AnalysisNodeRecord, AnalysisStatus, ArchivePosition, BindingRecord, ConditionRecord,
    ConfigurationRecord, ContextRecord, DexDeclarationPosition, DexRecord, Endpoint, FactBundle,
    Capability, FieldRecord, InstructionRecord, MethodRecord, NonNegative, ParameterRecord, Ref, RelationKind,
    RelationRecord, ResourceRecord, SHA256, StrictModel, VersionedArtifact,
)
from androserum.facts.validation import check_facts, walk_models

STORE_VERSION = "fact-store.v1"
SNAPSHOT_VERSION = "fact-snapshot.v1"
QUERY_VERSION = "fact-query.v1"
APPLICATION_ID = 0x4153524D


class EvidenceFile(StrictModel):
    archive_entry: str
    sha256: SHA256
    path: str
    bytes: NonNegative

    @model_validator(mode="after")
    def relative_names(self):
        archive_path(self.archive_entry)
        archive_path(self.path)
        if self.path.startswith("evidence/base64-v1/") and self.path != f"evidence/base64-v1/{self.sha256}.b64":
            raise ValueError("Encoded evidence path must name its original content SHA-256")
        if self.path.startswith("evidence/apk-entry-v1/") and self.path != f"evidence/apk-entry-v1/{self.sha256}.json":
            raise ValueError("APK-entry descriptor must name its original content SHA-256")
        return self


class SnapshotManifest(StrictModel):
    schema_version: Literal["fact-snapshot.v1"] = SNAPSHOT_VERSION
    store_version: Literal["fact-store.v1"] = STORE_VERSION
    query_version: Literal["fact-query.v1"] = QUERY_VERSION
    fact_schema_version: Literal["program-facts.v2"] = "program-facts.v2"
    state: Literal["published"] = "published"
    run_ref: Ref
    apk_sha256: SHA256
    snapshot_id: SHA256
    database: Literal["facts.sqlite"] = "facts.sqlite"
    database_sha256: SHA256
    counts: dict[str, NonNegative]
    files: list[EvidenceFile]
    coverage: dict[str, str]
    created_at: str
    writer_version: str


class RefFilter(StrictModel):
    mode: Literal["all", "missing", "exact", "exact_or_missing"]
    ref: Ref | None = None

    @model_validator(mode="after")
    def explicit_mode(self):
        if (self.mode in {"exact", "exact_or_missing"}) != (self.ref is not None):
            raise ValueError("Only exact/exact_or_missing filters require a reference")
        return self


@dataclass
class QueryResult:
    run_ref: str
    snapshot_id: str
    records: list[BaseModel]
    total_matches: int
    coverage: dict[str, str]
    truncated: bool = False
    missing_refs: list[str] = field(default_factory=list)
    issues: list[AnalysisStatus] = field(default_factory=list)
    issues_truncated: bool = False
    files: list[EvidenceFile] = field(default_factory=list)
    filters: dict = field(default_factory=dict)
    is_subset: bool = False
    pending_refs: list[str] = field(default_factory=list)

    def to_dict(self):
        return {"schema_version": QUERY_VERSION, "run_ref": self.run_ref, "snapshot_id": self.snapshot_id,
                "records": [record.model_dump(mode="json") for record in self.records], "total_matches": self.total_matches,
                "returned_count": len(self.records), "coverage": self.coverage, "truncated": self.truncated,
                "missing_refs": self.missing_refs, "issues": [issue.model_dump(mode="json") for issue in self.issues],
                "issues_truncated": self.issues_truncated, "files": [value.model_dump(mode="json") for value in self.files],
                "filters": self.filters, "is_subset": self.is_subset, "pending_refs": self.pending_refs,
                "path_compatibility_checked": False}


def _json_read(path: Path):
    text = path.read_text(encoding="utf-8-sig")
    strict_json_syntax(text)
    return json.loads(text)


def _json_write(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _inside(root: Path, relative: str) -> Path:
    archive_path(relative)
    candidate = filesystem_path(root / relative)
    candidate.relative_to(filesystem_path(root))
    return candidate


def evidence_is_encoded(item: EvidenceFile) -> bool:
    """The namespace declares a codec; original identities remain unchanged."""
    return item.path.startswith("evidence/base64-v1/")


def evidence_is_apk_entry(item: EvidenceFile) -> bool:
    return item.path.startswith("evidence/apk-entry-v1/")


def apk_entry_descriptor(root: str | Path, item: EvidenceFile) -> dict:
    """Read a bounded, strictly package-local original-APK reference."""
    path = _inside(filesystem_path(root), item.path)
    if path.stat().st_size > 65536:
        raise ValueError('APK-entry descriptor exceeds its metadata budget')
    value = _json_read(path)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'container_path', 'container_sha256',
            'archive_entries', 'content_sha256', 'content_bytes'} or
            value.get('schema_version') != 'apk-entry-evidence.v1' or
            value.get('content_sha256') != item.sha256 or value.get('content_bytes') != item.bytes or
            not isinstance(value.get('container_sha256'), str) or
            len(value['container_sha256']) != 64 or
            any(c not in '0123456789abcdef' for c in value['container_sha256']) or
            value.get('container_path') != 'evidence/source-apk/' + value['container_sha256'] + '.apk'):
        raise ValueError('APK-entry descriptor identity differs')
    entries = value['archive_entries']
    if (not isinstance(entries, list) or not entries or not all(isinstance(e,str) for e in entries) or
            len(entries) != len(set(entries)) or item.archive_entry not in entries):
        raise ValueError('APK-entry descriptor does not bind this original entry')
    for entry in entries:
        archive_path(entry)
    _inside(filesystem_path(root), value['container_path'])
    return value


def copy_evidence_storage(source_root, destination_root, item: EvidenceFile, destination: EvidenceFile | None = None):
    """Copy storage as storage, preserving inert references and containers."""
    source_root, destination_root = filesystem_path(source_root), filesystem_path(destination_root)
    target = _inside(destination_root, (destination or item).path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copyfile(_inside(source_root, item.path), target)
    if evidence_is_apk_entry(item):
        descriptor = apk_entry_descriptor(source_root, item)
        container = _inside(destination_root, descriptor['container_path'])
        container.parent.mkdir(parents=True, exist_ok=True)
        if not container.exists():
            shutil.copyfile(_inside(source_root, descriptor['container_path']), container)


def read_evidence_file(root: str | Path, item: EvidenceFile) -> bytes:
    """Return checked original bytes in memory, without materializing code.

    Existing raw packages remain the default. The explicit base64 namespace is
    canonical ASCII storage only; malformed, wrong-size or wrong-hash content
    is rejected rather than treated as an alternate encoding or executed.
    """
    item = EvidenceFile.model_validate(item.model_dump())
    if evidence_is_apk_entry(item):
        descriptor = apk_entry_descriptor(root, item)
        container = _inside(filesystem_path(root), descriptor['container_path'])
        if sha256_file(container) != descriptor['container_sha256']:
            raise ValueError('Original APK container checksum mismatch')
        with zipfile.ZipFile(container) as archive:
            if archive.namelist().count(item.archive_entry) != 1 or archive.getinfo(item.archive_entry).file_size != item.bytes:
                raise ValueError('Original APK entry is ambiguous or has the wrong size')
            data = archive.read(item.archive_entry)
        if len(data) != item.bytes or hashlib.sha256(data).hexdigest() != item.sha256:
            raise ValueError('Original APK entry checksum mismatch')
        return data
    data = _inside(filesystem_path(root), item.path).read_bytes()
    if evidence_is_encoded(item):
        if len(data) != 4 * ((item.bytes + 2) // 3):
            raise ValueError(f"Encoded evidence length mismatch: {item.archive_entry}")
        try:
            decoded = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError(f"Invalid base64 evidence: {item.archive_entry}") from error
        if base64.b64encode(decoded) != data:
            raise ValueError(f"Non-canonical base64 evidence: {item.archive_entry}")
        data = decoded
    if len(data) != item.bytes or hashlib.sha256(data).hexdigest() != item.sha256:
        raise ValueError(f"Evidence content checksum mismatch: {item.archive_entry}")
    return data


def _record_json(record: BaseModel) -> str:
    return canonical_json(record.model_dump(mode="json"))


def endpoint_key(run_ref: str, endpoint: Endpoint) -> str:
    return fingerprint([run_ref, endpoint.model_dump(mode="json")])


def _file_identity(files):
    # Resolver paths are packaging details; original entry names and bytes are content.
    return sorted([{"archive_entry": item.archive_entry, "sha256": item.sha256, "bytes": item.bytes}
                   for item in files], key=lambda value: value["archive_entry"])


def logical_digest(facts: FactBundle, files: list[EvidenceFile]) -> str:
    digest = hashlib.sha256((canonical_json(metadata_for(facts)) + "\n").encode("utf-8"))
    # Record order is part of the exchanged bundle; payload key order is normalized.
    for section, ordinal, record in iter_records(facts):
        digest.update((canonical_json([section, ordinal, record.model_dump(mode="json")]) + "\n").encode("utf-8"))
    digest.update(canonical_json(_file_identity(files)).encode("utf-8"))
    return digest.hexdigest()


SCHEMA_SQL = """
CREATE TABLE analysis_runs (
 run_id TEXT PRIMARY KEY, store_version TEXT NOT NULL, metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
 apk_sha256 TEXT NOT NULL, snapshot_id TEXT NOT NULL
);
CREATE TABLE records (
 run_id TEXT NOT NULL, record_id TEXT NOT NULL, section TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 kind TEXT NOT NULL, payload_json TEXT NOT NULL CHECK(json_valid(payload_json)), payload_sha256 TEXT NOT NULL,
 PRIMARY KEY(run_id,record_id), UNIQUE(run_id,section,ordinal), FOREIGN KEY(run_id) REFERENCES analysis_runs(run_id)
);
CREATE TABLE evidence_files (
 run_id TEXT NOT NULL, entry TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL CHECK(bytes>=0), path TEXT NOT NULL,
 PRIMARY KEY(run_id,entry), FOREIGN KEY(run_id) REFERENCES analysis_runs(run_id)
);
CREATE TABLE program_elements (
 run_id TEXT NOT NULL, record_id TEXT NOT NULL, kind TEXT NOT NULL, dex_ref TEXT, method_ref TEXT, signature TEXT,
 descriptor TEXT, offset_bytes INTEGER, operation TEXT, declared_signature TEXT, is_definition INTEGER,
 resource_id INTEGER, qualifiers TEXT, archive_path TEXT,
 PRIMARY KEY(run_id,record_id), FOREIGN KEY(run_id,record_id) REFERENCES records(run_id,record_id),
 FOREIGN KEY(run_id,dex_ref) REFERENCES records(run_id,record_id), FOREIGN KEY(run_id,method_ref) REFERENCES records(run_id,record_id)
);
CREATE TABLE endpoints (
 run_id TEXT NOT NULL, endpoint_key TEXT NOT NULL, element_ref TEXT NOT NULL, position_label TEXT,
 slot_kind TEXT NOT NULL, slot_index INTEGER, slot_label TEXT,
 PRIMARY KEY(run_id,endpoint_key), FOREIGN KEY(run_id,element_ref) REFERENCES program_elements(run_id,record_id)
);
CREATE TABLE relations (
 run_id TEXT NOT NULL, record_id TEXT NOT NULL, kind TEXT NOT NULL, source_key TEXT NOT NULL, target_key TEXT,
 source_element TEXT NOT NULL, target_element TEXT, context_ref TEXT, callsite_ref TEXT, resolution TEXT NOT NULL,
 candidate_signature TEXT,
 PRIMARY KEY(run_id,record_id), FOREIGN KEY(run_id,record_id) REFERENCES records(run_id,record_id),
 FOREIGN KEY(run_id,source_key) REFERENCES endpoints(run_id,endpoint_key), FOREIGN KEY(run_id,target_key) REFERENCES endpoints(run_id,endpoint_key),
 FOREIGN KEY(run_id,context_ref) REFERENCES records(run_id,record_id), FOREIGN KEY(run_id,callsite_ref) REFERENCES records(run_id,record_id)
);
CREATE TABLE record_refs (
 run_id TEXT NOT NULL, owner_id TEXT NOT NULL, path TEXT NOT NULL, role TEXT NOT NULL, ordinal INTEGER NOT NULL,
 target_id TEXT NOT NULL, PRIMARY KEY(run_id,owner_id,path),
 FOREIGN KEY(run_id,owner_id) REFERENCES records(run_id,record_id), FOREIGN KEY(run_id,target_id) REFERENCES records(run_id,record_id)
);
CREATE TABLE record_endpoints (
 run_id TEXT NOT NULL, owner_id TEXT NOT NULL, path TEXT NOT NULL, endpoint_key TEXT NOT NULL,
 PRIMARY KEY(run_id,owner_id,path), FOREIGN KEY(run_id,owner_id) REFERENCES records(run_id,record_id),
 FOREIGN KEY(run_id,endpoint_key) REFERENCES endpoints(run_id,endpoint_key)
);
CREATE TABLE contexts (
 run_id TEXT NOT NULL, record_id TEXT NOT NULL, abstraction TEXT NOT NULL, parent_ref TEXT, truncated INTEGER NOT NULL,
 PRIMARY KEY(run_id,record_id), FOREIGN KEY(run_id,record_id) REFERENCES records(run_id,record_id),
 FOREIGN KEY(run_id,parent_ref) REFERENCES contexts(run_id,record_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE context_calls (
 run_id TEXT NOT NULL, context_ref TEXT NOT NULL, ordinal INTEGER NOT NULL, callsite_ref TEXT NOT NULL,
 PRIMARY KEY(run_id,context_ref,ordinal), FOREIGN KEY(run_id,context_ref) REFERENCES contexts(run_id,record_id),
 FOREIGN KEY(run_id,callsite_ref) REFERENCES records(run_id,record_id)
);
CREATE TABLE bindings (
 run_id TEXT NOT NULL, record_id TEXT NOT NULL, kind TEXT NOT NULL, context_ref TEXT,
 PRIMARY KEY(run_id,record_id), FOREIGN KEY(run_id,record_id) REFERENCES records(run_id,record_id),
 FOREIGN KEY(run_id,context_ref) REFERENCES contexts(run_id,record_id)
);
CREATE TABLE analysis_statuses (
 run_id TEXT NOT NULL, record_id TEXT NOT NULL, capability TEXT NOT NULL, scope_kind TEXT NOT NULL,
 element_ref TEXT, location_path TEXT, state TEXT NOT NULL, issue_code TEXT,
 PRIMARY KEY(run_id,record_id), FOREIGN KEY(run_id,record_id) REFERENCES records(run_id,record_id),
 FOREIGN KEY(run_id,element_ref) REFERENCES program_elements(run_id,record_id)
);
CREATE TABLE record_files (
 run_id TEXT NOT NULL, record_id TEXT NOT NULL, entry TEXT NOT NULL,
 PRIMARY KEY(run_id,record_id,entry), FOREIGN KEY(run_id,record_id) REFERENCES records(run_id,record_id),
 FOREIGN KEY(run_id,entry) REFERENCES evidence_files(run_id,entry)
);
CREATE INDEX method_signature ON program_elements(run_id,signature,dex_ref);
CREATE INDEX declared_calls ON program_elements(run_id,declared_signature,method_ref,offset_bytes);
CREATE INDEX instruction_location ON program_elements(run_id,method_ref,offset_bytes);
CREATE INDEX resource_location ON program_elements(run_id,resource_id,qualifiers,archive_path);
CREATE INDEX source_relations ON relations(run_id,source_key,kind,context_ref);
CREATE INDEX target_relations ON relations(run_id,target_key,kind,context_ref);
CREATE INDEX relation_targets ON relations(run_id,target_element,kind);
CREATE INDEX relation_sources ON relations(run_id,source_element,kind);
CREATE INDEX call_bindings ON relations(run_id,callsite_ref,kind,context_ref);
CREATE INDEX candidate_calls ON relations(run_id,candidate_signature,kind,source_element);
CREATE INDEX forward_refs ON record_refs(run_id,owner_id,role,target_id);
CREATE INDEX reverse_refs ON record_refs(run_id,target_id,role,owner_id);
CREATE INDEX endpoint_elements ON endpoints(run_id,element_ref,slot_kind,slot_index);
CREATE INDEX status_scopes ON analysis_statuses(run_id,capability,scope_kind,element_ref,location_path);
CREATE VIEW binding_endpoints AS SELECT e.* FROM record_endpoints e JOIN bindings b
 ON e.run_id=b.run_id AND e.owner_id=b.record_id WHERE e.path LIKE 'endpoints[%';
CREATE VIEW tools AS SELECT * FROM records WHERE section='tools';
CREATE VIEW artifacts AS SELECT * FROM records WHERE section='artifacts';
"""
PROJECTION_TABLES = ("program_elements", "endpoints", "relations", "record_refs", "record_endpoints", "contexts",
                     "context_calls", "bindings", "analysis_statuses", "record_files")


def _projection(facts: FactBundle, files: list[EvidenceFile]) -> dict[str, list[tuple]]:
    run = facts.run.run_id
    rows = {name: [] for name in PROJECTION_TABLES}
    elements = {record.id: record for record in facts.elements}
    entries = {item.archive_entry for item in files}
    endpoints = {}

    def endpoint(value):
        key = endpoint_key(run, value)
        endpoints[key] = (run, key, value.element_ref, value.position_label, value.slot_kind, value.slot_index, value.slot_label)
        return key

    def add_slots(record):
        label = getattr(getattr(record, "position", None), "position_label", None)
        def add(kind, index=None, slot_label=None):
            endpoint(Endpoint(element_ref=record.id, position_label=label, slot_kind=kind, slot_index=index, slot_label=slot_label))
        add("element")
        if isinstance(record, MethodRecord):
            _, _, parameters, result = parse_method_signature(record.signature)
            add("entry")
            for i in range(len(parameters)):
                add("parameter", i)
            if record.is_static is False:
                add("receiver")
            if result != "V":
                add("return")
        elif isinstance(record, (ParameterRecord, FieldRecord, ConfigurationRecord, ResourceRecord)):
            add("value")
        elif isinstance(record, ConditionRecord):
            add("value")
            add("condition")
        elif isinstance(record, (InstructionRecord, AnalysisNodeRecord)):
            for value in record.slots:
                add(value.slot_kind, value.slot_index, value.slot_label)
            if isinstance(record, AnalysisNodeRecord) and record.node_kind == "entry":
                add("entry")

    def file_for(record, visited=None):
        visited = set() if visited is None else visited
        if record is None or record.id in visited:
            return None
        visited.add(record.id)
        position = getattr(record, "position", None)
        if isinstance(position, ArchivePosition):
            return position.path if position.path in entries else None
        path = getattr(position, "artifact_path", None)
        if path in entries:
            return path
        reference = getattr(position, "dex_ref", None) or getattr(record, "method_ref", None) or getattr(record, "branch_ref", None)
        return file_for(elements.get(reference), visited) if reference else None

    for record in facts.elements:
        position = getattr(record, "position", None)
        dex_ref = getattr(position, "dex_ref", None)
        method_ref = getattr(position, "method_ref", None) or getattr(record, "method_ref", None)
        rows["program_elements"].append((run, record.id, record.kind, dex_ref, method_ref,
            getattr(record, "signature", None), getattr(record, "descriptor", None), getattr(position, "offset_bytes", None),
            getattr(record, "operation", None), record.declared_target.signature if isinstance(record, InstructionRecord) and record.declared_target else None,
            int(record.is_definition) if isinstance(record, (MethodRecord, FieldRecord)) else None,
            getattr(record, "resource_id", None), getattr(record, "qualifiers", None), getattr(position, "path", None)))
        add_slots(record)
        entry = file_for(record)
        if entry:
            rows["record_files"].append((run, record.id, entry))
    for section, _, record in iter_records(facts):
        owner = record_identity(section, record)
        if isinstance(record, VersionedArtifact) and record.location in entries:
            rows["record_files"].append((run, owner, record.location))
        for value, path in walk_models(record, ""):
            path = path.removeprefix(".")
            if isinstance(value, Endpoint):
                rows["record_endpoints"].append((run, owner, path, endpoint(value)))
            # Inspect typed models only. Strings inside code/resources/JsonValue are never references.
            for name in type(value).model_fields:
                if name == "run_ref":
                    continue
                reference = getattr(value, name)
                target_path = (path + "." if path else "") + name
                if name.endswith("_ref") and reference is not None:
                    rows["record_refs"].append((run, owner, target_path, name, 0, reference))
                elif name.endswith("_refs"):
                    for i, target in enumerate(reference):
                        rows["record_refs"].append((run, owner, f"{target_path}[{i}]", name, i, target))
        if isinstance(record, RelationRecord):
            target = elements.get(record.target.element_ref) if record.target else None
            rows["relations"].append((run, record.id, record.relation_kind, endpoint(record.source),
                endpoint(record.target) if record.target else None, record.source.element_ref,
                record.target.element_ref if record.target else None, record.context_ref, record.callsite_ref, record.resolution,
                target.signature if record.relation_kind == "candidate_call" and isinstance(target, MethodRecord) else None))
        elif isinstance(record, ContextRecord):
            rows["contexts"].append((run, record.id, record.abstraction, record.parent_ref, int(record.truncated)))
            rows["context_calls"].extend((run, record.id, i, ref) for i, ref in enumerate(record.callsite_refs))
        elif isinstance(record, BindingRecord):
            rows["bindings"].append((run, record.id, record.binding_kind, record.context_ref))
        elif isinstance(record, AnalysisStatus):
            location = record.scope.location
            rows["analysis_statuses"].append((run, record.id, record.capability, record.scope.kind, record.scope.element_ref,
                getattr(location, "path", None) or getattr(location, "artifact_path", None), record.state, record.issue_code))
    rows["endpoints"] = list(endpoints.values())
    return rows


def _batches(values, size=500):
    batch = []
    for value in values:
        batch.append(value)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def _insert_records(connection, facts):
    def values():
        for section, ordinal, record in iter_records(facts):
            payload = _record_json(record)
            yield (facts.run.run_id, record_identity(section, record), section, ordinal,
                   getattr(record, "kind", section), payload, hashlib.sha256(payload.encode("utf-8")).hexdigest())
    for batch in _batches(values()):
        connection.executemany("INSERT INTO records VALUES (?,?,?,?,?,?,?)", batch)


def _insert_projection(connection, rows):
    for table in PROJECTION_TABLES:
        values = rows[table]
        for batch in _batches(values):
            placeholders = ",".join("?" for _ in batch[0])
            connection.executemany(f"INSERT INTO {table} VALUES ({placeholders})", batch)


def _bundle_from_connection(connection) -> FactBundle:
    header = connection.execute("SELECT metadata_json FROM analysis_runs").fetchall()
    if len(header) != 1:
        raise ValueError("A snapshot must contain exactly one analysis run")
    metadata = json.loads(header[0][0])
    def records():
        for section in SECTIONS:
            for row in connection.execute("SELECT ordinal,payload_json FROM records WHERE section=? ORDER BY ordinal", (section,)):
                yield section, row[0], ADAPTERS[section].validate_json(row[1])
    return assemble(metadata, records())


def _check_connection(connection, facts, files):
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("SQLite integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise ValueError("SQLite foreign key check failed")
    for payload, digest in connection.execute("SELECT payload_json,payload_sha256 FROM records"):
        if hashlib.sha256(payload.encode("utf-8")).hexdigest() != digest:
            raise ValueError("Record payload digest mismatch")
    expected = _projection(facts, files)
    for table in PROJECTION_TABLES:
        actual = connection.execute(f"SELECT * FROM {table}").fetchall()
        if Counter(actual) != Counter(expected[table]):
            raise ValueError(f"Projection differs from typed records: {table}")


def _validate_files(facts, files, source_root, *, require_direct=True):
    if len({item.archive_entry for item in files}) != len(files):
        raise ValueError("Duplicate evidence entry names")
    by_entry = {item.archive_entry: item for item in files}
    for artifact in facts.run.artifacts:
        if artifact.location in by_entry and artifact.sha256 is not None and by_entry[artifact.location].sha256 != artifact.sha256:
            raise ValueError("Rule/model artifact checksum differs from its evidence entry")
    for item in files:
        if source_root is None:
            raise ValueError("Evidence files require an explicit source root")
        if evidence_is_encoded(item) or evidence_is_apk_entry(item):
            if evidence_is_apk_entry(item) and facts.run.input_kind == 'apk':
                descriptor = apk_entry_descriptor(source_root, item)
                if descriptor['container_sha256'] != facts.run.apk_sha256:
                    raise ValueError('Evidence container differs from the analyzed APK')
            read_evidence_file(source_root, item)
        else:
            path = _inside(source_root, item.path)
            if path.stat().st_size != item.bytes or sha256_file(path) != item.sha256:
                raise ValueError(f"Evidence missing/corrupt: {item.archive_entry}")
    for record in facts.elements:
        if isinstance(record, DexRecord):
            item = by_entry.get(record.position.path)
            if item is None:
                if require_direct:
                    raise ValueError(f"DEX evidence missing: {record.position.path}")
            elif (item.sha256, item.bytes) != (record.sha256, record.size_bytes):
                raise ValueError("DEX identity and evidence file disagree")
        position = getattr(record, "position", None)
        if require_direct and isinstance(record, (ConfigurationRecord, ResourceRecord)) and position.path not in by_entry:
            raise ValueError(f"Direct evidence missing: {position.path}")


def create_snapshot(facts: FactBundle, output_root: str | Path, *, files: list[EvidenceFile] | None = None,
                    evidence_root: str | Path | None = None) -> Path:
    """Publish one validated, self-contained run; synthetic contracts may omit raw blobs explicitly."""
    facts = loads_facts(facts.model_dump_json())
    files = [EvidenceFile.model_validate(item.model_dump()) for item in (files or [])]
    source_root = filesystem_path(evidence_root) if evidence_root else None
    _validate_files(facts, files, source_root, require_direct=facts.run.input_kind == "apk")
    from androserum.facts.jimple import verify_jimple_evidence
    by_entry = {item.archive_entry: item for item in files}
    def read_ir_entry(entry):
        if entry not in by_entry:
            raise ValueError("Structured IR evidence is missing: " + entry)
        return read_evidence_file(source_root, by_entry[entry])
    verify_jimple_evidence(facts, read_ir_entry)
    from androserum.facts.local_flow import verify_local_flow_evidence
    verify_local_flow_evidence(facts, read_ir_entry)
    from androserum.facts.call_flow import verify_call_evidence
    verify_call_evidence(facts, read_ir_entry)
    from androserum.facts.heap_flow import verify_heap_evidence
    verify_heap_evidence(facts, read_ir_entry)
    from androserum.facts.context_heap import verify_context_heap
    verify_context_heap(facts, read_ir_entry)
    from androserum.facts.selected_flow import verify_selected_flow
    verify_selected_flow(facts, read_ir_entry)
    from androserum.facts.points_to import verify_points_to
    verify_points_to(facts, read_ir_entry)
    from androserum.facts.operations import verify_operations
    verify_operations(facts, read_ir_entry)
    from androserum.facts.buffer_state import verify_buffer_state
    verify_buffer_state(facts, read_ir_entry)
    from androserum.facts.jca_state import verify_jca_state
    verify_jca_state(facts, read_ir_entry)
    from androserum.facts.method_outputs import verify_method_outputs
    verify_method_outputs(facts, read_ir_entry)
    from androserum.facts.audio_read_sites import verify_audio_read_sites
    verify_audio_read_sites(facts, read_ir_entry)
    from androserum.facts.control import verify_control
    verify_control(facts, read_ir_entry)
    from androserum.facts.events import verify_events
    verify_events(facts, read_ir_entry)
    portable_files = [item.model_copy(update={"path": item.path if evidence_is_apk_entry(item) else
                                             f"evidence/base64-v1/{item.sha256}.b64" if evidence_is_encoded(item)
                                             else f"evidence/{item.sha256}"}) for item in files]
    snapshot_id = logical_digest(facts, portable_files)
    base = filesystem_path(output_root)
    if source_root is not None and base.is_relative_to(source_root):
        raise ValueError("Output must be outside the input evidence package")
    final = base / facts.run.apk_sha256 / facts.run.run_id.replace(":", "_")
    final.relative_to(base)
    if final.exists():
        raise FileExistsError(f"Published run already exists: {final}")
    work = final.with_name(".building_" + uuid4().hex)
    work.mkdir(parents=True, exist_ok=False)
    connection = None
    try:
        (work / "evidence").mkdir()
        for source, destination in zip(files, portable_files):
            copy_evidence_storage(source_root, work, source, destination)
        _validate_files(facts, portable_files, work, require_direct=facts.run.input_kind == "apk")
        connection = sqlite3.connect(str(work / "facts.sqlite"))
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")
        connection.executescript(SCHEMA_SQL)
        with connection:
            connection.execute("INSERT INTO analysis_runs VALUES (?,?,?,?,?)", (facts.run.run_id, STORE_VERSION,
                canonical_json(metadata_for(facts)), facts.run.apk_sha256, snapshot_id))
            _insert_records(connection, facts)
            connection.executemany("INSERT INTO evidence_files VALUES (?,?,?,?,?)", [(facts.run.run_id, item.archive_entry,
                item.sha256, item.bytes, item.path) for item in portable_files])
            _insert_projection(connection, _projection(facts, portable_files))
            _check_connection(connection, facts, portable_files)
            if _bundle_from_connection(connection) != facts:
                raise ValueError("SQLite round-trip differs from input")
        connection.close()
        connection = None
        counts = dict(Counter(section for section, _, _ in iter_records(facts)))
        counts = {section: counts.get(section, 0) for section in SECTIONS}
        manifest = SnapshotManifest(run_ref=facts.run.run_id, apk_sha256=facts.run.apk_sha256, snapshot_id=snapshot_id,
            database_sha256=sha256_file(work / "facts.sqlite"), counts=counts, files=portable_files,
            coverage={status.capability: status.state for status in facts.statuses if status.scope.kind == "run"},
            created_at=datetime.now(timezone.utc).isoformat(), writer_version=__version__)
        _json_write(work / "manifest.json", manifest.model_dump(mode="json"))
        _json_write(work / "validation.json", {"valid": True, "schema_version": "fact-store-check.v1",
            "run_ref": facts.run.run_id, "snapshot_id": snapshot_id, "synthetic": facts.run.input_kind == "synthetic",
            "checked": ["fact_contract", "integrity", "foreign_keys", "payload_digests", "projection_consistency", "evidence", "roundtrip"],
            "unchecked": ["static_analysis_correctness", "path_compatibility", "behavior_semantics"]})
        work.rename(final)
        return final
    except BaseException:
        if connection is not None:
            connection.close()
        # Only our new, checked staging path may be removed; no accepted run is touched.
        work.resolve().relative_to(base)
        shutil.rmtree(work)
        raise


def import_snapshot(source: str | Path, output_root: str | Path) -> Path:
    source = filesystem_path(source)
    if source.is_dir():
        manifest_path = source / "manifest.json"
        if manifest_path.exists():
            manifest = _json_read(manifest_path)
            if manifest.get("schema_version") == SNAPSHOT_VERSION:
                with FactView(source) as view:
                    view.verify()
                    return create_snapshot(view.export_bundle(), output_root, files=view.manifest.files, evidence_root=view.root)
            filename = manifest.get("facts_file", "facts.json")
            source = _inside(source, filename)
        else:
            source = source / "facts.json"
    facts = load_jsonl(source) if source.suffix == ".jsonl" else load_facts(source)
    manifest_path = source.parent / "manifest.json"
    files = []
    if manifest_path.exists():
        manifest = _json_read(manifest_path)
        if manifest.get("schema_version") != "fact-evidence.v1" or manifest.get("run_ref") != facts.run.run_id:
            raise ValueError("Unsupported evidence manifest or run mismatch")
        if manifest.get("facts_sha256") != sha256_file(source):
            raise ValueError("Input fact file digest mismatch")
        files = TypeAdapter(list[EvidenceFile]).validate_json(canonical_json(manifest["files"]))
    return create_snapshot(facts, output_root, files=files, evidence_root=source.parent)


def _limit(limit):
    if type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError("Query budget must be an integer between 1 and 100000")


class FactView:
    """A single run/snapshot, read-only. Query edges are candidates, never validated paths."""

    def __init__(self, path: str | Path, *, run_ref: str | None = None, snapshot_id: str | None = None):
        self.root = filesystem_path(path)
        self.manifest = SnapshotManifest.model_validate_json(canonical_json(_json_read(self.root / "manifest.json")))
        if run_ref is not None and self.manifest.run_ref != run_ref:
            raise ValueError("Requested run differs from snapshot")
        if snapshot_id is not None and self.manifest.snapshot_id != snapshot_id:
            raise ValueError("Requested snapshot identity differs")
        database = _inside(self.root, self.manifest.database)
        if sha256_file(database) != self.manifest.database_sha256:
            raise ValueError("Database checksum mismatch")
        # Windows extended filesystem paths are not URI authorities.
        normal = str(database)
        if normal.startswith("\\\\?\\UNC\\"):
            normal = "\\\\" + normal[8:]
        elif normal.startswith("\\\\?\\"):
            normal = normal[4:]
        self._connection = sqlite3.connect(Path(normal).as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA query_only=ON")
            if (self._connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID or
                    self._connection.execute("PRAGMA user_version").fetchone()[0] != 1):
                raise ValueError("Unsupported SQLite application/layout version")
            rows = self._connection.execute("SELECT run_id,store_version,snapshot_id,apk_sha256 FROM analysis_runs").fetchall()
            if rows != [(self.manifest.run_ref, STORE_VERSION, self.manifest.snapshot_id, self.manifest.apk_sha256)]:
                raise ValueError("Database and manifest identity disagree")
            counts = dict(self._connection.execute("SELECT section,COUNT(*) FROM records GROUP BY section"))
            if set(counts) - set(SECTIONS) or {section: counts.get(section, 0) for section in SECTIONS} != self.manifest.counts:
                raise ValueError("Database and manifest record counts disagree")
            coverage = dict(self._connection.execute("SELECT capability,state FROM analysis_statuses WHERE scope_kind='run'"))
            if coverage != self.manifest.coverage:
                raise ValueError("Database and manifest coverage disagree")
            files = self._connection.execute("SELECT entry,sha256,bytes,path FROM evidence_files ORDER BY entry").fetchall()
            if files != sorted((item.archive_entry, item.sha256, item.bytes, item.path) for item in self.manifest.files):
                raise ValueError("Database and manifest evidence disagree")
        except BaseException:
            self.close()
            raise
        self.run_ref, self.snapshot_id = self.manifest.run_ref, self.manifest.snapshot_id

    def close(self):
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def export_bundle(self):
        return _bundle_from_connection(self._connection)

    def verify(self):
        facts = self.export_bundle()
        _check_connection(self._connection, facts, self.manifest.files)
        _validate_files(facts, self.manifest.files, self.root, require_direct=facts.run.input_kind == "apk")
        stored_files = self._connection.execute("SELECT entry,sha256,bytes,path FROM evidence_files ORDER BY entry").fetchall()
        if stored_files != sorted((item.archive_entry, item.sha256, item.bytes, item.path) for item in self.manifest.files):
            raise ValueError("Evidence table differs from manifest")
        counts = Counter(section for section, _, _ in iter_records(facts))
        if self.manifest.counts != {section: counts[section] for section in SECTIONS}:
            raise ValueError("Manifest record counts differ")
        coverage = {status.capability: status.state for status in facts.statuses if status.scope.kind == "run"}
        if self.manifest.coverage != coverage or logical_digest(facts, self.manifest.files) != self.snapshot_id:
            raise ValueError("Logical snapshot identity/coverage mismatch")
        from androserum.facts.jimple import verify_jimple_evidence
        verify_jimple_evidence(facts, self.read_evidence)
        from androserum.facts.local_flow import verify_local_flow_evidence
        verify_local_flow_evidence(facts, self.read_evidence)
        from androserum.facts.call_flow import verify_call_evidence
        verify_call_evidence(facts, self.read_evidence)
        from androserum.facts.heap_flow import verify_heap_evidence
        verify_heap_evidence(facts, self.read_evidence)
        from androserum.facts.context_heap import verify_context_heap
        verify_context_heap(facts, self.read_evidence)
        from androserum.facts.selected_flow import verify_selected_flow
        verify_selected_flow(facts, self.read_evidence)
        from androserum.facts.points_to import verify_points_to
        verify_points_to(facts, self.read_evidence)
        from androserum.facts.operations import verify_operations
        verify_operations(facts, self.read_evidence)
        from androserum.facts.buffer_state import verify_buffer_state
        verify_buffer_state(facts, self.read_evidence)
        from androserum.facts.jca_state import verify_jca_state
        verify_jca_state(facts, self.read_evidence)
        from androserum.facts.method_outputs import verify_method_outputs
        verify_method_outputs(facts, self.read_evidence)
        from androserum.facts.audio_read_sites import verify_audio_read_sites
        verify_audio_read_sites(facts, self.read_evidence)
        from androserum.facts.control import verify_control
        verify_control(facts, self.read_evidence)
        from androserum.facts.events import verify_events
        verify_events(facts, self.read_evidence)
        return {"valid": True, "run_ref": self.run_ref, "snapshot_id": self.snapshot_id,
                "counts": self.manifest.counts, "coverage": coverage}

    @staticmethod
    def _decode(row):
        return ADAPTERS[row[0]].validate_json(row[1])

    def _result(self, records, total, *, limit, missing=(), filters=None):
        ids = {record_identity("tools" if hasattr(value, "tool_id") else "artifacts" if hasattr(value, "artifact_id") else "elements", value) for value in records}
        relevant = set(ids)
        for value in records:
            if isinstance(value, RelationRecord):
                relevant.add(value.source.element_ref)
                if value.target:
                    relevant.add(value.target.element_ref)
        local = []
        status_sql=("SELECT r.section,r.payload_json FROM records r JOIN analysis_statuses s ON r.run_id=s.run_id AND r.record_id=s.record_id "
                    "WHERE s.scope_kind='location'")
        status_args=sorted(relevant)
        if status_args:
            status_sql += " OR (s.scope_kind<>'run' AND s.element_ref IN ("+','.join('?' for _ in status_args)+"))"
        # Keep the original location-or-associated-element semantics. Filter
        # before decoding: BU support closure performs many single-ID reads,
        # which must not repeatedly parse every unrelated method's statuses.
        for row in self._connection.execute(status_sql+' ORDER BY r.ordinal',status_args):
            issue = self._decode(row)
            if issue.scope.kind == "location" or issue.scope.element_ref in relevant:
                local.append(issue)
        return QueryResult(self.run_ref, self.snapshot_id, records, total, dict(self.manifest.coverage), total > limit,
                           list(missing), local[:limit], len(local) > limit, filters=filters or {})

    def _query(self, sql, args=(), *, limit=100, filters=None):
        _limit(limit)
        total = self._connection.execute("SELECT COUNT(*) FROM (" + sql + ")", args).fetchone()[0]
        rows = self._connection.execute(sql + " LIMIT ?", (*args, limit)).fetchall()
        return self._result([self._decode(row) for row in rows], total, limit=limit, filters=filters)

    def get_records(self, refs: list[str], *, limit=100):
        _limit(limit)
        refs = list(dict.fromkeys(TypeAdapter(list[Ref]).validate_python(refs)))
        values, missing = [], []
        for ref in refs[:limit]:
            row = self._connection.execute("SELECT section,payload_json FROM records WHERE run_id=? AND record_id=?", (self.run_ref, ref)).fetchone()
            if row is None:
                missing.append(ref)
            else:
                values.append(self._decode(row))
        total = 0
        for batch in _batches(refs):
            total += self._connection.execute("SELECT COUNT(*) FROM records WHERE run_id=? AND record_id IN (" + ",".join("?" for _ in batch) + ")", (self.run_ref, *batch)).fetchone()[0]
        result = self._result(values, total, limit=limit, missing=missing, filters={"requested_count": len(refs)})
        result.truncated = len(refs) > limit
        result.pending_refs = refs[limit:]
        return result

    def find_methods(self, signature: str, *, dex_ref: str | None = None, limit=100):
        method_signature(signature)
        sql = "SELECT r.section,r.payload_json FROM records r JOIN program_elements e USING(run_id,record_id) WHERE e.run_id=? AND e.kind='method' AND e.signature=?"
        args = [self.run_ref, signature]
        if dex_ref is not None:
            sql += " AND e.dex_ref=?"
            args.append(dex_ref)
        return self._query(sql + " ORDER BY r.ordinal", args, limit=limit)

    def find_calls(self, *, declared_signature: str | None = None, candidate_signature: str | None = None, limit=100):
        if (declared_signature is None) == (candidate_signature is None):
            raise ValueError("Choose exactly one declared or candidate signature")
        method_signature(declared_signature or candidate_signature)
        if declared_signature is not None:
            sql = "SELECT r.section,r.payload_json FROM records r JOIN program_elements e USING(run_id,record_id) WHERE e.run_id=? AND e.declared_signature=? ORDER BY r.ordinal"
            return self._query(sql, (self.run_ref, declared_signature), limit=limit, filters={"match": "declared"})
        sql = "SELECT DISTINCT r.section,r.payload_json,r.ordinal FROM relations rel JOIN records r ON r.run_id=rel.run_id AND r.record_id=rel.source_element WHERE rel.run_id=? AND rel.kind='candidate_call' AND rel.candidate_signature=? ORDER BY r.ordinal"
        return self._query(sql, (self.run_ref, candidate_signature), limit=limit, filters={"match": "candidate"})

    def get_operation(self, ref: str):
        result = self.get_records([ref])
        if result.missing_refs:
            raise ValueError("Operation is absent from this snapshot")
        if not isinstance(result.records[0], (InstructionRecord, AnalysisNodeRecord)):
            raise ValueError("Selected record is not an operation")
        return result

    def find_instructions(self, method_ref: str, *, offset_bytes: int | None = None, limit=100):
        sql = "SELECT r.section,r.payload_json FROM records r JOIN program_elements e USING(run_id,record_id) WHERE e.run_id=? AND e.method_ref=? AND e.kind='instruction'"
        args = [self.run_ref, method_ref]
        if offset_bytes is not None:
            if type(offset_bytes) is not int or offset_bytes < 0 or offset_bytes % 2:
                raise ValueError("Instruction offsets must be non-negative byte offsets aligned to 2")
            sql += " AND e.offset_bytes=?"
            args.append(offset_bytes)
        return self._query(sql + " ORDER BY e.offset_bytes,r.ordinal", args, limit=limit)

    @staticmethod
    def _filter(sql, args, column, value: RefFilter):
        if value.mode == "missing":
            sql += f" AND {column} IS NULL"
        elif value.mode in {"exact", "exact_or_missing"}:
            sql += f" AND ({column}=?" + (f" OR {column} IS NULL)" if value.mode == "exact_or_missing" else ")")
            args.append(value.ref)
        return sql

    def get_relations(self, endpoint: Endpoint, *, direction: Literal["in", "out"], relation_kinds: list[str],
                      context: RefFilter, binding: RefFilter, limit=100):
        if direction not in {"in", "out"}:
            raise ValueError("Direction must be in or out")
        endpoint = Endpoint.model_validate(endpoint.model_dump())
        key = endpoint_key(self.run_ref, endpoint)
        if not self._connection.execute("SELECT 1 FROM endpoints WHERE run_id=? AND endpoint_key=?", (self.run_ref, key)).fetchone():
            raise ValueError("Endpoint is absent or its slot/position is invalid")
        kinds = TypeAdapter(list[RelationKind]).validate_python(relation_kinds)
        if not kinds:
            raise ValueError("Relation kinds must be explicitly selected")
        context, binding = RefFilter.model_validate(context.model_dump()), RefFilter.model_validate(binding.model_dump())
        sql = "SELECT r.section,r.payload_json FROM relations e JOIN records r USING(run_id,record_id) WHERE e.run_id=? AND e." + ("target_key" if direction == "in" else "source_key") + "=? AND e.kind IN (" + ",".join("?" for _ in kinds) + ")"
        args = [self.run_ref, key, *kinds]
        sql = self._filter(sql, args, "e.context_ref", context)
        exists = "EXISTS(SELECT 1 FROM record_refs b WHERE b.run_id=e.run_id AND b.owner_id=e.record_id AND b.role='binding_refs'"
        if binding.mode == "missing":
            sql += " AND NOT " + exists + ")"
        elif binding.mode in {"exact", "exact_or_missing"}:
            sql += " AND (" + exists + " AND b.target_id=?)"
            args.append(binding.ref)
            sql += " OR NOT " + exists + "))" if binding.mode == "exact_or_missing" else ")"
        return self._query(sql + " ORDER BY r.ordinal", args, limit=limit,
            filters={"direction": direction, "relation_kinds": kinds, "context": context.model_dump(), "binding": binding.model_dump()})

    def get_status(self, *, capability: str | None = None, element_ref: str | None = None, location_path: str | None = None, limit=100):
        if capability is not None:
            TypeAdapter(Capability).validate_python(capability)
        sql = "SELECT r.section,r.payload_json FROM records r JOIN analysis_statuses s USING(run_id,record_id) WHERE s.run_id=?"
        args = [self.run_ref]
        for name, value in [("capability", capability), ("element_ref", element_ref), ("location_path", location_path)]:
            if value is not None:
                sql += f" AND s.{name}=?"
                args.append(value)
        return self._query(sql + " ORDER BY r.ordinal", args, limit=limit)

    def _incoming(self, operation_ref, kinds, *, include_method=False, limit=100):
        operation = self.get_operation(operation_ref).records[0]
        ids = [operation_ref]
        if include_method:
            method = getattr(operation.position, "method_ref", None) or getattr(operation, "method_ref", None)
            if method:
                ids.append(method)
        sql = "SELECT r.section,r.payload_json FROM relations e JOIN records r USING(run_id,record_id) WHERE e.run_id=? AND e.target_element IN (" + ",".join("?" for _ in ids) + ") AND e.kind IN (" + ",".join("?" for _ in kinds) + ") ORDER BY r.ordinal"
        return self._query(sql, (self.run_ref, *ids, *kinds), limit=limit,
                           filters={"scope": "direct_target_or_owning_method" if include_method else "direct_target"})

    def get_constraints(self, operation_ref, *, limit=100):
        return self._incoming(operation_ref, ["control_dependency"], limit=limit)

    def get_event_context(self, operation_ref, *, limit=100):
        return self._incoming(operation_ref, ["event_trigger", "icc_target"], include_method=True, limit=limit)

    def collect_support(self, selected_refs: list[str], *, limit=1000):
        _limit(limit)
        ref_adapter=TypeAdapter(Ref)
        queue = deque(dict.fromkeys(TypeAdapter(list[Ref]).validate_python(selected_refs)))
        seen, values, missing, files = set(), [], [], {}
        while queue and len(seen) < limit:
            ref = queue.popleft()
            if ref in seen:
                continue
            ref=ref_adapter.validate_python(ref)
            seen.add(ref)
            row=self._connection.execute("SELECT section,payload_json FROM records WHERE run_id=? AND record_id=?",(self.run_ref,ref)).fetchone()
            if row is None:
                missing.append(ref)
                continue
            # Only records/missing identity were consumed here. Status metadata
            # is still computed once for the complete closure below.
            values.append(self._decode(row))
            queue.extend(row[0] for row in self._connection.execute("SELECT target_id FROM record_refs WHERE run_id=? AND owner_id=? ORDER BY path", (self.run_ref, ref)) if row[0] not in seen)
            for item in self.get_evidence(ref):
                files[item.archive_entry] = item
        pending = list(dict.fromkeys(ref for ref in queue if ref not in seen))
        result = self._result(values, len(seen) + len(pending), limit=limit, missing=missing)
        result.truncated, result.pending_refs, result.is_subset = bool(pending), pending, True
        result.files = list(files.values())
        result.filters = {"reference_closure_complete": not pending and not missing, "expansion": "explicit_forward_references_only"}
        return result

    def get_evidence(self, record_ref: str) -> list[EvidenceFile]:
        return [EvidenceFile(archive_entry=row[0], sha256=row[1], bytes=row[2], path=row[3]) for row in
                self._connection.execute("SELECT f.entry,f.sha256,f.bytes,f.path FROM record_files r JOIN evidence_files f ON r.run_id=f.run_id AND r.entry=f.entry WHERE r.run_id=? AND r.record_id=? ORDER BY f.entry", (self.run_ref, record_ref))]

    def read_evidence(self, entry: str) -> bytes:
        cache=getattr(self,'_checked_evidence_cache',None)
        if cache is None:return self._read_evidence_uncached(entry)
        if entry not in cache:cache[entry]=self._read_evidence_uncached(entry)
        return cache[entry]

    @contextmanager
    def checked_evidence_reads(self):
        """One immutable offline operation: checked bytes plus an end-of-scope guard.

        The complete BU result cannot leave this scope before every reused
        source is checked again. This does not cache verification across runs.
        """
        if getattr(self,'_checked_evidence_cache',None) is not None:
            raise ValueError('Nested checked evidence scope is not supported')
        manifest_hash=sha256_file(self.root/'manifest.json')
        self._checked_evidence_cache={}
        try:
            yield self
        finally:
            cache=self._checked_evidence_cache;self._checked_evidence_cache=None
            if sha256_file(self.root/'manifest.json')!=manifest_hash or sha256_file(self.root/'facts.sqlite')!=self.manifest.database_sha256:
                raise ValueError('Immutable source changed during checked evidence scope')
            for entry,expected in cache.items():
                if self._read_evidence_uncached(entry)!=expected:
                    raise ValueError('Evidence bytes changed during checked evidence scope')

    def _read_evidence_uncached(self, entry: str) -> bytes:
        row = self._connection.execute("SELECT sha256,bytes,path FROM evidence_files WHERE run_id=? AND entry=?", (self.run_ref, entry)).fetchone()
        if row is None:
            raise ValueError(f"Evidence entry is absent: {entry}")
        item=EvidenceFile(archive_entry=entry, sha256=row[0], bytes=row[1], path=row[2])
        if evidence_is_apk_entry(item) and apk_entry_descriptor(self.root,item)['container_sha256'] != self.manifest.apk_sha256:
            raise ValueError('Evidence container differs from the analyzed APK')
        return read_evidence_file(self.root,item)

    def read_jimple(self, node_ref: str):
        """Resolve a versioned structured IR unit through its checked evidence artifact."""
        from androserum.facts.jimple import JimpleMethod
        node = self.get_operation(node_ref).records[0]
        if not isinstance(node, AnalysisNodeRecord) or node.node_kind != "jimple" or node.position.kind != "analysis":
            raise ValueError("Selected record is not a positioned Jimple unit")
        data = self.read_evidence(node.position.artifact_path).decode("utf-8")
        from androserum.facts.io import strict_json_syntax
        strict_json_syntax(data)
        method = JimpleMethod.model_validate_json(data)
        owner = self.get_records([node.method_ref]).records
        label = node.position.position_label
        if not label.startswith("unit:") or not label[5:].isdigit() or not owner or not isinstance(owner[0], MethodRecord):
            raise ValueError("Invalid IR unit/method reference")
        index = int(label[5:])
        if method.signature != owner[0].signature or index >= len(method.units) or method.units[index].text != node.text:
            raise ValueError("IR artifact disagrees with its fact record")
        return method.units[index]

    def read_local_flow(self, method_ref: str):
        from androserum.facts.local_flow import MethodFlow
        for row in self._connection.execute("SELECT r.payload_json FROM records r JOIN program_elements e USING(run_id,record_id) WHERE e.run_id=? AND e.kind='analysis_node' AND e.method_ref=? ORDER BY r.ordinal", (self.run_ref, method_ref)):
            value = json.loads(row[0])
            position = value.get("position", {})
            if value.get("node_kind") == "cfg" and position.get("artifact_path", "").startswith("analysis/local-flow/"):
                return MethodFlow.model_validate_json(self.read_evidence(position["artifact_path"]))
        raise ValueError("No F4-A method-local analysis is present for this method")

    def read_call_flow(self):
        from androserum.facts.call_flow import CallReport, ENTRY
        return CallReport.model_validate_json(self.read_evidence(ENTRY))

    def trace_call_sources(self, endpoint: Endpoint, *, limit=1000, initial_call_path=()):
        from androserum.facts.call_flow import trace_sources
        _limit(limit)
        endpoint = Endpoint.model_validate(endpoint.model_dump())
        self.get_operation(endpoint.element_ref)
        result = trace_sources(self.export_bundle(), self.read_evidence, endpoint, limit=limit, initial_call_path=initial_call_path)
        return {**result, "snapshot_id": self.snapshot_id, "coverage": self.manifest.coverage}

    def read_context_heap(self, method_ref):
        from androserum.facts.context_heap import ContextHeapReport,entry_for
        return ContextHeapReport.model_validate_json(self.read_evidence(entry_for(method_ref)))

    def operation_evidence(self, refs):
        from androserum.facts.operations import operation_evidence
        result=operation_evidence(self.export_bundle(),self.read_evidence,refs)
        return {**result,'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def points_to_evidence(self, refs=()):
        from androserum.facts.points_to import points_to_evidence
        return {**points_to_evidence(self.export_bundle(),self.read_evidence,refs),
            'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def summary_evidence(self, refs=()):
        from androserum.facts.flow_summaries import summary_evidence
        return {**summary_evidence(self.export_bundle(),self.read_evidence,refs),
            'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def buffer_evidence(self, refs=()):
        from androserum.facts.buffer_state import buffer_evidence
        return {**buffer_evidence(self.export_bundle(),self.read_evidence,refs),
            'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def jca_evidence(self, refs=()):
        from androserum.facts.jca_state import jca_evidence
        return {**jca_evidence(self.export_bundle(),self.read_evidence,refs),
            'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def method_output_evidence(self, refs=()):
        from androserum.facts.method_outputs import method_output_evidence
        return {**method_output_evidence(self.export_bundle(),self.read_evidence,refs),
            'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def audio_read_evidence(self, refs=()):
        from androserum.facts.audio_read_sites import audio_read_evidence
        return {**audio_read_evidence(self.export_bundle(),self.read_evidence,refs),
            'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def control_evidence(self, refs):
        from androserum.facts.control import control_evidence
        return {**control_evidence(self.export_bundle(),self.read_evidence,refs),'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def event_evidence(self, refs):
        from androserum.facts.events import event_evidence
        return {**event_evidence(self.export_bundle(),self.read_evidence,refs),'snapshot_id':self.snapshot_id,'coverage':self.manifest.coverage}

    def joint_evidence(self, refs, catalog, *, limit=5000):
        from androserum.facts.joint import joint_evidence
        _limit(limit)
        return joint_evidence(self,refs,catalog,limit=limit)

    def behavior_units(self, catalog_path, config=None):
        from androserum.facts.bu import build_units
        return build_units(self, catalog_path, config)

    def trace_context_sources(self, root_method_ref, endpoint, *, call_path=None, limit=1000):
        from androserum.facts.context_heap import trace_context_sources
        _limit(limit)
        result=trace_context_sources(self.export_bundle(),self.read_evidence,root_method_ref,endpoint,call_path=call_path,limit=limit)
        return {**result,"snapshot_id":self.snapshot_id,"coverage":self.manifest.coverage}

    def read_heap_flow(self, method_ref):
        from androserum.facts.heap_flow import HeapMethod, method_entry
        return HeapMethod.model_validate_json(self.read_evidence(method_entry(method_ref)))

    def trace_heap_sources(self, endpoint: Endpoint, *, limit=1000):
        from androserum.facts.heap_flow import trace_heap_sources
        _limit(limit)
        result = trace_heap_sources(self.export_bundle(), self.read_evidence, Endpoint.model_validate(endpoint.model_dump()), limit=limit)
        return {**result, "snapshot_id": self.snapshot_id, "coverage": self.manifest.coverage}

    def trace_local_sources(self, endpoint: Endpoint, *, limit=1000):
        """Traverse only accepted F4-A links in one method; return unknown roots explicitly."""
        _limit(limit)
        selected = self.get_operation(endpoint.element_ref).records[0]
        method_ref = getattr(selected, "method_ref", None)
        if method_ref is None: raise ValueError("Selected endpoint has no method-local scope")
        report = self.read_local_flow(method_ref)
        if report.state != "complete":
            return {"schema_version": "local-sources.v1", "run_ref": self.run_ref, "snapshot_id": self.snapshot_id,
                    "scope": report.scope, "method_ref": method_ref, "state": report.state, "reason": report.reason,
                    "roots": [], "truncated": True, "coverage": self.manifest.coverage,
                    "path_feasibility_checked": False, "heap_and_callee_resolved": False}
        allowed = {endpoint_key(self.run_ref, value) for link in report.links for value in [link.source, link.target]}
        allowed.update(endpoint_key(self.run_ref, root.endpoint) for root in report.roots)
        start = endpoint_key(self.run_ref, endpoint)
        if start not in allowed: raise ValueError("Endpoint is not an analyzed scalar use/result in this method")
        incoming = defaultdict(list)
        roots = defaultdict(list)
        for link in report.links: incoming[endpoint_key(self.run_ref, link.target)].append(link)
        for root in report.roots: roots[endpoint_key(self.run_ref, root.endpoint)].append(root)
        queue, seen, found, cycles = deque([(endpoint, [])]), set(), [], []
        while queue and len(seen) < limit:
            point, path = queue.popleft(); key = endpoint_key(self.run_ref, point)
            if key in seen: continue
            seen.add(key)
            for root in roots[key]: found.append({"root": root.model_dump(mode="json"), "links_to_target": [link.model_dump(mode="json") for link in reversed(path)]})
            path_keys = {start, *(endpoint_key(self.run_ref, value.source) for value in path)}
            for link in incoming[key]:
                if endpoint_key(self.run_ref, link.source) in path_keys:
                    cycles.append(link.source.model_dump(mode="json"))
                else: queue.append((link.source, path + [link]))
        return {"schema_version": "local-sources.v1", "run_ref": self.run_ref, "snapshot_id": self.snapshot_id,
                "scope": report.scope, "method_ref": method_ref, "target": endpoint.model_dump(mode="json"), "roots": found,
                "truncated": bool(queue), "pending": [point.model_dump(mode="json") for point, _ in queue], "cycles": cycles,
                "path_feasibility_checked": False, "heap_and_callee_resolved": False, "coverage": self.manifest.coverage}


def export_snapshot(view: FactView, destination: str | Path, *, format: Literal["json", "jsonl"] = "json") -> Path:
    if format not in {"json", "jsonl"}:
        raise ValueError("Export format must be json or jsonl")
    view.verify()
    final = filesystem_path(destination)
    if final.is_relative_to(view.root):
        raise ValueError("Exports must be outside the published snapshot")
    if final.exists():
        raise FileExistsError("Export destination already exists")
    work = final.with_name(".export_" + uuid4().hex)
    work.mkdir(parents=True, exist_ok=False)
    try:
        (work / "evidence").mkdir()
        for item in view.manifest.files:
            target = _inside(work, item.path)
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                # Preserve the storage codec; reading must never write an
                # encoded DEX back to a raw file during export.
                copy_evidence_storage(view.root, work, item)
        filename = "facts." + format
        facts = view.export_bundle()
        if format == "json":
            dump_facts(facts, work / filename)
        else:
            export_jsonl(facts, work / filename)
        _json_write(work / "manifest.json", {"schema_version": "fact-evidence.v1", "run_ref": view.run_ref,
            "facts_file": filename, "facts_sha256": sha256_file(work / filename), "files": [item.model_dump(mode="json") for item in view.manifest.files]})
        work.rename(final)
        return final
    except BaseException:
        work.resolve().relative_to(final.parent)
        shutil.rmtree(work)
        raise


def rebuild_snapshot(path: str | Path, output_root: str | Path) -> Path:
    """Rebuild a new projection/file from validated payloads; preserve old snapshot."""
    with FactView(path) as view:
        facts = view.export_bundle()
        if logical_digest(facts, view.manifest.files) != view.snapshot_id:
            raise ValueError("Source logical payload digest mismatch")
        return create_snapshot(facts, output_root, files=view.manifest.files, evidence_root=view.root)


def rebuild_catalog(root: str | Path) -> Path:
    root = filesystem_path(root)
    if (root / "manifest.json").exists() and _json_read(root / "manifest.json").get("schema_version") == SNAPSHOT_VERSION:
        raise ValueError("A catalog must be outside a published snapshot")
    root.mkdir(parents=True, exist_ok=True)
    final = root / "catalog.sqlite"
    temporary = root / (".catalog_" + uuid4().hex + ".sqlite")
    connection = sqlite3.connect(str(temporary))
    try:
        connection.execute("CREATE TABLE snapshots(run_ref TEXT NOT NULL,snapshot_id TEXT NOT NULL,apk_sha256 TEXT NOT NULL,path TEXT NOT NULL,PRIMARY KEY(run_ref,snapshot_id,path))")
        with connection:
            for path in sorted(root.rglob("manifest.json")):
                if any(part.startswith((".building_", ".export_")) for part in path.relative_to(root).parts):
                    continue
                value = _json_read(path)
                if value.get("schema_version") != SNAPSHOT_VERSION:
                    continue
                with FactView(path.parent) as view:
                    connection.execute("INSERT INTO snapshots VALUES(?,?,?,?)", (view.run_ref, view.snapshot_id,
                        view.manifest.apk_sha256, path.parent.relative_to(root).as_posix()))
        connection.close()
        temporary.replace(final)
        return final
    except BaseException:
        connection.close()
        temporary.unlink(missing_ok=True)
        raise
