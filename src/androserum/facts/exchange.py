"""Framed JSONL exchange of complete fact bundles, with explicit end/count/digest checks."""

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Iterator

from pydantic import BaseModel, TypeAdapter

from androserum.facts.identity import canonical_json, filesystem_path
from androserum.facts.io import loads_facts, strict_json_syntax
from androserum.facts.models import (
    AnalysisStatus, BindingRecord, ContextRecord, Element, FactBundle, RelationRecord,
    ToolVersion, VersionedArtifact,
)

STREAM_VERSION = "fact-stream.v1"
SECTIONS = ("tools", "artifacts", "elements", "relations", "contexts", "bindings", "statuses")
ADAPTERS = dict(zip(SECTIONS, [TypeAdapter(value) for value in
                [ToolVersion, VersionedArtifact, Element, RelationRecord, ContextRecord, BindingRecord, AnalysisStatus]]))


def metadata_for(facts: FactBundle) -> dict:
    value = facts.model_dump(mode="json", exclude=set(SECTIONS[2:]))
    value["run"].pop("tools")
    value["run"].pop("artifacts")
    return value


def iter_records(facts: FactBundle) -> Iterator[tuple[str, int, BaseModel]]:
    for section in SECTIONS:
        owner = facts.run if section in {"tools", "artifacts"} else facts
        for ordinal, record in enumerate(getattr(owner, section)):
            yield section, ordinal, record


def record_identity(section: str, record: BaseModel) -> str:
    return getattr(record, {"tools": "tool_id", "artifacts": "artifact_id"}.get(section, "id"))


def assemble(metadata: dict, records: Iterator[tuple[str, int, BaseModel]]) -> FactBundle:
    value = json.loads(canonical_json(metadata))
    value["run"]["tools"], value["run"]["artifacts"] = [], []
    for section in SECTIONS[2:]:
        value[section] = []
    for section, ordinal, record in records:
        owner = value["run"] if section in {"tools", "artifacts"} else value
        if ordinal != len(owner[section]):
            raise ValueError("Record ordinals are missing or out of order")
        owner[section].append(record.model_dump(mode="json"))
    return loads_facts(canonical_json(value))


def export_jsonl(facts: FactBundle, destination: str | Path) -> None:
    facts = loads_facts(facts.model_dump_json())
    path = filesystem_path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter(section for section, _, _ in iter_records(facts))
    counts = {section: counts[section] for section in SECTIONS}
    digest = hashlib.sha256()
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as target:
            def write(value):
                line = canonical_json(value) + "\n"
                target.write(line)
                digest.update(line.encode("utf-8"))
            write({"type": "header", "schema_version": STREAM_VERSION, "metadata": metadata_for(facts), "counts": counts})
            for section, ordinal, record in iter_records(facts):
                write({"type": "record", "section": section, "ordinal": ordinal, "record": record.model_dump(mode="json")})
            target.write(canonical_json({"type": "end", "counts": counts, "sha256": digest.hexdigest()}) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def load_jsonl(source: str | Path, *, max_line_bytes: int = 16 * 1024 * 1024) -> FactBundle:
    """Read bounded lines without loading one giant JSON text.

    Current cross-record validation still materializes the typed run in memory.
    This is a framed complete-bundle format, not a subset or append-only log.
    """
    if type(max_line_bytes) is not int or max_line_bytes < 1:
        raise ValueError("max_line_bytes must be a positive integer")
    values = {section: [] for section in SECTIONS}
    counts = {section: 0 for section in SECTIONS}
    digest, header, ended = hashlib.sha256(), None, False
    section_order = -1
    with filesystem_path(source).open("rb") as stream:
        while raw := stream.readline(max_line_bytes + 1):
            if len(raw) > max_line_bytes:
                raise ValueError("JSONL line budget exceeded")
            if ended:
                raise ValueError("JSONL contains content after the end frame")
            line = raw.decode("utf-8")
            strict_json_syntax(line)
            frame = json.loads(line)
            if not isinstance(frame, dict):
                raise ValueError("JSONL frames must be objects")
            if header is None:
                if set(frame) != {"type", "schema_version", "metadata", "counts"} or frame.get("type") != "header" or frame.get("schema_version") != STREAM_VERSION:
                    raise ValueError("Unsupported or malformed JSONL header")
                expected = frame["counts"]
                if (not isinstance(expected, dict) or set(expected) != set(SECTIONS) or
                        any(type(count) is not int or count < 0 for count in expected.values())):
                    raise ValueError("Invalid JSONL section counts")
                header = frame
            elif frame.get("type") == "record":
                if set(frame) != {"type", "section", "ordinal", "record"} or frame["section"] not in SECTIONS:
                    raise ValueError("Malformed JSONL record frame")
                section = frame["section"]
                current = SECTIONS.index(section)
                if current < section_order or type(frame["ordinal"]) is not int or frame["ordinal"] != counts[section]:
                    raise ValueError("JSONL section order/ordinal mismatch")
                section_order = current
                if counts[section] >= header["counts"][section]:
                    raise ValueError("JSONL record count exceeds header")
                values[section].append(ADAPTERS[section].validate_json(canonical_json(frame["record"])))
                counts[section] += 1
            elif frame.get("type") == "end":
                if set(frame) != {"type", "counts", "sha256"} or frame["counts"] != counts or header["counts"] != counts or frame["sha256"] != digest.hexdigest():
                    raise ValueError("JSONL end/count/digest mismatch")
                ended = True
                continue
            else:
                raise ValueError("Unexpected JSONL frame")
            digest.update((canonical_json(frame) + "\n").encode("utf-8"))
    if not ended or header is None:
        raise ValueError("JSONL is truncated: missing header or verified end frame")
    return assemble(header["metadata"], ((section, i, record) for section in SECTIONS for i, record in enumerate(values[section])))
