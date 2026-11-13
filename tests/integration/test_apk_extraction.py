"""F1 acceptance uses real compiled APKs and independent Android tool dumps.

The one monkeypatch test is engineering fault injection, not damaged-APK evidence.
"""

from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

import jsonschema
import pytest
from pydantic import ValidationError

from androserum.facts.extractor import ALL, Extractor, extract_apk, write_extraction
from androserum.facts.io import load_facts, loads_facts
from androserum.facts.models import FactBundle, FactConfig

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "artifacts/fixtures/f1"
SOURCE = ROOT / "tests/fixtures/extraction"
MAIN = "Lorg/androserum/extraction/MainActivity;"
REAL = Path(os.environ.get("F1_REAL_APK", r"D:\AndroSerum260309\downloaded_samples\2013\039E9C23EBB8B5789B5AA0681CD6757C10442302E2504AE3A0F9C93165D68B76.apk"))


@pytest.fixture(scope="session", autouse=True)
def build_fixtures():
    subprocess.run([sys.executable, "scripts/build_extraction_fixture.py"], cwd=ROOT,
                   check=True, capture_output=True, timeout=180)


@pytest.fixture(scope="module")
def extracted(build_fixtures):
    return extract_apk(FIXTURES / "valid.apk")


def records(result, kind):
    return [record for record in result.facts.elements if record.kind == kind]


def body(result, signature):
    method = next(record for record in records(result, "method") if record.signature == signature and record.is_definition)
    return method, sorted([record for record in records(result, "instruction") if record.position.method_ref == method.id],
                          key=lambda record: record.position.offset_bytes)


def slot(instruction, kind, index=None):
    return next(value for value in instruction.slots if value.slot_kind == kind and value.slot_index == index)


def parsed_dump(text):
    """Independent dexdump text -> declaration + instruction locations/opcodes."""
    owner = name = descriptor = None
    found = {}
    for line in text.splitlines():
        match = re.search(r"Class descriptor\s*:\s*'([^']+)'", line)
        if match:
            owner = match[1]
        match = re.match(r"\s+name\s*:\s*'([^']+)'", line)
        if match:
            name = match[1]
        match = re.match(r"\s+type\s*:\s*'([^']+)'", line)
        if match:
            descriptor = match[1]
        match = re.match(r"^([0-9a-f]+):.*\|([0-9a-f]+):\s+(\S+)", line)
        if match:
            found[(owner + "->" + name + descriptor, int(match[2], 16) * 2)] = (int(match[1], 16), match[3])
    return found


def normalized(result):
    """Replace run-scoped identities by stable ordered placeholders for comparison."""
    value = deepcopy(result.facts.model_dump(mode="json"))
    value["run"].pop("created_at")
    value["run"].pop("input_name")
    ids = [value["run"]["run_id"]]
    for key in ["elements", "relations", "contexts", "bindings", "statuses"]:
        ids.extend(record["id"] for record in value[key])
    replacements = {identifier: f"identity:{index}" for index, identifier in enumerate(ids)}

    def replace(item):
        if isinstance(item, str):
            return replacements.get(item, item)
        if isinstance(item, list):
            return [replace(child) for child in item]
        if isinstance(item, dict):
            return {key: replace(child) for key, child in item.items()}
        return item
    return replace(value)


def test_full_fixture_structure_and_requested_coverage(extracted):
    assert extracted.summary["outcome"] == "complete"
    assert extracted.summary["issues"] == 0
    assert loads_facts(extracted.facts.model_dump_json()) == extracted.facts
    jsonschema.validate(extracted.facts.model_dump(mode="json"), FactBundle.model_json_schema())
    assert extracted.summary["coverage"] == {key: ("complete" if key in {"dex", "manifest", "resources"} else "not_started")
                                             for key in extracted.summary["coverage"]}
    assert set(extracted.summary["coverage"]) == set(extracted.facts.run.configuration.requested_capabilities)
    assert not any(relation.relation_kind in {"data_dependency", "control_dependency", "event_trigger", "candidate_call"}
                   for relation in extracted.facts.relations)


def test_dex_header_counts_and_every_instruction_against_independent_dump(extracted):
    elements = {record.id: record for record in extracted.facts.elements}
    with zipfile.ZipFile(FIXTURES / "valid.apk") as archive:
        for index, dex in enumerate(records(extracted, "dex"), 1):
            raw = archive.read(dex.position.path)
            assert hashlib.sha256(raw).hexdigest() == dex.sha256
            dump = parsed_dump((FIXTURES / f"dexdump-{index}.txt").read_text(encoding="utf-8"))
            found = {}
            for instruction in records(extracted, "instruction"):
                if instruction.position.dex_ref != dex.id:
                    continue
                method = elements[instruction.position.method_ref]
                absolute = method.code_offset_bytes + 16 + instruction.position.offset_bytes
                assert raw[absolute:absolute + instruction.length_bytes].hex() == instruction.raw_hex
                found[(method.signature, instruction.position.offset_bytes)] = (absolute, instruction.opcode)
            assert found == dump and found
            # DEX header fields read with struct, independent of Androguard.
            for kind, offset in [("type_reference", 64), ("field", 80), ("method", 88), ("class", 96)]:
                assert sum(record.kind == kind and record.position.dex_ref == dex.id
                           for record in extracted.facts.elements if record.kind in {"type_reference", "field", "method", "class"}) == struct.unpack_from("<I", raw, offset)[0]


def test_repeated_call_sites_preserve_raw_constants_without_inventing_argument_values(extracted):
    _, instructions = body(extracted, MAIN + "->onCreate(Landroid/os/Bundle;)V")
    calls = [(i, record) for i, record in enumerate(instructions)
             if record.declared_target and record.declared_target.signature == MAIN + "->consume(Ljava/lang/String;)V"]
    assert len(calls) == 3
    assert [next(operand.value.value for operand in instructions[i - 1].operands if operand.kind == "string")
            for i, _ in calls[:2]] == ["alpha", "beta"]
    assert len({record.id for _, record in calls}) == 3
    assert len({record.position.position_label for _, record in calls}) == 3
    for _, call in calls:
        assert call.invoke_kind == "static" and slot(call, "argument", 0).registers == [0]
        assert slot(call, "argument", 0).value.status == "unknown"
        assert not any(value.slot_kind == "receiver" for value in call.slots)


def test_receiver_wide_actual_and_formal_register_groups(extracted):
    _, instructions = body(extracted, MAIN + "->onCreate(Landroid/os/Bundle;)V")
    instance = next(record for record in instructions if record.declared_target and "->instanceSink" in record.declared_target.signature)
    assert slot(instance, "receiver").registers == [5]
    assert slot(instance, "argument", 0).registers == [0]
    wide = next(record for record in instructions if record.declared_target and "->wide(" in record.declared_target.signature)
    assert [slot(wide, "argument", i).registers for i in range(3)] == [[3, 4], [0, 1], [2]]
    method, _ = body(extracted, MAIN + "->wide(JDLjava/lang/String;)V")
    parameters = sorted([record for record in records(extracted, "parameter") if record.method_ref == method.id], key=lambda p: p.index)
    assert [(p.index, p.type_descriptor, p.register_index) for p in parameters] == [(0, "J", 0), (1, "D", 2), (2, "Ljava/lang/String;", 4)]
    method, _ = body(extracted, MAIN + "->instanceSink(Ljava/lang/String;)V")
    assert next(record for record in records(extracted, "parameter") if record.method_ref == method.id).register_index == 1


def test_abstract_native_external_and_cross_dex_reference_resolution(extracted):
    assert {record.body_status for record in records(extracted, "method")} == {"available", "abstract", "native", "external"}
    helper = [record for record in records(extracted, "method") if record.signature == "Lorg/androserum/extraction/Helper;->decorate(Ljava/lang/String;)Ljava/lang/String;"]
    assert len(helper) == 2 and helper[0].id != helper[1].id
    reference = next(record for record in helper if not record.is_definition)
    definition = next(record for record in helper if record.is_definition)
    assert reference.position.dex_ref != definition.position.dex_ref
    assert any(relation.relation_kind == "reference_resolution" and relation.source.element_ref == reference.id
               and relation.target.element_ref == definition.id for relation in extracted.facts.relations)
    assert any(record.descriptor == "V" for record in records(extracted, "type_reference"))


def test_call_results_link_to_actual_receiving_instructions(extracted):
    elements = {record.id: record for record in extracted.facts.elements}
    relations = [relation for relation in extracted.facts.relations if relation.relation_kind == "call_result_assignment"]
    assert len(relations) == 4
    for relation in relations:
        call, receiver = elements[relation.source.element_ref], elements[relation.target.element_ref]
        assert call.result_receiver_ref == receiver.id
        assert receiver.opcode.startswith("move-result")
        assert call.position.method_ref == receiver.position.method_ref
        assert call.position.offset_bytes + call.length_bytes == receiver.position.offset_bytes
        assert slot(call, "result").registers == slot(receiver, "result").registers


def test_nonfinite_and_large_constants_preserve_exact_encoded_bits(extracted):
    fields = {record.signature: record for record in records(extracted, "field") if record.is_definition}
    assert fields[MAIN + "->NAN:F"].initial_value.value == {"encoding": "ieee754-bits", "bits": 32, "hex": "7fc00000", "encoded_hex": "c07f"}
    assert fields[MAIN + "->LARGE:J"].initial_value.value == 0x1122334455667788
    literals = [operand.value.value for record in records(extracted, "instruction") for operand in record.operands if operand.kind == "literal"]
    assert 0x1122334455667788 in literals and 0x7ff0000000000000 in literals
    json.loads(extracted.facts.model_dump_json(), parse_constant=lambda value: pytest.fail("Invalid JSON number: " + value))


def test_manifest_source_attributes_components_filters_and_aapt_dump(extracted):
    android = "{http://schemas.android.com/apk/res/android}"
    source = ET.parse(SOURCE / "AndroidManifest.xml").getroot()
    configs = records(extracted, "configuration")
    assert len(configs) == len(list(source.iter()))
    expected = {(node.tag, node.get(android + "name")) for node in source.iter()}
    actual = {(record.value.value["tag"], record.value.value["attributes"].get(android + "name")) for record in configs}
    assert expected == actual
    assert Counter(record.configuration_kind for record in configs)["component"] == 5
    assert Counter(record.configuration_kind for record in configs)["intent_filter"] == 2
    dump = (FIXTURES / "aapt2-manifest.txt").read_text(encoding="utf-8")
    assert 'package="org.androserum.extraction"' in dump and 'versionCode(0x0101021b)=7' in dump
    for record in configs:
        assert record.position.path == "AndroidManifest.xml" and record.position.selector.startswith("/manifest")
        if record.configuration_kind == "component":
            assert record.name in dump
    assert extracted.facts.run.apk_metadata == {"package": "org.androserum.extraction", "version_code": "7", "version_name": "fixture-1", "min_sdk": "16", "target_sdk": "28"}


def test_resource_variants_values_and_raw_file_against_source_and_aapt_dump(extracted):
    resources = records(extracted, "resource")
    assert len(resources) == 10
    dump = (FIXTURES / "aapt2-resources.txt").read_text(encoding="utf-8")
    for folder, qualifier in [("values", ""), ("values-zh-rCN", "zh-rCN")]:
        for node in ET.parse(SOURCE / "res" / folder / "strings.xml").getroot():
            record = next(record for record in resources if record.name == node.get("name") and record.qualifiers == qualifier)
            if node.tag == "string":
                assert record.value.value == node.text and node.text in dump
            elif node.tag == "integer":
                assert record.value.value == int(node.text)
            elif node.tag == "bool":
                assert record.value.value is True
            elif node.tag == "color":
                assert record.value.value.lower() == node.text
            elif node.tag == "string-array":
                assert [item["value"] for item in record.value.value] == [child.text for child in node]
            assert f"0x{record.resource_id:08x}" in dump
            assert record.raw_value is not None
    digest = extracted.entry_digests["res/raw/payload.txt"]
    assert extracted.blobs[digest] == (SOURCE / "res/raw/payload.txt").read_bytes()


def test_resource_links_have_explicit_use_and_config_alternatives(extracted):
    elements = {record.id: record for record in extracted.facts.elements}
    uses = [relation for relation in extracted.facts.relations if relation.relation_kind == "resource_use"]
    assert len(uses) == 2
    assert {elements[relation.source.element_ref].qualifiers for relation in uses} == {"", "zh-rCN"}
    for relation in uses:
        call = elements[relation.target.element_ref]
        assert "->getString(I)" in call.declared_target.signature
        assert relation.target.slot_kind == "argument" and relation.target.slot_index == 0
        assert relation.resolution == "partial" and "runtime configuration" in relation.unresolved_reason
        assert len(relation.provenance.support_refs) == 3
    refs = [relation for relation in extracted.facts.relations if relation.relation_kind == "resource_reference"]
    assert len(refs) == 2 and all(relation.source_selector.startswith("/manifest/application/@") for relation in refs)
    assert not any(elements[relation.target.element_ref].operation != "invoke" for relation in uses)
    method, instructions = body(extracted, MAIN + "->resourceLookingInteger()I")
    assert any(operand.value.value == 0x7f060002 for record in instructions for operand in record.operands)
    assert not any(relation.relation_kind == "resource_use" and relation.target.element_ref in {record.id for record in instructions}
                   for relation in extracted.facts.relations)


def test_field_array_operations_and_branch_operands_are_locatable(extracted):
    operations = {record.operation for record in records(extracted, "instruction")}
    assert {"assignment", "invoke", "field_read", "field_write", "array_read", "array_write", "constant", "branch", "return", "allocation"} <= operations
    branch = next(record for record in records(extracted, "instruction") if record.opcode == "if-eqz")
    target = next(operand.value.value["target_offset_bytes"] for operand in branch.operands if operand.kind == "branch")
    assert any(record.position.method_ref == branch.position.method_ref and record.position.offset_bytes == target
               for record in records(extracted, "instruction"))


@pytest.mark.parametrize("variant,capability,code,path", [
    ("broken-dex.apk", "dex", "dex_parse_error", "classes2.dex"),
    ("broken-resources.apk", "resources", "resource_parse_error", "resources.arsc"),
    ("broken-manifest.apk", "manifest", "manifest_parse_error", "AndroidManifest.xml"),
])
def test_real_local_corruption_keeps_other_usable_facts(variant, capability, code, path):
    result = extract_apk(FIXTURES / variant)
    assert result.summary["outcome"] == "partial"
    assert len(records(result, "instruction")) >= 59
    assert result.summary["coverage"][capability] in {"partial", "failed"}
    assert any(status.issue_code == code and status.scope.location.path == path for status in result.facts.statuses)
    assert path in result.entry_digests  # original damaged bytes remain inspectable
    if capability != "manifest":
        assert records(result, "configuration")
    if capability != "resources":
        assert records(result, "resource")
    assert loads_facts(result.facts.model_dump_json()) == result.facts


def test_invalid_container_has_valid_failure_envelope():
    result = extract_apk(FIXTURES / "invalid.apk")
    assert result.summary["outcome"] == "failed" and not result.facts.elements
    assert all(result.summary["coverage"][name] == "failed" for name in ["dex", "manifest", "resources"])
    assert loads_facts(result.facts.model_dump_json()) == result.facts


def test_method_fault_injection_is_scoped_and_preserves_other_methods(monkeypatch):
    # Explicit engineering fault injection; real corruption is separately tested above.
    original = Extractor.instructions

    def fail_one(self, dex, encoded, method, *args):
        if method.signature == MAIN + "->consume(Ljava/lang/String;)V":
            raise ValueError("acceptance injected method decoder failure")
        return original(self, dex, encoded, method, *args)
    monkeypatch.setattr(Extractor, "instructions", fail_one)
    result = extract_apk(FIXTURES / "valid.apk")
    method, instructions = body(result, MAIN + "->consume(Ljava/lang/String;)V")
    total = sum(len(parsed_dump((FIXTURES / f"dexdump-{i}.txt").read_text(encoding="utf-8"))) for i in [1, 2])
    assert not instructions and len(records(result, "instruction")) == total - 2
    assert any(status.issue_code == "method_decode_error" and status.scope.element_ref == method.id for status in result.facts.statuses)
    assert result.summary["coverage"]["dex"] == "partial"
    assert result.summary["observed_counts"]["partial_method_bodies"] == 1


def test_instruction_budget_keeps_valid_prefix_and_reports_truncation():
    result = extract_apk(FIXTURES / "valid.apk", FactConfig(requested_capabilities=list(ALL), options={"max_instructions_per_method": 1}))
    counts = Counter(record.position.method_ref for record in records(result, "instruction"))
    assert counts and all(count == 1 for count in counts.values())
    assert any(status.issue_code == "instruction_budget" and status.state == "truncated" for status in result.facts.statuses)
    assert result.summary["coverage"]["dex"] == "partial"
    expected = Counter(signature for i in [1, 2] for signature, offset in parsed_dump((FIXTURES / f"dexdump-{i}.txt").read_text(encoding="utf-8")))
    assert result.summary["observed_counts"]["partial_method_bodies"] == sum(count > 1 for count in expected.values())
    assert result.summary["observed_counts"]["decoded_method_bodies"] == sum(count == 1 for count in expected.values())


@pytest.mark.parametrize("options", [{"max_entry_bytes": 0}, {"max_instructions_per_method": True}, {"typo": 1}])
def test_invalid_extractor_options_are_rejected(options):
    with pytest.raises(ValidationError):
        extract_apk(FIXTURES / "valid.apk", FactConfig(requested_capabilities=list(ALL), options=options))


def test_zip_budget_failure_is_explicit_and_bounded():
    result = extract_apk(FIXTURES / "valid.apk", FactConfig(requested_capabilities=list(ALL), options={"max_entry_bytes": 1}))
    assert result.summary["outcome"] == "failed"
    assert not result.blobs and not result.entry_digests
    assert any("budget" in (status.reason or "") for status in result.facts.statuses)


def test_repeat_and_renamed_input_keep_content_and_change_run_identity(extracted, tmp_path):
    renamed = tmp_path / "renamed.apk"
    shutil.copyfile(FIXTURES / "valid.apk", renamed)
    second = extract_apk(renamed)
    assert extracted.facts.run.apk_sha256 == second.facts.run.apk_sha256
    assert extracted.facts.run.run_id != second.facts.run.run_id
    assert normalized(extracted) == normalized(second)


def test_atomic_evidence_publication_roundtrip_and_no_overwrite(extracted, tmp_path):
    output = write_extraction(extracted, tmp_path)
    assert load_facts(output / "facts.json") == extracted.facts
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert hashlib.sha256((output / "facts.json").read_bytes()).hexdigest() == manifest["facts_sha256"]
    with zipfile.ZipFile(FIXTURES / "valid.apk") as archive:
        for entry in manifest["files"]:
            data = (output / entry["path"]).read_bytes()
            assert data == archive.read(entry["archive_entry"])
            assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    before = (output / "facts.json").read_bytes()
    with pytest.raises(FileExistsError):
        write_extraction(extracted, tmp_path)
    assert (output / "facts.json").read_bytes() == before
    assert not list(tmp_path.rglob(".building_*"))


def test_existing_real_small_apk_has_raw_instruction_evidence_and_visible_limit():
    result = extract_apk(REAL)
    assert result.facts.run.apk_sha256 == hashlib.sha256(REAL.read_bytes()).hexdigest()
    assert result.facts.run.apk_metadata["package"] == "com.mno.dynamicprofile"
    assert result.summary["element_counts"]["instruction"] == 564
    assert result.summary["observed_counts"]["method_definitions"] == 43
    assert result.summary["observed_counts"]["method_references"] == 123
    assert result.summary["outcome"] == "partial"
    assert any(status.issue_code == "resource_argument_unresolved" for status in result.facts.statuses)
    assert result.summary["coverage"]["dex"] == result.summary["coverage"]["manifest"] == "complete"
    elements = {record.id: record for record in result.facts.elements}
    with zipfile.ZipFile(REAL) as archive:
        dex = archive.read("classes.dex")
        for instruction in records(result, "instruction"):
            method = elements[instruction.position.method_ref]
            absolute = method.code_offset_bytes + 16 + instruction.position.offset_bytes
            assert dex[absolute:absolute + instruction.length_bytes].hex() == instruction.raw_hex


def test_original_toolchain_fixture_remains_extractable():
    result = extract_apk(ROOT / "artifacts/toolchain-fixture/toolchain-fixture.apk")
    assert result.summary["coverage"]["dex"] == result.summary["coverage"]["manifest"] == "complete"
    assert result.summary["coverage"]["resources"] == "complete" and not records(result, "resource")
    assert any(record.declared_target and "->sink(" in (record.declared_target.signature or "") for record in records(result, "instruction"))

@pytest.mark.parametrize("stop", ["later_decode_failure", "instruction_budget"])
def test_result_reception_survives_later_partial_body(extracted, monkeypatch, stop):
    candidates = []
    for method in records(extracted, "method"):
        if not method.is_definition:
            continue
        instructions = sorted((r for r in records(extracted, "instruction") if r.position.method_ref == method.id), key=lambda r: r.position.offset_bytes)
        for index, call in enumerate(instructions[:-2]):
            if call.operation == "invoke" and call.result_receiver_ref == instructions[index + 1].id:
                candidates.append((method, instructions, index))
    assert candidates
    method, instructions, index = candidates[0]
    if stop == "later_decode_failure":
        original = Extractor.instruction
        def fail_later(self, dex, raw, offset, owner, method_ids, field_ids):
            if owner.signature == method.signature and offset == instructions[index + 2].position.offset_bytes:
                raise ValueError("injected unsupported later instruction")
            return original(self, dex, raw, offset, owner, method_ids, field_ids)
        monkeypatch.setattr(Extractor, "instruction", fail_later)
        result = extract_apk(FIXTURES / "valid.apk")
    else:
        result = extract_apk(FIXTURES / "valid.apk", FactConfig(requested_capabilities=list(ALL), options={"max_instructions_per_method": index + 2}))
    owner, prefix = body(result, method.signature)
    call = next(r for r in prefix if r.position.offset_bytes == instructions[index].position.offset_bytes)
    receiver = next(r for r in prefix if r.position.offset_bytes == instructions[index + 1].position.offset_bytes)
    assert call.result_receiver_ref == receiver.id
    assert slot(call, "result").registers == slot(receiver, "result").registers
    assert any(r.relation_kind == "call_result_assignment" and r.source.element_ref == call.id and r.target.element_ref == receiver.id for r in result.facts.relations)
    assert any(s.scope.element_ref == owner.id and s.state in {"failed", "truncated"} for s in result.facts.statuses)
    loads_facts(result.facts.model_dump_json())


@pytest.mark.parametrize("damage", ["nonadjacent", "void", "other_following"])
def test_result_reception_rejects_wrong_pair(extracted, damage):
    call = deepcopy(next(r for r in records(extracted, "instruction") if r.operation == "invoke" and r.result_receiver_ref))
    following = deepcopy(next(r for r in records(extracted, "instruction") if r.id == call.result_receiver_ref))
    call.result_receiver_ref = None
    call.slots = [s for s in call.slots if s.slot_kind != "result"]
    if damage == "nonadjacent":
        following.position.offset_bytes += 2
    elif damage == "void":
        call.declared_target.signature = call.declared_target.signature.split(")")[0] + ")V"
    else:
        following.opcode = "move-object"
    Extractor.link_result_receiver(call, following)
    assert call.result_receiver_ref is None
    assert not any(s.slot_kind == "result" for s in call.slots)


def test_truncation_before_move_result_does_not_invent_reception(extracted):
    candidates = []
    for method in records(extracted, "method"):
        if not method.is_definition:
            continue
        instructions = sorted((r for r in records(extracted, "instruction") if r.position.method_ref == method.id), key=lambda r: r.position.offset_bytes)
        for index, call in enumerate(instructions[:-1]):
            if call.operation == "invoke" and call.result_receiver_ref == instructions[index + 1].id:
                candidates.append((method, instructions, index))
    method, instructions, index = candidates[0]
    result = extract_apk(FIXTURES / "valid.apk", FactConfig(requested_capabilities=list(ALL), options={"max_instructions_per_method": index + 1}))
    _, prefix = body(result, method.signature)
    call = next(r for r in prefix if r.position.offset_bytes == instructions[index].position.offset_bytes)
    assert call.result_receiver_ref is None
    assert not any(s.slot_kind == "result" for s in call.slots)
    assert not any(r.relation_kind == "call_result_assignment" and r.source.element_ref == call.id for r in result.facts.relations)
