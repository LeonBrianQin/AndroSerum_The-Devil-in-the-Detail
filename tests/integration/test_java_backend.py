"""F3 real Java execution, independent DEX anchors, protocol and explicitly labeled fault tests."""

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

import jsonschema
import pytest

from androserum.cli import main
from androserum.facts import java_backend as backend
from androserum.facts.extractor import extract_apk, write_extraction
from androserum.facts.identity import canonical_json, filesystem_path, sha256_file
from androserum.facts.io import FactValidationError, loads_facts
from androserum.facts.java_backend import JavaConfig, extract_java, read_backend, select_platform
from androserum.facts.jimple import JimpleMethod, compatible_origin, verify_jimple_evidence
from androserum.facts.models import AnalysisNodeRecord
from androserum.facts.store import FactView, create_snapshot, export_snapshot, import_snapshot

ROOT = Path(__file__).resolve().parents[2]
MAIN = "Lorg/androserum/extraction/MainActivity;"
EXTRA = "Lorg/androserum/jimple/MainActivity;"
REAL = Path(r"D:\AndroSerum260309\downloaded_samples\2013\039E9C23EBB8B5789B5AA0681CD6757C10442302E2504AE3A0F9C93165D68B76.apk")


@pytest.fixture(scope="session")
def prepared_java():
    try:
        backend.verify_build()
    except (OSError, ValueError):
        backend.build_java_backend()
    for script in ["build_extraction_fixture.py", "build_java_fixture.py"]:
        subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=ROOT, check=True, capture_output=True, timeout=90)


@pytest.fixture(scope="module")
def controlled(prepared_java, tmp_path_factory):
    work = filesystem_path(tmp_path_factory.mktemp("f3-raw") / "work")
    return extract_java(ROOT / "artifacts/fixtures/f1/valid.apk", work_directory=work), work


@pytest.fixture(scope="module")
def extra(prepared_java):
    return extract_java(ROOT / "artifacts/fixtures/f3/valid.apk")


@pytest.fixture(scope="module")
def real(prepared_java):
    return extract_java(REAL)


def ir(result):
    return {entry: JimpleMethod.model_validate_json(result.blobs[digest]) for entry, digest in result.entry_digests.items()
            if re.fullmatch(r"analysis/java/methods/[0-9]+\.json", entry)}


def unit_for(result, node):
    return ir(result)[node.position.artifact_path].units[int(node.position.position_label.split(":")[1])]


def normalized(result):
    value = result.facts.model_dump(mode="json")
    value["run"].pop("created_at")
    value["run"].pop("input_name")
    identities = [value["run"]["run_id"]]
    for section in ["elements", "relations", "contexts", "bindings", "statuses"]:
        identities += [record["id"] for record in value[section]]
    replacements = {ref: f"id:{i}" for i, ref in enumerate(identities)}
    def replace(item):
        if isinstance(item, str): return replacements.get(item, item)
        if isinstance(item, list): return [replace(child) for child in item]
        if isinstance(item, dict): return {key: replace(child) for key, child in item.items()}
        return item
    return replace(value)


def test_real_java_method_coverage_and_versioned_schema(controlled):
    result, _ = controlled
    assert result.summary["java"]["methods"] == {"complete": 20, "abstract": 1, "native": 1}
    assert not result.summary["java"]["protocol_errors"]
    assert result.summary["stage"] == "F3" and result.facts.schema_version == "program-facts.v2"
    schema = json.loads((ROOT / "schemas/jimple-method.v1.schema.json").read_text(encoding="utf-8"))
    assert schema == JimpleMethod.model_json_schema()
    for method in ir(result).values():
        jsonschema.validate(method.model_dump(mode="json"), schema)
    assert sum(len(method.units) for method in ir(result).values()) == 77
    assert sum(isinstance(record, AnalysisNodeRecord) for record in result.facts.elements) == 77


def test_three_calls_match_independent_dexdump_byte_positions(controlled):
    result, _ = controlled
    # Android dexdump offsets are code units; these anchors are independent of the adapter.
    dump = (ROOT / "artifacts/fixtures/f1/dexdump-1.txt").read_text(encoding="utf-8")
    expected = [int(match[1], 16) * 2 for line in dump.splitlines()
                if "MainActivity;.consume:(Ljava/lang/String;)V" in line
                for match in [re.search(r"\|([0-9a-f]+):", line)] if match]
    elements = {value.id: value for value in result.facts.elements}
    found = []
    for relation in result.facts.relations:
        if relation.relation_kind != "dex_jimple_mapping": continue
        source, target = elements[relation.source.element_ref], elements[relation.target.element_ref]
        unit = unit_for(result, target)
        if unit.invoke and unit.invoke.signature == MAIN + "->consume(Ljava/lang/String;)V":
            found.append(source.position.offset_bytes)
            assert source.declared_target.signature == unit.invoke.signature
            assert source.position.offset_bytes in {offset * 2 for offset in unit.offsets_code_units}
    assert sorted(found) == expected and len(expected) == 3


def test_same_line_calls_not_matched_by_line_number(extra):
    elements = {value.id: value for value in extra.facts.elements}
    calls = []
    for relation in extra.facts.relations:
        if relation.relation_kind != "dex_jimple_mapping": continue
        unit = unit_for(extra, elements[relation.target.element_ref])
        if unit.invoke and unit.invoke.signature == EXTRA + "->sink(Ljava/lang/String;)V" and unit.invoke.arguments[0].constant_kind == "string":
            calls.append((unit.invoke.arguments[0].constant, unit.line_number, elements[relation.source.element_ref].position.offset_bytes))
    assert {row[0] for row in calls} == {"left", "right"}
    assert len({row[1] for row in calls}) == 1 and len({row[2] for row in calls}) == 2


def test_overloads_arrays_traps_and_phantom_reporting(extra):
    methods = {method.signature: method for method in ir(extra).values()}
    assert {EXTRA + "->overloaded(I)I", EXTRA + "->overloaded([Ljava/lang/String;)Ljava/lang/String;",
            EXTRA + "->arrays([[[I)[[I"} <= set(methods)
    assert methods[EXTRA + "->guarded(Ljava/lang/String;)Ljava/lang/String;"].traps
    assert "org.androserum.jimple.MissingBase" in extra.summary["java"]["end"]["phantom_classes"]
    assert any(status.issue_code == "java_phantom_call_owner" for status in extra.facts.statuses)
    assert not any(record.kind == "class" and record.descriptor == "Lorg/androserum/jimple/MissingBase;" for record in extra.facts.elements)


def test_one_dex_instruction_can_support_multiple_ir_expansion_units(controlled):
    result, _ = controlled
    elements = {value.id: value for value in result.facts.elements}
    targets = {}
    for relation in result.facts.relations:
        if relation.relation_kind == "dex_jimple_mapping":
            source = elements[relation.source.element_ref]
            if source.opcode.startswith("filled-new-array"):
                targets.setdefault(source.id, []).append(elements[relation.target.element_ref])
    assert any(len(values) == 2 for values in targets.values())
    assert all(unit_for(result, node).operation == "array_write" for values in targets.values() for node in values)


def test_stale_return_tags_and_missing_tags_stay_unmapped(controlled):
    result, _ = controlled
    mapped = {relation.target.element_ref for relation in result.facts.relations if relation.relation_kind == "dex_jimple_mapping"}
    nodes = [value for value in result.facts.elements if isinstance(value, AnalysisNodeRecord)]
    returns = [node for node in nodes if unit_for(result, node).operation == "return" and unit_for(result, node).offsets_code_units]
    assert returns and any(node.id not in mapped for node in returns)
    assert result.summary["java"]["mapping"]["implicit_identity"] == 23
    assert result.summary["java"]["mapping"]["unmapped"] > 0
    assert any(status.issue_code == "jimple_origin_unresolved" for status in result.facts.statuses)


def test_structured_arguments_keep_exact_wide_float_and_integer_values(controlled):
    result, _ = controlled
    units = [unit for method in ir(result).values() for unit in method.units]
    call = next(unit for unit in units if unit.invoke and unit.invoke.signature == MAIN + "->wide(JDLjava/lang/String;)V")
    assert call.invoke.arguments[0].constant == 0x1122334455667788
    assert call.invoke.arguments[1].constant_kind == "double_bits" and call.invoke.arguments[1].constant == "7ff0000000000000"
    assert call.invoke.arguments[2].constant == "wide"
    # Raw F1 argument slots remain unknown: IR simplification is not published as a data-flow proof.
    original_call = next(value for value in result.facts.elements if value.kind == "instruction" and value.declared_target and value.declared_target.signature == call.invoke.signature)
    assert all(slot.value.status == "unknown" for slot in original_call.slots if slot.slot_kind == "argument")
    assert not any(relation.relation_kind in {"data_dependency", "control_dependency", "candidate_call", "information_flow"} for relation in result.facts.relations)


def test_real_apk_all_methods_exported_with_explicit_platform_limits(real):
    assert real.summary["java"]["methods"] == {"complete": 43}
    assert sum(len(method.units) for method in ir(real).values()) == 455
    platform = real.summary["java"]["platform"]
    assert platform["target_sdk"] == 4 and platform["selected_api"] == 16 and platform["fallback"]
    assert any(status.issue_code == "java_phantom_classes" for status in real.facts.statuses)
    assert real.summary["coverage"]["resources"] == real.summary["coverage"]["dex_jimple_mapping"] == "partial"
    assert real.summary["java"]["mapping"].get("candidate", 0) > 0
    assert any(relation.relation_kind == "dex_jimple_mapping" and relation.resolution == "partial" for relation in real.facts.relations)


def test_platform_explicit_compile_target_and_no_silent_missing_fallback(controlled):
    result, _ = controlled
    assert select_platform(result.facts, JavaConfig())["basis"] == "declared_compile_sdk"
    assert select_platform(result.facts, JavaConfig(platform_api=35))["selected_api"] == 35
    missing = select_platform(result.facts, JavaConfig(platform_api=999))
    assert missing["selected_api"] is None and missing["basis"] == "explicit_platform_missing"
    data = result.facts.model_copy(deep=True)
    for value in data.elements:
        if value.kind == "configuration" and value.value.value.get("tag") == "manifest":
            value.value.value["attributes"].pop("{http://schemas.android.com/apk/res/android}compileSdkVersion", None)
    assert select_platform(data, JavaConfig())["basis"] == "target_sdk_heuristic"


def test_missing_platform_preserves_direct_facts(prepared_java):
    result = extract_java(ROOT / "artifacts/fixtures/f1/valid.apk", config=JavaConfig(platform_api=999))
    assert result.summary["coverage"]["dex"] == "complete" and result.summary["coverage"]["dex_jimple_mapping"] == "failed"
    assert not any(isinstance(record, AnalysisNodeRecord) for record in result.facts.elements)
    assert any(status.issue_code == "java_platform_unavailable" for status in result.facts.statuses)


@pytest.mark.parametrize("config", [{"max_methods": 1}, {"max_units_per_method": 1}, {"max_output_bytes": 1}])
def test_real_budget_limits_produce_valid_explicit_partial_results(prepared_java, config):
    result = extract_java(ROOT / "artifacts/fixtures/f1/valid.apk", config=JavaConfig(**config))
    assert result.summary["outcome"] == "partial"
    assert result.summary["coverage"]["dex"] == "complete"
    assert loads_facts(result.facts.model_dump_json()) == result.facts
    assert any(status.state in {"failed", "truncated", "partial"} and status.capability == "dex_jimple_mapping" for status in result.facts.statuses)
    if "max_output_bytes" in config:
        assert not any(isinstance(record, AnalysisNodeRecord) for record in result.facts.elements)


@pytest.mark.parametrize("config", [{"timeout_seconds": 0}, {"heap_mb": 1}, {"max_methods": True}, {"unknown": 1}])
def test_invalid_java_configuration_rejected(config):
    with pytest.raises(ValueError):
        JavaConfig(**config)


def test_method_fault_injection_is_scoped_and_labeled(prepared_java, monkeypatch):
    original = backend._request
    def request(*args):
        value = original(*args)
        value["test_fault_method"] = MAIN + "->consume(Ljava/lang/String;)V"
        return value
    monkeypatch.setattr(backend, "_request", request)
    result = extract_java(ROOT / "artifacts/fixtures/f1/valid.apk")
    assert result.summary["java"]["methods"]["failed"] == 1
    assert result.summary["java"]["methods"]["complete"] == 19
    assert any(status.issue_code == "java_method_failed" and "acceptance" in status.reason for status in result.facts.statuses)


def test_actual_timeout_keeps_only_individually_committed_methods(prepared_java, monkeypatch):
    original = backend._request
    def request(*args):
        value = original(*args)
        value.update(test_pause_after_commits=1, test_pause_millis=20000)
        return value
    monkeypatch.setattr(backend, "_request", request)
    result = extract_java(ROOT / "artifacts/fixtures/f1/valid.apk", config=JavaConfig(timeout_seconds=6))
    assert result.summary["java"]["process"]["state"] == "timeout"
    assert sum(result.summary["java"]["methods"].values()) == 1
    assert any("java_process_timeout" in error for error in result.summary["java"]["protocol_errors"])
    assert any(status.state == "truncated" and status.issue_code == "java_method_not_completed" for status in result.facts.statuses)


@pytest.mark.parametrize("damage", ["method-truncated", "bad-commit", "bad-start", "bad-end", "missing-end"])
def test_corrupt_protocol_never_becomes_a_complete_run(controlled, tmp_path, damage):
    _, raw = controlled
    copied = filesystem_path(tmp_path / "raw")
    shutil.copytree(raw, copied)
    request = json.loads((copied / "request.json").read_text(encoding="utf-8"))
    process = json.loads((copied / "process.json").read_text(encoding="utf-8"))
    if damage == "method-truncated":
        (copied / "methods/00000.json").write_text("{", encoding="utf-8")
    elif damage == "missing-end":
        (copied / "end.json").unlink()
    else:
        path = copied / ("methods/00000.commit.json" if damage == "bad-commit" else "start.json" if damage == "bad-start" else "end.json")
        value = json.loads(path.read_text(encoding="utf-8"))
        value["request_sha256"] = "0" * 64
        path.write_text(canonical_json(value), encoding="utf-8")
    methods, end, errors = read_backend(copied, request, process, JavaConfig())
    assert errors
    if damage == "bad-start": assert not methods
    elif damage in {"method-truncated", "bad-commit"}: assert len(methods) == 21
    else: assert len(methods) == 22
    assert end["state"] != "complete" or errors


def test_duplicate_classes_do_not_silently_merge_java_ownership(prepared_java, tmp_path):
    with zipfile.ZipFile(ROOT / "artifacts/fixtures/f1/valid.apk") as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    entries["classes3.dex"] = entries["classes.dex"]
    apk = tmp_path / "duplicates.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        for name, data in entries.items(): archive.writestr(name, data)
    result = extract_java(apk)
    ambiguous = {record.id for record in result.facts.elements if record.kind == "method" and record.is_definition and record.signature.startswith(MAIN)}
    assert any(status.issue_code == "java_definition_ambiguous" for status in result.facts.statuses)
    assert not any(isinstance(record, AnalysisNodeRecord) and record.method_ref in ambiguous for record in result.facts.elements)


def test_unrelated_same_api_mapping_rejected_before_publication(controlled, tmp_path):
    result, _ = controlled
    changed = deepcopy(result)
    elements = {value.id: value for value in changed.facts.elements}
    mappings = [relation for relation in changed.facts.relations if relation.relation_kind == "dex_jimple_mapping" and
                elements[relation.source.element_ref].declared_target and elements[relation.source.element_ref].declared_target.signature == MAIN + "->consume(Ljava/lang/String;)V"]
    mappings[0].target = mappings[1].target.model_copy(deep=True)
    mappings[0].provenance.support_refs = list(dict.fromkeys(mappings[0].provenance.support_refs + [mappings[0].target.element_ref]))
    # Endpoints and method ownership alone are insufficient; artifact-bound offsets must agree.
    assert loads_facts(changed.facts.model_dump_json())
    with pytest.raises(ValueError, match="offset/operation/signature"):
        verify_jimple_evidence(changed.facts, lambda entry: changed.blobs[changed.entry_digests[entry]])
    package = write_extraction(changed, tmp_path / "facts")
    with pytest.raises(ValueError, match="offset/operation/signature"):
        import_snapshot(package, tmp_path / "store")
    assert not (tmp_path / "store").exists()


def test_structured_ir_snapshot_move_export_roundtrip_and_cli(controlled, tmp_path, capsys):
    result, _ = controlled
    package = write_extraction(result, tmp_path / "facts")
    snapshot = import_snapshot(package, tmp_path / "store")
    node = next(record for record in result.facts.elements if isinstance(record, AnalysisNodeRecord))
    before = sha256_file(snapshot / "facts.sqlite")
    with FactView(snapshot) as view:
        assert view.verify()["valid"]
        assert view.read_jimple(node.id) == unit_for(result, node)
        exported = export_snapshot(view, tmp_path / "export", format="jsonl")
        expected_id = view.snapshot_id
    imported = import_snapshot(exported, tmp_path / "imported")
    moved = filesystem_path(tmp_path / "moved")
    shutil.copytree(imported, moved)
    with FactView(moved) as view:
        assert view.verify()["valid"] and view.snapshot_id == expected_id
    assert main(["store-query", str(moved), "--kind", "jimple", "--refs", node.id]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "jimple-query.v1" and payload["node_ref"] == node.id
    assert sha256_file(snapshot / "facts.sqlite") == before


def test_repeat_execution_has_same_normalized_facts_and_ir(controlled, prepared_java):
    first, _ = controlled
    second = extract_java(ROOT / "artifacts/fixtures/f1/valid.apk")
    assert first.facts.run.run_id != second.facts.run.run_id
    assert normalized(first) == normalized(second)
    assert {entry: method.model_dump(mode="json") for entry, method in ir(first).items()} == {
        entry: method.model_dump(mode="json") for entry, method in ir(second).items()}


def test_stale_java_build_is_rejected(controlled, monkeypatch):
    original = backend._sources
    monkeypatch.setattr(backend, "_sources", lambda: {**original(), "modified.java": "0" * 64})
    with pytest.raises(ValueError, match="stale"):
        backend.verify_build()


def test_formal_parameter_roles_and_exception_bindings_are_structured(controlled, extra):
    result, _ = controlled
    wide = next(method for method in ir(result).values() if method.signature == MAIN + "->wide(JDLjava/lang/String;)V")
    bindings = [unit for unit in wide.units if unit.operation == "identity"]
    assert [(unit.right.parameter_index, unit.right.type_descriptor) for unit in bindings] == [(0, "J"), (1, "D"), (2, "Ljava/lang/String;")]
    own = next(method for method in ir(result).values() if method.signature == MAIN + "->onCreate(Landroid/os/Bundle;)V")
    assert any(unit.right and unit.right.identity_kind == "this" for unit in own.units)
    caught = [unit for method in ir(extra).values() for unit in method.units if unit.right and unit.right.identity_kind == "caught_exception"]
    assert caught
    arrays = next(method for method in ir(extra).values() if method.signature == EXTRA + "->arrays([[[I)[[I")
    assert any(unit.right and unit.right.kind.endswith("ArrayRef") and unit.right.base is not None and unit.right.index_value is not None for unit in arrays.units)


def test_numeric_commit_order_survives_six_digit_method_ordinals(controlled, tmp_path):
    _, raw = controlled
    copied = filesystem_path(tmp_path / "raw")
    shutil.copytree(raw, copied)
    commits = []
    for i, number in enumerate([99999, 100000]):
        old = copied / f"methods/{i:05d}.commit.json"
        commit = json.loads(old.read_text(encoding="utf-8"))
        source = copied / commit["path"]
        commit["path"] = f"methods/{number}.json"
        source.rename(copied / commit["path"])
        destination = copied / f"methods/{number}.commit.json"
        destination.write_text(canonical_json(commit), encoding="utf-8")
        commits.append(destination.relative_to(copied).as_posix())
    for path in (copied / "methods").glob("*.commit.json"):
        if path.relative_to(copied).as_posix() not in commits: path.unlink()
    end_path = copied / "end.json"
    end = json.loads(end_path.read_text(encoding="utf-8"))
    end["commits"] = commits
    end_path.write_text(canonical_json(end), encoding="utf-8")
    request = json.loads((copied / "request.json").read_text(encoding="utf-8"))
    process = json.loads((copied / "process.json").read_text(encoding="utf-8"))
    methods, _, errors = read_backend(copied, request, process, JavaConfig())
    assert len(methods) == 2 and not errors
