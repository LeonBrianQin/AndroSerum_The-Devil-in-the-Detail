"""F2 storage acceptance. Synthetic fixtures test storage contracts, not static inference."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from androserum.cli import main
from androserum.facts.exchange import export_jsonl, load_jsonl
from androserum.facts.identity import canonical_json, filesystem_path, sha256_file
from androserum.facts.io import FactValidationError, load_facts, loads_facts
from androserum.facts.models import Endpoint
from androserum.facts import store as storage
from androserum.facts.store import (
    EvidenceFile, FactView, RefFilter, create_snapshot, export_snapshot, import_snapshot,
    logical_digest, rebuild_catalog, rebuild_snapshot,
)

ROOT = Path(__file__).resolve().parents[2]
F1_REPORT = Path(os.environ.get("F2_F1_REPORT", ROOT / "docs/evidence/f1_acceptance_20261021_152452_087854.json"))
ALL = RefFilter(mode="all")
MISSING = RefFilter(mode="missing")
MAIN = "Lorg/androserum/extraction/MainActivity;"


def accepted_package(label):
    report = json.loads(F1_REPORT.read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    return filesystem_path(ROOT / report["outputs"][label]["fact_bundle"])


@pytest.fixture(scope="module")
def real_store(tmp_path_factory):
    return import_snapshot(accepted_package("real"), tmp_path_factory.mktemp("f2-real"))


@pytest.fixture(scope="module")
def controlled_store(tmp_path_factory):
    return import_snapshot(accepted_package("controlled"), tmp_path_factory.mktemp("f2-controlled"))


def synthetic_facts():
    data = load_facts(ROOT / "tests/fixtures/contracts/valid.json").model_dump(mode="json")
    run = data["run"]["run_id"]
    provenance = {"kind": "static_analysis", "tool_ref": "tool:synthetic", "support_refs": ["instruction:heartbeat"]}
    endpoints = data["relations"][0]
    for label, call in [("a", "instruction:send-heartbeat"), ("b", "instruction:send-identifier")]:
        data["contexts"].append({"id": f"context:{label}", "run_ref": run, "provenance": provenance,
            "abstraction": "synthetic-for-storage-only", "callsite_refs": [call]})
        data["bindings"].append({"id": f"binding:{label}", "run_ref": run, "provenance": provenance,
            "binding_kind": "object", "endpoints": [endpoints["source"], endpoints["target"]], "context_ref": f"context:{label}"})
        relation = deepcopy(endpoints)
        relation.update(id=f"relation:parallel-{label}", context_ref=f"context:{label}", binding_refs=[f"binding:{label}"])
        data["relations"].append(relation)
    unresolved = deepcopy(endpoints)
    unresolved.update(id="relation:unresolved", target=None, resolution="unresolved", unresolved_reason="Synthetic unresolved target")
    data["relations"].append(unresolved)
    candidate = deepcopy(data["relations"][2])
    candidate.update(id="relation:candidate", relation_kind="candidate_call", provenance=provenance, context_ref="context:a")
    data["relations"].append(candidate)
    values = [{"status": "known", "value": None}, {"status": "unknown", "reason": "not resolved"},
              {"status": "not_applicable", "reason": "not relevant"},
              {"status": "partial", "value": {"tool_ref": "tool:not-a-reference", "text": "\u4e2d\u6587", "large": 0x1122334455667788}, "reason": "partial fixture"}]
    for index, value in enumerate(values):
        data["elements"].append({"kind": "resource", "id": f"resource:value{index}", "run_ref": run,
            "provenance": {"kind": "direct", "tool_ref": "tool:synthetic"},
            "position": {"kind": "archive", "path": "resources.arsc", "selector": f"fixture:{index}"},
            "resource_id": index, "resource_type": "synthetic", "name": f"value{index}", "value": value})
    return loads_facts(canonical_json(data))


@pytest.fixture
def synthetic_store(tmp_path):
    return create_snapshot(synthetic_facts(), tmp_path / "synthetic")


def copy_snapshot(source, target):
    target = filesystem_path(target)
    shutil.copytree(source, target)
    return target


def all_hashes(root):
    return {path.relative_to(root).as_posix(): sha256_file(path) for path in root.rglob("*") if path.is_file()}


def rehash_database(path):
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["database_sha256"] = sha256_file(path / "facts.sqlite")
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")


def test_real_complete_payload_and_partial_status_roundtrip(real_store):
    original = load_facts(accepted_package("real") / "facts.json")
    with FactView(real_store, run_ref=original.run.run_id) as view:
        assert view.verify()["valid"]
        assert view.export_bundle() == original
        methods = [value for value in original.elements if value.kind == "method"]
        assert len(methods) == 123 and sum(value.is_definition for value in methods) == 43
        assert view.manifest.counts["elements"] == len(original.elements)
        assert view.manifest.coverage["resources"] == "partial"
        issues = view.get_status(capability="resources").records
        assert any(value.issue_code == "resource_argument_unresolved" for value in issues)


def test_repeated_calls_and_byte_lookup_match_original(controlled_store):
    original = load_facts(accepted_package("controlled") / "facts.json")
    expected = [value for value in original.elements if value.kind == "instruction" and value.declared_target and
                value.declared_target.signature == MAIN + "->consume(Ljava/lang/String;)V"]
    with FactView(controlled_store) as view:
        calls = view.find_calls(declared_signature=MAIN + "->consume(Ljava/lang/String;)V").records
        assert calls == expected and len(calls) == len({value.id for value in calls}) == 3
        for call in calls:
            assert view.find_instructions(call.position.method_ref, offset_bytes=call.position.offset_bytes).records == [call]
            assert view.get_operation(call.id).records == [call]


def test_cross_dex_declarations_and_reference_resolution_remain_separate(controlled_store):
    with FactView(controlled_store) as view:
        methods = view.find_methods("Lorg/androserum/extraction/Helper;->decorate(Ljava/lang/String;)Ljava/lang/String;").records
        assert len(methods) == 2 and methods[0].position.dex_ref != methods[1].position.dex_ref
        reference = next(value for value in methods if not value.is_definition)
        relations = view.get_relations(Endpoint(element_ref=reference.id, slot_kind="element"), direction="out",
            relation_kinds=["reference_resolution"], context=ALL, binding=ALL).records
        assert len(relations) == 1 and relations[0].target.element_ref == next(value.id for value in methods if value.is_definition)


def test_every_direction_and_type_query_matches_independent_input_scan(controlled_store):
    original = load_facts(accepted_package("controlled") / "facts.json")
    with FactView(controlled_store) as view:
        for relation in original.relations:
            for direction, endpoint in [("out", relation.source), ("in", relation.target)]:
                if endpoint is None:
                    continue
                expected = [value for value in original.relations if value.relation_kind == relation.relation_kind and
                            (value.source if direction == "out" else value.target) == endpoint]
                result = view.get_relations(endpoint, direction=direction, relation_kinds=[relation.relation_kind], context=ALL, binding=ALL)
                assert result.records == expected
                assert result.to_dict()["path_compatibility_checked"] is False


def test_parallel_edges_context_binding_and_unresolved_target_survive(synthetic_store):
    source = synthetic_facts().relations[0].source
    with FactView(synthetic_store) as view:
        result = view.get_relations(source, direction="out", relation_kinds=["data_dependency"], context=ALL, binding=ALL)
        assert [value.id for value in result.records] == ["relation:data-heartbeat", "relation:parallel-a", "relation:parallel-b", "relation:unresolved"]
        exact = view.get_relations(source, direction="out", relation_kinds=["data_dependency"],
            context=RefFilter(mode="exact", ref="context:a"), binding=RefFilter(mode="exact", ref="binding:a"))
        assert [value.id for value in exact.records] == ["relation:parallel-a"]
        assert not view.get_relations(source, direction="out", relation_kinds=["data_dependency"],
            context=RefFilter(mode="exact", ref="context:a"), binding=RefFilter(mode="exact", ref="binding:b")).records
        missing = view.get_relations(source, direction="out", relation_kinds=["data_dependency"], context=MISSING, binding=MISSING)
        assert [value.id for value in missing.records] == ["relation:data-heartbeat", "relation:unresolved"]
        alternatives = view.get_relations(source, direction="out", relation_kinds=["data_dependency"],
            context=RefFilter(mode="exact_or_missing", ref="context:a"), binding=RefFilter(mode="exact_or_missing", ref="binding:a"))
        assert [value.id for value in alternatives.records] == ["relation:data-heartbeat", "relation:parallel-a", "relation:unresolved"]
        assert result.records[-1].target is None and result.records[-1].resolution == "unresolved"


def test_candidate_and_declared_queries_are_distinct(synthetic_store):
    with FactView(synthetic_store) as view:
        assert len(view.find_calls(declared_signature="Lexample/Network;->send(Ljava/lang/String;)V").records) == 2
        assert [value.id for value in view.find_calls(candidate_signature="Lexample/Network;->send(Ljava/lang/String;)V").records] == ["instruction:send-heartbeat"]


def test_values_null_unknown_unicode_and_large_integer_preserved(synthetic_store):
    with FactView(synthetic_store) as view:
        resources = view.get_records([f"resource:value{i}" for i in range(4)]).records
        assert [value.value.status for value in resources] == ["known", "unknown", "not_applicable", "partial"]
        assert resources[0].value.value is None
        assert resources[3].value.value == {"tool_ref": "tool:not-a-reference", "text": "\u4e2d\u6587", "large": 0x1122334455667788}
        assert view._connection.execute("SELECT count(*) FROM record_refs WHERE target_id='tool:not-a-reference'").fetchone()[0] == 0


def test_nonfinite_and_wide_groups_match_f1_records(controlled_store):
    with FactView(controlled_store) as view:
        restored = view.export_bundle()
        assert restored == load_facts(accepted_package("controlled") / "facts.json")
        nan = next(value for value in restored.elements if value.kind == "field" and value.signature == MAIN + "->NAN:F")
        assert nan.initial_value.value["hex"] == "7fc00000"
        call = view.find_calls(declared_signature=MAIN + "->wide(JDLjava/lang/String;)V").records[0]
        assert [value.registers for value in call.slots if value.slot_kind == "argument"] == [[3, 4], [0, 1], [2]]


def test_empty_not_analyzed_results_report_coverage(controlled_store):
    with FactView(controlled_store) as view:
        operation = view.find_calls(declared_signature=MAIN + "->consume(Ljava/lang/String;)V").records[0]
        for result in [view.get_constraints(operation.id), view.get_event_context(operation.id)]:
            assert not result.records and not result.truncated
            assert result.coverage["control"] == result.coverage["events"] == "not_started"


def test_support_closure_follows_refs_without_expanding_method_or_sibling_calls(synthetic_store):
    with FactView(synthetic_store) as view:
        result = view.collect_support(["relation:data-heartbeat"])
        ids = {value.id for value in result.records if hasattr(value, "id")}
        assert {"relation:data-heartbeat", "instruction:heartbeat", "instruction:send-heartbeat", "method:run", "dex:main"} <= ids
        assert "instruction:send-identifier" not in ids and "instruction:return" not in ids
        assert "relation:parallel-a" not in ids
        assert result.is_subset and result.filters["reference_closure_complete"]
        short = view.collect_support(["relation:data-heartbeat"], limit=1)
        assert short.truncated and short.pending_refs and not short.filters["reference_closure_complete"]


def test_budgets_missing_ids_and_invalid_endpoints_are_explicit(synthetic_store):
    with FactView(synthetic_store) as view:
        result = view.get_records(["instruction:missing", "method:run", "method:send"], limit=2)
        assert result.missing_refs == ["instruction:missing"] and result.pending_refs == ["method:send"] and result.truncated
        assert result.total_matches == 2 and len(result.records) == 1
        with pytest.raises(ValueError, match="Endpoint"):
            view.get_relations(Endpoint(element_ref="instruction:heartbeat", slot_kind="result", position_label="code+0x2"),
                direction="out", relation_kinds=["data_dependency"], context=ALL, binding=ALL)
        for budget in [0, -1, True, 100001]:
            with pytest.raises(ValueError):
                view.get_records(["method:run"], limit=budget)


@pytest.mark.parametrize("format", ["json", "jsonl"])
def test_export_import_roundtrip_includes_evidence(controlled_store, tmp_path, format):
    with FactView(controlled_store) as view:
        bundle = view.export_bundle()
        exported = export_snapshot(view, tmp_path / "export", format=format)
        snapshot_id = view.snapshot_id
    destination = import_snapshot(exported, tmp_path / "reimported")
    with FactView(destination) as view:
        assert view.verify()["valid"] and view.export_bundle() == bundle
        assert view.snapshot_id == snapshot_id
        assert view.read_evidence("classes2.dex") == next((controlled_store / item.path).read_bytes() for item in view.manifest.files if item.archive_entry == "classes2.dex")


@pytest.mark.parametrize("damage", ["truncate", "digest", "count", "order", "trailing", "version", "duplicate-key"])
def test_malformed_jsonl_is_rejected_before_publication(tmp_path, damage):
    path = tmp_path / "input.jsonl"
    export_jsonl(synthetic_facts(), path)
    lines = path.read_text(encoding="utf-8").splitlines()
    if damage == "truncate":
        lines.pop()
    elif damage == "trailing":
        lines.append("{}")
    elif damage == "duplicate-key":
        lines[0] = lines[0].replace('"type":"header"', '"type":"header","type":"header"')
    else:
        index = -1 if damage == "digest" else 1 if damage == "order" else 0
        value = json.loads(lines[index])
        if damage == "digest":
            value["sha256"] = "0" * 64
        elif damage == "count":
            value["counts"]["elements"] += 1
        elif damage == "order":
            value["ordinal"] = 99
        elif damage == "version":
            value["schema_version"] = "fact-stream.v999"
        lines[index] = canonical_json(value)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        import_snapshot(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_jsonl_line_budget_is_enforced(tmp_path):
    path = tmp_path / "input.jsonl"
    export_jsonl(synthetic_facts(), path)
    with pytest.raises(ValueError, match="budget"):
        load_jsonl(path, max_line_bytes=10)


def test_writing_failure_rolls_back_and_does_not_replace_existing_snapshot(synthetic_store, tmp_path, monkeypatch):
    before = all_hashes(synthetic_store)
    def fail_after_some_records(connection, facts):
        connection.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?)", (facts.run.run_id, "tool:dummy", "tools", 0, "tools", "{}", "bad"))
        raise RuntimeError("injected mid-transaction failure")
    monkeypatch.setattr(storage, "_insert_records", fail_after_some_records)
    with pytest.raises(RuntimeError, match="injected"):
        create_snapshot(synthetic_facts(), tmp_path / "failed")
    assert not list((tmp_path / "failed").rglob("facts.sqlite"))
    assert not list((tmp_path / "failed").rglob(".building_*"))
    assert all_hashes(synthetic_store) == before


def test_duplicate_run_is_not_overwritten(synthetic_store):
    before = all_hashes(synthetic_store)
    with pytest.raises(FileExistsError):
        create_snapshot(synthetic_facts(), synthetic_store.parent.parent)
    assert all_hashes(synthetic_store) == before


def test_dangling_and_cross_run_records_cannot_publish(tmp_path):
    for damage in ["dangling", "cross-run"]:
        facts = synthetic_facts()
        if damage == "dangling":
            facts.relations[0].target.element_ref = "instruction:absent"
        else:
            facts.elements[0].run_ref = "run:other"
        with pytest.raises(FactValidationError):
            create_snapshot(facts, tmp_path / damage)
        assert not (tmp_path / damage).exists()


def test_identical_record_ids_in_different_runs_remain_isolated(synthetic_store, tmp_path):
    data = synthetic_facts().model_dump(mode="json")
    new_run = "run:second-synthetic"
    data["run"]["run_id"] = new_run
    for section in ["elements", "relations", "contexts", "bindings", "statuses"]:
        for value in data[section]:
            value["run_ref"] = new_run
    second = create_snapshot(loads_facts(canonical_json(data)), tmp_path / "second")
    with FactView(synthetic_store) as a, FactView(second) as b:
        assert a.run_ref != b.run_ref and a.snapshot_id != b.snapshot_id
        assert a.get_records(["method:run"]).records[0].run_ref == a.run_ref
        assert b.get_records(["method:run"]).records[0].run_ref == new_run
    with pytest.raises(ValueError, match="run"):
        FactView(second, run_ref="run:synthetic-contract")


def test_sqlite_composite_foreign_keys_are_enabled_and_enforced(synthetic_store, tmp_path):
    path = copy_snapshot(synthetic_store, tmp_path / "copy")
    with sqlite3.connect(str(path / "facts.sqlite")) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE record_refs SET run_id='run:other' WHERE owner_id='relation:data-heartbeat'")
    connection.close()


def test_move_snapshot_reads_evidence_without_old_source_paths(controlled_store, tmp_path, monkeypatch):
    moved = copy_snapshot(controlled_store, tmp_path / "elsewhere" / "snapshot")
    # Prohibit all reads through the old package/store path; no real sample is moved/deleted.
    original = storage._inside
    def only_moved(root, relative):
        assert filesystem_path(root).is_relative_to(moved)
        return original(root, relative)
    monkeypatch.setattr(storage, "_inside", only_moved)
    with FactView(moved) as view:
        assert view.verify()["valid"]
        raw = view.read_evidence("classes.dex")
        assert raw.startswith(b"dex\n")
        call = view.find_calls(declared_signature=MAIN + "->consume(Ljava/lang/String;)V").records[0]
        support = view.collect_support([call.id])
        assert {item.archive_entry for item in support.files} == {"classes.dex"}


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_missing_and_corrupt_evidence_are_reported(controlled_store, tmp_path, damage):
    path = copy_snapshot(controlled_store, tmp_path / "copy")
    with FactView(path) as view:
        entry = next(item for item in view.manifest.files if item.archive_entry == "classes.dex")
        blob = path / entry.path
        if damage == "missing":
            blob.unlink()
        else:
            blob.write_bytes(b"damaged")
        with pytest.raises((OSError, ValueError)):
            view.read_evidence(entry.archive_entry)
        with pytest.raises((OSError, ValueError)):
            view.verify()


def test_evidence_path_escape_is_rejected_before_import(tmp_path):
    with pytest.raises(ValueError):
        EvidenceFile(archive_entry="classes.dex", sha256="0" * 64, path="../outside", bytes=1)


def test_corrupted_input_evidence_rejected_before_publication(tmp_path):
    source = copy_snapshot(accepted_package("controlled"), tmp_path / "input")
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    (source / manifest["files"][0]["path"]).write_bytes(b"corruption")
    with pytest.raises(ValueError, match="corrupt"):
        import_snapshot(source, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_database_corruption_and_unknown_versions_are_rejected(synthetic_store, tmp_path):
    path = copy_snapshot(synthetic_store, tmp_path / "corrupt")
    with (path / "facts.sqlite").open("ab") as target:
        target.write(b"modified")
    with pytest.raises(ValueError, match="checksum"):
        FactView(path)
    path = copy_snapshot(synthetic_store, tmp_path / "version")
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    manifest["store_version"] = "fact-store.v999"
    (path / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        FactView(path)


def test_projection_inconsistency_detected_and_rebuild_preserves_logical_identity(synthetic_store, tmp_path):
    damaged = copy_snapshot(synthetic_store, tmp_path / "damaged")
    with sqlite3.connect(str(damaged / "facts.sqlite")) as connection:
        connection.execute("UPDATE program_elements SET offset_bytes=100 WHERE record_id='instruction:heartbeat'")
    connection.close()
    rehash_database(damaged)  # Deliberately get past the file check to exercise payload/projection comparison.
    with FactView(damaged) as view:
        with pytest.raises(ValueError, match="Projection"):
            view.verify()
        original_id = view.snapshot_id
    rebuilt = rebuild_snapshot(damaged, tmp_path / "rebuilt")
    with FactView(rebuilt) as view:
        assert view.verify()["valid"] and view.snapshot_id == original_id


def test_rebuild_from_intact_snapshot_has_same_logical_content(controlled_store, tmp_path):
    rebuilt = rebuild_snapshot(controlled_store, tmp_path / "rebuilt")
    with FactView(rebuilt) as a, FactView(controlled_store) as b:
        assert a.verify()["valid"] and a.snapshot_id == b.snapshot_id
        assert a.export_bundle() == b.export_bundle()


def test_snapshot_read_only_queries_never_change_published_files(real_store):
    before = all_hashes(real_store)
    with FactView(real_store) as view:
        assert view._connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert view._connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            view._connection.execute("DELETE FROM records")
        view.verify()
        view.get_status()
        view.get_records(["instruction:absent"])
    assert before == all_hashes(real_store)


def test_catalog_can_be_rebuilt_from_manifests(synthetic_store, tmp_path):
    root = filesystem_path(tmp_path / "catalog-root")
    path = copy_snapshot(synthetic_store, root / "one")
    catalog = rebuild_catalog(root)
    with sqlite3.connect(str(catalog)) as connection:
        rows = connection.execute("SELECT run_ref,path FROM snapshots").fetchall()
        assert rows == [("run:synthetic-contract", "one")]
    connection.close()
    catalog.unlink()
    assert rebuild_catalog(root).exists() and (path / "facts.sqlite").exists()


def test_cli_import_check_query_export_and_protect_snapshot(tmp_path, capsys):
    assert main(["store-import", str(ROOT / "tests/fixtures/contracts/valid.json"), "--output", str(tmp_path / "store")]) == 0
    payload = json.loads(capsys.readouterr().out)
    path = filesystem_path(payload["output"])
    before = all_hashes(path)
    assert main(["store-check", str(path)]) == 0
    capsys.readouterr()
    assert main(["store-query", str(path), "--kind", "calls", "--signature", "Lexample/Network;->send(Ljava/lang/String;)V"]) == 0
    query = json.loads(capsys.readouterr().out)
    assert query["returned_count"] == 2 and query["coverage"]["control"] == "not_started"
    assert main(["store-query", str(path), "--kind", "records", "--refs", "method:run", "--output", str(path / "manifest.json")]) == 2
    capsys.readouterr()
    assert main(["store-export", str(path), "--output", str(tmp_path / "export"), "--format", "jsonl"]) == 0
    capsys.readouterr()
    assert all_hashes(path) == before
    assert main(["store-check", str(tmp_path / "absent")]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_exports_and_rebuild_cannot_write_inside_published_snapshot(synthetic_store):
    with FactView(synthetic_store) as view:
        with pytest.raises(ValueError, match="outside"):
            export_snapshot(view, synthetic_store / "export")
    with pytest.raises(ValueError, match="outside"):
        rebuild_snapshot(synthetic_store, synthetic_store / "rebuilt")
    with pytest.raises(ValueError, match="outside"):
        rebuild_catalog(synthetic_store)


@pytest.mark.parametrize("field", ["coverage", "counts", "apk_sha256"])
def test_manifest_metadata_cannot_silently_override_database(synthetic_store, tmp_path, field):
    path = copy_snapshot(synthetic_store, tmp_path / "tampered")
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if field == "coverage":
        manifest[field]["control"] = "complete"
    elif field == "counts":
        manifest[field]["elements"] += 1
    else:
        manifest[field] = "0" * 64
    (path / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="disagree"):
        FactView(path)


def test_missing_target_does_not_turn_into_fake_record(synthetic_store):
    with FactView(synthetic_store) as view:
        relation = view.get_records(["relation:unresolved"]).records[0]
        assert relation.target is None and relation.unresolved_reason
        assert view._connection.execute("SELECT target_key,target_element FROM relations WHERE record_id='relation:unresolved'").fetchone() == (None, None)


def test_conditions_statuses_and_ordered_context_calls_are_not_flattened(tmp_path):
    data = synthetic_facts().model_dump(mode="json")
    run = data["run"]["run_id"]
    branch = deepcopy(next(value for value in data["elements"] if value["id"] == "instruction:return"))
    branch.update(id="instruction:branch", opcode="if-eqz", operation="branch", slots=[{
        "slot_kind": "local", "slot_index": 0, "value": {"status": "unknown", "reason": "Synthetic condition"}}])
    branch["position"].update(offset_bytes=40, position_label="code+0x28")
    data["elements"].append(branch)
    for name, expected in [("true", True), ("false", False)]:
        condition = {"kind": "condition", "id": "condition:" + name, "run_ref": run,
            "provenance": {"kind": "static_analysis", "tool_ref": "tool:synthetic", "support_refs": ["instruction:branch"]},
            "branch_ref": "instruction:branch", "branch_label": name,
            "value_endpoint": {"element_ref": "instruction:branch", "slot_kind": "local", "slot_index": 0, "position_label": "code+0x28"},
            "expected_value": {"status": "known", "value": expected}}
        data["elements"].append(condition)
        relation = deepcopy(data["relations"][0])
        relation.update(id="relation:branch-" + name, condition_refs=[condition["id"]])
        data["relations"].append(relation)
    context = deepcopy(data["contexts"][0])
    context.update(id="context:ordered", callsite_refs=["instruction:send-heartbeat", "instruction:save"])
    data["contexts"].append(context)
    for state in ["unavailable", "truncated", "failed"]:
        data["statuses"].append({"id": "status:" + state, "run_ref": run, "tool_ref": "tool:synthetic", "capability": "data_flow",
            "scope": {"kind": "element", "element_ref": "instruction:branch"}, "state": state, "reason": "Synthetic status preservation"})
    facts = loads_facts(canonical_json(data))
    snapshot = create_snapshot(facts, tmp_path / "store")
    with FactView(snapshot) as view:
        assert view.verify()["valid"] and view.export_bundle() == facts
        alternatives = view.get_records(["relation:branch-true", "relation:branch-false"]).records
        assert [value.condition_refs for value in alternatives] == [["condition:true"], ["condition:false"]]
        assert view._connection.execute("SELECT callsite_ref FROM context_calls WHERE context_ref='context:ordered' ORDER BY ordinal").fetchall() == [("instruction:send-heartbeat",), ("instruction:save",)]
        assert {value.state for value in view.get_status(element_ref="instruction:branch").records} == {"unavailable", "truncated", "failed"}


def test_query_indexes_are_used_and_snapshot_identity_is_checked(controlled_store):
    with FactView(controlled_store) as view:
        plan = view._connection.execute("EXPLAIN QUERY PLAN SELECT record_id FROM program_elements WHERE run_id=? AND declared_signature=?",
            (view.run_ref, MAIN + "->consume(Ljava/lang/String;)V")).fetchall()
        assert any("declared_calls" in row[-1] for row in plan)
    with pytest.raises(ValueError, match="identity"):
        FactView(controlled_store, snapshot_id="0" * 64)
