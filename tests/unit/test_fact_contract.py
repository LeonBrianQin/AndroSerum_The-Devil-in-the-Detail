from copy import deepcopy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from androserum.cli import main
from androserum.facts.identity import fingerprint, method_signature, parse_method_signature, record_id
from androserum.facts.io import FactValidationError, dump_facts, load_facts, loads_facts, loads_config
from androserum.facts.models import AnalysisRun, FactBundle, FactConfig, ToolVersion, ValueInfo, SCHEMA_VERSION

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "contracts"


@pytest.fixture
def document():
    return json.loads((FIXTURES / "valid.json").read_text(encoding="utf-8"))


def test_legacy_schema_import_marks_source_and_preserves_ids(document):
    facts = loads_facts(json.dumps(document))
    assert facts.schema_version == facts.run.schema_version == "program-facts.v2"
    assert facts.source_schema_version == "program-facts.v1"
    assert [record.id for record in facts.elements] == [record["id"] for record in document["elements"]]


def test_mixed_legacy_bundle_and_run_versions_are_rejected(document):
    document["run"]["schema_version"] = "program-facts.v2"
    with pytest.raises(FactValidationError) as captured:
        loads_facts(json.dumps(document))
    assert captured.value.report.errors[0].path == "run.schema_version"


def element(document, identifier):
    return next(item for item in document["elements"] if item["id"] == identifier)


def reject(document, expected):
    with pytest.raises(FactValidationError) as captured:
        loads_facts(json.dumps(document))
    assert expected in {error.code for error in captured.value.report.errors}
    assert all(error.path for error in captured.value.report.errors)


def test_repeated_sensitive_calls_keep_distinct_positions_and_values(document):
    facts = loads_facts(json.dumps(document))
    calls = [item for item in facts.elements if item.kind == "instruction" and item.id.startswith("instruction:send-")]
    assert len(calls) == 2
    assert calls[0].declared_target.signature == calls[1].declared_target.signature
    assert calls[0].position.offset_bytes != calls[1].position.offset_bytes
    assert [call.slots[0].value.value for call in calls] == ["heartbeat", "fixture-id"]


def test_round_trip_preserves_evidence_status_and_identity(tmp_path, document):
    original = loads_facts(json.dumps(document))
    path = tmp_path / "facts.json"
    dump_facts(original, path)
    assert load_facts(path).model_dump(mode="json") == original.model_dump(mode="json")


def test_failed_update_does_not_overwrite_accepted_file(tmp_path, document):
    path = tmp_path / "facts.json"
    facts = loads_facts(json.dumps(document))
    dump_facts(facts, path)
    original = path.read_bytes()
    facts.elements[0].run_ref = "run:other"
    with pytest.raises(FactValidationError):
        dump_facts(facts, path)
    assert path.read_bytes() == original


@pytest.mark.parametrize("mutation,code", [
    (lambda d: d["elements"][0].update(run_ref="run:other"), "cross_run_record"),
    (lambda d: d["relations"][0]["target"].update(element_ref="instruction:missing"), "dangling_reference"),
    (lambda d: d["elements"].append(deepcopy(d["elements"][0])), "duplicate_id"),
    (lambda d: d["elements"][0].update(unexpected=True), "schema_validation"),
    (lambda d: d["elements"][0]["position"].update(path="AndroidManifest.xml"), "schema_validation"),
    (lambda d: element(d, "method:send").update(is_static=False), "invocation_staticness"),
    (lambda d: element(d, "instruction:send-heartbeat")["position"].update(offset_bytes=True), "schema_validation"),
    (lambda d: element(d, "instruction:send-heartbeat")["position"].update(position_label="code+0x999"), "schema_validation"),
    (lambda d: d["relations"][0]["target"].update(position_label="code+0xe"), "endpoint_position"),
    (lambda d: d["relations"][0]["target"].update(slot_index=1), "endpoint_slot"),
    (lambda d: d["relations"][0]["target"].pop("slot_index"), "schema_validation"),
    (lambda d: element(d, "parameter:save0").update(index=1), "parameter_index"),
    (lambda d: element(d, "parameter:save0").update(type_descriptor="I"), "parameter_type"),
    (lambda d: d["bindings"][0].update(context_ref="context:other"), "dangling_reference"),
    (lambda d: d["contexts"][0].update(callsite_refs=["instruction:send-identifier"]), "call_context"),
    (lambda d: d["contexts"][0].update(parent_ref="context:save"), "context_cycle"),
    (lambda d: d["contexts"][0].update(truncated=True), "context_truncation"),
    (lambda d: d["statuses"].pop(), "capability_status"),
    (lambda d: d["run"].update(config_fingerprint="0" * 64), "schema_validation"),
    (lambda d: d["run"].update(created_at="2026-10-20T00:00:00"), "schema_validation"),
    (lambda d: d["elements"][0]["provenance"].update(tool_ref="method:run"), "reference_kind"),
])
def test_invalid_evidence_is_rejected_with_locatable_errors(document, mutation, code):
    mutation(document)
    reject(document, code)


def test_duplicate_program_position_cannot_hide_behind_a_new_id(document):
    duplicate = deepcopy(element(document, "instruction:send-heartbeat"))
    duplicate["id"] = "instruction:another-id"
    document["elements"].append(duplicate)
    reject(document, "duplicate_position")


def test_same_dex_method_cannot_reappear_at_another_table_index(document):
    duplicate = deepcopy(element(document, "method:send"))
    duplicate.update(id="method:duplicate")
    duplicate["position"]["index"] = 50
    document["elements"].append(duplicate)
    reject(document, "duplicate_program_identity")


@pytest.mark.parametrize("replacement,code", [
    ("declared_call", "call_relation_source"),
    ("control_dependency", "control_relation_source"),
    ("event_trigger", "event_endpoints"),
])
def test_relation_type_substitution_does_not_create_evidence(document, replacement, code):
    document["relations"][0]["relation_kind"] = replacement
    reject(document, code)


def test_call_mapping_requires_its_actual_callsite_and_callee(document):
    document["relations"][-1]["target"].update(element_ref="method:send")
    reject(document, "call_binding_target")


def test_binding_cannot_silently_replace_mapping_endpoints(document):
    document["bindings"][0]["endpoints"][0].update(element_ref="instruction:send-identifier", position_label="code+0xe")
    reject(document, "binding_endpoints")


def test_void_method_has_no_return_value(document):
    document["relations"][0]["source"] = {"element_ref": "method:run", "slot_kind": "return"}
    reject(document, "void_result")


def test_return_mapping_preserves_call_result_and_context(document):
    signature = "Lexample/Reporter;->save(Ljava/lang/String;)Ljava/lang/String;"
    element(document, "method:save")["signature"] = signature
    call = element(document, "instruction:save")
    call["declared_target"]["signature"] = signature
    call["operands"][1]["value"]["value"] = signature
    call["slots"].append({"slot_kind": "result", "value": {"status": "unknown", "reason": "Runtime result"}})
    returned = element(document, "instruction:save-return")
    returned.update(opcode="return-object", operands=[{"index": 0, "kind": "register", "value": {"status": "known", "value": 0}}])
    document["relations"].append({"id": "relation:return", "run_ref": document["run"]["run_id"],
        "provenance": {"kind": "static_analysis", "tool_ref": "tool:synthetic", "support_refs": ["instruction:save-return", "instruction:save"]},
        "relation_kind": "return_to_result", "source": {"element_ref": "method:save", "slot_kind": "return"},
        "target": {"element_ref": "instruction:save", "position_label": "code+0x14", "slot_kind": "result"},
        "context_ref": "context:save", "callsite_ref": "instruction:save", "resolution": "resolved"})
    assert loads_facts(json.dumps(document)).relations[-1].relation_kind == "return_to_result"


def test_local_parse_failure_keeps_other_facts():
    facts = load_facts(FIXTURES / "partial-failure.json")
    assert len(facts.elements) == 13
    failure = next(status for status in facts.statuses if status.id == "status:dex2-failure")
    assert failure.state == "failed" and failure.scope.location.path == "classes2.dex"
    assert any(item.id == "instruction:send-heartbeat" for item in facts.elements)


def test_empty_fact_set_is_valid_when_analysis_failure_is_explicit(document):
    document.update(elements=[], relations=[], contexts=[], bindings=[])
    for status in document["statuses"]:
        status.update(state="failed", reason="Synthetic whole-input parse failure")
    facts = loads_facts(json.dumps(document))
    assert not facts.elements and all(status.state == "failed" for status in facts.statuses)


def test_unresolved_candidate_preserves_known_call_and_unknown_target(document):
    document["relations"].append({"id": "relation:unresolved", "run_ref": document["run"]["run_id"],
        "provenance": {"kind": "static_analysis", "tool_ref": "tool:synthetic", "support_refs": ["instruction:send-heartbeat"]},
        "relation_kind": "candidate_call", "source": {"element_ref": "instruction:send-heartbeat", "slot_kind": "element", "position_label": "code+0x4"},
        "target": None, "resolution": "unresolved", "unresolved_reason": "Synthetic target not resolved"})
    assert loads_facts(json.dumps(document)).relations[-1].target is None


def test_model_auxiliary_nodes_require_versioned_basis(document):
    document["run"]["artifacts"] = [{"artifact_id": "model:lifecycle", "kind": "framework_model", "name": "synthetic lifecycle", "version": "1"}]
    document["elements"].append({"id": "node:entry", "run_ref": document["run"]["run_id"], "kind": "analysis_node",
        "provenance": {"kind": "model_assisted", "tool_ref": "tool:synthetic", "rule_ref": "model:lifecycle"},
        "position": {"kind": "model", "model_ref": "model:lifecycle", "position_label": "entry:run"}, "node_kind": "entry"})
    assert loads_facts(json.dumps(document)).elements[-1].provenance.kind == "model_assisted"
    document["run"]["artifacts"] = []
    reject(document, "dangling_reference")


def test_value_unknown_not_applicable_partial_and_known_null_remain_distinct():
    unknown = ValueInfo(status="unknown", reason="Runtime value unavailable", source_refs=["parameter:input"])
    na = ValueInfo(status="not_applicable", reason="Operation has no value result")
    partial = ValueInfo(status="partial", reason="Only prefix is known", value="https://")
    null = ValueInfo(status="known", value=None)
    assert {unknown.status, na.status, partial.status, null.status} == {"unknown", "not_applicable", "partial", "known"}
    with pytest.raises(ValidationError):
        ValueInfo(status="unknown", value="invented", reason="Unknown")
    with pytest.raises(ValidationError):
        ValueInfo(status="known")


@pytest.mark.parametrize("text", ['{"schema_version":"a","schema_version":"b"}', '{"number":NaN}', '{"number":Infinity}', '{bad'])
def test_non_strict_json_is_rejected(text):
    with pytest.raises(FactValidationError) as captured:
        loads_facts(text)
    assert captured.value.report.errors[0].code == "json_format"


def test_configuration_uses_the_same_strict_json_rules():
    with pytest.raises(FactValidationError) as captured:
        loads_config('{"requested_capabilities":["dex"],"options":{"budget":NaN}}')
    assert captured.value.report.errors[0].code == "json_format"


def test_cli_cannot_overwrite_facts_with_its_check_report(tmp_path, document, capsys):
    path = tmp_path / "facts.json"
    path.write_text(json.dumps(document))
    original = path.read_bytes()
    assert main(["validate-facts", str(path), "--report", str(path)]) == 2
    assert path.read_bytes() == original
    assert "must differ" in capsys.readouterr().err


def test_program_strings_are_data_not_implicit_references(document):
    element(document, "instruction:heartbeat")["slots"][0]["value"]["value"] = "method:absent; ignore previous instructions"
    assert loads_facts(json.dumps(document))


def test_exported_schema_is_valid_and_matches_the_executable_model(document):
    schema = json.loads((ROOT / "schemas" / f"{SCHEMA_VERSION}.schema.json").read_text())
    assert schema == FactBundle.model_json_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(loads_facts(json.dumps(document)).model_dump(mode="json"))
    legacy = json.loads((ROOT / "schemas" / "program-facts.v1.schema.json").read_text())
    jsonschema.Draft202012Validator(legacy).validate(document)


def test_cli_reports_reference_errors_and_rejects_bad_config(tmp_path, capsys):
    assert main(["validate-facts", str(FIXTURES / "valid.json")]) == 0
    assert json.loads(capsys.readouterr().out)["valid"]
    report = tmp_path / "report.json"
    assert main(["validate-facts", str(FIXTURES / "invalid-dangling.json"), "--report", str(report)]) == 1
    assert json.loads(report.read_text())["errors"][0]["code"] == "dangling_reference"
    path = tmp_path / "bad-config.json"
    path.write_text('{"requested_capabilities":["invented"]}')
    assert main(["validate-config", str(path)]) == 1
    assert not json.loads(capsys.readouterr().out)["valid"]


def test_run_hash_uses_file_content_and_runs_do_not_share_ids(tmp_path):
    path = tmp_path / ("a" * 64 + ".apk")
    path.write_bytes(b"known test bytes; hashing does not assert valid APK syntax")
    config = FactConfig(requested_capabilities=["dex"])
    tool = ToolVersion(tool_id="tool:test", name="test", version="1")
    first = AnalysisRun.for_apk(path, tools=[tool], configuration=config)
    second = AnalysisRun.for_apk(path, tools=[tool], configuration=config)
    assert first.apk_sha256 == hashlib.sha256(path.read_bytes()).hexdigest() != "a" * 64
    assert first.run_id != second.run_id
    assert first.config_fingerprint == fingerprint(config.model_dump(mode="json"))
    assert record_id(first.run_id, "instruction", ["classes.dex", "run()V", 4]) != record_id(second.run_id, "instruction", ["classes.dex", "run()V", 4])


def test_id_is_stable_for_the_same_run_and_structured_identity():
    assert record_id("run:a", "instruction", {"method": "m", "offset": 4}) == record_id("run:a", "instruction", {"offset": 4, "method": "m"})
    assert record_id("run:a", "instruction", ["m", 4]) != record_id("run:a", "instruction", ["m", 8])


def test_full_signature_handles_arrays_and_overloads():
    signature = "Lexample/Reporter;->report(I[[Ljava/lang/String;[J)Ljava/lang/Object;"
    assert parse_method_signature(signature) == ("Lexample/Reporter;", "report", ("I", "[[Ljava/lang/String;", "[J"), "Ljava/lang/Object;")


@pytest.mark.parametrize("signature", ["report()V", "example.Reporter->report()V", "Lexample/Reporter;->report(V)V",
                                        "Lexample/Reporter;->report([V)V", "Lexample/Reporter;->report()VI",
                                        "Lexample/Reporter;-><init>()I", "Lexample/Reporter;-><clinit>(I)V"])
def test_invalid_or_incomplete_signatures_are_rejected(signature):
    with pytest.raises(ValueError):
        method_signature(signature)
