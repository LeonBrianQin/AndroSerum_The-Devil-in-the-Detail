"""Export current schemas and explicitly synthetic, source-described contract examples."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from androserum.facts.identity import fingerprint
from androserum.facts.models import FactBundle, FactConfig, SCHEMA_VERSION
from androserum.facts.jimple import BackendEnd, BackendStart, JimpleMethod, MethodCommit
from androserum.facts.java_backend import JavaConfig
from androserum.facts.local_flow import CFGCommit, LocalFlowConfig, MethodCFG, MethodFlow
from androserum.facts.call_flow import CallConfig, CallReport
from androserum.facts.heap_flow import HeapConfig, HeapMethod
from androserum.facts.context_heap import ContextHeapConfig,ContextHeapReport
from androserum.facts.sapi import SapiImportConfig
from androserum.facts.selected_flow import FlowConfig
from androserum.facts.operations import OperationConfig
from androserum.facts.control import ControlConfig

ROOT = Path(__file__).resolve().parents[1]
RUN = "run:synthetic-contract"
CALLER = "method:run"
SIGNATURE = "Lexample/Network;->send(Ljava/lang/String;)V"


def write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def provenance(*support: str) -> dict:
    return {"kind": "static_analysis" if support else "direct", "tool_ref": "tool:synthetic", "support_refs": list(support)}


def base(identifier: str, kind: str, **fields) -> dict:
    return {"id": identifier, "run_ref": RUN, "kind": kind, "provenance": provenance(), **fields}


def declaration(table: str, index: int) -> dict:
    return {"kind": "dex_declaration", "dex_ref": "dex:main", "table": table, "index": index}


def position(offset: int, method: str = CALLER) -> dict:
    return {"kind": "dex_instruction", "dex_ref": "dex:main", "method_ref": method,
            "offset_bytes": offset, "position_label": f"code+0x{offset:x}"}


def endpoint(instruction: str, offset: int, kind: str, index: int | None = None) -> dict:
    result = {"element_ref": instruction, "position_label": f"code+0x{offset:x}", "slot_kind": kind}
    if index is not None:
        result["slot_index"] = index
    return result


def known(value, *sources: str) -> dict:
    return {"status": "known", "value": value, "source_refs": list(sources)}


def invocation(identifier: str, offset: int, value: str, origin: str, target: str, signature: str) -> dict:
    return base(identifier, "instruction", position=position(offset), opcode="invoke-static", operation="invoke",
                operands=[{"index": 0, "kind": "register", "value": known(0)},
                          {"index": 1, "kind": "method", "value": known(signature), "reference_ref": target}],
                slots=[{"slot_kind": "argument", "slot_index": 0, "type_descriptor": "Ljava/lang/String;",
                        "value": known(value, origin)}], slots_complete=True, invoke_kind="static",
                declared_target={"signature": signature, "method_ref": target})


def example() -> dict:
    configuration = {"schema_version": "facts-config.v1", "requested_capabilities": ["dex", "calls", "data_flow", "control"], "options": {}}
    save_signature = "Lexample/Reporter;->save(Ljava/lang/String;)V"
    elements = [
        base("dex:main", "dex", position={"kind": "archive", "path": "classes.dex"},
             sha256=hashlib.sha256(b"synthetic DEX placeholder; not a real APK").hexdigest(),
             size_bytes=len(b"synthetic DEX placeholder; not a real APK")),
        base("class:reporter", "class", position=declaration("class_def", 0), descriptor="Lexample/Reporter;",
             superclass="Ljava/lang/Object;", interfaces=[]),
        base(CALLER, "method", position=declaration("method_id", 0), signature="Lexample/Reporter;->run()V",
             is_definition=True, class_ref="class:reporter", is_static=True, body_status="available"),
        base("method:send", "method", position=declaration("method_id", 1), signature=SIGNATURE,
             is_definition=False, is_static=True, body_status="external"),
        base("method:save", "method", position=declaration("method_id", 2), signature=save_signature,
             is_definition=True, class_ref="class:reporter", is_static=True, body_status="available"),
        base("parameter:save0", "parameter", method_ref="method:save", index=0, type_descriptor="Ljava/lang/String;", register_index=0),
        base("instruction:heartbeat", "instruction", position=position(0), opcode="const-string", operation="constant",
             operands=[{"index": 0, "kind": "register", "value": known(0)}, {"index": 1, "kind": "string", "value": known("heartbeat")}],
             slots=[{"slot_kind": "result", "value": known("heartbeat")}], slots_complete=True),
        invocation("instruction:send-heartbeat", 4, "heartbeat", "instruction:heartbeat", "method:send", SIGNATURE),
        base("instruction:identifier", "instruction", position=position(10), opcode="const-string", operation="constant",
             operands=[{"index": 0, "kind": "register", "value": known(0)}, {"index": 1, "kind": "string", "value": known("fixture-id")}],
             slots=[{"slot_kind": "result", "value": known("fixture-id")}], slots_complete=True),
        invocation("instruction:send-identifier", 14, "fixture-id", "instruction:identifier", "method:send", SIGNATURE),
        invocation("instruction:save", 20, "fixture-id", "instruction:identifier", "method:save", save_signature),
        base("instruction:return", "instruction", position=position(26), opcode="return-void", operation="return", operands=[], slots_complete=True),
        base("instruction:save-return", "instruction", position=position(0, "method:save"), opcode="return-void", operation="return", operands=[], slots_complete=True),
    ]
    relations = []
    for suffix, source, source_offset, target, target_offset in [
        ("heartbeat", "instruction:heartbeat", 0, "instruction:send-heartbeat", 4),
        ("identifier", "instruction:identifier", 10, "instruction:send-identifier", 14),
    ]:
        relations.append({"id": "relation:data-" + suffix, "run_ref": RUN, "provenance": provenance(source, target),
                          "relation_kind": "data_dependency", "source": endpoint(source, source_offset, "result"),
                          "target": endpoint(target, target_offset, "argument", 0), "resolution": "resolved"})
    for call, offset, target in [("instruction:send-heartbeat", 4, "method:send"),
                                 ("instruction:send-identifier", 14, "method:send"), ("instruction:save", 20, "method:save")]:
        relations.append({"id": "relation:call-" + call.split(":")[1], "run_ref": RUN,
                          "provenance": {**provenance(), "support_refs": [call, target]}, "relation_kind": "declared_call",
                          "source": endpoint(call, offset, "element"), "target": {"element_ref": target, "slot_kind": "entry"},
                          "resolution": "resolved"})
    argument = endpoint("instruction:save", 20, "argument", 0)
    parameter = {"element_ref": "method:save", "slot_kind": "parameter", "slot_index": 0}
    relations.append({"id": "relation:save-argument", "run_ref": RUN,
                      "provenance": provenance("instruction:save", "parameter:save0"), "relation_kind": "argument_to_parameter",
                      "source": argument, "target": parameter, "callsite_ref": "instruction:save",
                      "context_ref": "context:save", "binding_refs": ["binding:save"], "resolution": "resolved"})
    statuses = [{"id": "status:" + capability, "run_ref": RUN, "tool_ref": "tool:synthetic", "capability": capability,
                 "scope": {"kind": "run"}, "state": state, **({"reason": reason} if reason else {})}
                for capability, state, reason in [
                    ("dex", "complete", None), ("calls", "partial", "Synthetic contract contains selected call records only"),
                    ("data_flow", "partial", "Synthetic contract contains selected data records only"),
                    ("control", "not_started", "No control analysis is represented by this contract example")]]
    return {"schema_version": "program-facts.v1", "run": {"run_id": RUN, "input_kind": "synthetic",
            "apk_sha256": hashlib.sha256(b"synthetic-contract").hexdigest(), "apk_size_bytes": 0,
            "input_name": "synthetic-contract-not-an-apk", "created_at": "2026-10-20T00:00:00+00:00",
            "tools": [{"tool_id": "tool:synthetic", "name": "hand-authored-contract", "version": "1"}],
            "configuration": configuration, "config_fingerprint": fingerprint(configuration)},
            "elements": elements, "relations": relations,
            "contexts": [{"id": "context:save", "run_ref": RUN, "provenance": provenance("instruction:save"),
                          "abstraction": "synthetic-callstring-k1", "callsite_refs": ["instruction:save"]}],
            "bindings": [{"id": "binding:save", "run_ref": RUN,
                          "provenance": provenance("instruction:save", "parameter:save0"), "binding_kind": "value",
                          "endpoints": [argument, parameter], "context_ref": "context:save"}],
            "statuses": statuses}


def main() -> None:
    for name, model in [(SCHEMA_VERSION, FactBundle), ("facts-config.v1", FactConfig),
                        ("jimple-method.v1", JimpleMethod), ("java-config.v1", JavaConfig),
                        ("jimple-run.v1", BackendStart), ("jimple-commit.v1", MethodCommit), ("jimple-end.v1", BackendEnd),
                        ("jimple-cfg.v1", MethodCFG), ("jimple-cfg-commit.v1", CFGCommit),
                        ("local-flow-config.v1", LocalFlowConfig), ("local-flow-method.v1", MethodFlow),
                        ("call-flow-config.v1", CallConfig), ("call-flow-run.v1", CallReport),
                        ("heap-flow-config.v1", HeapConfig), ("heap-flow-method.v1", HeapMethod),
                        ("context-heap-config.v1",ContextHeapConfig),("context-heap-method.v1",ContextHeapReport),
                        ("sapi-import-config.v1",SapiImportConfig),("selected-flow-config.v1",FlowConfig),
                        ("operation-view-config.v1",OperationConfig),("control-config.v1",ControlConfig)]:
        write(ROOT / "schemas" / f"{name}.schema.json", model.model_json_schema())
    target = ROOT / "tests" / "fixtures" / "contracts"
    valid = example()
    write(target / "valid.json", valid)
    partial = deepcopy(valid)
    partial["statuses"][0].update(state="partial", reason="Synthetic second DEX could not be parsed", unknowns=["classes2.dex"])
    partial["statuses"].append({"id": "status:dex2-failure", "run_ref": RUN, "tool_ref": "tool:synthetic",
        "capability": "dex", "scope": {"kind": "location", "location": {"kind": "archive", "path": "classes2.dex"}},
        "state": "failed", "reason": "Synthetic local parse failure", "issue_code": "dex_parse_error"})
    write(target / "partial-failure.json", partial)
    dangling = deepcopy(valid)
    dangling["relations"][0]["target"]["element_ref"] = "instruction:missing"
    write(target / "invalid-dangling.json", dangling)
    print("Exported schemas and synthetic contract examples")


if __name__ == "__main__":
    main()
