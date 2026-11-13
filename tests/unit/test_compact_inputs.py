"""Lossless transport closure and guard preservation; no semantic-quality claim."""
from copy import deepcopy
import json

import pytest

from androserum.facts.identity import canonical_json, fingerprint
from androserum.inference.compact import CompactError, compact_packet, expand_compact
from androserum.matching.checker import check_match
from androserum.matching.fixtures import protocol_cases


def rich_packet():
    evidence = {"record_id": "fact:" + "e" * 64, "condition": {"kind": "predicate", "operator": ">",
                "left": "count", "right": 0, "branch": True}, "context": ["frame:caller_a"],
                "binding": {"object": "allocated:buffer_a", "offset": 0, "length": "unknown"},
                "information_flow": {"role": "summary_only", "complete_fine_path": False},
                "status": "partial", "unknown": ["runtime success is unknown", "event coverage is not started"]}
    return {"current": {"evidence": [deepcopy(evidence) for _ in range(9)]},
            "repair_feedback": {"previous_proposal": deepcopy(evidence),
                                "program_check_errors": [{"code": "wrong_context", "expected": "frame:caller_a"}]}}


def test_exact_semantics_feedback_and_aliases_preserved():
    packet = rich_packet(); before = deepcopy(packet)
    envelope, metrics = compact_packet(packet)
    restored = expand_compact(json.dumps(envelope))
    assert restored == before == packet
    assert metrics["roundtrip_equal"] and metrics["evidence_removed"] == 0
    assert metrics["reduction_with_instruction_fraction"] > 0.3
    assert compact_packet(packet) == (envelope, metrics)
    restored["current"]["evidence"][0]["context"].append("unrelated")
    assert restored["current"]["evidence"][1] == before["current"]["evidence"][1]
    assert expand_compact(envelope) == before


def test_distinct_context_object_and_condition_do_not_merge():
    packet = rich_packet()
    packet["current"]["evidence"][1]["context"] = ["frame:caller_b"]
    packet["current"]["evidence"][2]["binding"]["object"] = "allocated:buffer_b"
    packet["current"]["evidence"][3]["condition"]["branch"] = False
    assert expand_compact(compact_packet(packet)[0]) == packet


def test_matching_native_guards_and_repair_envelope_unchanged():
    # All former positive/negative protocol cases see exactly the original
    # authorized packet after materialization, never the transport records table.
    for case in protocol_cases():
        packet = {"request": case["request"], "repair_feedback": {"previous_raw": canonical_json(case["response"]),
                   "program_check_errors": [{"code": "illustrative_feedback_only"}]}}
        restored = expand_compact(compact_packet(packet)[0])
        raw = canonical_json(case["response"])
        assert check_match(raw, restored["request"]) == check_match(raw, case["request"])
        assert restored["repair_feedback"] == packet["repair_feedback"]


def test_reference_collision_in_original_packet_rejected():
    with pytest.raises(CompactError, match="reserved"):
        compact_packet({"program": {"$ref": "not_a_transport_handle"}})


@pytest.mark.parametrize("kind", ["unknown", "cycle", "hash", "hidden", "malformed"])
def test_corrupt_reference_closure_rejected(kind):
    envelope, _ = compact_packet(rich_packet())
    handle = next(iter(envelope["records"]))
    if kind == "unknown": envelope["packet"] = {"$ref": "r999999"}
    elif kind == "cycle": envelope["records"][handle] = {"$ref": handle}
    elif kind == "hash": envelope["materialized_sha256"] = "0" * 64
    elif kind == "hidden": envelope["records"]["r999999"] = {"unauthorized": "hidden evidence"}
    else: envelope["packet"] = {"$ref": handle, "extra": "collision"}
    with pytest.raises(CompactError): expand_compact(envelope)


def test_duplicate_keys_are_rejected_before_reference_collision_overwrite():
    envelope, _ = compact_packet(rich_packet())
    raw = json.dumps(envelope)
    raw = raw[:-1] + ',"records":{}}'
    with pytest.raises(CompactError): expand_compact(raw)


def test_expansion_budget_and_no_loss_for_small_packet():
    envelope, _ = compact_packet(rich_packet())
    with pytest.raises(CompactError, match="budget"):
        expand_compact(envelope, max_expanded_chars=100)
    packet = {"unknown": None, "partial": True, "empty": [], "literal": "same"}
    envelope, metrics = compact_packet(packet)
    assert expand_compact(envelope) == packet
    assert metrics["reduction_fraction"] < 0  # Honest overhead for tiny inputs.
    assert envelope["materialized_sha256"] == fingerprint(packet)
