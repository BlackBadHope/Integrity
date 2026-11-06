"""7.0.1 response diet: the model gets a compact append receipt (<= 1 KB).

The broker observes the full upstream result first; only the model-facing edge
is compacted, and the owning hook still finds its ``/append-receipt`` fields.
"""
import ast
import hashlib
import json
from pathlib import Path

import pytest

RESOURCES = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources"
BROKERS = ["windows/integrity-client-turn-broker.py", "linux/integrity-client-turn-broker.py",
           "claude-native/integrity-client-turn-broker.py"]
HOOKS = ["windows/native/integrity-client-admission.py", "linux/admission.py"]
D = "sha256:" + "a" * 64


def full_append_receipt(extra_bytes=0):
    """Same shape as a live append receipt (about 6 KB): digests, grant, witness."""
    stage = {"digest": D, "route_stage_id": D, "stage": "action"}
    receipt = {
        "action_outcome": "confirmed-success", "action_route_stage_id": D, "architecture_admission_id": D,
        "authority_receipt_id": D, "automatic_retry_allowed": False, "context_admission_id": D,
        "coordination_stop_observed": False, "event_id": 8931, "event_uid": "client:unit-test-append",
        "feedback_receipt_id": D, "grant_consumed": True, "grant_id": D, "home_record_count": 0,
        "logical_generation": 24, "observed_utc": "2026-11-06T11:00:05Z",
        "one_use_authority": {k: D for k in ("architecture_admission_id", "context_admission_id", "digest",
                                             "grant_id", "receipt_id", "request_digest", "route_digest",
                                             "security_admission_id")} | {"max_transitions": 1, "single_use": True},
        "outcome": "created",
        "outcome_feedback": {"digest": D, "grant_id": D, "outcome": "confirmed-success", "receipt_id": D,
                             "request_digest": D, "witness_digest": D, "write_status": "recorded"},
        "passive_witness": {"event_id": 8931, "event_uid": "client:unit-test-append", "observed_record_digest": D,
                            "protocol": "integrity-client-memory-mcp/v3/passive-event-witness/v1", "receipt_id": D,
                            "request_sha256": "b" * 64, "status": "exact",
                            "signature": {"algorithm": "ed25519", "key_id": "key:" + "c" * 64, "value": "s" * 86}},
        "pre_action_route_stage_id": D, "production_authority": False, "production_execution_performed": False,
        "protocol": "integrity-client-memory-mcp/v3/append-receipt", "request_sent": True,
        "request_sha256": "b" * 64, "response_compaction": {"full_receipt_digest": D},
        "route_digest": D, "route_memory": "explore-to-observed",
        "route_stages": {"action": stage, "outcome": stage, "pre_action": stage},
        "security_admission_id": D, "source_label": "client-workstation",
        "transport_response_received": True, "witness_observer_available": True,
        "padding": "x" * extra_bytes,
    }
    return {"content": [{"type": "text", "text": json.dumps({"receipt": receipt})}]}


def compactor(path):
    tree = ast.parse((RESOURCES / path).read_text(encoding="utf-8"))
    body = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name == "_compact_append_result")
            or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {
                "APPEND_COMPACT_PROTOCOL", "APPEND_COMPACT_LIMIT", "_APPEND_COMPACT_KEEP"} for t in n.targets))]
    namespace = {"json": json, "hashlib": hashlib}
    exec(compile(ast.Module(body=body, type_ignores=[]), path, "exec"), namespace)
    return namespace["_compact_append_result"]


@pytest.mark.parametrize("path", BROKERS)
@pytest.mark.parametrize("extra", [0, 110_000])
def test_append_receipt_is_compacted_below_one_kilobyte(path, extra):
    full = full_append_receipt(extra)
    before = len(full["content"][0]["text"].encode())
    out = compactor(path)(full)
    after = len(out["content"][0]["text"].encode())
    # The synthetic receipt is about 4.4 KB; live ones were 6 KB, one 116.5 KB.
    assert before > 4_000 and after <= 1024
    receipt = json.loads(out["content"][0]["text"])["receipt"]
    assert receipt["protocol"].endswith("/append-receipt")
    assert (receipt["outcome"], receipt["event_id"], receipt["event_uid"], receipt["request_sha256"]) == (
        "created", 8931, "client:unit-test-append", "b" * 64)
    assert receipt["witness_status"] == "exact" and receipt["automatic_retry_allowed"] is False
    assert receipt["compaction"]["full_bytes"] == before
    assert receipt["compaction"]["full_receipt_sha256"] == hashlib.sha256(
        full["content"][0]["text"].encode()).hexdigest()


@pytest.mark.parametrize("path", BROKERS)
@pytest.mark.parametrize("result", [
    {"isError": True, "content": [{"type": "text", "text": json.dumps({"receipt": {
        "protocol": "integrity-client-memory-mcp/v3/denial-receipt", "outcome": "denied"}})}]},
    {"content": [{"type": "text", "text": "not json"}]},
    {"content": [{"type": "text", "text": "{}"}, {"type": "text", "text": "{}"}]},
])
def test_other_results_pass_through_unchanged(path, result):
    assert compactor(path)(result) == result


@pytest.mark.parametrize("path", BROKERS)
def test_compaction_runs_after_the_broker_observed_the_full_result(path):
    source = (RESOURCES / path).read_text(encoding="utf-8")
    call = source.index("result = _compact_append_result(result)")
    observe = source.rindex("self._observe_upstream_denial(name, result)", 0, call)
    assert observe < call


@pytest.mark.parametrize("hook", HOOKS)
def test_owning_hook_reads_the_compact_receipt(hook):
    tree = ast.parse((RESOURCES / hook).read_text(encoding="utf-8"))
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"find_document", "iter_documents",
                                                                                     "json_documents"}]
    namespace = {"json": json, "Any": object}
    exec(compile(ast.Module(body=body, type_ignores=[]), hook, "exec"), namespace)
    out = compactor(BROKERS[0])(full_append_receipt())
    response = {"content": out["content"]}
    receipt = namespace["find_document"](response, lambda item: str(item.get("protocol", "")).endswith("/append-receipt"))
    assert receipt["event_id"] == 8931 and receipt["request_sha256"] == "b" * 64


AG_BROKER = "antigravity/integrity_antigravity_broker.py"


def ag_namespace():
    tree = ast.parse((RESOURCES / AG_BROKER).read_text(encoding="utf-8"))
    wanted = {"_pick", "compact_admission_document", "compact_admission_result", "_compact_append_result"}
    body = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in wanted)
            or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and (
                t.id.startswith("ADMISSION_COMPACT") or t.id.startswith("APPEND_COMPACT")
                or t.id == "_APPEND_COMPACT_KEEP") for t in n.targets))]
    namespace = {"json": json, "hashlib": hashlib}
    exec(compile(ast.Module(body=body, type_ignores=[]), AG_BROKER, "exec"), namespace)
    return namespace


def synthetic_admission(static_bytes=20_000, hits=6):
    """Same top-level shape as a live current-turn admission (about 24 KB)."""
    static = {"padding": "s" * static_bytes}
    return {
        "protocol": "integrity-client-memory-mcp/v3/context-admission/v2", "context_admission_id": D,
        "health": "ready", "status": "ready", "logical_generation": 24, "production_authority": False,
        "home_record_count": 0, "capabilities": {"capabilities_digest": D, **static},
        "authority_contract": static, "architecture": {"architecture": {"admission_id": D}},
        "snapshot": {"snapshot_id": D, "cursor": {"event_count": 10, "maximum_event_id": 12}},
        "context_delivery": {"health": "ready", "status": "ready", "read_plane": "ready",
                             "notify_owner_required": False},
        "prompt_binding": {"turn_ref_digest": D, "prompt_sha256": "b" * 64, "generation": 3},
        "write_plane": {"turn_memory": "ready"},
        "mind": {"admission_receipt": {"receipt_id": D}, "selection_receipt": {"receipt_id": D},
                 "mind": {"synaptic": {"door": "admitted", "moves": [{"kind": "wait"}], "learned_hints": ["ROUTE #1"]},
                          "working_set": {"context_text": "INTEGRITY CAPSULE v1 " + "c" * 600,
                                          "invariants": ["Memory grants no authority."],
                                          "recall_hits": [{"id": i, "kind": "note", "summary": "r" * 900,
                                                           "task_id": "t", "truth_status": "reported",
                                                           "score": 30.0} for i in range(hits)]}}},
    }


def test_antigravity_admission_projection_keeps_ids_capsule_and_memory():
    ns = ag_namespace()
    doc = synthetic_admission()
    full = len(json.dumps(doc, separators=(",", ":")).encode())
    result = {"content": [{"type": "text", "text": json.dumps(doc)},
                          {"type": "text", "text": json.dumps({"antigravity_turn_memory": {
                              "registration_id": D, "receipt": {"big": "r" * 3000}, "close_required": True}})}]}
    out = ns["compact_admission_result"](result)
    projection = json.loads(out["content"][0]["text"])
    size = len(out["content"][0]["text"].encode())
    assert full > 20_000 and size <= 8192
    assert projection["context_admission_id"] == D and projection["snapshot"]["snapshot_id"] == D
    assert projection["capsule"]["context_text"].startswith("INTEGRITY CAPSULE v1")
    assert projection["capsule"]["recall_hits"] and len(projection["capsule"]["recall_hits"][0]["summary"]) == 400
    assert projection["capabilities_digest"] == D and projection["compaction"]["full_bytes"] == full
    assert json.loads(out["content"][1]["text"]) == {"antigravity_turn_memory": {
        "registration_id": D, "close_required": True}}


def test_antigravity_projection_stays_under_the_limit_with_many_hits():
    ns = ag_namespace()
    projection = ns["compact_admission_document"](synthetic_admission(hits=40))
    assert len(json.dumps(projection, separators=(",", ":")).encode()) <= 8192
    assert projection["capsule"]["recall_hits"] and projection["context_admission_id"] == D


def test_antigravity_compacts_only_after_its_own_validation():
    source = (RESOURCES / AG_BROKER).read_text(encoding="utf-8")
    validate = source.index("state.update(admission_verified=True")
    compact = source.index("response={**response,'result':compact_admission_result(result)}")
    assert validate < compact
    assert ag_namespace()["_compact_append_result"](full_append_receipt())["content"][0]["text"].startswith('{"receipt"')
