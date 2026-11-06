"""Antigravity admission-first gate and broker snapshot binding (live fixes of 06.11.2026)."""
import json
import os
import subprocess
import sys

import pytest

from integrity_client_memory import native_install as install
from integrity_client_memory import native_runtime as runtime

BINDINGS = {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
            "architecture_checkpoint_id": "checkpoint:fixture", "codex_executable": sys.executable}
UPSTREAM = {"command": sys.executable, "args": ["-c", "raise AssertionError('no upstream')"]}
CONVERSATION = "77777777-7777-4777-8777-777777777777"


def build(tmp_path, gate):
    root = tmp_path / ("profile-" + gate)
    install.build("antigravity", UPSTREAM, {**BINDINGS, "admission_first": gate}, root)
    value, _ = runtime.verify(root / "profile.json")
    return value, root


@pytest.fixture
def gated(tmp_path):
    return build(tmp_path, "block")


def run(ag, event, payload):
    value, root = ag
    result, code = runtime.hook(value, root, event, json.dumps(payload).encode())
    assert code == 0
    return result


def owner_payload(root, conversation=CONVERSATION, step=0, text="Fixture owner question"):
    artifact = root / "brain" / conversation
    path = artifact / ".system_generated/logs/transcript_full.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [{"step_index": i, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": text + " " + str(i)}
            for i in range(step + 1)]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return {"conversationId": conversation, "artifactDirectoryPath": str(artifact), "transcriptPath": str(path),
            "modelName": "gemini-2.5-flash", "invocationNum": 0, "initialNumSteps": step + 1}


def tool(payload, name="run_command"):
    return {**payload, "toolCall": {"name": name, "args": {"CommandLine": "hostname"}}}


def mcp(payload, server, name, arguments):
    return {**payload, "toolCall": {"name": "call_mcp_tool", "args": {
        "ServerName": server, "ToolName": name, "Arguments": arguments}}}


def state_path(root, conversation=CONVERSATION):
    return root / "state/admission-state" / (conversation + ".json")


def test_hooks_json_matcher_follows_the_installer_switch(tmp_path):
    _, off = build(tmp_path, "off")
    _, on = build(tmp_path, "block")
    read = lambda root: json.loads((root / "antigravity-plugin/hooks.json").read_text())["integrity-native"]
    assert read(off)["PreToolUse"][0]["matcher"] == "^call_mcp_tool$"
    matcher = read(on)["PreToolUse"][0]["matcher"]
    assert matcher.startswith("^(call_mcp_tool|") and "run_command" in matcher and "view_file" in matcher
    assert read(on)["PostToolUse"][0]["matcher"] == "^call_mcp_tool$"
    assert json.loads((on / "turn-guard.json").read_text())["admission_first"] == "block"
    assert json.loads((off / "turn-guard.json").read_text())["admission_first"] == "off"
    with pytest.raises(ValueError):
        build(tmp_path, "sometimes")


def test_no_state_passes_explicitly(gated):
    _, root = gated
    assert run(gated, "PreToolUse", tool(owner_payload(root))) == {"decision": "allow"}
    assert run(gated, "PreToolUse", mcp(owner_payload(root), "other_server", "x", {})) == {}


def test_pre_admission_denies_standard_and_other_mcp_tools(gated):
    _, root = gated
    payload = owner_payload(root)
    run(gated, "PreInvocation", payload)
    ref = json.loads(state_path(root).read_text())["turn_ref"]
    denied = run(gated, "PreToolUse", tool(payload))
    assert denied["decision"] == "deny" and "admission-first" in denied["reason"] and ref in denied["reason"]
    assert run(gated, "PreToolUse", mcp(payload, "other_server", "x", {}))["decision"] == "deny"


def test_admitted_turn_allows_standard_tools(gated):
    _, root = gated
    payload = owner_payload(root)
    run(gated, "PreInvocation", payload)
    ref = json.loads(state_path(root).read_text())["turn_ref"]
    admitted = run(gated, "PreToolUse", mcp(payload, "integrity_native", "integrity_context_admission_current_turn",
                                            {"turn_ref": ref}))
    assert admitted["decision"] == "allow"
    assert run(gated, "PreToolUse", tool(payload, "view_file")) == {"decision": "allow"}
    assert run(gated, "PreToolUse", mcp(payload, "other_server", "x", {})) == {}


@pytest.mark.parametrize("field", ["stopped", "turn_memory_closed"])
def test_previous_turn_stopped_or_closed_denies_until_new_invocation(gated, field):
    _, root = gated
    payload = owner_payload(root)
    run(gated, "PreInvocation", payload)
    path = state_path(root)
    value = json.loads(path.read_text())
    value.update(admission_attempted=True, **{field: True})
    path.write_text(json.dumps(value), encoding="utf-8")
    denied = run(gated, "PreToolUse", tool(payload))
    assert denied["decision"] == "deny" and "new owner turn" in denied["reason"]


def test_gate_off_is_a_plain_pass(tmp_path):
    ag = build(tmp_path, "off")
    _, root = ag
    payload = owner_payload(root)
    run(ag, "PreInvocation", payload)
    assert run(ag, "PreToolUse", tool(payload)) == {"decision": "allow"}


def test_broker_bind_snapshot_fills_only_a_missing_verified_id(gated):
    value, root = gated
    digest = "sha256:" + "b" * 64
    code = (
        "import json,sys;sys.path.insert(0,sys.argv[1]);import integrity_antigravity_broker as b\n"
        "tools=b.snapshot_bound_tools([{'name':'integrity_seed_tasks','inputSchema':{'properties':{'snapshot_id':{}}}},"
        "{'name':'integrity_append_event','inputSchema':{'properties':{'summary':{}}}}])\n"
        "ok={'admission_verified':True,'snapshot_id':sys.argv[2]}\n"
        "print(json.dumps([sorted(tools),"
        "b.bind_snapshot('integrity_seed_tasks',{},ok,tools),"
        "b.bind_snapshot('integrity_seed_tasks',{'snapshot_id':'sha256:'+'c'*64},ok,tools),"
        "b.bind_snapshot('integrity_seed_tasks',{},{'admission_verified':False,'snapshot_id':sys.argv[2]},tools),"
        "b.bind_snapshot('integrity_append_event',{},ok,tools)]))"
    )
    env = runtime.environment(value, root)
    done = subprocess.run([sys.executable, "-B", "-c", code, str(root / "runtime"), digest],
                          env=env, capture_output=True, timeout=60)
    assert done.returncode == 0, done.stderr.decode(errors="replace")
    tools, filled, kept, unadmitted, other = json.loads(done.stdout)
    assert tools == ["integrity_seed_tasks"]
    assert filled == {"snapshot_id": digest}
    assert kept == {"snapshot_id": "sha256:" + "c" * 64}
    assert unadmitted == {} and other == {}
