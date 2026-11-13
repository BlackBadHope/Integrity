"""Antigravity gate v2: uncovered turns, model and prompt normalisation, turn continuity.

The real hook ``process()`` and the real ``ConversationBroker.dispatch`` run in a child
process inside a built profile; the upstream is a fake worker. State lives in ``tmp_path``.
"""
import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from integrity_client_memory import native_install as install
from integrity_client_memory import native_runtime as runtime

BINDINGS = {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
            "architecture_checkpoint_id": "checkpoint:fixture", "codex_executable": sys.executable}
UPSTREAM = {"command": sys.executable, "args": ["-c", "raise AssertionError('no upstream')"]}
RESOURCES = Path(install.__file__).resolve().parent / "resources" / "antigravity"

DRIVER = r'''
import hashlib, json, sys, types, uuid
from pathlib import Path
sys.path.insert(0, sys.argv[1])
work = Path(sys.argv[2])
import antigravity_hook as hook
import integrity_antigravity_broker as brk
store = hook.store
ROOT = work / "state"; BUS = work / "bus"; BUS.mkdir(parents=True, exist_ok=True)
D = lambda s: "sha256:" + hashlib.sha256(s.encode()).hexdigest()
SERVER = hook.SERVER
CALLS = []

class FakeWorker:
    def __init__(self, fail=False, fail_registration=False):
        self.fail = fail; self.fail_registration = fail_registration; self.initialize_params = {}
    def dispatch(self, request, defer_replay_ack_until_public_delivery=False):
        if self.fail:
            raise OSError("upstream-initialize-timeout")
        adm = {"context_admission_id": D("adm"), "snapshot_id": D("snap")}
        return {"jsonrpc": "2.0", "id": request.get("id"),
                "result": {"structuredContent": {"admission": adm}, "content": []}}
    def _standalone_turn_memory_call(self, name, args):
        CALLS.append([name, args.get("stage"), args.get("registration_id")])
        if name == "integrity_turn_memory_gap":
            return {"structuredContent": {"receipt": {}}}
        if self.fail_registration:
            raise OSError("turn-memory-open-timeout")
        ident = {k: args[k] for k in ("machine_id", "thread_id", "turn_id")}
        return {"structuredContent": {"receipt": {
            "receipt_id": D("reg:" + args["turn_id"]), "protocol": "integrity-guardian/turn-memory-registration/v1",
            "identity": ident, "prompt_sha256": args["prompt_sha256"], "production_authority": False,
            "terminal_required": True, "signature": {"algorithm": "ed25519", "key_id": "fixture", "value": "fixture"}}}}
    def confirm_public_response_delivery(self):
        pass
    def shutdown(self):
        pass

def broker(fail=False, fail_registration=False):
    b = object.__new__(brk.ConversationBroker)
    b.root = ROOT; b.contexts = {}; b.pending = []; b.snapshot_tools = set()
    b.control = types.SimpleNamespace(initialize_params={})
    b.factory = lambda: FakeWorker(fail, fail_registration)
    return b

def transcript(conv, step, text):
    art = work / "brain" / conv; logs = art / ".system_generated/logs"; logs.mkdir(parents=True, exist_ok=True)
    rows = [{"step_index": i, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": text if i == step else "earlier " + str(i)}
            for i in range(step + 1)]
    (logs / "transcript_full.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return {"artifactDirectoryPath": str(art), "transcriptPath": str(logs / "transcript_full.jsonl"), "initialNumSteps": step + 1}

def new_turn(conv=None, step=0, text="Fixture owner question", model="gemini-2.5-flash"):
    conv = conv or str(uuid.uuid4())
    base = {"conversationId": conv, "modelName": model}
    hook.process("PreInvocation", {**base, **transcript(conv, step, text)}, root=ROOT, bus_dir=BUS)
    return conv, base

def state(conv):
    return store.load(ROOT, conv)

def admission(conv, base, fail=False, fail_registration=False):
    args = {"ServerName": SERVER, "ToolName": "integrity_context_admission_current_turn", "Arguments": {}}
    pre = hook.process("PreToolUse", {**base, "toolCall": {"name": "call_mcp_tool", "args": args}}, root=ROOT, bus_dir=BUS)
    assert pre.get("decision") == "allow", pre
    resp = broker(fail, fail_registration).dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "integrity_context_admission_current_turn", "arguments": pre["overwrite"]["Arguments"]}})
    return resp

def gate(conv, base, name, args=None):
    return hook.process("PreToolUse", {**base, "toolCall": {"name": name, "args": args or {}}}, root=ROOT, bus_dir=BUS)

OTHER = {"ServerName": "other_server", "ToolName": "create_issue", "Arguments": {"title": "x"}}
COVERAGE = {"ServerName": SERVER, "ToolName": "integrity_turn_memory_coverage", "Arguments": {}}
out = {}

conv, base = new_turn()
out["honest_before"] = gate(conv, base, "run_command")
resp = admission(conv, base)
s = state(conv)
out["honest_state"] = [s.get("admission_verified"), bool(s.get("registration_id"))]
out["honest_run"] = gate(conv, base, "run_command")
out["honest_write"] = gate(conv, base, "write_file")
out["honest_other"] = gate(conv, base, "call_mcp_tool", OTHER)

conv, base = new_turn()
resp = admission(conv, base, fail=True)
s = state(conv)
out["failed_error"] = resp["result"].get("isError")
out["failed_state"] = [s.get("admission_attempted"), s.get("admission_verified"), bool(s.get("registration_id"))]
out["failed"] = {name: gate(conv, base, name) for name in ("run_command", "write_file", "send_message", "view_file")}
out["failed_other"] = gate(conv, base, "call_mcp_tool", OTHER)
out["failed_coverage"] = gate(conv, base, "call_mcp_tool", COVERAGE).get("decision")

conv, base = new_turn()
admission(conv, base, fail_registration=True)
s = state(conv)
out["unresolved_state"] = [s.get("admission_verified"), bool(s.get("registration_id")), s.get("coverage_status")]
out["unresolved"] = {name: gate(conv, base, name) for name in ("run_command", "edit_file", "list_dir")}
out["unresolved_other"] = gate(conv, base, "call_mcp_tool", OTHER)
out["unresolved_coverage"] = gate(conv, base, "call_mcp_tool", COVERAGE).get("decision")

conv, base = new_turn()
admission(conv, base)
old = state(conv)["registration_id"]
new_turn(conv, step=1, text="Fixture follow-up")
out["superseded_marked"] = state(conv).get("superseded_registration_id") == old
CALLS.clear()
admission(conv, base)
out["superseded_calls"] = [[c[0], c[1], c[2] == old] for c in CALLS]
out["superseded_cleared"] = "superseded_registration_id" not in state(conv)

conv, base = new_turn(model="auto")
s = state(conv)
out["auto_state"] = [s.get("model_name"), s.get("vendor")]
admission(conv, base)
out["auto_verified"] = state(conv).get("admission_verified")
conv2, _ = new_turn(model="")
out["empty_model"] = state(conv2).get("model_name")

plain, _ = new_turn(text="Fixture wrapped question")
wrapped, _ = new_turn(text="<USER_REQUEST>\nFixture wrapped question\n</USER_REQUEST>\n<ADDITIONAL_METADATA>fixture</ADDITIONAL_METADATA>")
empty, _ = new_turn(text="<USER_REQUEST>  </USER_REQUEST> kept")
out["wrapped_same_prompt"] = state(plain)["prompt_sha256"] == state(wrapped)["prompt_sha256"]
out["wrapped_distinct_turn"] = state(plain)["message_fingerprint"] != state(wrapped)["message_fingerprint"]
out["empty_wrapper_kept"] = state(empty)["prompt_sha256"] != state(plain)["prompt_sha256"]

conv, base = new_turn()
payload = {**base, **transcript(conv, 0, "Fixture owner question")}
first_ref = state(conv)["turn_ref"]
hook.process("Stop", {**base, "terminationReason": "NO_TOOL_CALL"}, root=ROOT, bus_dir=BUS)
out["stopped"] = state(conv).get("stopped")
out["stopped_gate"] = gate(conv, base, "run_command")
hook.process("PreInvocation", payload, root=ROOT, bus_dir=BUS)
s = state(conv)
out["resumed"] = [s.get("stopped"), s.get("turn_ref") != first_ref, s.get("generation")]
admission(conv, base)
out["resumed_verified"] = state(conv).get("admission_verified")

class Named:
    def __init__(self, name, log): self.name = name; self.log = log; self.initialize_params = {}
    def shutdown(self): self.log.append(self.name)
log = []; made = iter(range(100))
b = broker(); b.factory = lambda: Named("w" + str(next(made)), log)
convs = [str(uuid.UUID(int=i + 1)) for i in range(6)]
for c in convs[:4]:
    b.worker(c, {"model_name": "m"})
b.worker(convs[0], {"model_name": "m"})
b.worker(convs[4], {"model_name": "m"})
out["lru_after_first"] = [list(b.contexts).index(c) if c in b.contexts else None for c in convs[:5]] + [list(log)]
b.pending.append(b.contexts[convs[2]])
b.worker(convs[5], {"model_name": "m"})
out["lru_pending"] = [convs[2] in b.contexts, list(log), len(b.contexts)]

b = broker()
b.control = types.SimpleNamespace(initialize_params={}, dispatch=lambda message: {"jsonrpc": "2.0", "id": 2, "result": {"tools": [
    {"name": "integrity_x", "inputSchema": {"type": "object", "not": {"required": ["a"]}, "properties": {"a": {}}}},
    {"name": "integrity_y"}]}})
tools = b.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
out["schemas"] = [["not" in t["inputSchema"], store.ROUTE_FIELD in t["inputSchema"]["properties"], "a" in t["inputSchema"]["properties"]] for t in tools]
print(json.dumps(out))
'''


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("antigravity-v2")
    root = tmp / "profile"
    install.build("antigravity", UPSTREAM, {**BINDINGS, "admission_first": "block"}, root)
    value, _ = runtime.verify(root / "profile.json")
    work = tmp / "work"
    work.mkdir()
    done = subprocess.run([sys.executable, "-B", "-c", DRIVER, str(root / "runtime"), str(work)],
                          env=runtime.environment(value, root), capture_output=True, timeout=180)
    assert done.returncode == 0, done.stderr.decode(errors="replace")[-4000:]
    return json.loads(done.stdout.decode().strip().splitlines()[-1])


def denied(result, marker):
    return result.get("decision") == "deny" and marker in result.get("reason", "")


def test_honest_turn_is_unchanged(results):
    assert denied(results["honest_before"], "admission-first")
    assert results["honest_state"] == [True, True]
    assert results["honest_run"] == {"decision": "allow"}
    assert results["honest_write"] == {"decision": "allow"}
    assert results["honest_other"] == {}


def test_failed_admission_blocks_state_changes_but_not_reads(results):
    assert results["failed_error"] is True
    assert results["failed_state"] == [True, False, False]
    for name in ("run_command", "write_file", "send_message"):
        assert denied(results["failed"][name], "admission-failed"), name
    assert results["failed"]["view_file"] == {"decision": "allow"}
    assert denied(results["failed_other"], "admission-failed")
    assert results["failed_coverage"] == "allow"


def test_unopened_registration_blocks_state_changes_but_not_reads(results):
    assert results["unresolved_state"] == [True, False, "registration-unresolved"]
    assert denied(results["unresolved"]["run_command"], "registration-unresolved")
    assert denied(results["unresolved"]["edit_file"], "registration-unresolved")
    assert results["unresolved"]["list_dir"] == {"decision": "allow"}
    assert denied(results["unresolved_other"], "registration-unresolved")
    assert results["unresolved_coverage"] == "allow"


def test_superseded_registration_gets_a_notify_gap_before_the_new_open(results):
    assert results["superseded_marked"] is True
    assert results["superseded_calls"][0] == ["integrity_turn_memory_gap", "notify", True]
    assert results["superseded_calls"][1][0] == "integrity_turn_memory_open"
    assert results["superseded_cleared"] is True


def test_automatic_model_selection_maps_to_a_gemini_vendor(results):
    assert results["auto_state"] == ["gemini-default", "Google"]
    assert results["auto_verified"] is True
    assert results["empty_model"] == "gemini-default"


def test_user_request_wrapper_is_not_part_of_the_bound_prompt(results):
    assert results["wrapped_same_prompt"] is True
    assert results["wrapped_distinct_turn"] is True
    assert results["empty_wrapper_kept"] is True


def test_new_invocation_after_stop_resumes_the_same_owner_turn(results):
    assert results["stopped"] is True
    assert denied(results["stopped_gate"], "new owner turn")
    stopped, new_ref, generation = results["resumed"]
    assert stopped is False and new_ref is True and generation == 1
    assert results["resumed_verified"] is True


def test_broker_keeps_at_most_four_conversation_workers(results):
    # c0 was touched again, so c1 is the least recently used and the only one shut down.
    assert results["lru_after_first"] == [2, None, 0, 1, 3, ["w1"]]
    in_contexts, log, size = results["lru_pending"]
    assert in_contexts is False and log == ["w1"] and size == 4


def test_tools_list_drops_unsupported_not_and_adds_the_route_field(results):
    assert results["schemas"] == [[False, True, True], [False, True, False]]


def test_state_changing_tools_are_gated_tools():
    tree = ast.parse((RESOURCES / "antigravity_hook.py").read_text(encoding="utf-8"))
    value = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(getattr(t, "id", None) == "STATE_CHANGING_TOOLS" for t in node.targets))
    names = set(ast.literal_eval(value.args[0]))
    assert names <= set(install.AG_GATED_TOOLS)
    assert {"run_command", "write_to_file", "send_message"} <= names
    assert not names & {"view_file", "read_file", "list_dir", "grep_search", "read_url_content"}
