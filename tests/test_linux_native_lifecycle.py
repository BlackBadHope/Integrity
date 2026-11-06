"""Linux Codex Native profile against a real disposable Memory stand.

This test process plays the Codex vendor: its interpreter is the pinned
``codex_executable``, and it launches the generated hook runner and MCP broker
as children, exactly as Codex launches them. The Memory server, signatures,
catalog and Turn Memory stores are real (RAM-only keys). No vendor binary,
model, network endpoint, credential or active configuration is used, so this
is not a live Codex acceptance.
"""
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
import uuid

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux user-custody Native lifecycle")

HERE = Path(__file__).resolve().parent
TOOL = "mcp__integrity_native__"


@pytest.fixture(params=["codex", "claude"])
def lifecycle(tmp_path, request):
    vendor = request.param
    native_install = pytest.importorskip("integrity_client_memory.native_install")
    runtime = pytest.importorskip("integrity_client_memory.native_runtime")
    sock, info_path = tmp_path / "stand.sock", tmp_path / "stand.json"
    stand = subprocess.Popen([sys.executable, "-B", str(HERE / "linux_native_stand_server.py"), str(tmp_path / "stand"),
                              str(sock), str(info_path), str(HERE.parent)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 60
    while not info_path.exists():
        assert stand.poll() is None and time.monotonic() < deadline, "stand did not start"
        time.sleep(0.05)
    info = json.loads(info_path.read_text())
    root = tmp_path / vendor
    native_install.build(vendor, {"command": sys.executable,
                                   "args": ["-B", str(HERE / "linux_native_stand_relay.py"), str(sock)]},
                         {"seed_namespace": info["seed_namespace"], "namespace_fingerprint": info["namespace_fingerprint"],
                          "architecture_checkpoint_id": "checkpoint:medor-architecture-custody",
                          vendor + "_executable": sys.executable}, root)
    runtime.verify(root / "profile.json")
    thread, turn = str(uuid.uuid4()), str(uuid.uuid4())
    broker_env = {k: v for k, v in os.environ.items() if k != "CODEX_THREAD_ID"}
    broker = subprocess.Popen([sys.executable, "-m", "integrity_client_memory.native_runtime", "--profile",
                               str(root / "profile.json"), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=broker_env)
    state = {"id": 0}

    def hook(event, **extra):
        payload = {"session_id": thread, "cwd": str(root), "hook_event_name": event, **extra}
        env = dict(broker_env)
        if vendor == "codex":
            payload["turn_id"] = turn
            env["CODEX_THREAD_ID"] = thread
        else:
            # Claude Code supplies neither a turn ID nor CODEX_THREAD_ID.
            payload["transcript_path"] = str(tmp_path / "projects" / (thread + ".jsonl"))
        done = subprocess.run([sys.executable, "-m", "integrity_client_memory.native_runtime", "--profile",
                               str(root / "profile.json"), "hook", event], input=json.dumps(payload).encode(),
                              capture_output=True, env=env, timeout=120)
        assert done.returncode == 0, done.stderr
        return done.stdout.decode()

    def rpc(method, params, *, notify=False):
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            state["id"] += 1
            message["id"] = state["id"]
        broker.stdin.write((json.dumps(message) + "\n").encode())
        broker.stdin.flush()
        while not notify:
            ready, _, _ = select.select([broker.stdout], [], [], 150)
            assert ready, "broker response timed out"
            reply = json.loads(broker.stdout.readline())
            if reply.get("id") == state["id"]:
                return reply["result"]
        return None

    try:
        rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "codex-vendor-fixture", "version": "1"}})
        rpc("notifications/initialized", {}, notify=True)
        yield {"root": root, "hook": hook, "rpc": rpc, "vendor": vendor}
    finally:
        broker.stdin.close()
        try:
            broker.wait(10)
        except subprocess.TimeoutExpired:
            broker.kill()
        stand.terminate()
        stand.wait(10)
        stand.stderr.close()
        broker.stdout.close()


def test_hook_admission_registration_and_signed_gap_run_on_linux(lifecycle):
    hook, rpc, root = lifecycle["hook"], lifecycle["rpc"], lifecycle["root"]
    assert "PENDING INTENT ADMISSION" in hook("SessionStart")
    pending = hook("UserPromptSubmit", prompt="GO record the Linux native acceptance result")
    ref = re.search(r"turnref:[A-Za-z0-9_-]{43}", pending).group(0)
    heads = list((root / "state/native-heads").iterdir())
    assert len(heads) == 1 and stat.S_IMODE(heads[0].stat().st_mode) == 0o600
    name = TOOL + "integrity_context_admission_current_turn"
    assert json.loads(hook("PreToolUse", tool_name=name, tool_input={"turn_ref": ref}) or "{}") == {}
    admission = rpc("tools/call", {"name": "integrity_context_admission_current_turn",
                                   "arguments": {"turn_ref": ref}})
    assert admission.get("isError") is not True, admission
    document = json.loads(admission["content"][0]["text"])
    assert document["admission"]["status"] == "ready" and document["admission"]["door"] == "admitted"
    # A second use of the same one-use reference is refused before any upstream send.
    replay = rpc("tools/call", {"name": "integrity_context_admission_current_turn", "arguments": {"turn_ref": ref}})
    assert replay.get("isError") is True and '"request_sent":false' in replay["content"][0]["text"]
    opened = hook("PostToolUse", tool_name=name, tool_input={"turn_ref": ref}, tool_response=admission)
    assert "CANONICAL READ PLANE READY" in opened
    assert re.search(r"TURN MEMORY LIVE registration_id=sha256:[a-f0-9]{64}", opened)
    stopped = hook("Stop", stop_hook_active=False)
    if lifecycle["vendor"] == "claude":
        terminal = json.loads(stopped)
        assert terminal["continue"] is True and "decision" not in terminal and "hookSpecificOutput" not in terminal
    # Without a terminal receipt the hook records signed coverage debt, never an invented no-event.
    assert re.search(r"COVERAGE GAP RECORDED: terminal receipt is missing; gap_receipt_id=sha256:[a-f0-9]{64}", stopped)
    for path in [root, *root.rglob("*")]:
        if not path.is_symlink() and not path.is_socket():
            assert stat.S_IMODE(path.lstat().st_mode) & 0o077 == 0, path


def test_model_facing_responses_fit_the_response_diet(lifecycle):
    """7.0.1: on the stand, the model sees at most 8 KB per admission and 1 KB per append.

    The full documents stay with the broker and the hook: the admission is
    file-backed and resolved by the hook, and the compact append receipt names
    the full receipt's digest and size.
    """
    hook, rpc, vendor = lifecycle["hook"], lifecycle["rpc"], lifecycle["vendor"]
    hook("SessionStart")
    pending = hook("UserPromptSubmit", prompt="GO record the response diet measurement")
    ref = re.search(r"turnref:[A-Za-z0-9_-]{43}", pending).group(0)
    admission = rpc("tools/call", {"name": "integrity_context_admission_current_turn",
                                   "arguments": {"turn_ref": ref}})
    admission_text = admission["content"][0]["text"]
    wrapper = json.loads(admission_text)
    assert len(admission_text.encode()) <= 8192
    # The full admission stays with the broker; its size is reported when the wrapper names it.
    full_admission = (wrapper.get("full_admission") or {}).get("bytes", "n/a")
    opened = hook("PostToolUse", tool_name=TOOL + "integrity_context_admission_current_turn",
                  tool_input={"turn_ref": ref}, tool_response=admission)
    assert "CANONICAL READ PLANE READY" in opened, opened
    arguments = {"event_uid": "client:response-diet-" + vendor, "kind": "task",
                 "summary": "Response diet measurement on the disposable stand.",
                 "context_admission_id": wrapper["admission"]["context_admission_id"]}
    appended = rpc("tools/call", {"name": "integrity_append_event", "arguments": arguments})
    assert appended.get("isError") is not True, appended
    append_text = appended["content"][0]["text"]
    receipt = json.loads(append_text)["receipt"]
    assert len(append_text.encode()) <= 1024
    assert receipt["outcome"] == "created" and receipt["protocol"].endswith("/append-receipt")
    witnessed = hook("PostToolUse", tool_name=TOOL + "integrity_append_event", tool_input=arguments,
                     tool_response=appended)
    assert "APPEND PASSIVE WITNESS: outcome=created" in witnessed, witnessed
    print(f"RESPONSE DIET {vendor}: admission {full_admission} -> {len(admission_text.encode())} bytes; "
          f"append {receipt['compaction']['full_bytes']} -> {len(append_text.encode())} bytes")
