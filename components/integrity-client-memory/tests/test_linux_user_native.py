"""Linux user-custody Native head: real /proc ancestry and owner-only custody.

The test process plays the vendor: its resolved interpreter is the pinned
executable, so every child it spawns is a genuine descendant. No vendor binary,
model, network, credential or active configuration is used.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import uuid

import pytest

from integrity_client_memory import linux_user_native as native
from integrity_client_memory import native_install as install
from integrity_client_memory import native_runtime as runtime

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc custody primitive")

PYTHON, PIN = native.pin_executable(sys.executable) if sys.platform.startswith("linux") else ("", "")
READER = """
import json, sys
from integrity_client_memory import linux_user_native as n
try:
    if sys.argv[1] == "ancestor":
        print(json.dumps(list(n.find_vendor_ancestor(sys.argv[2], sys.argv[3]))))
    else:
        print(json.dumps(n.verified_head(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])))
except n.LinuxNativeError as error:
    print(json.dumps({"error": str(error)}))
"""


def child(*args, env=None):
    done = subprocess.run([sys.executable, "-c", READER, *args], capture_output=True, text=True,
                          env=env, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def own_birth():
    return native.process_source(os.getpid())[1]


def head_root(tmp_path):
    root = tmp_path / "native-heads"
    native.private_directory(root)
    return root


def test_pin_resolves_the_kernel_image_and_refuses_writable_or_relative_paths(tmp_path):
    assert PYTHON == os.path.realpath(sys.executable)
    assert len(PIN) == 64
    writable = tmp_path / "vendor"
    shutil.copyfile(PYTHON, writable)
    writable.chmod(0o775)
    with pytest.raises(native.LinuxNativeError, match="custody_invalid"):
        native.pin_executable(str(writable))
    with pytest.raises(native.LinuxNativeError, match="not_absolute"):
        native.pin_executable("python3")
    with pytest.raises(native.LinuxNativeError, match="missing"):
        native.pin_executable(str(tmp_path / "absent"))


def test_descendant_finds_this_process_as_its_pinned_vendor_ancestor():
    assert child("ancestor", PYTHON, PIN) == [os.getpid(), own_birth()]


def test_a_different_image_pin_has_no_vendor_ancestor():
    assert child("ancestor", PYTHON, "0" * 64) == {"error": "linux_native_vendor_ancestor_missing"}
    assert child("ancestor", "/bin/true", PIN) == {"error": "linux_native_vendor_ancestor_missing"}


def test_published_head_is_owner_only_and_verified_by_a_descendant(tmp_path):
    root = head_root(tmp_path)
    thread, turn = str(uuid.uuid4()), str(uuid.uuid4())
    native.publish_head(root, thread_id=thread, turn_id=turn, status="inProgress",
                        pid=os.getpid(), birth=own_birth(), executable_sha256=PIN)
    files = list(root.iterdir())
    assert len(files) == 1 and stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert child("head", str(root), thread, PYTHON, PIN) == {"id": turn, "status": "inProgress"}


@pytest.mark.parametrize("change", ["dead-pid", "wrong-birth", "foreign-pin"])
def test_head_not_delivered_by_a_live_pinned_ancestor_is_refused(tmp_path, change):
    root = head_root(tmp_path)
    thread = str(uuid.uuid4())
    pid, birth, pin = os.getpid(), own_birth(), PIN
    if change == "dead-pid":
        gone = subprocess.Popen(["/bin/true"])
        gone.wait()
        pid = gone.pid
    elif change == "wrong-birth":
        birth = str(int(birth) + 1)
    else:
        pin = "f" * 64
    native.publish_head(root, thread_id=thread, turn_id=str(uuid.uuid4()), status="inProgress",
                        pid=pid, birth=birth, executable_sha256=pin)
    expected = "linux_native_executable_pin_changed" if change == "foreign-pin" else "linux_native_vendor_ancestor_missing"
    assert child("head", str(root), thread, PYTHON, PIN) == {"error": expected}


def test_reader_detached_from_the_vendor_tree_is_refused(tmp_path):
    root = head_root(tmp_path)
    thread = str(uuid.uuid4())
    native.publish_head(root, thread_id=thread, turn_id=str(uuid.uuid4()), status="inProgress",
                        pid=os.getpid(), birth=own_birth(), executable_sha256=PIN)
    out = tmp_path / "detached.json"
    # The intermediate shell exits at once, so the reader is re-parented away
    # from this (vendor) process before it inspects its ancestry.
    script = 'sleep 0.3; exec "$0" -c "$1" head "$2" "$3" "$4" "$5" > "$6"'
    subprocess.run(["/bin/sh", "-c", '(/bin/sh -c "$0" "$@" &)', script, sys.executable, READER,
                    str(root), thread, PYTHON, PIN, str(out)], check=True, timeout=30)
    deadline = time.monotonic() + 30
    while not (out.exists() and out.stat().st_size) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert json.loads(out.read_text()) == {"error": "linux_native_vendor_ancestor_missing"}


def test_custody_refusals_fail_closed(tmp_path, monkeypatch):
    root = head_root(tmp_path)
    thread = str(uuid.uuid4())
    native.publish_head(root, thread_id=thread, turn_id=str(uuid.uuid4()), status="inProgress",
                        pid=os.getpid(), birth=own_birth(), executable_sha256=PIN)
    path = next(root.iterdir())
    path.chmod(0o640)
    with pytest.raises(native.LinuxNativeError, match="head_custody_invalid"):
        native.read_head(root, thread)
    path.chmod(0o600)
    root.chmod(0o750)
    with pytest.raises(native.LinuxNativeError, match="head_root_custody_invalid"):
        native.read_head(root, thread)
    root.chmod(0o700)
    real = tmp_path / "elsewhere.json"
    path.rename(real)
    path.symlink_to(real)
    with pytest.raises(native.LinuxNativeError, match="head_custody_invalid"):
        native.read_head(root, thread)
    path.unlink()
    real.rename(path)
    assert native.read_head(root, thread)["thread_id"] == thread
    monkeypatch.setattr(native.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(native.LinuxNativeError, match="custody_invalid"):
        native.read_head(root, thread)
    with pytest.raises(native.LinuxNativeError, match="custody_invalid"):
        native.private_directory(root)


def test_missing_or_foreign_subject_heads_are_refused(tmp_path):
    root = head_root(tmp_path)
    with pytest.raises(native.LinuxNativeError, match="head_missing"):
        native.read_head(root, str(uuid.uuid4()))
    with pytest.raises(native.LinuxNativeError, match="subject_invalid"):
        native.read_head(root, "not-a-thread")
    with pytest.raises(native.LinuxNativeError, match="subject_invalid"):
        native.publish_head(root, thread_id=str(uuid.uuid4()), turn_id="model-chosen", status="inProgress",
                            pid=os.getpid(), birth=own_birth(), executable_sha256=PIN)


def fixture_bindings(**extra):
    return {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
            "architecture_checkpoint_id": "checkpoint:fixture", **extra}


def build(tmp_path, **extra):
    root = tmp_path / "codex"
    install.build("codex", {"command": sys.executable, "args": ["-c", "raise SystemExit(3)"]},
                  fixture_bindings(codex_executable=sys.executable, **extra), root)
    return root


def test_linux_codex_profile_requires_its_vendor_executable(tmp_path):
    with pytest.raises(ValueError, match="codex_executable"):
        install.build("codex", {"command": sys.executable}, fixture_bindings(), tmp_path / "unpinned")
    assert not (tmp_path / "unpinned").exists()


def test_linux_codex_profile_is_owner_only_and_declares_user_custody(tmp_path):
    root = build(tmp_path)
    value, _ = runtime.verify(root / "profile.json")
    assert value["linux_native"] == {"mode": "user", "executable": PYTHON, "executable_sha256": PIN,
                                     "head_root": str(root / "state/native-heads"), "trusted_roots": []}
    component = install.read_json(root / "component.json")["values"]
    assert component["linux_native_mode"] == "user"
    for path in [root, *root.rglob("*")]:
        assert stat.S_IMODE(path.lstat().st_mode) & 0o077 == 0, path
    root.chmod(0o750)
    with pytest.raises(ValueError, match="root custody invalid"):
        runtime.verify(root / "profile.json")


def test_linux_hook_paths_refuse_line_breaks(tmp_path):
    parent = tmp_path / "bad\nname"
    parent.mkdir()
    with pytest.raises(ValueError, match="line breaks"):
        install.build("codex", {"command": sys.executable},
                      fixture_bindings(codex_executable=sys.executable), parent / "codex")
    assert not (parent / "codex").exists()


def test_linux_custody_declaration_drift_is_refused(tmp_path):
    root = build(tmp_path)
    value = install.read_json(root / "profile.json")
    value["linux_native"]["mode"] = "system"
    install.write_json(root / "profile.json", value)
    with pytest.raises(ValueError, match="custody declaration invalid"):
        runtime.verify(root / "profile.json")


def run_hook(root, event, payload, env, *, check=True):
    done = subprocess.run([sys.executable, "-m", "integrity_client_memory.native_runtime", "--profile",
                           str(root / "profile.json"), "hook", event], input=json.dumps(payload).encode(),
                          capture_output=True, env=env, timeout=120)
    assert done.returncode == 0 or not check, done.stderr
    return json.loads(done.stdout or b"{}")


def test_hook_runner_publishes_the_vendor_head_and_the_broker_side_reads_it(tmp_path):
    root = build(tmp_path)
    thread, turn = str(uuid.uuid4()), str(uuid.uuid4())
    env = {**os.environ, "CODEX_THREAD_ID": thread}
    payload = {"session_id": thread, "turn_id": turn, "cwd": str(root), "prompt": "fixture"}
    result = run_hook(root, "UserPromptSubmit", {**payload, "hook_event_name": "UserPromptSubmit"}, env)
    assert "turnref:" in json.dumps(result)
    heads = root / "state/native-heads"
    assert stat.S_IMODE(heads.stat().st_mode) == 0o700
    # The broker inherits no CODEX_THREAD_ID; its proof is the live pinned ancestor.
    reader = {k: v for k, v in os.environ.items() if k != "CODEX_THREAD_ID"}
    reader["INTEGRITY_CLIENT_MEMORY_CONFIG"] = str(root / "component.json")
    code = ("import json,sys;from integrity_client_memory.owning_native import current_owning_turn;"
            "print(json.dumps(current_owning_turn(sys.argv[1])))")
    def owning():
        done = subprocess.run([sys.executable, "-c", code, thread], capture_output=True, text=True,
                              env=reader, timeout=60)
        assert done.returncode == 0, done.stderr
        return json.loads(done.stdout)
    assert owning() == {"id": turn, "status": "inProgress"}
    run_hook(root, "Stop", {**payload, "hook_event_name": "Stop"}, env)
    assert owning() == {"id": turn, "status": "completed"}
    foreign = {**reader, "CODEX_THREAD_ID": str(uuid.uuid4())}
    done = subprocess.run([sys.executable, "-c", code, thread], capture_output=True, text=True,
                          env=foreign, timeout=60)
    assert done.returncode != 0 and "linux_native_caller_mismatch" in done.stderr


def test_hook_runner_publishes_nothing_for_a_conflicting_caller_or_model_turn(tmp_path):
    root = build(tmp_path)
    thread = str(uuid.uuid4())
    env = {**os.environ, "CODEX_THREAD_ID": str(uuid.uuid4())}
    run_hook(root, "UserPromptSubmit", {"session_id": thread, "turn_id": str(uuid.uuid4()),
                                        "cwd": str(root), "prompt": "fixture"}, env, check=False)
    env["CODEX_THREAD_ID"] = thread
    run_hook(root, "UserPromptSubmit", {"session_id": thread, "turn_id": "not-a-native-turn",
                                        "cwd": str(root), "prompt": "fixture"}, env, check=False)
    heads = root / "state/native-heads"
    assert not heads.exists() or not list(heads.iterdir())


def build_claude(tmp_path):
    root = tmp_path / "claude"
    install.build("claude", {"command": sys.executable, "args": ["-c", "raise SystemExit(3)"]},
                  fixture_bindings(claude_executable=sys.executable), root)
    return root


def claude_payload(root, session, event, **extra):
    transcript = root.parent / "projects" / (session + ".jsonl")
    return {"session_id": session, "transcript_path": str(transcript), "cwd": str(root),
            "hook_event_name": event, **extra}


def test_linux_claude_profile_requires_its_vendor_executable(tmp_path):
    with pytest.raises(ValueError, match="claude_executable"):
        install.build("claude", {"command": sys.executable}, fixture_bindings(), tmp_path / "unpinned")
    assert not (tmp_path / "unpinned").exists()


def test_linux_claude_profile_is_owner_only_and_runs_the_shared_cohort(tmp_path):
    root = build_claude(tmp_path)
    value, _ = runtime.verify(root / "profile.json")
    assert value["linux_native"]["executable"] == PYTHON and value["hook"] == "integrity-client-admission.py"
    assert "delegation-native-reader.py" in value["files"] and "claude_owning_native.py" not in value["files"]
    assert install.read_json(root / "component.json")["values"]["native_agent_product"] == "claude"
    settings = install.read_json(root / "claude-workspace/.claude/settings.json")["hooks"]
    assert {"UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"} <= set(settings)
    mcp = install.read_json(root / "claude-workspace/.mcp.json")["mcpServers"]["integrity_native"]
    assert mcp["args"][-3:] == ["--tools-contract", str(root / "integrity-client-tools.json"), "mcp"]
    for path in [root, *root.rglob("*")]:
        assert stat.S_IMODE(path.lstat().st_mode) & 0o077 == 0, path


def test_claude_turns_are_minted_by_the_pinned_runner_and_stop_never_blocks(tmp_path):
    root = build_claude(tmp_path)
    session = str(uuid.uuid4())
    env = {k: v for k, v in os.environ.items() if k != "CODEX_THREAD_ID"}
    first = run_hook(root, "UserPromptSubmit", claude_payload(root, session, "UserPromptSubmit", prompt="first"), env)
    ref = json.dumps(first).split("turn_ref='")[1].split("'")[0]
    head = native.read_head(root / "state/native-heads", session)
    assert head["status"] == "inProgress" and head["native_pid"] == os.getpid()
    assert head["prompt_sha256"] == __import__("hashlib").sha256(b"first").hexdigest()
    name = "mcp__integrity_native__integrity_context_admission_current_turn"
    allowed = run_hook(root, "PreToolUse", claude_payload(root, session, "PreToolUse", tool_name=name,
                                                          tool_input={"turn_ref": ref}), env)
    assert not runtime.blocked(allowed)
    stopped = run_hook(root, "Stop", claude_payload(root, session, "Stop", stop_hook_active=False), env)
    assert stopped.get("continue") is True and "decision" not in stopped and "hookSpecificOutput" not in stopped
    assert native.read_head(root / "state/native-heads", session)["status"] == "completed"
    run_hook(root, "UserPromptSubmit", claude_payload(root, session, "UserPromptSubmit", prompt="second"), env)
    assert native.read_head(root / "state/native-heads", session)["turn_id"] != head["turn_id"]


def test_claude_foreign_transcript_or_process_never_gets_a_turn(tmp_path):
    root = build_claude(tmp_path)
    session = str(uuid.uuid4())
    env = {k: v for k, v in os.environ.items() if k != "CODEX_THREAD_ID"}
    foreign = claude_payload(root, session, "UserPromptSubmit", prompt="x")
    foreign["transcript_path"] = str(root.parent / (str(uuid.uuid4()) + ".jsonl"))
    refused = run_hook(root, "UserPromptSubmit", foreign, env)
    assert "turn_ref" not in json.dumps(refused) and "ownership unavailable" in refused["systemMessage"]
    shared = root.parent / "projects" / (session + ".jsonl")
    shared.parent.mkdir()
    shared.write_text("{}\n")
    shared.chmod(0o666)
    refused = run_hook(root, "UserPromptSubmit", claude_payload(root, session, "UserPromptSubmit", prompt="x"), env)
    assert "transcript_custody_invalid" in refused["systemMessage"]
    shared.chmod(0o600)
    # A head recorded for another (dead) Claude process cannot be reused by this one.
    native.private_directory(root / "state")
    gone = subprocess.Popen(["/bin/true"])
    gone.wait()
    native.publish_head(root / "state/native-heads", thread_id=session, turn_id=str(uuid.uuid4()),
                        status="inProgress", pid=gone.pid, birth="1", executable_sha256=PIN)
    name = "mcp__integrity_native__integrity_append_event"
    denied = run_hook(root, "PreToolUse", claude_payload(root, session, "PreToolUse", tool_name=name,
                                                         tool_input={}), env, check=False)
    assert runtime.blocked(denied)
