"""Offline boundary checks, not live Codex/SDK/production acceptance."""
import concurrent.futures
import os
import time

import pytest

from integrity_execution_bridge.catalog import validate
from integrity_execution_bridge.contracts import Control, Rejected, Task, decode, sha, MAX_OUTPUT
from integrity_execution_bridge.executor import CodexExecutor, Job
from integrity_execution_bridge.gateway import Bridge, DeliveryCache
from integrity_execution_bridge.workspace import Workspace


def test_strict_json_and_wire_integers():
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
        with pytest.raises(Rejected, match="invalid_json"):
            decode(raw)
    args = {"task_id": "task-1", "generation": 1.0, "snapshot_id": "snap",
            "path": "note.txt"}
    with pytest.raises(Rejected, match="integer_wire_type_required"):
        validate("workspace_read", args)


@pytest.mark.skipif(os.name != "posix", reason="POSIX workspace custody")
def test_workspace_denies_traversal_links_and_hardlinks(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (root / "link.txt").symlink_to(outside)
    os.link(outside, root / "hard.txt")
    workspace = Workspace(root)
    try:
        for path in ("../outside.txt", ".git/config", "dir/../outside.txt"):
            with pytest.raises(Rejected, match="path_not_admitted"):
                workspace.read(path)
        with pytest.raises((OSError, Rejected)):
            workspace.read("link.txt")
        with pytest.raises(Rejected, match="not_single_regular_file"):
            workspace.read("hard.txt")
        assert outside.read_text(encoding="utf-8") == "outside"
    finally:
        workspace.close()


@pytest.fixture
def bridge_runtime(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX workspace/cache custody")
    root = tmp_path / "work"
    root.mkdir()
    (root / "note.txt").write_text("alpha beta alpha", encoding="utf-8")
    workspace = Workspace(root)
    cache = DeliveryCache(tmp_path / "cache", "test-ns")
    state = {"control": Control(1, "snap-1")}
    bridge = Bridge(cache)
    bridge.register(Task("owner", "task-1", 1, "snap-1", time.time() + 60),
                    workspace, lambda: state["control"])
    try:
        yield bridge, root, state
    finally:
        bridge.close()
        workspace.close()
        cache.close()


def test_read_authorization_and_owner_control(bridge_runtime):
    bridge, _, state = bridge_runtime
    args = {"task_id": "task-1", "generation": 1, "snapshot_id": "snap-1",
            "path": "note.txt"}
    assert bridge.call("owner", "workspace_read", args)["text"] == "alpha beta alpha"
    with pytest.raises(Rejected, match="task_not_available"):
        bridge.call("another-owner", "workspace_read", args)
    with pytest.raises(Rejected, match="request_context_mismatch"):
        bridge.call("owner", "workspace_read", args | {"generation": 2})
    state["control"] = Control(1, "snap-1", state="PAUSED", read_allowed=False)
    with pytest.raises(Rejected, match="workspace_read_admission_closed"):
        bridge.call("owner", "workspace_read", args)


def test_mutation_without_sdk_is_denied_and_replay_refused(bridge_runtime):
    bridge, root, _ = bridge_runtime
    original = (root / "note.txt").read_bytes()
    args = {"task_id": "task-1", "generation": 1, "snapshot_id": "snap-1",
            "operation_id": "op-1", "path": "note.txt", "expected_sha256": sha(original),
            "old": "alpha", "new": "changed", "expected_count": 2}
    with pytest.raises(Rejected, match="sdk_admission_unavailable"):
        bridge.call("owner", "workspace_replace", args)
    assert (root / "note.txt").read_bytes() == original
    with pytest.raises(Rejected, match="operation_already_recorded_no_replay"):
        bridge.call("owner", "workspace_replace", args)
    assert (root / "note.txt").read_bytes() == original


def test_command_start_without_sdk_never_calls_backend(bridge_runtime):
    bridge, _, _ = bridge_runtime

    class Backend:
        binding = {"backend": "fixture"}

        def start(self, **_):
            raise AssertionError("command executed without SDK permit")

    bridge.backend = Backend()
    args = {"task_id": "task-1", "generation": 1, "snapshot_id": "snap-1",
            "operation_id": "op-command", "argv": ["/bin/echo", "not-executed"],
            "cwd": ".", "timeout_ms": 1000}
    with pytest.raises(Rejected, match="sdk_admission_unavailable"):
        bridge.call("owner", "command_start", args)


@pytest.mark.skipif(os.name != "posix", reason="POSIX argv contract")
def test_codex_executor_transmits_exact_argv_without_shell(tmp_path):
    class Channel:
        ready = True

        def __init__(self):
            self.calls = []

        def request(self, method, params, *, on_output=None):
            self.calls.append((method, params))
            return concurrent.futures.Future()

    channel = Channel()
    executor = CodexExecutor(channel, {"type": "readOnly", "networkAccess": False})
    argv = ("/bin/echo", "$HOME", "a; touch never", "space here")
    job = executor.start(job_id="job-1", argv=argv, cwd=str(tmp_path),
                         deadline=time.monotonic() + 10)
    assert job.job_id == "job-1"
    assert channel.calls[0][0] == "command/exec"
    assert channel.calls[0][1]["command"] == list(argv)
    assert channel.calls[0][1]["cwd"] == str(tmp_path)
    assert channel.calls[0][1]["sandboxPolicy"] == {"type": "readOnly",
                                                      "networkAccess": False}


def test_job_stop_ack_is_not_exit_and_output_truncation_is_explicit():
    stops = []
    job = Job("job-1", time.monotonic() + 10,
              lambda: stops.append("requested"), lambda *_: None)
    job.append(b"x" * (MAX_OUTPUT + 5))
    output = job.read(0, 128)
    assert output["truncated"] and output["gap"]
    assert output["cleanup_required"] and not output["independent_acceptance"]
    job.stop(wait=True)
    assert stops == ["requested"]
    after_stop = job.read(output["next_cursor"], 128)
    assert after_stop["stop_requested"] and after_stop["state"] == "submitted"
