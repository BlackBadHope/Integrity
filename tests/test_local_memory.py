# SPDX-License-Identifier: BUSL-1.1
"""Local memory profile: three agents on one machine, read back from memory alone."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from integrity_guardian import local_memory as lm

TASK = "demo-task"


def call(memory: lm.LocalMemory, name: str, **arguments) -> dict:
    """One tool call through the MCP dispatcher, as an agent client sends it."""
    reply = lm.dispatch(memory, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": name, "arguments": arguments}})
    value = json.loads(reply["result"]["content"][0]["text"])
    if reply["result"]["isError"]:
        raise AssertionError(value["error"])
    return value


def refused(memory: lm.LocalMemory, name: str, **arguments) -> str:
    reply = lm.dispatch(memory, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": name, "arguments": arguments}})
    assert reply["result"]["isError"] is True
    return json.loads(reply["result"]["content"][0]["text"])["error"]


@pytest.fixture
def memory(tmp_path: Path):
    value = lm.LocalMemory.create(tmp_path / "home")
    yield value
    value.close()


def work(memory: lm.LocalMemory, agent: str, client: str, result: str, *, finish: bool = True) -> dict:
    """What one agent does: open a turn, claim the task, write a result, release, close."""
    turn = call(memory, "lm_turn_open", declared_agent=agent, declared_client=client,
                declared_machine="machine-one", intent=f"{agent}: work on {TASK}")
    claim = call(memory, "lm_work_claim", registration_id=turn["registration_id"], task=TASK)
    assert claim["status"] == "acquired"
    event = call(memory, "lm_append_event", registration_id=turn["registration_id"],
                 kind="task", summary=result, task=TASK, details={"value": result})
    if finish:
        call(memory, "lm_work_release", registration_id=turn["registration_id"],
             claim_id=claim["claim_id"], fence_token=claim["fence_token"],
             result_event_uid=event["event_uid"])
        call(memory, "lm_turn_close", registration_id=turn["registration_id"])
    return {"turn": turn, "claim": claim, "event": event}


def test_c_reads_what_b_wrote_claimed_and_how_b_closed(memory) -> None:
    a = work(memory, "agent-a", "claude-code", "Result: 2")
    b = work(memory, "agent-b", "codex", "Result: X")

    # C never calls B. It reads the task, then asks about B's event.
    events = call(memory, "lm_seed_recall", task=TASK)["events"]
    assert [(item["actor"], item["summary"]) for item in events] == [
        ("agent-a", "Result: 2"), ("agent-b", "Result: X")]
    found = call(memory, "lm_turn_receipt_by_event", event_uid=events[1]["event_uid"])

    assert found["event"]["summary"] == "Result: X"                      # what B wrote, verbatim
    assert found["event"]["details"]["value"] == "Result: X"
    assert found["author"]["declared_agent"] == "agent-b"                # who B says it is
    assert found["author"]["declared_client"] == "codex"
    assert found["author"]["declared_machine"] == "machine-one"
    assert "not verified" in found["author"]["note"]
    turn = found["turn"]
    assert turn["status"] == "closed" and turn["registration_signature"] == "valid"
    assert turn["registration_id"] == b["turn"]["registration_id"]
    assert turn["opened_at"] == b["turn"]["opened_at"]
    assert turn["terminal_receipt"]["outcome"] == "events"               # how B closed its turn
    assert turn["terminal_receipt"]["events"][0]["event_uid"] == b["event"]["event_uid"]
    assert turn["event_listed_in_terminal_receipt"] is True
    kinds = [(item["kind"], item["fence_token"]) for item in found["claims"]]  # what B claimed
    assert kinds == [("claim-acquired", 2), ("claim-released", 2)]
    assert found["claims"][1]["outcome"] == b["event"]["event_uid"]
    assert found["claims"][0]["reference"]["registration_id"] == b["turn"]["registration_id"]

    log = call(memory, "lm_work_claims", task=TASK)
    assert log["chain_events_verified"] == 4 and log["signed"] is False
    assert a["claim"]["fence_token"] == 1
    assert call(memory, "lm_turn_coverage")["counts"]["unresolved"] == 0


def test_c_sees_that_b_broke_off_without_closing(memory) -> None:
    work(memory, "agent-a", "claude-code", "Result: 2")
    b = work(memory, "agent-b", "codex", "Result: X", finish=False)

    found = call(memory, "lm_turn_receipt_by_event", event_uid=b["event"]["event_uid"])
    assert found["event"]["summary"] == "Result: X"
    assert found["turn"]["status"] == "open"
    assert found["turn"]["terminal_receipt"] is None and found["turn"]["gap_receipt"] is None
    assert "never closed" in found["turn"]["note"]
    assert [item["kind"] for item in found["claims"]] == ["claim-acquired"]   # still held, never released

    # C's own claim waits behind B's unreleased claim, and names it.
    c_turn = call(memory, "lm_turn_open", declared_agent="agent-c", declared_client="claude-code")
    c_claim = call(memory, "lm_work_claim", registration_id=c_turn["registration_id"], task=TASK)
    assert c_claim["status"] == "waiting" and c_claim["blocked_by"] == [b["claim"]["claim_id"]]
    again = call(memory, "lm_work_claim", registration_id=c_turn["registration_id"],
                 claim_id=c_claim["claim_id"])
    assert again["status"] == "waiting"

    # C records what it saw. The gap is signed and does not close B's turn.
    gap = call(memory, "lm_turn_gap", registration_id=b["turn"]["registration_id"])
    assert gap["gap_recorded"] is True and gap["receipt"]["reason"] == "terminal-receipt-missing"
    found = call(memory, "lm_turn_receipt_by_event", event_uid=b["event"]["event_uid"])
    assert found["turn"]["status"] == "open"
    assert found["turn"]["gap_receipt"]["receipt_id"] == gap["receipt"]["receipt_id"]
    assert call(memory, "lm_turn_coverage")["counts"]["unresolved"] == 2


def test_refusals(memory, tmp_path: Path) -> None:
    done = work(memory, "agent-a", "claude-code", "Result: 2")
    closed = done["turn"]["registration_id"]
    assert "already closed" in refused(memory, "lm_append_event", registration_id=closed,
                                       kind="task", summary="late")
    assert "open a turn first" in refused(memory, "lm_append_event",
                                          registration_id="sha256:" + "0" * 64, kind="task", summary="x")
    turn = call(memory, "lm_turn_open", declared_agent="agent-b")
    rid = turn["registration_id"]
    assert "reserved key" in refused(memory, "lm_append_event", registration_id=rid, kind="task",
                                     summary="x", details={lm.MARKER: {}})
    first = call(memory, "lm_append_event", registration_id=rid, kind="task", summary="one",
                 event_uid="client:fixed-uid-0001")
    again = call(memory, "lm_append_event", registration_id=rid, kind="task", summary="one",
                 event_uid="client:fixed-uid-0001")
    assert again["replayed"] is True and again["event_id"] == first["event_id"]
    assert "different content" in refused(memory, "lm_append_event", registration_id=rid,
                                          kind="task", summary="two", event_uid="client:fixed-uid-0001")
    claim = call(memory, "lm_work_claim", registration_id=rid, task=TASK)
    assert "written under this turn" in refused(
        memory, "lm_work_release", registration_id=rid, claim_id=claim["claim_id"],
        fence_token=claim["fence_token"], result_event_uid=done["event"]["event_uid"])
    assert "cannot be closed as no-event" in refused(memory, "lm_turn_close",
                                                     registration_id=rid, outcome="no-event")
    assert "invalid arguments" in refused(memory, "lm_turn_open", declared_agent="has space")
    assert "exactly one" in refused(memory, "lm_seed_recall")
    assert call(memory, "lm_turn_receipt_by_event",
                event_uid="client:does-not-exist")["outcome"] == "not_found"
    with pytest.raises(lm.LocalMemoryError, match="not an empty folder"):
        lm.LocalMemory.create(memory.home)


def test_capabilities_state_the_limits(memory) -> None:
    value = call(memory, "lm_capabilities")
    assert value["production_authority"] is False
    assert any("not verified" in item for item in value["limits"])
    assert any("no Action Log" in item for item in value["limits"])
    assert value["tools"] == [tool["name"] for tool in lm.TOOLS]
    listed = lm.dispatch(memory, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
    assert len(listed) == 11
    assert lm.dispatch(memory, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def rpc(process: subprocess.Popen, request_id: int, method: str, params: dict) -> dict:
    process.stdin.write((json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method,
                                     "params": params}) + "\n").encode("utf-8"))
    process.stdin.flush()
    return json.loads(process.stdout.readline())["result"]


def tool(process: subprocess.Popen, name: str, **arguments) -> dict:
    result = rpc(process, 7, "tools/call", {"name": name, "arguments": arguments})
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


ROOT = Path(__file__).resolve().parents[1]
NATIVE_HOOK = (ROOT / "components" / "integrity-client-memory" / "src" / "integrity_client_memory"
               / "resources" / "windows" / "admission-system.ps1")


def test_tool_names_are_not_the_names_of_the_core() -> None:
    """A Native lifecycle hook knows the core tools by name; these must be other names."""
    from integrity_guardian.memory_synapse_mcp import tools as core_tools

    names = [item["name"] for item in lm.TOOLS]
    assert len(names) == len(set(names)) == 11
    assert all(name.startswith("lm_") for name in names)
    assert not set(names) & {item["name"] for item in core_tools()}

    # Every pattern with which the published Windows hook recognises a tool by its name.
    source = NATIVE_HOOK.read_text(encoding="utf-8")
    patterns = sorted(set(re.findall(r"'(\(\?i\)[^'\n]*integrity_[^'\n]*)'", source)))
    assert len(patterns) >= 8, patterns
    for pattern in patterns:
        assert [name for name in names if re.search(pattern, name)] == [], pattern
    # A client shows a tool as server and name. The hook compares its patterns with the name
    # without the server, and only for a tool of its own server; that function is run in
    # components/integrity-client-memory/tests/test_windows_hook_tool_names.py. No pattern
    # matches the full name either, although the server is called integrity_local_memory.
    shown = ["mcp__integrity_local_memory__" + name for name in names]
    for pattern in patterns:
        assert [name for name in shown if re.search(pattern, name)] == [], pattern


def test_init_accepts_an_existing_empty_folder(tmp_path: Path, capsys) -> None:
    """docs/LOCAL_MEMORY.md: the folder "must be empty or missing" (an Explorer or mkdir folder)."""
    home = tmp_path / "made-by-hand"
    home.mkdir()                                      # inherits the parent's rules on Windows
    target = tmp_path / ".mcp.json"
    assert lm.main(["init", "--home", str(home), "--client", "claude-code",
                    "--write-mcp", str(target), "--json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["home"] == str(home.absolute()) and printed["written"] == str(target.absolute())
    assert target.read_bytes() == printed["config"].encode("utf-8")
    entry = json.loads(target.read_text(encoding="utf-8"))["mcpServers"]["integrity_local_memory"]
    assert entry["args"][-1] == str(home.absolute())
    if sys.platform == "win32":
        from integrity_guardian._windows_files import assert_private_directory_acl

        assert_private_directory_acl(home)            # protected, exact: account, SYSTEM, Administrators
    else:
        assert home.stat().st_mode & 0o777 == 0o700
    assert lm.main(["doctor", "--home", str(home)]) == 0
    # --write-mcp never overwrites, and a refusal happens before anything is created.
    other = tmp_path / "second"
    assert lm.main(["init", "--home", str(other), "--client", "claude-code",
                    "--write-mcp", str(target)]) == 2
    assert not other.exists()
    assert lm.main(["init", "--home", str(other), "--write-mcp", str(tmp_path / "x.json")]) == 2
    assert not other.exists()


def test_init_refusal_is_a_message_not_a_traceback(tmp_path: Path, capsys, monkeypatch) -> None:
    def boundary(path: Path) -> None:
        raise lm.WindowsFileBoundaryError("private Windows directory is owned by another account")

    monkeypatch.setattr(lm, "_private_folder", boundary)
    home = tmp_path / "foreign"
    home.mkdir()
    assert lm.main(["init", "--home", str(home)]) == 2
    error = capsys.readouterr().err
    assert error.startswith("guardian-local-memory: ") and "Traceback" not in error
    assert "owned by another account" in error and "no instance was created" in error
    assert list(home.iterdir()) == []


def test_command_line_and_two_server_processes(tmp_path: Path, capsys) -> None:
    home = tmp_path / "instance"
    assert lm.main(["doctor", "--home", str(home)]) == 1                 # nothing there yet
    assert lm.main(["init", "--home", str(home), "--client", "claude-code"]) == 0
    printed = capsys.readouterr().out
    block = json.loads(printed[printed.index("{"):])
    entry = block["mcpServers"]["integrity_local_memory"]
    assert entry["args"][-1] == str(home.absolute())
    codex = tomllib.loads(lm.client_config("codex", home))["mcp_servers"]["integrity_local_memory"]
    assert codex["command"] == entry["command"] and codex["args"] == entry["args"]
    # `codex exec` cannot ask a person, so the block approves the tools of this one server.
    assert codex["default_tools_approval_mode"] == "approve"
    assert lm.main(["init", "--home", str(home)]) == 2                   # never overwrites an instance

    # Each agent client starts its own server process on the same folder.
    def start() -> subprocess.Popen:
        return subprocess.Popen([entry["command"], *entry["args"]], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)

    writer, reader = start(), start()
    try:
        ready = rpc(writer, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
        assert ready["serverInfo"]["name"] == lm.SERVER_NAME and ready["protocolVersion"] == "2025-06-18"
        turn = tool(writer, "lm_turn_open", declared_agent="agent-a", declared_client="one")
        claim = tool(writer, "lm_work_claim", registration_id=turn["registration_id"], task=TASK)
        event = tool(writer, "lm_append_event", registration_id=turn["registration_id"],
                     kind="task", summary="Result: 2", task=TASK)
        tool(writer, "lm_work_release", registration_id=turn["registration_id"],
             claim_id=claim["claim_id"], fence_token=claim["fence_token"], result_event_uid=event["event_uid"])
        tool(writer, "lm_turn_close", registration_id=turn["registration_id"])
        found = tool(reader, "lm_turn_receipt_by_event", event_uid=event["event_uid"])
        assert found["turn"]["status"] == "closed" and found["author"]["declared_agent"] == "agent-a"
    finally:
        for process in (writer, reader):
            process.stdin.close()
            process.wait(timeout=30)
            process.stdout.close()

    capsys.readouterr()
    assert lm.main(["doctor", "--home", str(home), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {item["check"]: item["result"] for item in report["checks"]} == {
        "package": "ok", "instance": "ok", "events": "ok", "turns": "ok", "claims": "ok", "scope": "ok"}
    assert lm.main(["uninstall", "--home", str(home)]) == 0 and home.exists()      # dry run
    assert lm.main(["uninstall", "--home", str(home), "--yes"]) == 0 and not home.exists()
    other = tmp_path / "other"
    other.mkdir()
    (other / "instance.json").write_text("{}", encoding="utf-8")
    assert lm.main(["uninstall", "--home", str(other), "--yes"]) == 2 and other.exists()
