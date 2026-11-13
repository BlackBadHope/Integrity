# SPDX-License-Identifier: BUSL-1.1
"""Local memory profile: three agents on one machine, read back from memory alone."""
from __future__ import annotations

import json
import subprocess
import sys
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
    turn = call(memory, "integrity_turn_memory_open", declared_agent=agent, declared_client=client,
                declared_machine="machine-one", intent=f"{agent}: work on {TASK}")
    claim = call(memory, "integrity_work_claim", registration_id=turn["registration_id"], task=TASK)
    assert claim["status"] == "acquired"
    event = call(memory, "integrity_append_event", registration_id=turn["registration_id"],
                 kind="task", summary=result, task=TASK, details={"value": result})
    if finish:
        call(memory, "integrity_work_release", registration_id=turn["registration_id"],
             claim_id=claim["claim_id"], fence_token=claim["fence_token"],
             result_event_uid=event["event_uid"])
        call(memory, "integrity_turn_memory_close", registration_id=turn["registration_id"])
    return {"turn": turn, "claim": claim, "event": event}


def test_c_reads_what_b_wrote_claimed_and_how_b_closed(memory) -> None:
    a = work(memory, "agent-a", "claude-code", "Result: 2")
    b = work(memory, "agent-b", "codex", "Result: X")

    # C never calls B. It reads the task, then asks about B's event.
    events = call(memory, "integrity_seed_recall", task=TASK)["events"]
    assert [(item["actor"], item["summary"]) for item in events] == [
        ("agent-a", "Result: 2"), ("agent-b", "Result: X")]
    found = call(memory, "integrity_turn_receipt_by_event", event_uid=events[1]["event_uid"])

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

    log = call(memory, "integrity_work_claims", task=TASK)
    assert log["chain_events_verified"] == 4 and log["signed"] is False
    assert a["claim"]["fence_token"] == 1
    assert call(memory, "integrity_turn_memory_coverage")["counts"]["unresolved"] == 0


def test_c_sees_that_b_broke_off_without_closing(memory) -> None:
    work(memory, "agent-a", "claude-code", "Result: 2")
    b = work(memory, "agent-b", "codex", "Result: X", finish=False)

    found = call(memory, "integrity_turn_receipt_by_event", event_uid=b["event"]["event_uid"])
    assert found["event"]["summary"] == "Result: X"
    assert found["turn"]["status"] == "open"
    assert found["turn"]["terminal_receipt"] is None and found["turn"]["gap_receipt"] is None
    assert "never closed" in found["turn"]["note"]
    assert [item["kind"] for item in found["claims"]] == ["claim-acquired"]   # still held, never released

    # C's own claim waits behind B's unreleased claim, and names it.
    c_turn = call(memory, "integrity_turn_memory_open", declared_agent="agent-c", declared_client="claude-code")
    c_claim = call(memory, "integrity_work_claim", registration_id=c_turn["registration_id"], task=TASK)
    assert c_claim["status"] == "waiting" and c_claim["blocked_by"] == [b["claim"]["claim_id"]]
    again = call(memory, "integrity_work_claim", registration_id=c_turn["registration_id"],
                 claim_id=c_claim["claim_id"])
    assert again["status"] == "waiting"

    # C records what it saw. The gap is signed and does not close B's turn.
    gap = call(memory, "integrity_turn_memory_gap", registration_id=b["turn"]["registration_id"])
    assert gap["gap_recorded"] is True and gap["receipt"]["reason"] == "terminal-receipt-missing"
    found = call(memory, "integrity_turn_receipt_by_event", event_uid=b["event"]["event_uid"])
    assert found["turn"]["status"] == "open"
    assert found["turn"]["gap_receipt"]["receipt_id"] == gap["receipt"]["receipt_id"]
    assert call(memory, "integrity_turn_memory_coverage")["counts"]["unresolved"] == 2


def test_refusals(memory, tmp_path: Path) -> None:
    done = work(memory, "agent-a", "claude-code", "Result: 2")
    closed = done["turn"]["registration_id"]
    assert "already closed" in refused(memory, "integrity_append_event", registration_id=closed,
                                       kind="task", summary="late")
    assert "open a turn first" in refused(memory, "integrity_append_event",
                                          registration_id="sha256:" + "0" * 64, kind="task", summary="x")
    turn = call(memory, "integrity_turn_memory_open", declared_agent="agent-b")
    rid = turn["registration_id"]
    assert "reserved key" in refused(memory, "integrity_append_event", registration_id=rid, kind="task",
                                     summary="x", details={lm.MARKER: {}})
    first = call(memory, "integrity_append_event", registration_id=rid, kind="task", summary="one",
                 event_uid="client:fixed-uid-0001")
    again = call(memory, "integrity_append_event", registration_id=rid, kind="task", summary="one",
                 event_uid="client:fixed-uid-0001")
    assert again["replayed"] is True and again["event_id"] == first["event_id"]
    assert "different content" in refused(memory, "integrity_append_event", registration_id=rid,
                                          kind="task", summary="two", event_uid="client:fixed-uid-0001")
    claim = call(memory, "integrity_work_claim", registration_id=rid, task=TASK)
    assert "written under this turn" in refused(
        memory, "integrity_work_release", registration_id=rid, claim_id=claim["claim_id"],
        fence_token=claim["fence_token"], result_event_uid=done["event"]["event_uid"])
    assert "cannot be closed as no-event" in refused(memory, "integrity_turn_memory_close",
                                                     registration_id=rid, outcome="no-event")
    assert "invalid arguments" in refused(memory, "integrity_turn_memory_open", declared_agent="has space")
    assert "exactly one" in refused(memory, "integrity_seed_recall")
    assert call(memory, "integrity_turn_receipt_by_event",
                event_uid="client:does-not-exist")["outcome"] == "not_found"
    with pytest.raises(lm.LocalMemoryError, match="not an empty folder"):
        lm.LocalMemory.create(memory.home)


def test_capabilities_state_the_limits(memory) -> None:
    value = call(memory, "integrity_memory_capabilities")
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


def test_command_line_and_two_server_processes(tmp_path: Path, capsys) -> None:
    home = tmp_path / "instance"
    assert lm.main(["doctor", "--home", str(home)]) == 1                 # nothing there yet
    assert lm.main(["init", "--home", str(home), "--client", "claude-code"]) == 0
    printed = capsys.readouterr().out
    block = json.loads(printed[printed.index("{"):])
    entry = block["mcpServers"]["integrity_local_memory"]
    assert entry["args"][-1] == str(home.absolute())
    assert "mcp_servers.integrity_local_memory" in lm.client_config("codex", home)
    assert lm.main(["init", "--home", str(home)]) == 2                   # never overwrites an instance

    # Each agent client starts its own server process on the same folder.
    def start() -> subprocess.Popen:
        return subprocess.Popen([entry["command"], *entry["args"]], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)

    writer, reader = start(), start()
    try:
        ready = rpc(writer, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
        assert ready["serverInfo"]["name"] == lm.SERVER_NAME and ready["protocolVersion"] == "2025-06-18"
        turn = tool(writer, "integrity_turn_memory_open", declared_agent="agent-a", declared_client="one")
        claim = tool(writer, "integrity_work_claim", registration_id=turn["registration_id"], task=TASK)
        event = tool(writer, "integrity_append_event", registration_id=turn["registration_id"],
                     kind="task", summary="Result: 2", task=TASK)
        tool(writer, "integrity_work_release", registration_id=turn["registration_id"],
             claim_id=claim["claim_id"], fence_token=claim["fence_token"], result_event_uid=event["event_uid"])
        tool(writer, "integrity_turn_memory_close", registration_id=turn["registration_id"])
        found = tool(reader, "integrity_turn_receipt_by_event", event_uid=event["event_uid"])
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
