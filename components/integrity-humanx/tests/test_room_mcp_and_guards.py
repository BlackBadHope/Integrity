"""Codex room MCP server and the two read-only hooks (room_ro_guard, vendor_room_guard)."""
import json
import os
import uuid

import pytest


@pytest.fixture
def mcp(hx, monkeypatch):
    m = hx.load_module("mcp_" + uuid.uuid4().hex[:8], hx.RESOURCES / "room" / "humanx_room_ro_mcp.py")
    seen = []
    monkeypatch.setattr(m, "run_room_tool", lambda op, a: (seen.append((op, a)) or json.dumps({"op": op, "args": a}, ensure_ascii=False)))
    return m, seen


def call(m, name, arguments):
    return m.handle_request({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments}})


def test_mcp_initialize_and_list(mcp):
    m, _ = mcp
    assert m.handle_request({"id": 1, "method": "initialize"})["result"]["serverInfo"]["name"] == "humanx-room-ro"
    names = {t["name"] for t in m.handle_request({"id": 2, "method": "tools/list"})["result"]["tools"]}
    assert {"room_sql", "room_switch", "room_host", "room_integrity", "room_reply", "room_escalate"} <= names
    assert m.handle_request({"id": 3, "method": "notifications/initialized"}) is None
    assert m.handle_request({"id": 4, "method": "nope"})["error"]["code"] == -32601


def test_mcp_maps_tools_to_room_tool_ops(mcp):
    m, seen = mcp
    call(m, "room_switch", {"ip": "198.51.100.5", "cmd": "show switch"})
    call(m, "room_host", {"host": "node-a", "cmd": "status unit-a"})
    call(m, "room_reply", {"reply_to": "00000000-0000-4000-8000-000000000001", "topic": "Тема: Кольцо", "body": "Тема: Кольцо\nтекст"})
    assert seen[0] == ("switch", {"ip": "198.51.100.5", "cmds": ["show switch"]})
    assert seen[1] == ("host", {"host": "node-a", "op": "status", "args": ["unit-a"]})
    assert seen[2][0] == "reply" and seen[2][1]["body"] == "Тема: Кольцо\nтекст"
    r = call(m, "room_reply", {"topic": "x", "body": "y"})
    assert "reply_to обязателен" in r["result"]["content"][0]["text"] and len(seen) == 3
    assert call(m, "room_write", {})["error"]["code"] == -32601


@pytest.fixture
def guard(hx):
    return hx.load_module("guard_" + uuid.uuid4().hex[:8], hx.RESOURCES / "room" / "room_ro_guard.py")


def test_room_guard_integrity_tools_use_configured_server(guard, hx):
    server = hx.VALUES["integrity_mcp_server"]
    assert guard.INTEGRITY_OK == {"mcp__%s__integrity_context_admission_current_turn" % server,
                                  "mcp__%s__integrity_turn_memory_close" % server}


def test_room_guard_decisions(guard):
    room = guard.ROOM
    assert guard.decide("Bash", {"command": "python -I room_tool.py sql work/q.json"})[0]
    assert not guard.decide("Bash", {"command": "python -I room_tool.py sql work/q.json; rm -rf x"})[0]
    assert not guard.decide("Bash", {"command": "python -I room_tool.py poll", "run_in_background": True})[0]
    assert guard.decide("Read", {"file_path": os.path.join(room, "room_tool.py")})[0]
    assert not guard.decide("Read", {"file_path": os.path.join(room, "..", "conf.json")})[0]
    assert guard.decide("Write", {"file_path": os.path.join(room, "work", "a.json")})[0]
    assert not guard.decide("Write", {"file_path": os.path.join(room, "room.json")})[0]
    assert not guard.decide("Grep", {"path": room, "pattern": "../x"})[0]
    assert not guard.decide("WebFetch", {"url": "http://web.example.invalid/"})[0]


def test_vendor_guard_reads_configuration(hx):
    g = hx.load_module("vguard_" + uuid.uuid4().hex[:8], hx.RESOURCES / "client" / "vendor_room_guard.py")
    assert g.SYS_STEPS_ROOT == hx.VALUES["antigravity_steps_root"] and g.ROOM_PY == hx.VALUES["python"]
