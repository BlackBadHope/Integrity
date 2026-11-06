"""Configured seats reach the default hub server, and seat tools persist what they claim."""
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import anyio
import pytest

from integrity_home.seat_policy import SeatPolicyRouter
from integrity_home.seat_registry import SeatRegistry
from integrity_home.seats_cli import main as seats_main
from integrity_llm_bus.bus_server import BusCore, BusSeat
from integrity_llm_bus.mesh import Mesh
from integrity_space import hub as hub_module
from integrity_space.hub import argument_parser, build_default_server
from integrity_space.seat_hub import SeatHubError, dispatch_seat_tool


def _utc(offset_seconds: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _configured_alice(tmp_path, monkeypatch):
    registry_path = tmp_path / "seats.sqlite3"
    registry = SeatRegistry(registry_path)
    registry.create_seat("alice", "Alice", ["read", "write"], ["team/*", "seat/alice/*"])
    issued = registry.issue_token("alice", "host-a", _utc(600))
    token = tmp_path / "seat.token"
    token.write_text(issued.token, encoding="utf-8")
    if os.name == "posix":
        os.chmod(token, 0o600)
    monkeypatch.setenv("INTEGRITY_SEAT_TOKEN_FILE", str(token))
    return registry_path, issued, token


def _server(tmp_path, registry_path, **kwargs):
    return build_default_server(
        object(),
        object(),
        object(),
        name="integrity-seats-bridge",
        ui_mode="workbench",
        instructions="test",
        seat_registry=registry_path,
        **kwargs,
    )


def test_default_server_with_seat_context_allows_configured_user(tmp_path, monkeypatch):
    registry_path, issued, token = _configured_alice(tmp_path, monkeypatch)
    server = _server(tmp_path, registry_path)
    assert server.seat_context.seat_id == "alice"
    assert server.seat_router is not None

    async def run():
        token.write_text("not-the-issued-token", encoding="utf-8")
        denied = await server.call_tool("seat_whoami", {})
        assert denied.is_error
        assert denied.structured_content["status"] == 401
        token.write_text(issued.token, encoding="utf-8")
        allowed = await server.call_tool("seat_whoami", {})
        assert not allowed.is_error
        assert allowed.structured_content["seat_id"] == "alice"
        assert allowed.structured_content["host_id"] == "host-a"
        noted = await server.call_tool("seat_append_note", {"note": "kept"})
        assert not noted.is_error
        assert noted.structured_content["stored"] is True
        assert noted.structured_content["namespace"] == "seat/alice/notes"

    anyio.run(run)
    connection = sqlite3.connect(server.notes.path)
    try:
        row = connection.execute("SELECT seat_id, namespace, note FROM seat_notes").fetchone()
    finally:
        connection.close()
    assert row == ("alice", "seat/alice/notes", "kept")
    assert server.notes.read(server.seat_context)[0]["note"] == "kept"
    server.notes.close()


def test_main_passes_seat_registry_into_the_default_server(tmp_path, monkeypatch):
    config = tmp_path / "space.json"
    manifest = tmp_path / "hub-manifest.json"
    hosts = tmp_path / "hosts.json"
    registry = tmp_path / "seats.sqlite3"
    config.write_text("{}", encoding="utf-8")
    manifest.write_text("{}", encoding="utf-8")
    hosts.write_text('{"server_name": "integrity-seats-bridge"}\n', encoding="utf-8")
    seen = {}

    class Backend:
        def __init__(self, path):
            self.path = path

        def projects(self):
            return {}

    class Server:
        def run(self):
            seen["ran"] = True

    monkeypatch.setattr(hub_module, "Backend", Backend)
    monkeypatch.setattr(hub_module, "load_hub", lambda *_args: (object(), object()))
    def fake_build(backend, hub, core, **kwargs):
        seen["seat_registry"] = kwargs["seat_registry"]
        seen["name"] = kwargs["name"]
        return Server()

    monkeypatch.setattr(hub_module, "build_default_server", fake_build)
    monkeypatch.setattr(sys, "argv", [
        "integrity-space-workbench",
        "--config", str(config),
        "--hub-manifest", str(manifest),
        "--hosts-config", str(hosts),
        "--seat-registry", str(registry),
    ])
    previous_umask = os.umask(0o022)
    os.umask(previous_umask)
    try:
        hub_module.main()
    finally:
        os.umask(previous_umask)
    assert seen["ran"] is True
    assert Path(seen["seat_registry"]) == registry
    assert seen["name"] == "integrity-seats-bridge"


def test_bus_post_forwards_body(tmp_path, monkeypatch):
    registry_path, _issued, _token = _configured_alice(tmp_path, monkeypatch)
    core = BusCore(tmp_path / "bus.sqlite3", lambda _token: None)
    core.register_agent(
        BusSeat("example-memory", "upstream", frozenset({"read"}), ("team/*",)),
        "example-memory",
    )
    server = _server(tmp_path, registry_path, bus=core)

    async def run():
        missing = await server.call_tool("bus_post_message", {"upstream_id": "example-memory"})
        assert missing.is_error
        assert missing.structured_content["error"] == "body invalid"
        posted = await server.call_tool(
            "bus_post_message",
            {"upstream_id": "example-memory", "body": "ping"},
        )
        assert not posted.is_error
        body = posted.structured_content
        assert body["delivery"] == "steer"
        assert body["payload"]["body"] == "ping"
        assert body["payload"]["delivery"] == "steer"
        assert body["upstream"] == "https://example.invalid/integrity-seats"
        return body["payload"]["id"]

    message_id = anyio.run(run)
    fetched = core.fetch(server.seat_context, message_id)
    assert fetched["body"] == "ping"
    assert fetched["to"] == "example-memory"
    core.close()
    server.notes.close()


def test_mesh_status_reads_recorded_state(tmp_path, monkeypatch):
    registry_path, _issued, _token = _configured_alice(tmp_path, monkeypatch)
    mesh = Mesh(tmp_path / "mesh.sqlite3")
    mesh.open("alice", "work-1", "shared", "team/work", now=datetime.now(timezone.utc))
    server = _server(tmp_path, registry_path, mesh=mesh)
    direct = dispatch_seat_tool(
        "mesh_status",
        {"work_id": "work-1"},
        server.seat_context,
        mesh=mesh,
        router=SeatPolicyRouter(SeatRegistry(registry_path)),
    )
    assert direct["state"] == "open"
    assert direct["work_id"] == "work-1"

    async def run():
        result = await server.call_tool("mesh_status", {"work_id": "work-1"})
        assert not result.is_error
        assert result.structured_content["state"] == "open"
        missing = await server.call_tool("mesh_status", {"work_id": "missing-work"})
        assert missing.is_error
        assert missing.structured_content["error"] == "work unknown"

    anyio.run(run)
    mesh.close()
    server.notes.close()


def test_note_without_a_store_does_not_claim_success(tmp_path):
    registry = SeatRegistry(tmp_path / "seats.sqlite3")
    registry.create_seat("alice", "Alice", ["read", "write"], ["team/*", "seat/alice/*"])
    context = SeatPolicyRouter(registry).resolve_token(
        registry.issue_token("alice", "host-a", _utc(600)).token,
        now_utc=_utc(0),
    )
    with pytest.raises(SeatHubError) as missing:
        dispatch_seat_tool("seat_append_note", {"note": "nope"}, context)
    assert missing.value.status == 503
    assert missing.value.code == "note store unavailable"


def test_quickstart_puts_global_args_before_init(tmp_path):
    registry = tmp_path / "seat-registry.sqlite3"
    root = tmp_path / "core"
    assert seats_main([
        "--registry", str(registry),
        "--isolation-mode", "shared-core",
        "init",
        "--root", str(root),
    ]) == 0
    assert (root / "isolation-mode.json").is_file()
    with pytest.raises(SystemExit):
        seats_main([
            "init",
            "--registry", str(registry),
            "--root", str(root),
            "--isolation-mode", "shared-core",
        ])


def test_codex_hub_example_includes_required_args():
    args = argument_parser().parse_args([
        "--config", "/absolute/path/space-config.json",
        "--hub-manifest", "/absolute/path/hub-manifest.json",
        "--hosts-config", "/absolute/path/hosts.json",
        "--seat-registry", "/absolute/path/seat-registry.sqlite3",
    ])
    assert args.config == Path("/absolute/path/space-config.json")
    assert args.hub_manifest == Path("/absolute/path/hub-manifest.json")
    assert args.hosts_config == Path("/absolute/path/hosts.json")
    with pytest.raises(SystemExit):
        argument_parser().parse_args([])
