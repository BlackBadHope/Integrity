"""Add the lab UI to the pinned owner hub using the official MCP wire server.

Existing hub definitions and dispatch are reused verbatim. This module does not
create an executor route, read its transcripts, or modify its operation ledger.
The hub's ordinary constructor retains its existing startup/schema behaviour.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, Tool

from .backend import Backend, private_path
from .seat_hub import SeatHubError, SeatNoteStore, dispatch_seat_tool
from .seat_hub import tool_definitions as seat_tool_definitions
from .server import create_server, http_app

UI_NAMES = frozenset({"integrity_projects", "integrity_project", "integrity_task",
                      "integrity_context", "integrity_source"})
HUB_FILES = frozenset({"host_hub.py", "host_node.py", "unified_mcp.py",
                       "claude_owner.py", "ping_pong.py", "unix_ws_stdio.py"})
SERIALIZED_WRITES = frozenset({"codex_send_prompt", "codex_interrupt_turn",
    "codex_archive_task", "codex_unarchive_task", "codex_copy_turn"})
WORKBENCH_INSTRUCTIONS = (
    "Existing owner memory and host routes retain their permissions and exact request IDs. "
    "Host writes require the owner's explicit instruction; reconcile unknown outcomes before any new send. "
    "The workbench reads explicitly enrolled hosts and existing task responses. "
    "It does not dispatch work or certify completion. Lab tools retain their own checks."
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seat_tool_error(code: str, status: int):
    return CallToolResult.model_validate({
        "content": [{"type": "text", "text": code}],
        "structuredContent": {"error": code, "status": status},
        "isError": True,
    })


def _optional_path(value) -> Path | None:
    if value is None or value == "":
        return None
    return Path(value)


class HubServer(MCPServer):
    """Public SDK list/call overrides; old business dispatch stays authoritative."""

    def __init__(self, *args, hub, core, **kwargs):
        self.hub, self.core = hub, core
        self._old_definitions = None
        self._definition_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._capacity = threading.BoundedSemaphore(8)
        self.seat_context = kwargs.pop("seat_context", None)
        self.seat_router = kwargs.pop("seat_router", None)
        self.notes = kwargs.pop("notes", None)
        self.mesh = kwargs.pop("mesh", None)
        self.bus = kwargs.pop("bus", None)
        super().__init__(*args, **kwargs)

    def request_seat(self):
        """Routes resolve the caller through SeatPolicyRouter when the server has one."""

        if self.seat_router is not None:
            return self.seat_router.resolve_request(now_utc=utc_now())
        return self.seat_context

    def mesh_state_for(self, name: str, arguments: dict):
        if name != "mesh_status" or self.mesh is None:
            return None
        work_id = arguments.get("work_id")
        if not isinstance(work_id, str):
            return None
        try:
            return self.mesh.status(work_id)
        except ValueError:
            return None

    def old_definitions(self):
        with self._definition_lock:
            if self._old_definitions is None:
                definitions = self.hub.definitions()
                names = [item["name"] for item in definitions]
                if len(set(names)) != len(names) or UI_NAMES.intersection(names):
                    raise ValueError("existing hub tool name collision")
                self._old_definitions = copy.deepcopy(definitions)
            return copy.deepcopy(self._old_definitions)

    async def list_tools(self):
        definitions = await anyio.to_thread.run_sync(self.old_definitions)
        seat_tools = [Tool.model_validate(item) for item in seat_tool_definitions()]
        return [Tool.model_validate(item) for item in definitions] + seat_tools + await super().list_tools()

    async def call_tool(self, name, arguments, context=None):
        if name in {item["name"] for item in seat_tool_definitions()}:
            try:
                seat = self.request_seat()
                payload = dispatch_seat_tool(
                    name,
                    arguments or {},
                    seat,
                    notes=self.notes,
                    mesh=self.mesh,
                    mesh_status=self.mesh_state_for(name, arguments or {}),
                    bus=self.bus,
                    router=self.seat_router,
                )
                return CallToolResult.model_validate({
                    "content": [{"type": "text", "text": json.dumps(payload)}],
                    "structuredContent": payload,
                })
            except SeatHubError as exc:
                return _seat_tool_error(exc.code, exc.status)
            except PermissionError as exc:
                code = getattr(exc, "code", None)
                if isinstance(code, str) and code:
                    return _seat_tool_error(code, int(getattr(exc, "status", 403)))
                raise
        if name in UI_NAMES:
            return await super().call_tool(name, arguments, context)
        definitions = await anyio.to_thread.run_sync(self.old_definitions)
        if name not in {item["name"] for item in definitions}:
            return await super().call_tool(name, arguments, context)
        # No rewriting of host/task/turn/request IDs, model choices or arguments.
        try:
            def dispatch():
                with self._capacity:
                    if name in SERIALIZED_WRITES:
                        with self._write_lock:
                            return self.hub.call(name, arguments)
                    return self.hub.call(name, arguments)
            result = await anyio.to_thread.run_sync(dispatch)
        except self.core.RpcError as exc:
            result = self.core.tool_error_result(exc)
        return CallToolResult.model_validate(result)


def load_hub(manifest_path: Path, config_path: Path):
    """Admit exact installed source bytes; paths never come from an MCP caller."""
    private_path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    directory = Path(manifest["directory"])
    members = manifest.get("files")
    if (not directory.is_absolute() or not isinstance(members, dict)
            or not HUB_FILES <= set(members) or not 6 <= len(members) <= 64
            or any(not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", name) is None
                   for name in members)):
        raise ValueError("invalid pinned hub manifest")
    private_path(directory, directory=True)
    if {path.name for path in directory.glob("*.py")} != set(members):
        raise ValueError("unpinned hub source present")
    for name, digest in members.items():
        path = directory / name
        if (not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or path.is_symlink() or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError("pinned hub source changed")
    private_path(config_path)
    sys.path.insert(0, str(directory))
    module = importlib.import_module("host_hub")
    if Path(module.__file__).resolve() != (directory / "host_hub.py").resolve():
        raise ValueError("wrong hub module loaded")
    for name in members:
        loaded = sys.modules.get(Path(name).stem)
        if loaded is not None and Path(loaded.__file__).resolve() != (directory / name).resolve():
            raise ValueError("wrong hub dependency loaded")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    hub = module.Hub(config)
    import host_node
    host_node.DISPATCH = module.BASE_CALL
    return hub, module.core


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--hub-manifest", required=True, type=Path)
    parser.add_argument("--hosts-config", type=Path,
                        default=os.environ.get("INTEGRITY_HOSTS_FILE"))
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument(
        "--server-name",
        default=None,
        help="advertised MCP server name; deprecated aliases are accepted",
    )
    parser.add_argument("--seat-registry", type=Path, default=os.environ.get("INTEGRITY_SEAT_REGISTRY"))
    parser.add_argument("--notes-db", type=Path, default=os.environ.get("INTEGRITY_SEAT_NOTES"))
    parser.add_argument("--mesh-db", type=Path, default=os.environ.get("INTEGRITY_MESH_DB"))
    parser.add_argument("--bus-db", type=Path, default=os.environ.get("INTEGRITY_BUS_DB"))
    return parser


def resolve_default_seat(registry_path: Path, *, now_utc: str | None = None):
    """Load the configured registry and resolve the process seat. Identity is not taken from tool arguments."""

    from integrity_home.seat_policy import SeatPolicyRouter
    from integrity_home.seat_registry import SeatRegistry

    path = Path(registry_path).expanduser().resolve()
    router = SeatPolicyRouter(SeatRegistry(path))
    context = router.resolve_request(now_utc=now_utc or utc_now())
    return router, context


def notes_path_for(registry_path: Path | None, notes_path: Path | None) -> Path | None:
    if notes_path is not None:
        return Path(notes_path)
    if registry_path is None:
        return None
    registry = Path(registry_path)
    return registry.with_name(registry.stem + "-notes.sqlite3")


def build_default_server(
    backend,
    hub,
    core,
    *,
    name: str,
    ui_mode: str,
    instructions: str,
    seat_registry: Path | None,
    now_utc: str | None = None,
    notes_path: Path | None = None,
    mesh_path: Path | None = None,
    bus_path: Path | None = None,
    notes: SeatNoteStore | None = None,
    mesh=None,
    bus=None,
):
    """The default workbench server. A configured seat registry is passed in as SeatContext."""

    router = None
    context = None
    if seat_registry is not None:
        router, context = resolve_default_seat(seat_registry, now_utc=now_utc)
    if notes is None:
        opened = notes_path_for(seat_registry, notes_path)
        if opened is not None:
            notes = SeatNoteStore(opened)
    if mesh is None and mesh_path is not None:
        from integrity_llm_bus.mesh import Mesh
        mesh = Mesh(Path(mesh_path))
    if bus is None and bus_path is not None:
        from integrity_llm_bus.bus_server import BusCore, BusError

        def reject_unresolved_token(_token: str):
            raise BusError("seat required", 401)

        bus = BusCore(Path(bus_path), reject_unresolved_token)
    return create_server(
        backend,
        server_factory=partial(
            HubServer,
            hub=hub,
            core=core,
            seat_context=context,
            seat_router=router,
            notes=notes,
            mesh=mesh,
            bus=bus,
        ),
        name=name,
        version="0.2.0",
        ui_mode=ui_mode,
        instructions=instructions,
    )


def _hosts_document(path: Path | None):
    if path is None:
        return None
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _seat_registry_path(args, hosts_document) -> Path | None:
    configured = _optional_path(args.seat_registry)
    if configured is not None:
        return configured
    if isinstance(hosts_document, dict) and isinstance(hosts_document.get("seat_registry"), str):
        raw = hosts_document["seat_registry"].strip()
        if raw:
            return Path(raw)
    return None


def main(*, workbench: bool = True):
    parser = argument_parser()
    args = parser.parse_args()
    if args.hosts_config is None:
        parser.error("existing owner hosts config required")
    os.umask(0o077)
    backend = Backend(args.config)
    backend.projects()  # Reject a private namespace before exposing any UI.
    hub, core = load_hub(args.hub_manifest, args.hosts_config)
    if workbench:
        from .workspace_backend import WorkspaceBackend
        backend = WorkspaceBackend(backend, hub)
    import warnings

    from integrity_bridges.server_names import SEATS_BRIDGE, ServerNameError, resolve_server_name

    hosts_document = _hosts_document(args.hosts_config)
    requested = args.server_name
    if (
        requested is None
        and isinstance(hosts_document, dict)
        and isinstance(hosts_document.get("server_name"), str)
    ):
        requested = hosts_document["server_name"]
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            server_name = resolve_server_name(requested, canonical=SEATS_BRIDGE)
    except ServerNameError as err:
        parser.error(str(err))
    for item in caught:
        print(item.message, file=sys.stderr)
    ui_mode = "workbench" if workbench else "lab"
    seat_registry = _seat_registry_path(args, hosts_document)
    seat_errors = ()
    if seat_registry is not None:
        from integrity_home.seat_policy import SeatAccessError
        seat_errors = (SeatAccessError,)
    try:
        server = build_default_server(
            backend,
            hub,
            core,
            name=server_name,
            ui_mode=ui_mode,
            instructions=WORKBENCH_INSTRUCTIONS,
            seat_registry=seat_registry,
            notes_path=_optional_path(args.notes_db),
            mesh_path=_optional_path(args.mesh_db),
            bus_path=_optional_path(args.bus_db),
        )
    except seat_errors as err:
        parser.error(err.code)
    if args.transport == "stdio":
        server.run()
    else:
        if args.token_file is None:
            parser.error("HTTP requires --token-file")
        import uvicorn
        uvicorn.run(http_app(server, backend, args.token_file, ui_mode=ui_mode),
                    host="127.0.0.1", port=args.port, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
