"""Synthetic HumanX configuration in a temporary folder: no real homes, no network, no real bus.

The resources read their configuration at import time, so the whole session shares one synthetic tree.
Every address and name below is invented (documentation IP ranges, example.invalid).
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import types
import uuid
from pathlib import Path

import pytest

COMPONENT = Path(__file__).resolve().parents[1]
RESOURCES = COMPONENT / "src" / "integrity_humanx" / "resources"
ROOT = Path(tempfile.mkdtemp(prefix="humanx-test-"))
OPERATOR = "operator"
GW_UID, WEB_UID, OTHER_UID = 51001, 51002, 51003


def _write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data, encoding="utf-8")
    return path


def make_replica(path: Path) -> Path:
    db = sqlite3.connect(str(path))
    db.execute("CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT, sender TEXT, recipient TEXT, "
               "body TEXT, reply_to TEXT, status TEXT, created_at INTEGER, expires_at INTEGER, acked_at INTEGER)")
    db.commit()
    db.close()
    return path


def put_message(replica: Path, mid, sender, recipient, body="Вопрос оператора", age_s=0, status="pending", reply_to=None):
    db = sqlite3.connect(str(replica), timeout=10)
    now = int(time.time())
    db.execute("INSERT INTO messages(id,sender,recipient,body,reply_to,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
               (mid, sender, recipient, body, reply_to, status, now - int(age_s), now + 86400))
    db.commit()
    db.close()


RING_MAP = {
    "source": "invented test map",
    "cores": ["192.0.2.1", "192.0.2.2"],
    "not_polled": [{"ring": "300", "core": "192.0.2.3"}],
    "access_prefix": "198.51",
    "rings": [
        {"ring": "100", "core": "192.0.2.1", "ports": [1, 2], "class": "A"},
        {"ring": "101", "core": "192.0.2.1", "ports": [3], "class": "B"},
        {"ring": "200", "core": "192.0.2.2", "ports": [5, 6], "class": "A"},
    ],
}


def _build_tree():
    state = ROOT / "web-state"
    state.mkdir()
    token = ROOT / "web-token"
    token.write_text("t-" + uuid.uuid4().hex[:6], encoding="utf-8")   # built at run time, never a real value
    ro = ROOT / "ro"
    ro.mkdir()
    values = {
        "operator_id": OPERATOR,
        "python": sys.executable,
        "bus_replica": str(make_replica(ROOT / "bus.sqlite3")),
        "antigravity_wake_dir": str(ROOT / "no-antigravity"),
        "hosts_file": str(_write(ROOT / "hosts.json", {"jump": "jump-alias", "hosts": {
            "node-a": {"dest": "reader@192.0.2.21", "jump": True}, "core": {"dest": "core-alias", "jump": False}}})),
        "host_ssh_key": str(ROOT / "no-key"),
        "ssh_config": str(ROOT / "no-ssh-config"),
        "web_url": "http://web.example.invalid:8890",
        "host_label": "client-a",
        "integrity_mcp_server": "integrity-memory",
        "antigravity_steps_root": str(ROOT / "steps"),
        "antigravity_language_server": str(ROOT / "no-language-server"),
        "web_config": str(_write(ROOT / "web-config.json", {"bind": "127.0.0.1", "port": 0, "allow": ["192.0.2.40"],
                                                            "socket": str(ROOT / "no-bus.sock"), "token_file": str(token)})),
        "web_state_dir": str(state),
        "ring_map_file": str(_write(ROOT / "ring-map.json", RING_MAP)),
        "ro_gateway_socket": str(ROOT / "no-gw.sock"),
        "ro_gateway_config": str(_write(ROOT / "gw-config.json", {
            "socket": str(ro / "gw.sock"), "socket_group": "gw-sock", "gateway_user": "gw-user", "web_user": "web-user",
            "vendors": ["claude", "codex", "gemini", "grok"], "mysql": str(ro / "no-mariadb"),
            "mysql_defaults_file": str(ro / "my.cnf"), "integrity_snapshot": str(ro / "seed.sqlite3"), "log": str(ro / "gw.jsonl"),
            "switch_nets": ["198.51.100.0/24"], "switch_cred": str(ro / "switch.cred"), "sw_share_off": str(ro / "sw-share.off"),
            "web_rings_ips": ["192.0.2.1", "192.0.2.2"], "web_rings_off": str(ro / "web-rings.off"),
            "web_storm_off": str(ro / "web-storm.off"), "storm_key": str(ro / "no-storm-key"),
            "storm_known_hosts": str(ro / "known_hosts"), "storm_host": "reader@192.0.2.50"})),
        "integrity_action_log": str(ROOT / "no-action-log.sqlite3"),
        "ro_integrity_snapshot": str(ro / "seed.sqlite3"),
        "ro_group": "gw-sock",
    }
    cfg = _write(ROOT / "configuration.json", {
        "schema": "integrity/component-config/v1", "component": "integrity-humanx", "configured": True,
        "guardian_version": "6.1.0", "memory_api_version": "2.11.0", "owner_local_catalogue": None, "values": values})
    os.environ["INTEGRITY_HUMANX_CONFIG"] = str(cfg)
    for name in ("BUS_REPLICA", "HUMANX_WEB", "HUMANX_BUS_DIR", "HUMANX_RINGS_FIXTURES", "HUMANX_STORM_FIXTURES",
                 "HUMANX_SHARED_DIR", "HUMANX_MR_DIR", "STATE_DIRECTORY"):
        os.environ.pop(name, None)
    for sub in ("client", "web", "ro"):
        p = str(RESOURCES / sub)
        if p not in sys.path:
            sys.path.insert(0, p)
    return values


VALUES = _build_tree()


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(ROOT, ignore_errors=True)


@pytest.fixture(scope="session")
def values():
    return VALUES


@pytest.fixture(scope="session")
def operator():
    return "human-" + OPERATOR


def room_addr(vendor):
    return "room-%s-%s" % (OPERATOR, vendor)


def new_room(tmp_path: Path, vendor="claude", ssh="no-such-ssh-binary") -> Path:
    """A room folder from the room template: room_tool.py + room.json beside it (ssh that cannot start)."""
    d = tmp_path / ("room-" + vendor)
    (d / "work").mkdir(parents=True)
    (d / "journal").mkdir()
    shutil.copy(RESOURCES / "room" / "room_tool.py", d / "room_tool.py")
    _write(d / "room.json", {"mode": "core", "address": room_addr(vendor), "ssh": str(tmp_path / ssh), "ssh_args": [],
                             "dest": "bus@192.0.2.10", "key": str(tmp_path / "no-key")})
    return d


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def hx():
    """Helpers for the test modules (they are imported with --import-mode=importlib, so no 'from conftest import')."""
    return types.SimpleNamespace(ROOT=ROOT, RESOURCES=RESOURCES, OPERATOR=OPERATOR, HUMAN="human-" + OPERATOR,
                                 RING_MAP=RING_MAP, GW_UID=GW_UID, WEB_UID=WEB_UID, OTHER_UID=OTHER_UID, VALUES=VALUES,
                                 room_addr=room_addr, new_room=new_room, load_module=load_module,
                                 put_message=put_message, make_replica=make_replica)


@pytest.fixture(scope="session")
def gateway():
    """humanx_ro_gw with fake pwd/grp (the gateway is Linux-only; the fakes keep the test identical on every platform)."""
    pwd_fake = types.SimpleNamespace(getpwnam=lambda n: types.SimpleNamespace(pw_uid={"gw-user": GW_UID, "web-user": WEB_UID}[n]))
    grp_fake = types.SimpleNamespace(getgrnam=lambda n: types.SimpleNamespace(gr_gid=51010))
    saved = {k: sys.modules.get(k) for k in ("pwd", "grp")}
    sys.modules["pwd"], sys.modules["grp"] = pwd_fake, grp_fake
    import socket
    import socketserver
    shims = []
    if not hasattr(socketserver, "UnixStreamServer"):      # Windows: class definition only; no server is started in tests
        socketserver.UnixStreamServer = socketserver.TCPServer
        shims.append((socketserver, "UnixStreamServer"))
    if not hasattr(socket, "SO_PEERCRED"):                 # Windows: the fake connection ignores the option number
        socket.SO_PEERCRED = 17
        shims.append((socket, "SO_PEERCRED"))
    try:
        mod = load_module("humanx_ro_gw", RESOURCES / "ro" / "humanx_ro_gw.py")
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    yield mod
    for owner, name in shims:
        delattr(owner, name)
