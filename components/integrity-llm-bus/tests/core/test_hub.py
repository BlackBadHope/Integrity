"""Hub (resources/core) tests: protocol checks, key rules, room rules, journal chain, replica, migration.

The hub daemon is imported in-process with a synthetic core.json and principals.json in a temporary
folder and its request function ``execute`` is called directly. No socket is opened; the unix-socket
handler (SO_PEERCRED) and the systemd sandbox are not exercised here. On Windows ``fcntl`` is replaced
by a no-op lock so the journal code can run; that stub is only used when the real module is missing.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import types
import uuid

import pytest

COMPONENT = Path(__file__).resolve().parents[2]
RESOURCES = COMPONENT / "src" / "integrity_llm_bus" / "resources"
CORE = RESOURCES / "core"

if "fcntl" not in sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:
        sys.modules["fcntl"] = types.SimpleNamespace(LOCK_EX=2, LOCK_UN=8, flock=lambda *_a: None)
if not hasattr(socketserver, "UnixStreamServer"):
    # only so the daemon's server class can be defined on Windows; no server is started in these tests
    socketserver.UnixStreamServer = socketserver.TCPServer

TOKENS = {name: f"test-token-{name}-{'x' * 8}" for name in (
    "claude-k", "grok-ro", "codex-k", "revoked-k", "hub-k", "owner-k", "human-k", "room-k", "seat-1", "seat-2", "no-acct", "secret-acct", "acct-r1")}


def _p(name, **kw):
    base = {"key_sha256": hashlib.sha256(TOKENS[name].encode()).hexdigest(), "account": "acct-a",
            "ops": ["send", "poll", "get", "ack", "status", "list-rooms"], "write": True, "rate_per_min": 30}
    base.update(kw)
    return base


@pytest.fixture(scope="module")
def hub():
    root = Path(tempfile.mkdtemp(prefix="integrity-llm-bus-hub-"))
    state = root / "state"
    state.mkdir()
    principals = {
        "claude-k": _p("claude-k", vendor="claude", addresses=["claude"]),
        "grok-ro": _p("grok-ro", vendor="grok", addresses=["grok"], write=False, ops=["send", "poll"]),
        "codex-k": _p("codex-k", vendor="codex", addresses=["codex"], rate_per_min=3),
        "revoked-k": _p("revoked-k", vendor="codex", addresses=["codexfc"], revoked=True),
        "hub-k": _p("hub-k", vendor="bus", role="hub", any_address=True, addresses=["codex"],
                    ops=["send", "poll", "changes", "registry"]),
        "owner-k": _p("owner-k", vendor="human", role="owner-console", addresses=["owner"],
                      ops=["send", "room-arbiter-set", "room-arbiter"]),
        "human-k": _p("human-k", vendor="human", addresses=["human-op"],
                      ops=["send", "poll", "room-arbiter", "room-arbiter-set"]),
        "room-k": _p("room-k", vendor="claude", addresses=["room-op-claude"], ops=["send", "poll"]),
        "seat-1": _p("seat-1", vendor="grok", addresses=["grok"], account="acct-s"),
        "seat-2": _p("seat-2", vendor="grok", addresses=["grok"], account="acct-s"),
        "no-acct": _p("no-acct", vendor="grok", addresses=["grok"], account=None),
        "secret-acct": _p("secret-acct", vendor="grok", addresses=["grok"], account="sk-" + "a" * 20),
        "acct-r1": _p("acct-r1", vendor="claude", addresses=["claude"], account="acct-r"),
    }
    (root / "principals.json").write_text(json.dumps({"principals": principals,
                                                      "accounts": {"acct-s": {"seats": 1}, "acct-r": {"rate_per_min": 2}}}), encoding="utf-8")
    (state / "room.json").write_text(json.dumps({
        "human": "human-op", "vendors": ["room-op-claude", "room-op-grok"],
        "arbiters": {"claude": {"address": "room-op-claude", "ro": "sandbox", "ro_verified": True},
                     "grok": {"address": "room-op-grok", "ro": "none", "ro_verified": False}}}), encoding="utf-8")
    conf = {"state_dir": str(state), "principals": str(root / "principals.json"), "journal_dir": str(root / "journal"),
            "socket": str(root / "core.sock"), "socket_group": "unused-in-tests", "ttl_hours": 24,
            "bus_dir": str(RESOURCES)}
    (root / "core.json").write_text(json.dumps(conf), encoding="utf-8")
    old = os.environ.get("BUS_CORE_CONF")
    os.environ["BUS_CORE_CONF"] = str(root / "core.json")
    try:
        spec = importlib.util.spec_from_file_location("bus_core_daemon_under_test", CORE / "bus_core_daemon.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        if old is None:
            os.environ.pop("BUS_CORE_CONF", None)
        else:
            os.environ["BUS_CORE_CONF"] = old
    mod.repl_setup()
    mod.TEST_ROOT = root
    yield mod


def call(hub, key, op, args):
    name, p = hub.principal_for({"token": TOKENS[key]}, None)
    return hub.execute(name, p, op, args)


def mid():
    return uuid.uuid4().hex[:16]


def send(hub, key, to, body="hello", **extra):
    return call(hub, key, "send", {"to": to, "id": mid(), "body": body, **extra})


def test_own_send_and_poll(hub):
    out = send(hub, "claude-k", "grok")
    assert out["duplicate"] is False and "body" not in out["message"]
    page = call(hub, "seat-1", "poll", {})
    assert any(item["from"] == "claude" for item in page["queue"])


def test_spoofed_sender_denied(hub):
    with pytest.raises(hub.Deny, match="not granted"):
        send(hub, "claude-k", "grok", **{"as": "codex"})


def test_other_queue_denied(hub):
    with pytest.raises(hub.Deny, match="not granted"):
        call(hub, "claude-k", "poll", {"as": "grok"})


def test_read_only_key_cannot_write(hub):
    with pytest.raises(hub.Deny, match="read-only key"):
        send(hub, "grok-ro", "claude")


def test_unknown_and_revoked_keys(hub):
    with pytest.raises(hub.Deny, match="unknown vendor key"):
        hub.principal_for({"token": "not-a-configured-token"}, None)
    with pytest.raises(hub.Deny, match="no key"):
        hub.principal_for({}, None)
    with pytest.raises(hub.Deny, match="revoked"):
        hub.principal_for({"token": TOKENS["revoked-k"]}, None)


def test_seat_limit(hub):
    hub.principal_for({"token": TOKENS["seat-1"]}, None)
    with pytest.raises(hub.Deny, match="seats limit"):
        hub.principal_for({"token": TOKENS["seat-2"]}, None)


def test_op_not_granted_and_role_only_ops(hub):
    with pytest.raises(hub.Deny, match="not granted"):
        call(hub, "grok-ro", "status", {"id": mid()})
    with pytest.raises(hub.Deny, match="not granted"):
        call(hub, "claude-k", "changes", {"since": 0})


def test_rate_limit(hub):
    for _ in range(3):
        call(hub, "codex-k", "poll", {})
    with pytest.raises(hub.Deny, match="rate limit"):
        call(hub, "codex-k", "poll", {})


@pytest.mark.parametrize("args,reason", [
    ({"to": "grok", "id": "x", "body": "b", "extra": 1}, "field not allowed"),
    ({"to": "grok", "body": "b"}, "missing field"),
    ({"to": "Grok!", "id": "abcdef0123456789", "body": "b"}, "bad address"),
    ({"to": "grok", "id": "abcdef0123456789", "body": 5}, "bad type"),
    ({"to": "grok", "id": "abcdef0123456789", "body": "b", "delivery": "shell"}, "bad delivery"),
])
def test_argument_whitelist(hub, args, reason):
    with pytest.raises(hub.Deny, match=reason):
        hub.check_args("send", args)


def test_account_labels(hub):
    with pytest.raises(hub.Deny, match="valid account label"):
        hub.principal_for({"token": TOKENS["no-acct"]}, None)
    with pytest.raises(hub.Deny, match="valid account label"):
        hub.principal_for({"token": TOKENS["secret-acct"]}, None)


def test_account_rate_limit_spans_keys(hub):
    for _ in range(2):
        call(hub, "acct-r1", "poll", {})
    with pytest.raises(hub.Deny, match="account acct-r: rate limit"):
        call(hub, "acct-r1", "poll", {})


@pytest.mark.parametrize("op,args,reason", [
    ("send", {"to": "../../etc/passwd", "id": "abcdef0123456789", "body": "x"}, "bad address"),
    ("get", {"id": "../../x"}, "bad id"),
    ("list-rooms", {"room": "../etc"}, "field not allowed"),
    ("send", {"to": "codex", "id": "abcdef0123456789", "body": "x" * 150000}, "body too large"),
    ("poll", {"limit": 51}, "limit 1..50"),
])
def test_paths_and_sizes_rejected(hub, op, args, reason):
    with pytest.raises(hub.Deny, match=reason):
        hub.check_args(op, args)


def test_script_like_body_is_stored_as_data(hub):
    body = "$(touch /tmp/should-not-exist); `id`; <script>x</script>"
    out = send(hub, "claude-k", "codex", body=body)
    with hub.STORE._connection() as db:
        stored = db.execute("SELECT body FROM messages WHERE id=?", (out["message"]["id"],)).fetchone()[0]
    assert stored == body


def test_unknown_op(hub):
    with pytest.raises(hub.Deny, match="unknown op"):
        hub.check_args("exec", {})


@pytest.mark.parametrize("raw,reason", [
    (b'{"v":1,"v":1}', "duplicate JSON key"),
    (b'{"v":NaN}', "bad constant"),
    (b'\xff\xfe', "invalid JSON"),
    (b'{"v":', "invalid JSON"),
])
def test_strict_json(hub, raw, reason):
    with pytest.raises(hub.Deny, match=reason):
        hub.strict_json(raw)


def test_owner_address_rules(hub):
    with pytest.raises(hub.Deny, match="not granted"):
        send(hub, "claude-k", "grok", **{"as": "owner"})
    # the owner-console key may act as owner, but an unsigned owner message fails the owner gate
    with pytest.raises(Exception) as caught:
        send(hub, "owner-k", "claude", body=json.dumps({"k": "go"}))
    assert not isinstance(caught.value, hub.Deny)


@pytest.mark.parametrize("address", ["owner", "human-op", "room-op-claude", "bus-relay"])
def test_hub_key_cannot_act_as_reserved(hub, address):
    with pytest.raises(hub.Deny, match="hub key may not act"):
        send(hub, "hub-k", "claude", **{"as": address})


def test_hub_key_may_act_as_registry_address(hub):
    assert send(hub, "hub-k", "claude", **{"as": "codexfc"})["message"]["from"] == "codexfc"


def test_room_rules(hub):
    arbiter = hub.STATE / "room-arbiter.json"
    if arbiter.exists():
        arbiter.unlink()
    with pytest.raises(hub.Deny, match="no room Arbiter selected"):
        send(hub, "human-k", "room-op-claude")
    assert send(hub, "human-k", "owner")["message"]["to"] == "owner"
    with pytest.raises(hub.Deny, match="read-only mechanism not verified"):
        call(hub, "human-k", "room-arbiter-set", {"vendor": "grok"})
    with pytest.raises(hub.Deny, match="unknown room Arbiter candidate"):
        call(hub, "human-k", "room-arbiter-set", {"vendor": "codex"})
    doc = call(hub, "human-k", "room-arbiter-set", {"vendor": "claude"})
    assert (doc["arbiter"], doc["set_by"]) == ("claude", "human-op")
    assert send(hub, "human-k", "room-op-claude")["message"]["to"] == "room-op-claude"
    with pytest.raises(hub.Deny, match="only to the selected room Arbiter"):
        send(hub, "human-k", "room-op-grok")
    with pytest.raises(hub.Deny, match="room Arbiter is chosen only"):
        hub.execute("claude-k", dict(hub.principals()["claude-k"], ops=["room-arbiter-set"]),
                    "room-arbiter-set", {"vendor": "claude"})


def test_room_acl_in_store(hub):
    import room_acl
    with pytest.raises(room_acl.RoomPolicyError):
        send(hub, "room-k", "claude")  # room vendors answer only the human-* address or the owner
    with pytest.raises(room_acl.RoomPolicyError):
        send(hub, "claude-k", "room-op-claude")  # only the human-* address or the owner writes to room vendors
    with pytest.raises(room_acl.RoomPolicyError):
        send(hub, "room-k", "human-op", body=json.dumps({"own": {"sig": "x"}}))
    assert send(hub, "room-k", "human-op")["message"]["to"] == "human-op"


def test_room_addresses_are_reserved(hub):
    import agent_registry
    for address in ("human-new", "room-new-vendor"):
        with pytest.raises(ValueError, match="reserved"):
            agent_registry.register(address, str(uuid.uuid4()), state_dir=hub.STATE)
    agent_registry.load(hub.STATE)  # the registry stays readable
    assert "room-op-claude" in agent_registry.all_agents(hub.STATE)


def test_journal_chain_and_tamper(hub, tmp_path):
    import bus_journal
    for i in range(3):
        bus_journal.append(str(tmp_path), {"verdict": "ok", "i": i})
    ok = bus_journal.verify(str(tmp_path))
    assert ok["ok"] and ok["records"] == 3
    path = next(tmp_path.glob("journal-*.jsonl"))
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1]); rec["verdict"] = "denied"; lines[1] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = bus_journal.verify(str(tmp_path))
    assert bad == {"ok": False, "file": path.name, "line": 2}


def test_changes_only_for_hub_and_apply_to_guarded_replica(hub, tmp_path):
    import bus_remote
    send(hub, "claude-k", "codex", body="replicated")
    chunk = call(hub, "hub-k", "changes", {"since": 0, "limit": 2000})
    assert chunk["changes"] and not chunk["more"]
    replica = tmp_path / "bus.sqlite3"
    src = sqlite3.connect(hub.STATE / "bus.sqlite3")
    dst = sqlite3.connect(replica)
    src.backup(dst)
    dst.execute("DELETE FROM messages"); dst.commit()
    src.close(); dst.close()
    bus_remote.install_guard(replica)
    with pytest.raises(sqlite3.OperationalError, match="bus_moved_to_core__use_bus_remote"):
        db = sqlite3.connect(replica)
        try:
            db.execute("INSERT INTO messages(id) VALUES ('x')")
        finally:
            db.close()
    cursor = bus_remote.apply(replica, chunk)
    assert cursor == chunk["cursor"] > 0
    db = sqlite3.connect(replica)
    try:
        bodies = {r[0] for r in db.execute("SELECT body FROM messages")}
    finally:
        db.close()
    assert "replicated" in bodies
    assert bus_remote.apply(replica, chunk) == cursor  # idempotent


def test_migrate_copies_and_verifies(hub, tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("bus_core_migrate_under_test", CORE / "migrate.py")
    migrate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migrate)
    src = sqlite3.connect(hub.STATE / "bus.sqlite3")
    copy = tmp_path / "source.sqlite3"
    dst = sqlite3.connect(copy)
    src.backup(dst)
    src.close(); dst.close()
    assert migrate.main(str(copy), str(tmp_path / "dest")) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] and report["tables"]["_archive_matches_messages"]
    assert migrate.main(str(copy), str(tmp_path / "dest")) == 2  # never overwrites a destination


def test_daemon_requires_configuration_before_serving(tmp_path):
    """Started as a program without the component configuration, the daemon refuses before any socket work."""
    env = {k: v for k, v in os.environ.items() if k not in ("INTEGRITY_LLM_BUS_CONFIG", "BUS_CORE_CONF")}
    env["PYTHONPATH"] = str(COMPONENT / "src")
    proc = subprocess.run([sys.executable, "-B", str(CORE / "bus_core_daemon.py")], env=env, cwd=str(tmp_path),
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0
    assert "unconfigured" in proc.stderr
