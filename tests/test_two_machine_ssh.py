"""Two machines over an OpenSSH forced command, reproduced on one Linux host.

Machine A (core) and machine B (client) get separate directories, keys and a
dedicated known_hosts. A non-root ``sshd`` on loopback stands in for the
network. The core runs the actual Guardian Memory MCP server from
``recovery_stdio_worker.py``: real NativeTrust, signatures, Seed catalog, HTTP
Action Log and witness; only the producer envelope is synthetic, so this is
not a live Codex/Claude acceptance. The same admission -> open -> append ->
close lifecycle runs once over local stdio and once through ``ssh`` and must
yield the same tool sequence, receipt shapes and append outcome.

Set INTEGRITY_REMOTE_E2E_REQUIRED=1 to turn a missing OpenSSH into a failure.
"""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid

import pytest

from integrity_guardian import memory_synapse_mcp as mcp
from recovery_stand_fixture import Stand

REQUIRED = os.environ.get("INTEGRITY_REMOTE_E2E_REQUIRED") == "1"
WORKER = Path(__file__).with_name("recovery_stdio_worker.py")
SERVE = """import os, sys, uuid
sessions, worker = sys.argv[1], sys.argv[2]
root = os.path.join(sessions, "session-" + uuid.uuid4().hex)
os.execv(sys.executable, [sys.executable, "-u", worker, root])
"""
PROBE = ("import json,os,sys;print(json.dumps({'argv':sys.argv[1:],"
         "'device':os.environ.get('INTEGRITY_REMOTE_DEVICE_ID'),"
         "'original':os.environ.get('SSH_ORIGINAL_COMMAND')}),flush=True)")


def _tool(name: str, *extra: str) -> str:
    found = shutil.which(name) or next((p for p in extra if os.access(p, os.X_OK)), None)
    if not found:
        message = f"OpenSSH {name} is not installed"
        if REQUIRED:
            pytest.fail(message)
        pytest.skip(message)
    return found


def _cli(*args: str) -> str:
    done = subprocess.run([sys.executable, "-m", "integrity_remote", *args],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout


def _keygen(keygen: str, path: Path, comment: str) -> str:
    subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
                   check=True, stdin=subprocess.DEVNULL)
    return path.with_suffix(".pub").read_text().split()[:2]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def machines(tmp_path_factory):
    if not sys.platform.startswith("linux"):
        pytest.skip("the core side is Linux-only")
    pytest.importorskip("integrity_remote")
    ssh, keygen = _tool("ssh"), _tool("ssh-keygen")
    sshd = _tool("sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd")
    base = tmp_path_factory.mktemp("two-machines")
    a, b = base / "machine-a", base / "machine-b"
    for folder in (a, b):
        folder.mkdir(mode=0o700)
    host_key = _keygen(keygen, a / "host_ed25519", "core-a-host")
    _keygen(keygen, b / "device_ed25519", "device-b")
    _keygen(keygen, b / "probe_ed25519", "device-b-probe")
    _keygen(keygen, b / "stranger_ed25519", "stranger")
    _keygen(keygen, b / "revoked_ed25519", "revoked")
    other_host = _keygen(keygen, b / "impostor_host_ed25519", "impostor")

    (a / "serve.py").write_text(SERVE)
    memory_spec, probe_spec = a / "memory-server.json", a / "probe-server.json"
    memory_spec.write_text(json.dumps({"argv": [sys.executable, "-u", str(a / "serve.py"),
                                                str(a / "sessions"), str(WORKER)]}))
    probe_spec.write_text(json.dumps({"argv": [sys.executable, "-c", PROBE, "{device_id}"]}))
    (a / "sessions").mkdir(mode=0o700)
    memory = json.loads(_cli("core", "init", "--root", str(a / "core"), "--server-json", str(memory_spec)))
    probe = json.loads(_cli("core", "init", "--root", str(a / "probe-core"), "--server-json", str(probe_spec)))
    lines = {
        "device": _cli("authorize", "--release", memory["release"], "--device-id", "laptop-b",
                       "--public-key", str(b / "device_ed25519.pub")),
        "probe": _cli("authorize", "--release", probe["release"], "--device-id", "laptop-b",
                      "--public-key", str(b / "probe_ed25519.pub")),
        "revoked": _cli("authorize", "--release", probe["release"], "--device-id", "old-laptop",
                        "--public-key", str(b / "revoked_ed25519.pub")),
    }
    authorized = a / "authorized_keys"
    authorized.write_text("".join(lines.values()))
    authorized.chmod(0o600)
    port = _free_port()
    config = a / "sshd_config"
    config.write_text("\n".join([
        f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {a / 'host_ed25519'}",
        f"PidFile {a / 'sshd.pid'}", f"AuthorizedKeysFile {authorized}",
        f"AllowUsers {getpass.getuser()}", "AuthenticationMethods publickey",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no",
        "PermitRootLogin no", "PermitUserEnvironment no", "StrictModes no", "LogLevel VERBOSE", ""]))
    log = open(a / "sshd.log", "wb")
    daemon = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], stdin=subprocess.DEVNULL,
                              stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 15
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if daemon.poll() is not None or time.monotonic() > deadline:
                log.close()
                pytest.fail("sshd did not start: " + (a / "sshd.log").read_text()[-2000:])
            time.sleep(0.1)
    known = b / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {' '.join(host_key)}\n")
    impostor = b / "impostor_known_hosts"
    impostor.write_text(f"[127.0.0.1]:{port} {' '.join(other_host)}\n")

    def upstream(identity: str, known_hosts: Path = known) -> list[str]:
        out = b / f"upstream-{identity}-{uuid.uuid4().hex[:6]}.json"
        _cli("client-upstream", "--host", "127.0.0.1", "--port", str(port), "--user", getpass.getuser(),
             "--identity", str(b / identity), "--known-hosts", str(known_hosts), "--ssh", ssh,
             "--output", str(out))
        spec = json.loads(out.read_text())
        return [spec["command"], *spec["args"]]

    try:
        yield {"a": a, "b": b, "upstream": upstream, "impostor": impostor, "authorized": authorized,
               "lines": lines, "memory_argv": json.loads(memory_spec.read_text())["argv"]}
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
        log.close()


def lifecycle(argv: list[str], label: str) -> dict:
    """Drive the real lifecycle over whatever stdio command ``argv`` starts."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    class Wire(Stand):
        def __init__(self):
            self.subject_thread = str(uuid.uuid4())
            self.admissions, self.wire, self.next_id = {}, [], 0

        def rpc(self, _facade, method, params):
            self.next_id += 1
            self.wire.append((method, params.get("name")))
            message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
            process.stdin.write(json.dumps(message).encode() + b"\n")
            process.stdin.flush()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(30), "bounded stdio response timed out"
            line = process.stdout.readline()
            assert line, process.stderr.read().decode(errors="replace")[-2000:]
            response = json.loads(line)
            assert response.get("id") == self.next_id and "error" not in response, response
            return response["result"]

    wire = Wire()
    try:
        replay, caps = wire.initialize(None)
        admission = wire.admit(None, 1, replay)
        opened = wire.tool(None, "integrity_turn_memory_open", wire.args)
        event = wire.append(None, admission, label)
        terminal = wire.close_turn(None, opened, event)
        process.stdin.close()
        process.wait(timeout=20)
        return {
            "returncode": process.returncode,
            "wire": wire.wire,
            "reservation": caps[mcp.CONTEXT_ADMISSION_REPLAY_CAPABILITY]["reservation_status"],
            "admission_keys": sorted(admission),
            "append": (event["receipt"]["outcome"], event["receipt"]["action_outcome"]),
            "append_keys": sorted(event["receipt"]),
            "terminal_keys": sorted(terminal["receipt"]),
            "terminal_bound": terminal["receipt"]["registration_id"] == opened["receipt"]["receipt_id"],
            "terminal_signature": terminal["receipt"]["signature"]["algorithm"],
        }
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()


def _events(session_root: Path) -> int:
    with sqlite3.connect((session_root / "stand-events.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
        return db.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def test_ssh_lifecycle_matches_local_stdio(machines, tmp_path):
    local_sessions = tmp_path / "local-sessions"
    local_sessions.mkdir(mode=0o700)
    argv = list(machines["memory_argv"])
    argv[3] = str(local_sessions)
    local = lifecycle(argv, "local")
    before = set((machines["a"] / "sessions").glob("session-*"))
    remote = lifecycle(machines["upstream"]("device_ed25519"), "remote")
    assert local["returncode"] == 0 and remote["returncode"] == 0
    assert remote == local
    assert local["append"] == ("created", "confirmed-success") and local["terminal_bound"]
    remote_roots = sorted(set((machines["a"] / "sessions").glob("session-*")) - before)
    assert len(remote_roots) == 1
    assert _events(remote_roots[0]) == _events(next(local_sessions.glob("session-*"))) == 2


def _ssh(machines, identity, *remote, known=None):
    argv = machines["upstream"](identity, **({"known_hosts": known} if known else {}))
    return subprocess.run([*argv, *remote], stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=60)


def test_requested_remote_command_is_ignored(machines):
    done = _ssh(machines, "probe_ed25519", "--", "--device", "evil;", "echo", "PWNED")
    assert done.returncode == 0, done.stderr
    assert "PWNED" not in done.stdout
    assert json.loads(done.stdout) == {"argv": ["laptop-b"], "device": "laptop-b", "original": None}


def test_unknown_key_is_denied(machines):
    done = _ssh(machines, "stranger_ed25519")
    assert done.returncode == 255 and done.stdout == ""


def test_changed_host_key_is_refused(machines):
    done = _ssh(machines, "probe_ed25519", known=machines["impostor"])
    assert done.returncode == 255 and done.stdout == ""
    assert "host key" in done.stderr.lower()


def test_removing_the_line_revokes_the_device(machines):
    before = _ssh(machines, "revoked_ed25519")
    assert before.returncode == 0 and json.loads(before.stdout)["device"] == "old-laptop"
    authorized = machines["authorized"]
    original = authorized.read_text()
    authorized.write_text(original.replace(machines["lines"]["revoked"], ""))
    try:
        after = _ssh(machines, "revoked_ed25519")
        assert after.returncode == 255 and after.stdout == ""
    finally:
        authorized.write_text(original)


def test_check_command_reaches_the_core_tools(machines):
    argv = machines["upstream"]("device_ed25519")
    upstream = machines["b"] / f"check-{uuid.uuid4().hex[:6]}.json"
    upstream.write_text(json.dumps({"command": argv[0], "args": argv[1:], "env": {}}))
    result = json.loads(subprocess.run([sys.executable, "-m", "integrity_remote", "check", str(upstream)],
                                       capture_output=True, text=True, timeout=120).stdout)
    assert result["ok"] is True and result["exit_code"] == 0
    assert {"integrity_context_admission", "integrity_append_event",
            "integrity_turn_memory_close"} <= set(result["tools"])
