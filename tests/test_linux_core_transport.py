"""Static and behavioural checks for the Linux core release wrapper and transport.

The files under ``deploy/linux-core`` are shipped as they run on a Linux core
host. Static checks run everywhere. Behaviour that needs a POSIX shell, POSIX
file modes or Linux pidfds is skipped elsewhere.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "deploy" / "linux-core"

SHELL_SCRIPTS = (
    "transport/run-mcp",
    "transport/run-mcp-child",
    "transport/verify-release",
    "release/run-mcp",
    "release/provision-state",
    "release/refresh-seed-read-acl",
    "host/integrity-custody-full-verify",
    "host/integrity-memory-mcp",
)
PYTHON_SCRIPTS = (
    "transport/transport-supervisor.py",
    "release/action-log-passive-witness",
    "release/verify-release",
    "host/integrity-seed-wal-holder",
)
OTHER_FILES = ("release/action-log-witness.sudoers.in",)
ALL_FILES = SHELL_SCRIPTS + PYTHON_SCRIPTS + OTHER_FILES
PLACEHOLDERS = {
    "@FACADE_RELEASE_DIR@",
    "@ACTION_LOG_WITNESS_HELPER@",
    "@DEPLOYMENT_PROFILE_SHA256@",
    "@MEMORY_RELEASE_DIR@",
    "@ACTION_LOG_WITNESS@",
    "@FACADE_RUN_MCP_SHA256@",
}

POSIX = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX shell and file modes")
LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux pidfd/prctl")

HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _load(relative: str, name: str):
    path = CORE / relative
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _text(relative: str) -> str:
    return (CORE / relative).read_bytes().decode("utf-8")


# --- static checks (all platforms) -------------------------------------------------


def test_every_listed_file_exists_and_nothing_unlisted():
    present = {p.relative_to(CORE).as_posix() for p in CORE.rglob("*") if p.is_file()}
    assert present == set(ALL_FILES) | {"README.md"}


@pytest.mark.parametrize("relative", ALL_FILES + ("README.md",))
def test_lf_utf8_and_no_bom(relative):
    data = (CORE / relative).read_bytes()
    assert b"\r" not in data
    assert not data.startswith(b"\xef\xbb\xbf")
    data.decode("utf-8")


@pytest.mark.parametrize("relative", SHELL_SCRIPTS)
def test_shell_scripts_have_sh_shebang_and_strict_mode(relative):
    lines = _text(relative).split("\n")
    assert lines[0] == "#!/bin/sh"
    assert lines[1] == "set -eu"


@pytest.mark.parametrize("relative", PYTHON_SCRIPTS)
def test_python_scripts_compile(relative):
    compile(_text(relative), relative, "exec")


@pytest.mark.parametrize("relative", PYTHON_SCRIPTS[1:])
def test_executable_python_scripts_have_python_shebang(relative):
    assert _text(relative).split("\n")[0].startswith("#!/usr/bin/python3")


def test_transport_supervisor_is_run_by_interpreter_not_shebang():
    # transport/run-mcp runs it with an explicit isolated interpreter.
    assert not _text("transport/transport-supervisor.py").startswith("#!")
    assert 'python3 -I "$SCRIPT_DIR/transport-supervisor.py" "$SCRIPT_DIR/run-mcp-child"' in _text(
        "transport/run-mcp"
    )


@pytest.mark.parametrize("relative", ALL_FILES)
def test_no_release_digest_paths_or_ipv4(relative):
    text = _text(relative)
    assert re.search(r"/releases/[0-9a-f]{64}", text) is None
    # The only 64-hex run allowed is the all-zero health-probe request digest.
    assert {m for m in HEX64.findall(text) if set(m) != {"0"}} == set()
    assert IPV4.findall(text) == []


def test_placeholders_are_the_documented_set():
    found = set()
    for relative in ALL_FILES:
        found |= set(re.findall(r"@[A-Z][A-Z0-9_]*@", _text(relative)))
    assert found == PLACEHOLDERS
    readme = _text("README.md")
    for placeholder in PLACEHOLDERS:
        assert placeholder in readme


def test_start_chain_references_are_consistent():
    assert "@FACADE_RELEASE_DIR@/run-mcp" in _text("transport/run-mcp-child")
    assert '"$SCRIPT_DIR/verify-release" --transport-only' in _text("transport/run-mcp")
    facade = _text("release/run-mcp")
    assert '"$SCRIPT_DIR/verify-release"' in facade
    assert '"$SCRIPT_DIR/venv/bin/guardian-memory-synapse-mcp"' in facade
    assert "--action-log-witness-helper @ACTION_LOG_WITNESS_HELPER@" in facade
    host = _text("host/integrity-custody-full-verify")
    assert "SCRIPT_DIR=@FACADE_RELEASE_DIR@" in host
    assert host.rstrip("\n").endswith('exec "$@" --custody-full-verify')


def test_custody_full_verify_differs_from_facade_only_in_fixed_dir_and_flag():
    facade = _text("release/run-mcp").split("\n")
    host = _text("host/integrity-custody-full-verify").split("\n")
    assert len(facade) == len(host)
    diff = [i for i, (a, b) in enumerate(zip(facade, host)) if a != b]
    assert [facade[i].split("=")[0] for i in diff[:1]] == ["SCRIPT_DIR"]
    assert host[diff[1]] == 'exec "$@" --custody-full-verify'
    assert len(diff) == 2


# --- pure Python behaviour (all platforms) -------------------------------------------


def test_wal_holder_parses_catalog_and_refresh_commands():
    holder = _load("host/integrity-seed-wal-holder", "wal_holder_under_test")
    catalog, commands = holder.parse_arguments(
        ["/c.sqlite3", "/bin/refresh", "--refresh-command", "/bin/refresh integrity-reader"]
    )
    assert catalog == "/c.sqlite3"
    assert commands == [["/bin/refresh"], ["/bin/refresh", "integrity-reader"]]
    for bad in ([], ["--refresh-command"], ["/c", "--refresh-command", "  "]):
        with pytest.raises(ValueError):
            holder.parse_arguments(bad)


def test_verify_release_canonical_path_rules():
    vr = _load("release/verify-release", "verify_release_under_test")
    digest = hashlib.sha256(b"release").hexdigest()
    assert vr._release_digest(digest) == digest
    for bad in (digest.upper(), digest[:-1], "sha256:" + digest):
        with pytest.raises(vr.ReleaseInventoryError):
            vr._release_digest(bad)
    assert vr._relative_path("venv/bin/python") == "venv/bin/python"
    for bad in ("", "/abs", "a/../b", "a\\b", "./a", "a//b", "release-inventory.json", ".incomplete"):
        with pytest.raises(vr.ReleaseInventoryError):
            vr._relative_path(bad)
    assert vr._symlink_target("python3") == "python3"
    with pytest.raises(vr.ReleaseInventoryError):
        vr._symlink_target("/usr/bin/python3")


def _witness(tmp_path, monkeypatch, line: bytes, rows=()):
    witness = _load("release/action-log-passive-witness", "witness_under_test")
    database = tmp_path / "log.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, event_uid TEXT, details TEXT)")
        conn.executemany("INSERT INTO events (id, event_uid, details) VALUES (?, ?, ?)", rows)
    conn.close()
    monkeypatch.setattr(witness, "DATABASE", database.as_posix())
    out = io.BytesIO()
    stdout = io.TextIOWrapper(out)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(line)))
    monkeypatch.setattr(sys, "stdout", stdout)
    code = witness.main()
    stdout.flush()
    return code, out.getvalue()


def _request(uid="client:test-event-1", digest="ab" * 32) -> bytes:
    return json.dumps({"event_uid": uid, "request_sha256": digest}).encode() + b"\n"


def test_witness_reports_absent_exact_and_collision(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    code, out = _witness(tmp_path / "a", monkeypatch, _request())
    assert code == 0 and json.loads(out)["status"] == "absent"
    marker = json.dumps({"_integrity_client": {"request_sha256": "ab" * 32}})
    (tmp_path / "b").mkdir()
    code, out = _witness(tmp_path / "b", monkeypatch, _request(), [(5, "client:test-event-1", marker)])
    response = json.loads(out)
    assert code == 0 and response["status"] == "exact" and response["event_id"] == 5
    (tmp_path / "c").mkdir()
    code, out = _witness(tmp_path / "c", monkeypatch, _request(digest="cd" * 32),
                         [(5, "client:test-event-1", marker)])
    assert code == 0 and json.loads(out)["status"] == "collision"


@pytest.mark.parametrize("line", [
    b"",
    b"not json\n",
    json.dumps({"event_uid": "client:test-event-1"}).encode() + b"\n",
    _request(uid="other:test-event-1"),
    _request(digest="AB" * 32),
    _request() + b"trailing",
])
def test_witness_rejects_malformed_requests(tmp_path, monkeypatch, line):
    code, out = _witness(tmp_path, monkeypatch, line)
    assert code == 1 and out == b""


# --- POSIX shell behaviour -----------------------------------------------------------


@POSIX
@pytest.mark.parametrize("relative", SHELL_SCRIPTS)
def test_shell_syntax(relative):
    subprocess.run(["/bin/sh", "-n", str(CORE / relative)], check=True)


@POSIX
@pytest.mark.parametrize("principal", ["seed-reader", "integrity-", "integrity-Bad", "integrity-a/b"])
def test_refresh_seed_acl_rejects_bad_principal_before_any_change(principal):
    result = subprocess.run(["/bin/sh", str(CORE / "release/refresh-seed-read-acl"), principal],
                            capture_output=True, text=True)
    assert result.returncode == 2


@POSIX
def test_provision_state_refuses_arguments():
    result = subprocess.run(["/bin/sh", str(CORE / "release/provision-state"), "--key", "x"],
                            capture_output=True, text=True)
    assert result.returncode == 1 and "accepts no key" in result.stderr


@POSIX
def test_facade_run_mcp_refuses_a_non_digest_directory(tmp_path):
    target = tmp_path / "not-a-digest"
    target.mkdir()
    script = target / "run-mcp"
    script.write_bytes((CORE / "release/run-mcp").read_bytes())
    result = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True)
    assert result.returncode == 1 and "invalid immutable release path" in result.stderr


@POSIX
def test_verify_release_build_verify_and_tamper(tmp_path):
    vr = _load("release/verify-release", "verify_release_posix")
    digest = hashlib.sha256(b"release").hexdigest()
    root = tmp_path / digest
    (root / "venv" / "bin").mkdir(parents=True)
    (root / "run-mcp").write_text("#!/bin/sh\n")
    (root / "venv" / "bin" / "python3").symlink_to("python3.12")
    vr.build_inventory(root, digest)
    receipt = vr.verify_inventory(root, digest)
    assert receipt
    (root / "run-mcp").write_text("#!/bin/sh\necho changed\n")
    with pytest.raises(vr.ReleaseInventoryError):
        vr.verify_inventory(root, digest)
    with pytest.raises(vr.ReleaseInventoryError):
        vr.verify_inventory(root, hashlib.sha256(b"other").hexdigest())


# --- Linux transport supervisor ------------------------------------------------------

_DRIVER = """
import importlib.machinery, importlib.util, sys
from pathlib import Path
loader = importlib.machinery.SourceFileLoader("ts", sys.argv[1])
spec = importlib.util.spec_from_loader("ts", loader)
mod = importlib.util.module_from_spec(spec); loader.exec_module(mod)
sys.exit(mod.supervise(["/bin/sh", sys.argv[2]], Path(sys.argv[3]), queue_wait=2.0))
"""


def _supervised(tmp_path, child_body: str):
    child = tmp_path / "child.sh"
    child.write_text("#!/bin/sh\n" + child_body)
    gate = tmp_path / "gate"
    return subprocess.Popen(
        [sys.executable, "-I", "-c", _DRIVER, str(CORE / "transport/transport-supervisor.py"),
         str(child), str(gate)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ), gate


@LINUX
def test_supervisor_relays_bytes_and_child_exit_status(tmp_path):
    os.chmod(tmp_path, 0o700)
    proc, gate = _supervised(tmp_path, "read line\necho \"got $line\"\nexit 7\n")
    proc.stdin.write(b"ping\n"); proc.stdin.flush()
    assert proc.stdout.readline() == b"got ping\n"
    proc.stdin.close()
    assert proc.wait(timeout=20) == 7
    assert sorted(p.name for p in gate.iterdir()) == ["slot-0.lock", "slot-1.lock"]
    assert oct(gate.stat().st_mode & 0o777) == "0o700"


@LINUX
def test_supervisor_without_input_starts_no_child(tmp_path):
    os.chmod(tmp_path, 0o700)
    marker = tmp_path / "started"
    proc, _ = _supervised(tmp_path, f"touch '{marker}'\n")
    proc.stdin.close()
    assert proc.wait(timeout=20) == 0
    assert not marker.exists()


@LINUX
def test_supervisor_main_rejects_wrong_argument_count():
    result = subprocess.run([sys.executable, "-I", str(CORE / "transport/transport-supervisor.py")],
                            capture_output=True)
    assert result.returncode == 64
