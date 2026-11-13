"""Install stage 2: one persistent core instance on Linux.

Every test starts the real ``guardian-core-instance serve`` process and talks
to it over stdio, the way an ``integrity-remote`` release does.  The Action
Log HTTP service, its witness, the Seed catalog, native trust with file keys
and the lifecycle stores are the real ones.  Only the producer envelope is
synthetic (the stand's wire helper), so this is not an acceptance of a live
agent client.

What the tests fix: the instance survives its server process, a second
session reads what the first one wrote, two sessions can be open at once, and
the same instance is reached through an OpenSSH forced command.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import selectors
import sqlite3
import stat
import subprocess
import sys
import uuid

import pytest

from integrity_guardian import core_instance
from recovery_stand_fixture import Stand

LINUX = sys.platform.startswith("linux")
# Set INTEGRITY_CORE_INSTANCE_REQUIRED=1 to turn a missing prerequisite into a failure.
REQUIRED = os.environ.get("INTEGRITY_CORE_INSTANCE_REQUIRED") == "1"
CLI = [sys.executable, "-m", "integrity_guardian.core_instance"]


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([*CLI, *args], capture_output=True, text=True, timeout=180)


def _probe(code: str, *args: str) -> subprocess.CompletedProcess:
    """Run launcher internals in their own process: loading the Action Log changes the environment."""
    return subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, timeout=180)


# One session inserts an event; another session of the same instance imports it
# into the catalog first.  The first session must then find nothing left to do.
SYNC_PROBE = """
import json, sqlite3, sys
from integrity_guardian import core_instance
from integrity_guardian.seed_catalog import SeedCatalog

core = core_instance.Core(sys.argv[1])
try:
    core.action_log.insert_event({
        "actor": "core-instance",
        "action": "agent_change_start",
        "summary": "written while two sessions are open",
        "details": {"task_id": "core-instance"},
        "tags": ["core-instance"],
        "event_uid": "client:core-instance:test-two-sessions",
    })
    with core.action_log.open_db() as database:
        database.row_factory = sqlite3.Row
        rows = database.execute("SELECT * FROM events WHERE id > ? ORDER BY id",
                                (core.catalog.event_cursor()[1],)).fetchall()
        events = core.action_log.rows_to_events(rows)
    SeedCatalog(core.paths.catalog).import_events(events)
    print(json.dumps({"read": len(events), "synced": core.sync(), "catalog": core.catalog.event_cursor()[0]}))
finally:
    core.close()
"""

# create() fails after the marker, the folders, the configuration, the database
# and the first event are written.
FAILED_INIT_PROBE = """
import sys
from integrity_guardian import core_instance


class Stopped(Exception):
    pass


def stopped(home):
    raise Stopped("stopped in the middle")


core_instance.Core = stopped
try:
    core_instance.create(sys.argv[1])
except Stopped:
    sys.exit(7)
sys.exit(0)
"""


class Session(Stand):
    """The stand's lifecycle helper over the stdio of one server process."""

    def __init__(self, argv: list[str]) -> None:
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        self.subject_thread = str(uuid.uuid4())
        self.admissions, self.wire, self.next_id = {}, [], 0

    def rpc(self, _facade, method, params):
        self.next_id += 1
        self.wire.append((method, params.get("name")))
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        self.process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(60), "bounded stdio response timed out"
        line = self.process.stdout.readline()
        assert line, self.process.stderr.read().decode(errors="replace")[-3000:]
        response = json.loads(line)
        assert response.get("id") == self.next_id and "error" not in response, response
        return response["result"]

    def begin(self, number: int) -> tuple[dict, dict]:
        replay, _ = self.initialize(None)
        admission = self.admit(None, number, replay)
        opened = self.tool(None, "integrity_turn_memory_open", self.args)
        return admission, opened

    def finish(self, admission: dict, opened: dict, label: str) -> dict:
        event = self.append(None, admission, label)
        terminal = self.close_turn(None, opened, event)
        self.process.stdin.close()
        self.process.wait(timeout=30)
        return {
            "returncode": self.process.returncode,
            "append": (event["receipt"]["outcome"], event["receipt"]["action_outcome"]),
            "event_uid": event["receipt"]["event_uid"],
            "terminal_bound": terminal["receipt"]["registration_id"] == opened["receipt"]["receipt_id"],
            "terminal_signature": terminal["receipt"]["signature"]["algorithm"],
        }

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream and not stream.closed:
                stream.close()


def _lifecycle(argv: list[str], number: int, label: str) -> tuple[dict, dict]:
    session = Session(argv)
    try:
        admission, opened = session.begin(number)
        return admission, session.finish(admission, opened, label)
    finally:
        session.stop()


def _event_uids(home: Path) -> list[str]:
    database = home / "action-log" / "events.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        return [row[0] for row in connection.execute("SELECT event_uid FROM events ORDER BY id")]


def _doctor(home: Path) -> dict:
    done = _run("doctor", "--home", str(home), "--json")
    report = json.loads(done.stdout)
    report["exit"] = done.returncode
    report["by_name"] = {item["check"]: item for item in report["checks"]}
    return report


def _catalog_count(home: Path) -> int:
    from integrity_guardian.seed_catalog import SeedCatalog

    return SeedCatalog(core_instance.Paths(home).catalog).event_cursor()[0]


def _prerequisites() -> None:
    if not LINUX:
        pytest.skip("the core instance runs on Linux only")
    if importlib.util.find_spec("integrity_action_log") is None:
        message = "the Action Log component is not installed"
        if REQUIRED:
            pytest.fail(message)
        pytest.skip(message)


@pytest.fixture
def home(tmp_path):
    _prerequisites()
    folder = tmp_path / "core"
    done = _run("init", "--home", str(folder))
    assert done.returncode == 0, done.stderr[-3000:]
    created = json.loads(done.stdout)
    assert created["server"] == core_instance.server_spec(folder)
    return folder


def test_other_systems_are_refused_with_a_way_forward(tmp_path, capsys):
    if LINUX:
        pytest.skip("the refusal is for systems other than Linux")
    assert core_instance.main(["init", "--home", str(tmp_path / "core")]) == 2
    assert "guardian-local-memory" in capsys.readouterr().err
    assert not (tmp_path / "core").exists()


def test_init_makes_a_private_instance_that_doctor_accepts(home):
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    marker = json.loads((home / "instance.json").read_text())
    assert marker["profile"] == core_instance.PROFILE and marker["instance_id"].startswith("instance:core-")
    keys = [item for item in (home / "native").rglob("*") if item.is_file() and "keys" in item.parts]
    assert keys and all(stat.S_IMODE(item.stat().st_mode) & 0o077 == 0 for item in keys)
    assert _event_uids(home) == [core_instance.GENESIS_EVENT_UID]

    report = _doctor(home)
    assert report["exit"] == 0 and report["passed"] is True, report["checks"]
    assert {item["result"] for item in report["checks"]} == {"ok"}
    assert report["by_name"]["action-log"]["detail"].startswith("1 events")

    again = _run("init", "--home", str(home))
    assert again.returncode == 2 and "not empty" in again.stderr
    assert _event_uids(home) == [core_instance.GENESIS_EVENT_UID]


def test_doctor_fails_when_a_key_is_readable_by_others(home):
    key = next(item for item in (home / "native").rglob("*") if item.is_file() and "keys" in item.parts)
    key.chmod(0o644)
    report = _doctor(home)
    assert report["exit"] == 1 and report["by_name"]["files"]["result"] == "fail"


def test_a_second_session_reads_what_the_first_one_wrote(home):
    argv = core_instance.server_spec(home)["argv"]
    first_admission, first = _lifecycle(argv, 1, "first")
    assert first["returncode"] == 0 and first["append"] == ("created", "confirmed-success")
    assert first["terminal_bound"] and first["terminal_signature"] == "ed25519"
    assert first_admission["snapshot"]["cursor"]["event_count"] == 1

    second_admission, second = _lifecycle(argv, 2, "second")
    assert second["returncode"] == 0 and second["append"] == ("created", "confirmed-success")
    # The first server process is gone; its event came back from the instance folder.
    assert second_admission["snapshot"]["cursor"]["event_count"] == 2
    assert _event_uids(home) == [core_instance.GENESIS_EVENT_UID, first["event_uid"], second["event_uid"]]

    report = _doctor(home)
    assert report["exit"] == 0, report["checks"]
    assert report["by_name"]["action-log"]["detail"].startswith("3 events")
    assert report["by_name"]["catalog"]["result"] in {"ok", "warn"}


def test_two_sessions_open_at_once_both_write(home):
    argv = core_instance.server_spec(home)["argv"]
    held = Session(argv)
    try:
        admission, opened = held.begin(1)
        _, other = _lifecycle(argv, 2, "other")
        assert other["returncode"] == 0 and other["append"] == ("created", "confirmed-success")
        mine = held.finish(admission, opened, "held")
    finally:
        held.stop()
    assert mine["returncode"] == 0 and mine["append"] == ("created", "confirmed-success")
    assert set(_event_uids(home)) == {core_instance.GENESIS_EVENT_UID, other["event_uid"], mine["event_uid"]}
    # The catalog holds each Action Log event once: three, with nothing left to import.
    assert len(_event_uids(home)) == 3 and _catalog_count(home) == 3
    report = _doctor(home)
    assert report["exit"] == 0 and report["by_name"]["catalog"]["result"] == "ok", report["checks"]


def test_a_session_does_not_import_what_another_session_imported(home):
    done = _probe(SYNC_PROBE, str(home))
    assert done.returncode == 0, done.stderr[-3000:]
    # One event was new; the other session imported it, so this one imports nothing.
    assert json.loads(done.stdout) == {"read": 1, "synced": 0, "catalog": 2}
    assert _doctor(home)["exit"] == 0


def test_a_failed_init_leaves_nothing_behind(tmp_path):
    _prerequisites()
    absent = tmp_path / "absent"
    failed = _probe(FAILED_INIT_PROBE, str(absent))
    assert failed.returncode == 7, failed.stderr[-3000:]
    assert not absent.exists()

    empty = tmp_path / "empty"
    empty.mkdir(mode=0o750)
    empty.chmod(0o750)
    failed = _probe(FAILED_INIT_PROBE, str(empty))
    assert failed.returncode == 7, failed.stderr[-3000:]
    assert empty.is_dir() and not any(empty.iterdir())
    assert stat.S_IMODE(empty.stat().st_mode) == 0o750

    for folder in (absent, empty):
        again = _run("init", "--home", str(folder))
        assert again.returncode == 0, again.stderr[-3000:]
        assert _doctor(folder)["exit"] == 0


def test_uninstall_is_a_dry_run_until_confirmed(home, tmp_path):
    dry = _run("uninstall", "--home", str(home))
    assert dry.returncode == 0 and "Dry run" in dry.stdout and home.is_dir()
    stranger = tmp_path / "not-an-instance"
    stranger.mkdir()
    (stranger / "instance.json").write_text(json.dumps({"profile": "something-else"}))
    refused = _run("uninstall", "--home", str(stranger), "--yes")
    assert refused.returncode == 2 and stranger.is_dir()
    done = _run("uninstall", "--home", str(home), "--yes")
    assert done.returncode == 0 and not home.exists()


# The sshd fixture and its helpers belong to the two-machine test.
import test_two_machine_ssh as two_machines  # noqa: E402

machines = two_machines.machines


def test_the_instance_is_reached_through_a_forced_command(machines, home):
    """Machine B has only an ssh key; the release on machine A starts ``serve``."""
    pytest.importorskip("integrity_remote")
    a, b = machines["a"], machines["b"]
    name = "core_" + uuid.uuid4().hex[:6] + "_ed25519"
    two_machines._keygen(two_machines._tool("ssh-keygen"), b / name, "device-b-core")
    spec = a / f"core-instance-{uuid.uuid4().hex[:6]}.json"
    spec.write_text(json.dumps(core_instance.server_spec(home)))
    release = json.loads(two_machines._cli("core", "init", "--root", str(a / ("instance-" + uuid.uuid4().hex[:6])),
                                           "--server-json", str(spec)))
    line = two_machines._cli("authorize", "--release", release["release"], "--device-id", "laptop-b",
                             "--public-key", str(b / (name + ".pub")))
    authorized = machines["authorized"]
    original = authorized.read_text()
    authorized.write_text(original + line)
    try:
        remote_argv = machines["upstream"](name)
        _, first = _lifecycle(remote_argv, 1, "over-ssh")
        assert first["returncode"] == 0 and first["append"] == ("created", "confirmed-success")
        # A local session of the core's own account reads the event the remote device wrote.
        admission, second = _lifecycle(core_instance.server_spec(home)["argv"], 2, "local")
        assert admission["snapshot"]["cursor"]["event_count"] == 2
        assert second["returncode"] == 0
    finally:
        authorized.write_text(original)
    assert _event_uids(home) == [core_instance.GENESIS_EVENT_UID, first["event_uid"], second["event_uid"]]
