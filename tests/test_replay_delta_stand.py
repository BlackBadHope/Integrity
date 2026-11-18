"""ISS-113 on the full stand: a later replay is stored as a page delta and restores exactly.

Two admissions on two different frozen Seed catalogs: the first becomes a full
pool member, the second a delta against it. A cold facade then restores the
second retained replay through the delta (transport break: the original
connection is gone), and the append and close of the interrupted turn pass.
"""
import dataclasses
import sqlite3

import pytest

from recovery_stand_fixture import Stand
from test_recovery_full_path import RealConnection
from integrity_guardian import deployment_profile
from integrity_guardian import memory_synapse_mcp as mcp
from integrity_guardian import replay_catalog_pool as pool
from integrity_client_memory import operation_ledger, recovery_client


@pytest.fixture
def stand(tmp_path, monkeypatch):
    if __import__("os").name != "posix":
        pytest.skip("actual POSIX recovery custody requires Linux stand")
    pooled = dataclasses.replace(deployment_profile._PUBLIC, replay_catalog_pool=True)
    monkeypatch.setattr(mcp._deployment_profile, "current", lambda: pooled)
    result = Stand(tmp_path, monkeypatch)
    yield result
    result.stop()


def _grow_catalog(stand, count):
    for index in range(count):
        stand.al.insert_event({"actor": "stand", "action": "agent_note",
            "summary": "ISS-113 delta stand catalog growth " + str(index),
            "details": {"task_id": "stand-iss-113"}, "tags": ["stand"],
            "event_uid": "client:stand:iss113:" + str(index)})
    with stand.al.open_db() as db:
        db.row_factory = sqlite3.Row
        events = stand.al.rows_to_events(db.execute("SELECT * FROM events ORDER BY id").fetchall())
    stand.catalog.import_events(events)


def _replay_names(stand):
    root = stand.archroot / "context-admission-replay-v3"
    return sorted(p.name for p in root.iterdir())


@pytest.mark.parametrize("fault", ["lost-after-commit", "unsent"])
def test_second_replay_is_a_delta_and_interrupted_turn_completes(stand, monkeypatch, fault):
    first = stand.facade()
    replay, _ = stand.initialize(first)
    stand.admit(first, 1, replay)
    names = _replay_names(stand)
    assert sum(pool.is_pool_name(n) for n in names) == 1
    assert not any(pool.is_delta_name(n) for n in names)

    _grow_catalog(stand, 3)
    f = stand.facade()
    replay, _ = stand.initialize(f)
    admitted = stand.admit(f, 2, replay)
    names = _replay_names(stand)
    deltas = [n for n in names if pool.is_delta_name(n)]
    assert len(deltas) == 1 and sum(pool.is_pool_name(n) for n in names) == 1
    root = stand.archroot / "context-admission-replay-v3"
    base = next(n for n in names if pool.is_pool_name(n))
    # The stand catalog is a few dozen pages, so most of them change; the
    # production ratio is measured on full-size copies (see the PR).
    assert (root / deltas[0]).stat().st_size < (root / base).stat().st_size

    opened = stand.tool(f, "integrity_turn_memory_open", stand.args)
    assert opened["session_recovery"]["available"] is True, opened["session_recovery"]

    restored = []
    original = mcp.MemorySynapseMcp._open_delta_context_replay_catalog
    def spy(self, *args, **kwargs):
        restored.append(args[1])
        return original(self, *args, **kwargs)
    monkeypatch.setattr(mcp.MemorySynapseMcp, "_open_delta_context_replay_catalog", spy)

    controls = stand.controls(2, opened)
    registration = controls.pop("registration_id")
    connections = [RealConnection(stand, f, fault=fault)]
    custody = stand.root / "client-custody"
    custody.mkdir(mode=0o700)
    ledger = operation_ledger.OperationLedger(custody / "operations.sqlite3")
    def connect():
        cold = stand.facade()
        stand.initialize(cold, control_only=True)
        current = RealConnection(stand, cold, restore=True)
        connections.append(current)
        return current
    def validate():
        assert opened["receipt"]["identity"] == {k: stand.args[k] for k in
            ("machine_id", "thread_id", "turn_id", "intent_id")}
    client = recovery_client.RecoveryClient(ledger, validate_own=validate, connect=connect)

    arguments = {"context_admission_id": admitted["context_admission_id"],
        "event_uid": "client:stand46:" + stand.subject_thread + ":iss113-" + fault,
        "kind": "thought", "summary": "Interrupted turn append over a delta-restored replay"}
    events_before = stand.event_count()
    result = client.execute("integrity_append_event", arguments, registration_id=registration,
        control=controls, connection=connections[0])
    assert recovery_client.confirmed_result("integrity_append_event", arguments, result)
    assert len(connections) == 2
    if fault == "unsent":
        # The append is resent on the cold facade, which restores the retained
        # admission through the delta member.
        assert [c.send_count for c in connections] == [1, 1]
        assert restored == [deltas[0]], "the cold facade did not restore through the delta"
    else:
        # Committed before the break: the status answer needs no resend.
        assert [c.send_count for c in connections] == [1, 0]
    assert stand.event_count() == events_before + 1          # exactly once
    body = recovery_client.unpack(result)
    closing = {"registration_id": registration, "outcome": "events",
        "events": [{k: body["receipt"][k] for k in ("event_id", "event_uid", "request_sha256")}]}
    terminal = client.execute("integrity_turn_memory_close", closing, registration_id=registration,
        control=controls, connection=connections[-1])
    assert recovery_client.confirmed_result("integrity_turn_memory_close", closing, terminal)
    assert sum(x.get("tool") == "integrity_context_admission" for x in stand.wire) == 2
    if fault == "unsent":
        # The rebuilt private copy lives only while the cold facade holds it.
        sessions = lambda: sorted(p.name for p in stand.snapshots.iterdir()
                                  if p.name.startswith(mcp.SEED_SNAPSHOT_SESSION_PREFIX))
        before = sessions()
        connections[-1].close()
        assert len(sessions()) == len(before) - 1
