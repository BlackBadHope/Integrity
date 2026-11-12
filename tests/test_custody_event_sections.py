"""K5 acceptance: event-append grant and outcome custody sections with the anchored pass before the lock.
Run against the live K4 v2 modules (base) and the K5 modules via PYTHONPATH. Linux, real processes,
real flock, real WAL, real Ed25519 (signatures included)."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from integrity_guardian import medor_architecture as a
from integrity_guardian.ledger import LedgerStore, LedgerVerificationError, build_ledger_event, merkle_root
from integrity_guardian.signing import Ed25519Signer, TrustedKey

pytestmark = pytest.mark.skipif(os.name != "posix", reason="custody root requires POSIX")
K5 = hasattr(a.PersistentMedorArchitectureService, "_run_custody")
T0 = "2026-11-11T00:00:00Z"


def _d(tag, i):
    return "sha256:" + hashlib.sha256(f"{tag}:{i}".encode()).hexdigest()


def _keys():
    return (a.MedorArchitectureKeys(
        source_signer=Ed25519Signer.generate("key:medor-architecture-source"),
        checkpoint_signer=Ed25519Signer.generate("key:medor-architecture-checkpoint")),
        Ed25519Signer.generate("key:event-authority"))


def _service(root, keys):
    k, authority = keys
    return a.PersistentMedorArchitectureService(
        root, keys=k, event_authority_key=TrustedKey(authority.key_id, authority.public_key))


def _now():
    return datetime.now(UTC).replace(microsecond=0)


def _iso(t):
    return t.isoformat().replace("+00:00", "Z")


def _bulk(service, n):
    with LedgerStore(service.ledger_path, tenant_id=a.architecture_tenant_id(), ledger_id=a.CUSTODY_LEDGER_ID) as led:
        prev, batch = None, []
        for i in range(n):
            e = build_ledger_event(tenant_id=a.architecture_tenant_id(), source_id=a.SOURCE_ID, source_sequence=i,
                                   event_type="observation", payload_digest=_d("bulk", i), previous_event_digest=prev,
                                   signer=service.keys.source_signer, recorded_at=T0)
            prev = a.event_digest(e)
            batch.append(e)
        led.append_many(batch)
        cp = led.checkpoint(checkpoint_id=a.CUSTODY_CHECKPOINT_ID, signer=service.keys.checkpoint_signer, created_at=T0)
    service._store_checkpoint(cp)


def _grant(service, keys, tag, at=None):
    at = at or _now()
    arch, sec, req = _d("arch", tag), _d("sec", tag), _d("req", tag)
    decision = a.build_medor_event_append_decision(
        architecture_admission_id=arch, security_admission_id=sec, request_digest=req,
        valid_from=_iso(at - timedelta(minutes=1)), valid_until=_iso(at + timedelta(minutes=5)),
        authority_signer=keys[1])
    return service.authorize_event_append(
        architecture_admission_id=arch, security_admission_id=sec, request_digest=req,
        route_digest=_d("route", tag), external_decision=decision, recorded_at=_iso(at))


def _outcome(service, receipt, at=None, outcome="confirmed-success"):
    return service.record_event_append_outcome(
        grant_id=receipt["grant_id"], request_digest=receipt["request_digest"], outcome=outcome,
        witness_digest=_d("witness", receipt["grant_id"]), recorded_at=_iso(at or _now()))


def _rows(service):
    raw = sqlite3.connect(service.ledger_path)
    try:
        return raw.execute("SELECT ledger_sequence, event_digest, event_json FROM ledger_events "
                           "ORDER BY ledger_sequence").fetchall()
    finally:
        raw.close()


def _consistent(service):
    rows = _rows(service)
    cp = service._load_checkpoint()
    assert cp["tree_size"] == len(rows) and cp["root_digest"] == merkle_root([r[1] for r in rows])
    events = [json.loads(r[2]) for r in rows]
    keys = [(e["source_id"], e["source_sequence"]) for e in events]
    assert len(keys) == len(set(keys)), "duplicate source position"
    assert service.full_verify()["result"] == "pass"
    return events


def _count_opens(service):
    opened = []
    original = service._open_custody_ledger if hasattr(service, "_open_custody_ledger") else None
    if original is None:
        return opened
    state = {"in_lock": False}
    orig_lock = service._exclusive_custody

    @contextmanager
    def lock():
        with orig_lock():
            state["in_lock"] = True
            try:
                yield
            finally:
                state["in_lock"] = False

    def tracked():
        store = original()
        opened.append((store, state["in_lock"]))
        return store

    service._exclusive_custody = lock
    service._open_custody_ledger = tracked
    return opened


# ----------------------------------------------------------------------------- equivalence
def test_fast_and_old_body_give_identical_receipts(tmp_path):
    if not K5:
        pytest.skip("base has only the old body for grant/outcome")
    keys, at = _keys(), _now()
    out = []
    for name, force_full in (("fast", False), ("full", True)):
        s = _service(tmp_path / name, keys)
        _bulk(s, 150)
        if force_full:
            s._prepare_custody = lambda ledger: None
        opened = _count_opens(s)
        g = _grant(s, keys, "eq", at)
        o1 = _outcome(s, g, at)
        o2 = _outcome(s, g, at)  # replay -> already-recorded
        with pytest.raises(a.MedorArchitectureError) as replay:
            _grant(s, keys, "eq", at)  # second consumption of the same request
        out.append((g, o1, o2, str(replay.value), [x[1] for x in opened]))
        _consistent(s)
    (g1, a1, b1, r1, open1), (g2, a2, b2, r2, open2) = out
    assert g1 == g2 and a1 == a2 and b1 == b2 and r1 == r2
    assert b1["write_status"] == "already-recorded" and a1["write_status"] == "recorded"
    # fast: one store opened before the lock per call (+1 fresh store under it only for the replayed grant)
    assert open1.count(True) == 1, open1  # only the rejected replay fell back to the old body
    assert open2.count(True) == 4, open2


# ----------------------------------------------------------------------------- tamper between phases
def _tamper(path, mode):
    raw = sqlite3.connect(path)
    try:
        if mode == "byte":
            d = raw.execute("SELECT event_json FROM ledger_events WHERE ledger_sequence=6").fetchone()[0]
            raw.execute("UPDATE ledger_events SET event_json=? WHERE ledger_sequence=6",
                        (d.replace(b"observation", b"observatioN"),))
        else:
            r5, r6 = raw.execute("SELECT event_json, event_digest FROM ledger_events WHERE ledger_sequence IN (5,6) "
                                 "ORDER BY ledger_sequence").fetchall()
            raw.execute("UPDATE ledger_events SET event_digest='x' WHERE ledger_sequence=5")
            raw.execute("UPDATE ledger_events SET event_json=?, event_digest=? WHERE ledger_sequence=6", r5)
            raw.execute("UPDATE ledger_events SET event_json=?, event_digest=? WHERE ledger_sequence=5", r6)
        raw.commit()
    finally:
        raw.close()


@pytest.mark.parametrize("section", ["grant", "outcome"])
@pytest.mark.parametrize("mode", ["byte", "reorder"])
def test_change_between_phase1_and_lock_is_caught_by_old_body(tmp_path, section, mode):
    keys = _keys()
    s = _service(tmp_path / "arch", keys)
    _bulk(s, 40)
    g = _grant(s, keys, "t") if section == "outcome" else None
    before_cp, before_n = s._load_checkpoint(), len(_rows(s))
    opened = _count_opens(s) if K5 else []
    orig = s._exclusive_custody

    @contextmanager
    def tamper_then_lock():
        _tamper(s.ledger_path, mode)
        with orig():
            yield

    s._exclusive_custody = tamper_then_lock
    with pytest.raises((a.MedorArchitectureError, LedgerVerificationError)) as info:
        _grant(s, keys, "t2") if section == "grant" else _outcome(s, g)
    print(f"\n{section}/{mode}: {type(info.value).__name__}: {info.value}")
    assert s._load_checkpoint() == before_cp, "checkpoint re-signed over changed data"
    assert len(_rows(s)) == before_n, "something was appended"
    if K5:
        assert [x[1] for x in opened] == [False, True], opened  # pre-lock store, then a fresh one under the lock


# ----------------------------------------------------------------------------- after the point of no return
@pytest.mark.parametrize("section", ["grant", "outcome"])
def test_failure_after_last_write_surfaces_as_itself(tmp_path, section):
    """K5 v2 condition 1: a failure after the section's last append is not masked by the old body."""
    if not K5:
        pytest.skip("base has no fast path")
    keys = _keys()
    s = _service(tmp_path / "arch", keys)
    _bulk(s, 60)
    g = _grant(s, keys, "nr") if section == "outcome" else None

    def broken(*_a, **_k):
        raise a.MedorArchitectureError("injected post-write binding failure")

    s._bind_after_write = broken
    with pytest.raises(a.MedorArchitectureError) as info:
        _grant(s, keys, "nr2") if section == "grant" else _outcome(s, g)
    msg = str(info.value)
    print(f"\npost-write failure/{section}: {msg}")
    assert "injected post-write binding failure" in msg, msg
    assert "already consumed" not in msg and "already-recorded" not in msg


def test_existing_decision_without_consumption_goes_to_old_body(tmp_path):
    """K5 v2 condition 2: interrupted grant (decision committed, no consumption) -> old body, same receipt."""
    if not K5:
        pytest.skip("base has no fast path")
    keys, at = _keys(), _now()
    receipts = []
    for name in ("fast", "full"):
        s = _service(tmp_path / name, keys)
        _bulk(s, 80)
        orig_bind = s._bind_after_write if name == "fast" else None
        # interrupt the first call right after the decision commit: fail the second _verified_head
        calls = {"n": 0}
        orig_head = s._verified_head

        @contextmanager
        def head_once(ledger, state, cp, _orig=orig_head, _calls=calls):
            _calls["n"] += 1
            if _calls["n"] == 2:
                raise RuntimeError("simulated crash between decision and consumption")
            with _orig(ledger, state, cp) as value:
                yield value

        s._verified_head = head_once
        with pytest.raises(RuntimeError):
            _grant(s, keys, "rec", at)
        s._verified_head = orig_head
        if name == "full":
            s._prepare_custody = lambda ledger: None
        opened = _count_opens(s)
        receipts.append(_grant(s, keys, "rec", at))
        assert [x[1] for x in opened][-1] is True  # resumed by the old body under the lock
        _consistent(s)
    assert receipts[0] == receipts[1]


def test_iss033_interpreter_version_changes_verifier_digest(monkeypatch):
    from integrity_guardian import seed_catalog as sc
    if not hasattr(sc, "sys"):
        pytest.skip("base has no ISS-033 line")
    monkeypatch.setattr(sc, "_verifier_identity", None)
    first = sc._verifier_digest()
    monkeypatch.setattr(sc, "_verifier_identity", None)
    monkeypatch.setattr(sc.sys, "version", sc.sys.version + " (other build)")
    assert sc._verifier_digest() != first


# ----------------------------------------------------------------------------- race
def _racer(root, keys, tag, shared, start, out):
    s = _service(root, keys)
    start.wait()
    res = []
    for i in range(6):
        for req in (f"{tag}-{i}", shared[i]):
            for attempt in range(a.CUSTODY_ADMISSION_ATTEMPTS):
                try:
                    g = _grant(s, keys, req)
                    o = _outcome(s, g)
                    res.append((req, "ok", o["write_status"]))
                    break
                except a.MedorArchitectureError as exc:
                    res.append((req, "refused", str(exc)[:60]))
                    break
                except Exception as exc:  # noqa: BLE001
                    if attempt + 1 >= a.CUSTODY_ADMISSION_ATTEMPTS or not a._is_retryable_custody_conflict(exc):
                        res.append((req, "error", type(exc).__name__))
                        break
                    time.sleep(0.05 * 2 ** attempt)
            s._record_admission_custody(payload_digest=_d(f"adm-{tag}", i), observed_at=T0)
    out.put((tag, res))


@pytest.mark.parametrize("history", [1, 3000])
def test_race_two_writers_grants_outcomes_admissions(tmp_path, history):
    keys = _keys()
    root = tmp_path / "arch"
    s = _service(root, keys)
    _bulk(s, history)
    shared = [f"shared-{i}" for i in range(6)]
    ctx = multiprocessing.get_context("fork")
    start, out = ctx.Event(), ctx.Queue()
    procs = [ctx.Process(target=_racer, args=(root, keys, t, shared, start, out)) for t in ("p1", "p2")]
    for p in procs:
        p.start()
    start.set()
    got = dict(out.get(timeout=600) for _ in procs)
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    events = _consistent(s)
    results = [r for rs in got.values() for r in rs]
    assert not [r for r in results if r[1] == "error"], results
    for req in shared:
        mine = [r for r in results if r[0] == req]
        assert [r[1] for r in mine].count("ok") == 1, mine  # exactly one consumption of a shared request
    grants = [e for e in events if e["source_id"].startswith("source:medor-event-grant:")]
    outcomes = [e for e in events if e["source_id"].startswith("source:medor-event-outcome:")]
    assert len(grants) == 2 * (12 + 6) and len(outcomes) == 12 + 6
    print(f"\nrace history={history}: grants={len(grants)//2} outcomes={len(outcomes)} rows={len(events)}")


# ----------------------------------------------------------------------------- SQLITE_BUSY
def _writer_hold(path, ready, seconds):
    raw = sqlite3.connect(path, timeout=0)
    raw.execute("BEGIN IMMEDIATE")
    ready.set()
    time.sleep(seconds)
    raw.rollback()
    raw.close()


def test_sqlite_busy_on_grant_is_retryable_and_writes_nothing(tmp_path):
    keys = _keys()
    s = _service(tmp_path / "arch", keys)
    _bulk(s, 200)
    before, cp = _rows(s), s._load_checkpoint()
    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    p = ctx.Process(target=_writer_hold, args=(s.ledger_path, ready, 6))
    p.start()
    assert ready.wait(10)
    with pytest.raises(sqlite3.OperationalError) as info:
        _grant(s, keys, "busy")
    assert a._is_retryable_custody_conflict(info.value)
    assert _rows(s) == before and s._load_checkpoint() == cp
    p.join(20)
    g = _grant(s, keys, "busy")
    assert _outcome(s, g)["write_status"] == "recorded"
    _consistent(s)


# ----------------------------------------------------------------------------- hold
def test_hold_at_16900(tmp_path):
    keys = _keys()
    s = _service(tmp_path / "arch", keys)
    _bulk(s, 16_900)
    holds = []
    orig = s._exclusive_custody

    @contextmanager
    def timed():
        with orig():
            t = time.perf_counter()
            try:
                yield
            finally:
                holds.append(time.perf_counter() - t)

    s._exclusive_custody = timed
    res = {"grant": [], "outcome": [], "admission": []}
    for i in range(3):
        n = len(holds); g = _grant(s, keys, f"h{i}"); res["grant"].append(holds[n] if len(holds) > n else None)
        n = len(holds); _outcome(s, g); res["outcome"].append(holds[n] if len(holds) > n else None)
        n = len(holds); s._record_admission_custody(payload_digest=_d("hadm", i), observed_at=T0)
        res["admission"].append(holds[n] if len(holds) > n else None)
    res["refused_grant_replay"] = []
    for i in range(2):  # business refusal: fast path misses, the old body raises "already consumed"
        n = len(holds)
        with pytest.raises(a.MedorArchitectureError, match="already consumed"):
            _grant(s, keys, f"h{i}")
        res["refused_grant_replay"].append(holds[n] if len(holds) > n else None)
    print("\nhold16900 " + json.dumps({k: [round(x, 3) for x in v] for k, v in res.items()}))
    _consistent(s)
    if K5:
        assert max(res["grant"] + res["outcome"] + res["admission"]) < 0.5, res
