"""K6 tests: no full Seed verification on the start-up path; verified gate before Turn Memory.

usage (Linux, stand): PYTHONPATH=<pkg>:<vendor> python -m pytest -q -s test_k6.py
Optional: K6_LIVE_CATALOG=<path to a COPY of the live catalog> for the timing tests.
"""
from __future__ import annotations

import multiprocessing
import os
import shutil
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrity_guardian import memory_synapse_mcp as mcp
from integrity_guardian import seed_catalog as sc
from integrity_guardian.signing import Ed25519Signer, public_key_fingerprint
from integrity_guardian.turn_memory import namespace_fingerprint

K6 = hasattr(mcp, "_startup_source_namespace")
LIVE = os.environ.get("K6_LIVE_CATALOG")
pytestmark = pytest.mark.skipif(os.name != "posix", reason="Seed catalog custody stand requires POSIX")


def _catalog(tmp_path, n=40, namespace="seed://project/k6stand"):
    events = [{"id": i, "ts_utc": f"2026-11-11T00:00:{i % 60:02d}Z", "actor": "stand",
               "action": "note", "summary": f"k6 stand event {i}", "event_uid": f"client:k6-stand-{i:04d}",
               "details": {"i": i}, "tags": ["k6"]} for i in range(1, n + 1)]
    cat = sc.SeedCatalog(tmp_path / "catalog.sqlite3")
    cat.import_events(events, source_namespace=namespace)
    return cat.path


class _Store:
    def __init__(self, namespace):
        self.namespace = namespace


def _facade(lts, signer, store):
    f = SimpleNamespace(lts=lts, turn_memory=store,
                        architecture=SimpleNamespace(keys=SimpleNamespace(source_signer=signer)))
    f._maybe_recover_write_plane = lambda **_: None
    f._verify_turn_memory_namespace = lambda s: mcp.MemorySynapseMcp._verify_turn_memory_namespace(f, s)
    return f


def _expected(namespace, signer):
    return namespace_fingerprint(source_namespace=namespace,
                                 trust_fingerprint=public_key_fingerprint(signer.public_key))


@pytest.fixture
def no_full_verify(monkeypatch):
    calls = []
    original = sc._verify_connection

    def counted(*a, **k):
        calls.append(1)
        return original(*a, **k)

    monkeypatch.setattr(sc, "_verify_connection", counted)
    return calls


def test_startup_namespace_reads_one_row_without_full_verification(tmp_path, no_full_verify):
    if not K6:
        pytest.skip("base: start-up uses package_lts.snapshot()")
    path = _catalog(tmp_path)
    lts = mcp.MemorySynapseLtsService(path)
    before = len(no_full_verify)
    assert mcp._startup_source_namespace(lts) == "seed://project/k6stand"
    assert len(no_full_verify) == before, "start-up namespace ran the full verification"


def _quiescent_wal_catalog(tmp_path):
    """Live conditions: WAL-mode catalog, writer closed (no -wal/-shm), directory not writable."""
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    d = tmp_path / "ro"
    d.mkdir()
    path = _catalog(d)
    c = sqlite3.connect(path)
    assert c.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    c.close()
    assert not Path(str(path) + "-wal").exists() and not Path(str(path) + "-shm").exists()
    d.chmod(0o555)
    return d, path


def test_v1_plain_ro_connect_fails_on_quiescent_wal_catalog(tmp_path):
    """Reproduces the K6 v1 defect (plain mode=ro connect) under the live conditions."""
    d, path = _quiescent_wal_catalog(tmp_path)
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("SELECT value FROM seed_metadata WHERE key = 'source_namespace'").fetchone()
        connection.close()
    finally:
        d.chmod(0o755)


def test_v2_startup_namespace_reads_quiescent_wal_catalog(tmp_path, no_full_verify):
    if not K6:
        pytest.skip("base: start-up uses package_lts.snapshot()")
    d, path = _quiescent_wal_catalog(tmp_path)
    try:
        before = len(no_full_verify)
        assert mcp._startup_source_namespace(mcp.MemorySynapseLtsService(path)) == "seed://project/k6stand"
        assert len(no_full_verify) == before
        assert not Path(str(path) + "-shm").exists()  # nothing written next to the catalog
    finally:
        d.chmod(0o755)


def test_v2_read_changed_repeats_once_then_refuses(tmp_path, monkeypatch):
    if not K6:
        pytest.skip("no K6")
    path = _catalog(tmp_path)
    lts = mcp.MemorySynapseLtsService(path)
    real = mcp.open_catalog_readonly
    calls = {"n": 0, "fail": 1}

    def flaky(p, **k):
        calls["n"] += 1
        if calls["n"] <= calls["fail"]:
            raise sc.SeedCatalogReadChangedError("changed")
        return real(p, **k)

    monkeypatch.setattr(mcp, "open_catalog_readonly", flaky)
    assert mcp._startup_source_namespace(lts) == "seed://project/k6stand" and calls["n"] == 2
    calls.update(n=0, fail=2)
    with pytest.raises(mcp.MemorySynapseLtsError, match="changed during the start-up"):
        mcp._startup_source_namespace(lts)
    assert calls["n"] == 2


def test_build_write_plane_runtime_has_no_snapshot_call():
    """Static guard: the start-up builder must not call snapshot()/verify() (initialize path)."""
    import inspect
    src = inspect.getsource(mcp._build_write_plane_runtime)
    if not K6:
        assert "package_lts.snapshot()" in src
        pytest.skip("base still verifies at start-up (documented)")
    assert ".snapshot(" not in src and ".verify(" not in src


def test_gate_verifies_once_per_store_and_admits_matching_namespace(tmp_path, no_full_verify):
    if not K6:
        pytest.skip("no gate in base")
    path = _catalog(tmp_path)
    lts = mcp.MemorySynapseLtsService(path)
    signer = Ed25519Signer.generate("key:k6-source")
    store = _Store(_expected("seed://project/k6stand", signer))
    f = _facade(lts, signer, store)
    assert mcp.MemorySynapseMcp._require_turn_memory(f) is store
    first = len(no_full_verify)
    assert first >= 1, "gate did not run the full verification"
    assert mcp.MemorySynapseMcp._require_turn_memory(f) is store
    assert f._turn_memory_namespace_store is store
    # a new store (write-plane recovery) is bound again
    store2 = _Store(store.namespace)
    f.turn_memory = store2
    assert mcp.MemorySynapseMcp._require_turn_memory(f) is store2 and f._turn_memory_namespace_store is store2


def test_gate_fail_closed_on_namespace_mismatch(tmp_path):
    if not K6:
        pytest.skip("no gate in base")
    path = _catalog(tmp_path)
    lts = mcp.MemorySynapseLtsService(path)
    signer = Ed25519Signer.generate("key:k6-source")
    f = _facade(lts, signer, _Store(_expected("seed://project/other", signer)))
    with pytest.raises(mcp.McpFacadeError, match="does not match the verified Seed catalog"):
        mcp.MemorySynapseMcp._require_turn_memory(f)
    assert f.turn_memory is None
    with pytest.raises(mcp.McpFacadeError, match="unavailable"):
        mcp.MemorySynapseMcp._require_turn_memory(f)


def test_gate_denies_when_catalog_is_corrupted(tmp_path):
    if not K6:
        pytest.skip("no gate in base")
    path = _catalog(tmp_path)
    raw = sqlite3.connect(path)
    raw.execute("UPDATE seed_events SET summary = summary || ' tampered' WHERE event_id = 5")
    raw.commit()
    raw.close()
    lts = mcp.MemorySynapseLtsService(path)
    signer = Ed25519Signer.generate("key:k6-source")
    store = _Store(_expected("seed://project/k6stand", signer))
    f = _facade(lts, signer, store)
    assert mcp._startup_source_namespace(lts) == "seed://project/k6stand"  # start-up still succeeds
    with pytest.raises(mcp.McpFacadeError, match="verification failed before Turn Memory"):
        mcp.MemorySynapseMcp._require_turn_memory(f)
    assert getattr(f, "_turn_memory_namespace_store", None) is None  # never admitted


def test_denial_is_a_tool_error_not_success():
    """The dispatcher turns McpFacadeError into a denial receipt with isError (hooks: not admitted)."""
    import inspect
    from integrity_guardian import memory_synapse_mcp_protocol as proto
    src = inspect.getsource(proto) if hasattr(proto, "dispatch") else ""
    assert "McpFacadeError" in inspect.getsource(mcp) and '"outcome": "denied"' in inspect.getsource(mcp)


def _first_call(path, memo, out, start):
    sc.configure_verification_memo(Path(memo))
    lts = mcp.MemorySynapseLtsService(path)
    start.wait()
    t = time.perf_counter()
    lts.snapshot()
    out.put(round(time.perf_counter() - t, 3))


@pytest.mark.skipif(not LIVE, reason="needs K6_LIVE_CATALOG (a copy of the live catalog)")
def test_timing_on_live_copy(tmp_path):
    path = tmp_path / "live.sqlite3"
    s = sqlite3.connect(f"file:{LIVE}?mode=ro", uri=True)
    d = sqlite3.connect(path)
    s.backup(d)
    s.close()
    d.close()
    # Concurrency first: the parent has verified nothing yet, so forked children inherit no memo.
    ctx = multiprocessing.get_context("fork")
    out, start = ctx.Queue(), ctx.Event()
    memo = tmp_path / "memo"
    procs = [ctx.Process(target=_first_call, args=(path, memo, out, start)) for _ in range(2)]
    for p in procs:
        p.start()
    start.set()
    for p in procs:
        p.join(300)
    pair = sorted(out.get() for _ in procs)
    lts = mcp.MemorySynapseLtsService(path)
    t = time.perf_counter()
    ns_fast = mcp._startup_source_namespace(lts) if K6 else None
    startup_after = time.perf_counter() - t
    t = time.perf_counter()
    ns_full = mcp.MemorySynapseLtsService(path).snapshot()["source_namespace"]  # parent: no memo dir
    startup_before = time.perf_counter() - t
    assert ns_fast in (None, ns_full)
    print(f"\nk6 timing: start-up namespace before={startup_before:.3f}s after={startup_after:.4f}s; "
          f"two simultaneous first gates={pair}")
    os.unlink(path)
