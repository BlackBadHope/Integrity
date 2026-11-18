"""Replay accounting cache: the same totals as the full check, never more trust than it gave.

The accounting pass of the replay inventory reads and parses every committed record twice
under the maintenance lock; with 128 live records that is about a second per admission and
seconds of queueing for a burst of facades. Positive verdicts are cached in a private sibling
directory, keyed by the full stat identity of the record, its catalog leaf and the pool member
behind it. These tests pin the contract: equal totals, a miss on any change, an unreadable or
foreign cache reads as empty, nothing new inside the replay root.
"""
from __future__ import annotations

import json
import os

import pytest

from integrity_guardian import memory_synapse_mcp as m
from test_replay_capacity_limits import pool, private_file_state, retained_fixture  # noqa: F401

posix = pytest.mark.skipif(os.name != "posix", reason="Actual POSIX replay custody")


def inventory(f):
    with f._context_replay_maintenance_lock():
        return f._context_replay_inventory(prune=False)


def full_check(f):
    f._context_replay_accounting_cache_enabled = False
    try:
        return inventory(f)
    finally:
        f._context_replay_accounting_cache_enabled = True


def stats(f):
    value = dict(f._context_replay_accounting_stats)
    for key in value:
        f._context_replay_accounting_stats[key] = 0
    return value


def cache_path(f):
    root = f._context_admission_replay_root
    return root.parent / m.CONTEXT_ADMISSION_REPLAY_ACCOUNTING_DIR_NAME / m.CONTEXT_ADMISSION_REPLAY_ACCOUNTING_FILE


@posix
def test_hit_gives_the_full_check_totals_and_touches_no_replay_file(pool, monkeypatch):
    retained_fixture(pool, monkeypatch)
    root = pool._context_admission_replay_root
    expected = full_check(pool)
    stats(pool)
    before = private_file_state(root)
    assert inventory(pool) == expected
    first = stats(pool)
    assert first["hit"] + first["miss"] == 1
    assert cache_path(pool).stat().st_mode & 0o777 == 0o600
    assert (cache_path(pool).parent.stat().st_mode & 0o777) == 0o700
    assert inventory(pool) == expected
    assert stats(pool) == {"hit": 1, "miss": 0, "write": 0}
    assert private_file_state(root) == before
    assert not any("verdict" in name or "accounting" in name for name in os.listdir(root))


@posix
def test_ack_rewrite_is_a_miss_and_releases_the_record_allowance(pool, monkeypatch):
    identity, record, path, _, response_digest = retained_fixture(pool, monkeypatch, delivered=False)
    inventory(pool)
    inventory(pool)
    assert stats(pool)["hit"] >= 1
    entry = json.loads(cache_path(pool).read_bytes())["entries"][path.stem]
    assert entry["acked"] is False
    stats(pool)
    assert pool._ack_context_replay(identity, record["request_digest"], response_digest)
    after = inventory(pool)
    assert after == full_check(pool)
    assert after[0] == sum(p.stat().st_size for p in path.parent.iterdir())
    observed = stats(pool)
    assert observed["miss"] >= 1 and observed["write"] >= 1
    assert json.loads(cache_path(pool).read_bytes())["entries"][path.stem]["acked"] is True


@posix
@pytest.mark.parametrize("case", ["corrupt", "wrong-ack", "missing-catalog", "temporary-record",
                                  "catalog-replaced", "migrated"])
def test_change_after_caching_falls_back_to_the_conservative_full_check(pool, monkeypatch, case):
    identity, record, path, catalog, _ = retained_fixture(pool, monkeypatch)
    inventory(pool)
    assert json.loads(cache_path(pool).read_bytes())["entries"]
    if case == "corrupt":
        path.write_bytes(b"{")
    elif case == "wrong-ack":
        record["delivered_response_digest"] = "sha256:" + "0" * 64
        path.write_bytes(m.canonical_json(record))
    elif case == "missing-catalog":
        catalog.unlink()
    elif case == "temporary-record":
        temporary = path.parent / ("." + path.name + ".123.1.tmp")
        temporary.write_bytes(b"pending replacement")
        temporary.chmod(0o600)
    elif case == "catalog-replaced":
        raw = catalog.read_bytes()
        catalog.unlink()
        catalog.write_bytes(raw)
        catalog.chmod(0o600)
    elif case == "migrated":
        pool._replay_migrations = {identity: object()}
        monkeypatch.setattr(pool, "_replay_migration", lambda _: None)
    stats(pool)
    assert inventory(pool) == full_check(pool)
    assert stats(pool)["hit"] == 0


@posix
@pytest.mark.parametrize("damage", ["garbage", "protocol", "root", "mode", "entry-shape", "symlink"])
def test_unreadable_or_foreign_cache_reads_as_empty(pool, monkeypatch, tmp_path, damage):
    retained_fixture(pool, monkeypatch)
    expected = full_check(pool)
    inventory(pool)
    target = cache_path(pool)
    document = json.loads(target.read_bytes())
    if damage == "garbage":
        target.write_bytes(b"\x00not json")
    elif damage == "protocol":
        document["protocol"] = "integrity-client/context-replay-accounting-cache/v0"
        target.write_bytes(m.canonical_json(document))
    elif damage == "root":
        document["root"][1] += 1
        target.write_bytes(m.canonical_json(document))
    elif damage == "mode":
        target.chmod(0o644)
    elif damage == "entry-shape":
        for entry in document["entries"].values():
            entry["extra"] = True
        target.write_bytes(m.canonical_json(document))
    elif damage == "symlink":
        outside = tmp_path / "outside.json"
        outside.write_bytes(m.canonical_json(document))
        outside.chmod(0o600)
        target.unlink()
        target.symlink_to(outside)
    stats(pool)
    assert inventory(pool) == expected
    observed = stats(pool)
    assert observed["hit"] == 0 and observed["miss"] == 1
    if damage != "symlink":
        # The damaged cache is replaced by the verdict of the full check.
        assert inventory(pool) == expected
        assert stats(pool)["hit"] == 1


@posix
def test_cache_directory_with_wrong_custody_is_never_used(pool, monkeypatch):
    retained_fixture(pool, monkeypatch)
    expected = full_check(pool)
    inventory(pool)
    cache_path(pool).parent.chmod(0o755)
    stats(pool)
    assert inventory(pool) == expected
    assert inventory(pool) == expected
    assert stats(pool)["hit"] == 0


@posix
def test_lock_wait_polls_short_and_growing_and_never_past_the_deadline(pool, monkeypatch):
    # A holder keeps the maintenance lock ~0.03 s after the cache; a fixed 0.05 s nap lost about
    # a whole step per hand-off (ISS-113 bench: 20 parallel reserves, median 0.58 s -> 0.34 s).
    holder = pool._open_context_replay_lock_file(".replay-maintenance.lock")
    m._fcntl.flock(holder, m._fcntl.LOCK_EX)
    naps = []
    release_after = [6]

    def nap(seconds):
        naps.append(seconds)
        if len(naps) == release_after[0]:
            m._fcntl.flock(holder, m._fcntl.LOCK_UN)

    monkeypatch.setattr(m.time, "sleep", nap)
    try:
        with pool._context_replay_maintenance_lock(timeout_seconds=5.0):
            pass
        assert naps == pytest.approx([0.001, 0.002, 0.004, 0.008, 0.01, 0.01], abs=1e-9)
        m._fcntl.flock(holder, m._fcntl.LOCK_EX)
        naps.clear()
        release_after[0] = -1
        with pytest.raises(m.McpFacadeError) as caught:
            with pool._context_replay_maintenance_lock(timeout_seconds=0.03):
                pass
        assert caught.value.integrity_failure_code == "context-retirement-lock-budget-exceeded"
        assert naps and max(naps) <= m.CONTEXT_REPLAY_LOCK_POLL_MAX_SECONDS
    finally:
        os.close(holder)
