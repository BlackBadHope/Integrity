"""Pooled replay layouts are collected, not pinned forever.

The live core filled its 4 GiB replay quota with pool members whose logical
replays had long expired or been retired, because pooled layouts were never
pruned. Expired replays now lose their own files under the unchanged TTL, and
a shared pool member goes only once no alias or journal references it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrity_guardian import memory_synapse_mcp as m
from integrity_guardian import replay_catalog_pool as pool

posix = pytest.mark.skipif(os.name != "posix", reason="Actual POSIX replay custody")
OLD = 3 * 24 * 3600


def hexid(text):
    return hashlib.sha256(text.encode()).hexdigest()


def write(root, name, raw, *, age=0):
    path = root / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    os.chmod(path, 0o600)
    if age:
        stamp = path.stat().st_mtime - age
        os.utime(path, (stamp, stamp))
    return path


def pooled_replay(root, label, *, age, content=None, journal=True, alias=True, record=True):
    """One promoted logical replay: record, alias leaf, journal and its pool member."""
    replay = hexid(label)
    content = content if content is not None else b"SQLite format 3\x00" + label.encode() * 64
    name = replay + ".catalog.sqlite3"
    binding = {"protocol": "integrity-client/context-admission-frozen-catalog/v1", "name": name,
               "sha256": "sha256:" + hashlib.sha256(content).hexdigest(), "bytes": len(content)}
    document = pool.alias_document(name, binding)
    if not (root / document["pool_name"]).exists():
        write(root, document["pool_name"], content, age=age)
    if alias:
        write(root, name, pool.canonical(document), age=age)
    if journal:
        raw = pool.canonical({"protocol": pool.JOURNAL, "alias": document,
                              "alias_sha256": pool.sha(pool.canonical(document))})
        write(root, "." + replay + ".catalog-pool.json", raw, age=age)
    if record:
        write(root, replay + ".json", json.dumps({"fixture": label}).encode(), age=age)
    return replay, document["pool_name"]


@pytest.fixture
def replay_root(tmp_path):
    root = tmp_path / "architecture"
    root.mkdir(mode=0o700)
    facade = m.MemorySynapseMcp(SimpleNamespace(), architecture=SimpleNamespace(root=root))
    facade._prepare_context_replay_custody()
    return facade, facade._context_admission_replay_root


def names(root):
    return {p.name for p in root.iterdir() if not p.name.startswith(".replay-")}


@posix
def test_expired_pooled_replay_and_its_pool_are_collected(replay_root):
    facade, root = replay_root
    expired, expired_pool = pooled_replay(root, "expired", age=OLD)
    live, live_pool = pooled_replay(root, "live", age=60)
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=True)
    left = names(root)
    assert not {expired + ".json", expired + ".catalog.sqlite3",
                "." + expired + ".catalog-pool.json", expired_pool} & left
    assert {live + ".json", live + ".catalog.sqlite3", "." + live + ".catalog-pool.json",
            live_pool} <= left


@posix
def test_shared_pool_survives_while_any_alias_references_it(replay_root):
    facade, root = replay_root
    shared = b"SQLite format 3\x00" + b"same frozen catalog" * 64
    expired, shared_pool = pooled_replay(root, "expired", age=OLD, content=shared)
    live, same_pool = pooled_replay(root, "live", age=60, content=shared)
    assert shared_pool == same_pool
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=True)
    left = names(root)
    assert expired + ".json" not in left
    assert {shared_pool, live + ".catalog.sqlite3"} <= left


@posix
def test_retired_replay_leaves_no_journal_or_pool_behind(replay_root):
    facade, root = replay_root
    # Retirement removes record, alias and reservation but not the journal.
    retired, retired_pool = pooled_replay(root, "retired", age=OLD, alias=False, record=False)
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=True)
    assert not {"." + retired + ".catalog-pool.json", retired_pool} & names(root)


@posix
def test_young_unreferenced_pool_is_kept_for_the_grace_period(replay_root):
    facade, root = replay_root
    _replay, young_pool = pooled_replay(root, "young", age=60, alias=False, journal=False,
                                        record=False)
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=True)
    assert young_pool in names(root)


@posix
def test_unparsed_alias_pins_every_pool(replay_root):
    facade, root = replay_root
    live, live_pool = pooled_replay(root, "live", age=60)
    _orphan, orphan_pool = pooled_replay(root, "orphan", age=OLD, alias=False, journal=False,
                                         record=False)
    (root / (live + ".catalog.sqlite3")).write_bytes(b'{"protocol":"unknown"}')
    with pytest.raises(pool.PoolError):
        pool.collect_unreferenced(os.open(root, os.O_RDONLY), now=__import__("time").time(),
                                  grace=0, check=lambda: None)
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=True)
    assert {live_pool, orphan_pool} <= names(root)


@posix
def test_sqlite_side_files_from_outside_readers_are_collected(replay_root):
    facade, root = replay_root
    replay = hexid("side-files")
    write(root, replay + ".catalog.sqlite3", b"SQLite format 3\x00" + b"x" * 64, age=60)
    write(root, replay + ".json", b"{}", age=60)
    write(root, replay + ".catalog.sqlite3-wal", b"", age=OLD)
    write(root, replay + ".catalog.sqlite3-shm", b"\x00" * 32768, age=OLD)
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=True)
    left = names(root)
    assert {replay + ".catalog.sqlite3", replay + ".json"} <= left
    assert not {replay + ".catalog.sqlite3-wal", replay + ".catalog.sqlite3-shm"} & left


@posix
def test_pending_wal_still_refuses_inventory(replay_root):
    facade, root = replay_root
    replay = hexid("pending-wal")
    write(root, replay + ".catalog.sqlite3", b"SQLite format 3\x00" + b"x" * 64, age=60)
    write(root, replay + ".catalog.sqlite3-wal", b"frame", age=OLD)
    with facade._context_replay_maintenance_lock(), pytest.raises(m.McpFacadeError,
                                                                  match="pending WAL"):
        facade._context_replay_inventory(prune=True)
    assert replay + ".catalog.sqlite3-wal" in names(root)


@posix
def test_inventory_without_prune_removes_nothing(replay_root):
    facade, root = replay_root
    pooled_replay(root, "expired", age=OLD)
    write(root, hexid("side") + ".catalog.sqlite3-shm", b"\x00" * 1024, age=OLD)
    before = names(root)
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=False)
    assert names(root) == before


def test_pool_reference_requires_exact_own_descriptor():
    replay = hexid("exact")
    name = replay + ".catalog.sqlite3"
    content = b"bytes"
    binding = {"protocol": "integrity-client/context-admission-frozen-catalog/v1", "name": name,
               "sha256": "sha256:" + hashlib.sha256(content).hexdigest(), "bytes": len(content)}
    document = pool.alias_document(name, binding)
    assert pool._reference(pool.canonical(document), name, journal=False) == document["pool_name"]
    journal = pool.canonical({"protocol": pool.JOURNAL, "alias": document,
                              "alias_sha256": pool.sha(pool.canonical(document))})
    assert pool._reference(journal, "." + replay + ".catalog-pool.json", journal=True) == document["pool_name"]
    other = hexid("other") + ".catalog.sqlite3"
    with pytest.raises(pool.PoolError):
        pool._reference(pool.canonical(document), other, journal=False)
    with pytest.raises(pool.PoolError):
        pool._reference(pool.canonical({**document, "pool_name": ".catalog-pool-" + "0" * 64 + ".sqlite3"}),
                        name, journal=False)


@posix
def test_pool_member_side_files_are_collected_with_and_without_the_pool(replay_root):
    facade, root = replay_root
    live, live_pool = pooled_replay(root, "live", age=60)
    _orphan, orphan_pool = pooled_replay(root, "orphan", age=OLD, alias=False, journal=False,
                                         record=False)
    for member in (live_pool, orphan_pool):
        write(root, member + "-wal", b"", age=OLD)
        write(root, member + "-shm", b"\x00" * 32768, age=OLD)
    with facade._context_replay_maintenance_lock():
        facade._context_replay_inventory(prune=True)
    left = names(root)
    assert live_pool in left and orphan_pool not in left
    assert not {name for name in left if name.endswith(("-wal", "-shm"))}
