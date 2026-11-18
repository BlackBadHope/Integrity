"""ISS-113: a replay catalog member stored as a page delta against one full member.

Consecutive frozen Seed catalogs differ in a few hundred pages, yet each used to
cost a full ~300 MB pool member, so the 4 GiB replay store held only ~12 replays.
These tests pin the delta contract: byte-exact reconstruction verified against the
unchanged logical binding, no reference without a present base, GC that never
leaves a delta pointing at collected bytes, and an explicit purge for rollback.
"""
from __future__ import annotations

import hashlib
import os

import pytest

from integrity_guardian import replay_catalog_pool as pool

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Actual POSIX replay custody")

PAGE = 4096


def _catalog(pages: int, seed: bytes = b"base", changed: dict[int, bytes] | None = None) -> bytes:
    header = bytearray(b"SQLite format 3\x00" + PAGE.to_bytes(2, "big") + b"\x00" * (PAGE - 18))
    body = [bytes(header)] + [(seed + i.to_bytes(4, "big")) * (PAGE // (len(seed) + 4)) for i in range(1, pages)]
    body = [chunk.ljust(PAGE, b"\x00")[:PAGE] for chunk in body]
    for index, value in (changed or {}).items():
        if index < len(body):
            body[index] = value.ljust(PAGE, b"\x01")[:PAGE]
        else:
            body.append(value.ljust(PAGE, b"\x01")[:PAGE])
    return b"".join(body)


def _write(root, name, raw):
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    os.chmod(root / name, 0o600)


def _binding(name, content):
    return {"protocol": "integrity-client/context-admission-frozen-catalog/v1", "name": name,
            "sha256": "sha256:" + hashlib.sha256(content).hexdigest(), "bytes": len(content)}


def _base_name(content):
    return ".catalog-pool-" + hashlib.sha256(content).hexdigest() + ".sqlite3"


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "replay"
    root.mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY)
    yield root, pool.FdStore(descriptor, lambda: None), tmp_path
    os.close(descriptor)


BASE = _catalog(64)
TARGET = _catalog(64, changed={3: b"three", 40: b"forty", 64: b"appended", 65: b"tail"})
NAME = "a" * 64 + ".catalog.sqlite3"
OTHER = "b" * 64 + ".catalog.sqlite3"


def _delta_tmp(root, fd_store, base, target, tmp_path, *, limit=pool.MAX_DELTA):
    source = tmp_path / ("source-" + hashlib.sha256(target).hexdigest()[:8])
    source.write_bytes(target)
    temporary = "." + NAME + ".1.1.tmp"
    out = os.open(root / temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    src = os.open(source, os.O_RDONLY)
    try:
        written = pool.write_delta_store(fd_store, base, src, len(target), out, limit=limit)
        os.fsync(out)
    finally:
        os.close(src)
        os.close(out)
    return temporary, written


def _rebuild(root, fd_store, member, binding, tmp_path):
    out = os.open(tmp_path / "rebuilt", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        fd_store.reconstruct(member, binding, out)
        return os.pread(out, binding["bytes"] + 1, 0)
    finally:
        os.close(out)


def test_delta_round_trip_is_byte_exact_and_small(store):
    root, fd_store, tmp_path = store
    _write(root, _base_name(BASE), BASE)
    temporary, written = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path)
    binding = _binding(NAME, TARGET)
    assert written["sha256"] == binding["sha256"] and written["bytes"] == len(TARGET)
    assert written["pages"] == 4
    assert written["delta_bytes"] == pool.DELTA_HEADER_AREA + 4 * (8 + PAGE) < len(TARGET) // 8
    assert pool.adopt_delta_store(fd_store, NAME, binding, temporary) is True
    member = ".catalog-delta-" + binding["sha256"][7:] + ".bin"
    assert pool.resolve(fd_store, NAME, binding) == member
    assert pool.logical_size(fd_store.root, NAME, binding, 1, lambda: None) == len(TARGET)
    assert _rebuild(root, fd_store, member, binding, tmp_path) == TARGET
    assert pool.referenced_pools(fd_store, sorted(os.listdir(root))) == {member, _base_name(BASE)}
    assert (root / ("." + "a" * 64 + ".catalog-pool.json")).exists()          # own journal


def test_shorter_target_and_existing_member_reuse(store):
    root, fd_store, tmp_path = store
    shorter = _catalog(40, changed={7: b"seven"})
    _write(root, _base_name(BASE), BASE)
    temporary, _ = _delta_tmp(root, fd_store, _base_name(BASE), shorter, tmp_path)
    assert pool.adopt_delta_store(fd_store, NAME, _binding(NAME, shorter), temporary) is True
    # A second replay of the same bytes reuses the content-addressed member.
    assert pool.adopt_delta_store(fd_store, OTHER, _binding(OTHER, shorter), None) is True
    member = pool.resolve(fd_store, OTHER, _binding(OTHER, shorter))
    assert _rebuild(root, fd_store, member, _binding(OTHER, shorter), tmp_path) == shorter


def test_over_limit_returns_none(store):
    root, fd_store, tmp_path = store
    _write(root, _base_name(BASE), BASE)
    _, written = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path, limit=2 * (8 + PAGE))
    assert written is None


def test_other_page_geometry_returns_none(store):
    root, fd_store, tmp_path = store
    odd = BASE[:16] + (8192).to_bytes(2, "big") + BASE[18:]
    _write(root, _base_name(odd), odd)
    _, written = _delta_tmp(root, fd_store, _base_name(odd), TARGET, tmp_path)
    assert written is None


def test_tampered_payload_or_base_is_refused(store):
    root, fd_store, tmp_path = store
    _write(root, _base_name(BASE), BASE)
    temporary, _ = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path)
    binding = _binding(NAME, TARGET)
    assert pool.adopt_delta_store(fd_store, NAME, binding, temporary) is True
    member = pool.resolve(fd_store, NAME, binding)
    raw = bytearray((root / member).read_bytes())
    raw[-1] ^= 0xFF
    (root / member).write_bytes(bytes(raw))
    with pytest.raises(pool.PoolError, match="content-changed"):
        _rebuild(root, fd_store, member, binding, tmp_path)
    raw[-1] ^= 0xFF
    (root / member).write_bytes(bytes(raw))
    base = bytearray((root / _base_name(BASE)).read_bytes())
    base[PAGE * 10] ^= 0xFF
    (root / _base_name(BASE)).write_bytes(bytes(base))
    with pytest.raises(pool.PoolError, match="base-changed"):
        _rebuild(root, fd_store, member, binding, tmp_path)


def test_wrong_binding_is_refused(store):
    root, fd_store, tmp_path = store
    _write(root, _base_name(BASE), BASE)
    temporary, _ = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path)
    assert pool.adopt_delta_store(fd_store, NAME, _binding(NAME, TARGET), temporary) is True
    member = pool.resolve(fd_store, NAME, _binding(NAME, TARGET))
    with pytest.raises(pool.PoolError, match="binding-mismatch"):
        _rebuild(root, fd_store, member, _binding(NAME, BASE), tmp_path)


def test_missing_base_writes_no_reference(store):
    root, fd_store, tmp_path = store
    _write(root, _base_name(BASE), BASE)
    temporary, _ = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path)
    os.unlink(root / _base_name(BASE))
    assert pool.adopt_delta_store(fd_store, NAME, _binding(NAME, TARGET), temporary) is False
    assert not (root / NAME).exists()
    assert not (root / ("." + "a" * 64 + ".catalog-pool.json")).exists()


def test_gc_keeps_base_while_any_delta_remains_then_collects_both(store):
    root, fd_store, tmp_path = store
    _write(root, _base_name(BASE), BASE)
    temporary, _ = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path)
    binding = _binding(NAME, TARGET)
    assert pool.adopt_delta_store(fd_store, NAME, binding, temporary) is True
    member = pool.resolve(fd_store, NAME, binding)
    assert pool.collect_unreferenced_store(fd_store, now=10 ** 12, grace=0) == []
    # The replay expires: its alias and journal go first (facade TTL policy).
    os.unlink(root / NAME)
    os.unlink(root / ("." + "a" * 64 + ".catalog-pool.json"))
    removed = pool.collect_unreferenced_store(fd_store, now=10 ** 12, grace=0)
    assert member in removed
    # The base stayed pinned by the delta during that pass; the next pass collects it.
    assert pool.collect_unreferenced_store(fd_store, now=10 ** 12, grace=0) == [_base_name(BASE)]
    assert os.listdir(root) == []


def test_unparsable_delta_pins_everything(store):
    root, fd_store, _ = store
    _write(root, _base_name(BASE), BASE)
    _write(root, ".catalog-delta-" + "c" * 64 + ".bin", b"garbage" * 10)
    with pytest.raises(pool.PoolError):
        pool.collect_unreferenced_store(fd_store, now=10 ** 12, grace=0)
    assert (root / _base_name(BASE)).exists()


def test_materialize_refuses_and_purge_retires_delta_replays(store):
    root, fd_store, tmp_path = store
    _write(root, _base_name(BASE), BASE)
    full = pool.alias_document(OTHER, _binding(OTHER, BASE))
    _write(root, OTHER, pool.canonical(full))                                # full-pool replay stays
    temporary, _ = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path)
    assert pool.adopt_delta_store(fd_store, NAME, _binding(NAME, TARGET), temporary) is True
    _write(root, "a" * 64 + ".json", b"{}")
    _write(root, "a" * 64 + ".reservation.json", b"{}")
    with pytest.raises(pool.PoolError, match="purge-first"):
        pool.materialize_store(fd_store, [], 0)
    result = pool.purge_delta_layout_store(fd_store)
    assert result["replays"] == 1 and result["canonical_writes"] == 0
    assert sorted(os.listdir(root)) == sorted([_base_name(BASE), OTHER])


def test_newest_base_ignores_deltas(store):
    root, fd_store, tmp_path = store
    assert pool.newest_base_store(fd_store) is None
    _write(root, _base_name(BASE), BASE)
    temporary, _ = _delta_tmp(root, fd_store, _base_name(BASE), TARGET, tmp_path)
    pool.adopt_delta_store(fd_store, NAME, _binding(NAME, TARGET), temporary)
    assert pool.newest_base_store(fd_store) == _base_name(BASE)
