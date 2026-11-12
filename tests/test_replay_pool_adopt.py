"""Adopting an existing content-addressed replay pool skips the second full copy.

Every admission used to write a full copy of the frozen Seed catalog (~239 MB live)
and fsync it, then hash the same bytes several times, even when the pool already held
those exact bytes. Adoption verifies the pool once and writes only the journal and
alias; any mismatch writes nothing and the caller keeps the original path.
"""
from __future__ import annotations

import hashlib
import os

import pytest

from integrity_guardian import replay_catalog_pool as pool

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Actual POSIX replay custody")


def _write(root, name, raw):
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    os.chmod(root / name, 0o600)


def _binding(name, content):
    return {"protocol": "integrity-client/context-admission-frozen-catalog/v1", "name": name,
            "sha256": "sha256:" + hashlib.sha256(content).hexdigest(), "bytes": len(content)}


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "replay"
    root.mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY)
    yield root, pool.FdStore(descriptor, lambda: None)
    os.close(descriptor)


CONTENT = b"SQLite format 3\x00" + b"seed" * 4096
NAME = "a" * 64 + ".catalog.sqlite3"


def test_existing_pool_is_adopted_without_a_copy(store):
    root, fd_store = store
    binding = _binding(NAME, CONTENT)
    document = pool.alias_document(NAME, binding)
    _write(root, document["pool_name"], CONTENT)
    assert pool.adopt_existing_pool_store(fd_store, NAME, binding) is True
    assert (root / NAME).read_bytes() == pool.canonical(document)        # alias, not bytes
    assert pool.resolve(fd_store, NAME, binding) == document["pool_name"]
    assert pool.referenced_pools(fd_store, sorted(os.listdir(root))) == {document["pool_name"]}
    # Same end state as promote_store over an existing pool: journal + alias.
    assert (root / ("." + "a" * 64 + ".catalog-pool.json")).exists()


def test_missing_pool_writes_nothing(store):
    root, fd_store = store
    assert pool.adopt_existing_pool_store(fd_store, NAME, _binding(NAME, CONTENT)) is False
    assert os.listdir(root) == []


def test_changed_pool_bytes_are_refused_and_nothing_is_written(store):
    root, fd_store = store
    binding = _binding(NAME, CONTENT)
    document = pool.alias_document(NAME, binding)
    _write(root, document["pool_name"], CONTENT[:-1] + b"X")             # same size, other bytes
    with pytest.raises(pool.PoolError, match="content-changed"):
        pool.adopt_existing_pool_store(fd_store, NAME, binding)
    assert sorted(os.listdir(root)) == [document["pool_name"]]


def test_existing_leaf_or_journal_keeps_the_original_path(store):
    root, fd_store = store
    binding = _binding(NAME, CONTENT)
    document = pool.alias_document(NAME, binding)
    _write(root, document["pool_name"], CONTENT)
    _write(root, NAME, CONTENT)                                            # unpromoted leaf
    assert pool.adopt_existing_pool_store(fd_store, NAME, binding) is False
    assert (root / NAME).read_bytes() == CONTENT
