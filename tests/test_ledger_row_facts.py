"""Repeated verify passes in one connection reuse facts only for exact verified bytes."""
from __future__ import annotations

import sqlite3

import pytest

from integrity_guardian import ledger as ledger_module
from integrity_guardian.ledger import LedgerStore, LedgerVerificationError, build_ledger_event
from integrity_guardian.signing import Ed25519Signer, TrustedKey


def _ledger(tmp_path, count, *, cache=True):
    signer = Ed25519Signer.generate("key:row-facts-source")
    store = LedgerStore(tmp_path / "l.sqlite3", tenant_id="tenant:t", ledger_id="ledger:l",
                        cache_verified_events=cache)
    previous = None
    for index in range(count):
        event = build_ledger_event(tenant_id="tenant:t", source_id="source:s", source_sequence=index,
                                   event_type="observation", payload_digest="sha256:" + f"{index:064x}",
                                   previous_event_digest=previous, signer=signer,
                                   recorded_at="2026-11-06T00:00:00Z")
        previous = store.append(event)
    return store, {"source:s": TrustedKey("key:row-facts-source", signer.public_key)}


def test_second_pass_skips_parse_and_digest_for_verified_bytes(tmp_path, monkeypatch):
    store, keys = _ledger(tmp_path, 6)
    first = store.verify(source_public_keys=keys)
    calls = {"parse": 0}
    original = ledger_module.parse_json_strict
    monkeypatch.setattr(ledger_module, "parse_json_strict",
                        lambda raw: (calls.__setitem__("parse", calls["parse"] + 1), original(raw))[1])
    assert store.verify(source_public_keys=keys) == first
    assert calls["parse"] == 0
    store.close()


def test_changed_bytes_miss_the_cache_and_fail(tmp_path):
    store, keys = _ledger(tmp_path, 4)
    store.verify(source_public_keys=keys)
    raw = sqlite3.connect(tmp_path / "l.sqlite3")
    row = raw.execute("SELECT event_json FROM ledger_events WHERE ledger_sequence = 2").fetchone()[0]
    changed = row.replace(b"observation", b"observatioN") if isinstance(row, bytes) else row.replace(
        "observation", "observatioN")
    raw.execute("UPDATE ledger_events SET event_json = ? WHERE ledger_sequence = 2", (changed,))
    raw.commit()
    raw.close()
    with pytest.raises(LedgerVerificationError):
        store.verify(source_public_keys=keys)
    store.close()


def test_changed_digest_column_still_fails_with_cached_facts(tmp_path):
    store, keys = _ledger(tmp_path, 3)
    store.verify(source_public_keys=keys)
    raw = sqlite3.connect(tmp_path / "l.sqlite3")
    raw.execute("UPDATE ledger_events SET event_digest = ? WHERE ledger_sequence = 2",
                ("sha256:" + "0" * 64,))
    raw.commit()
    raw.close()
    with pytest.raises(LedgerVerificationError, match="digest mismatch"):
        store.verify(source_public_keys=keys)
    store.close()


def test_other_key_material_does_not_reuse_facts(tmp_path):
    store, keys = _ledger(tmp_path, 3)
    store.verify(source_public_keys=keys)
    other = {"source:s": TrustedKey("key:row-facts-source", Ed25519Signer.generate("key:row-facts-source").public_key)}
    with pytest.raises(LedgerVerificationError, match="signature"):
        store.verify(source_public_keys=other)
    store.close()
