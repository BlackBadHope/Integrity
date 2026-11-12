"""Anchored ledger verification: a signed checkpoint binds the prefix, new rows get full checks."""

from __future__ import annotations

import sqlite3

import pytest

import integrity_guardian.ledger as ledger_module
from integrity_guardian.ledger import LedgerStore, LedgerVerificationError, build_ledger_event
from integrity_guardian.signing import Ed25519Signer, TrustedKey

TENANT = "tenant:anchor-test"
LEDGER = "ledger:anchor-test"
SOURCE = "source:anchor-test"


def _store(tmp_path, count, *, cache=False):
    source = Ed25519Signer.generate("key:source")
    checkpoint_signer = Ed25519Signer.generate("key:checkpoint")
    store = LedgerStore(tmp_path / "ledger.sqlite3", tenant_id=TENANT, ledger_id=LEDGER,
                        cache_verified_events=cache)
    previous = None
    for index in range(count):
        event = build_ledger_event(tenant_id=TENANT, source_id=SOURCE, source_sequence=index,
                                   event_type="observation", payload_digest="sha256:" + f"{index:064x}",
                                   previous_event_digest=previous, signer=source,
                                   recorded_at="2026-11-06T00:00:00Z")
        previous = store.append(event)
    keys = {SOURCE: TrustedKey("key:source", source.public_key)}
    checkpoint_key = TrustedKey("key:checkpoint", checkpoint_signer.public_key)
    return store, source, checkpoint_signer, keys, checkpoint_key, previous


def _append(store, source, sequence, previous):
    event = build_ledger_event(tenant_id=TENANT, source_id=SOURCE, source_sequence=sequence,
                               event_type="observation", payload_digest="sha256:" + f"{sequence:064x}",
                               previous_event_digest=previous, signer=source,
                               recorded_at="2026-11-06T00:00:00Z")
    return store.append(event)


def test_anchor_skips_per_row_checks_inside_the_prefix_only(tmp_path, monkeypatch):
    store, source, cp_signer, keys, cp_key, tip = _store(tmp_path, 20)
    anchor = store.checkpoint(checkpoint_id="checkpoint:a", signer=cp_signer)
    _append(store, source, 20, tip)
    calls = []
    real = ledger_module.verify_signature
    monkeypatch.setattr(ledger_module, "verify_signature", lambda obj, key: calls.append(1) or real(obj, key))
    result = store.verify(source_public_keys=keys, anchor=anchor, checkpoint_key=cp_key)
    assert result["tree_size"] == 21
    assert len(calls) == 2  # the anchor's own signature + the one row after it


def test_tampered_row_inside_the_anchor_is_still_rejected(tmp_path):
    store, _source, cp_signer, keys, cp_key, _tip = _store(tmp_path, 10)
    anchor = store.checkpoint(checkpoint_id="checkpoint:a", signer=cp_signer)
    store.close() if hasattr(store, "close") else None
    raw = sqlite3.connect(tmp_path / "ledger.sqlite3")
    row = raw.execute("SELECT event_json FROM ledger_events WHERE ledger_sequence = 3").fetchone()[0]
    raw.execute("UPDATE ledger_events SET event_json = ? WHERE ledger_sequence = 3",
                (row.replace(b"observation", b"observatioN"),))
    raw.commit()
    raw.close()
    reopened = LedgerStore(tmp_path / "ledger.sqlite3", tenant_id=TENANT, ledger_id=LEDGER)
    with pytest.raises(LedgerVerificationError):
        reopened.verify(source_public_keys=keys, anchor=anchor, checkpoint_key=cp_key)


def test_anchor_with_a_foreign_signature_or_scope_is_rejected(tmp_path):
    store, _source, cp_signer, keys, cp_key, _tip = _store(tmp_path, 5)
    anchor = store.checkpoint(checkpoint_id="checkpoint:a", signer=cp_signer)
    stranger = Ed25519Signer.generate("key:checkpoint")
    with pytest.raises(LedgerVerificationError):
        store.verify(source_public_keys=keys, anchor=anchor,
                     checkpoint_key=TrustedKey("key:checkpoint", stranger.public_key))
    forged = dict(anchor, root_digest="sha256:" + "0" * 64)
    with pytest.raises(LedgerVerificationError):
        store.verify(source_public_keys=keys, anchor=forged, checkpoint_key=cp_key)


def test_rows_after_the_anchor_keep_full_signature_checks(tmp_path):
    store, _source, cp_signer, keys, cp_key, tip = _store(tmp_path, 6)
    anchor = store.checkpoint(checkpoint_id="checkpoint:a", signer=cp_signer)
    intruder = Ed25519Signer.generate("key:source")  # same key id, wrong private key
    _append(store, intruder, 6, tip)
    with pytest.raises(LedgerVerificationError):
        store.verify(source_public_keys=keys, anchor=anchor, checkpoint_key=cp_key)


def test_anchor_larger_than_the_ledger_is_rejected(tmp_path):
    store, _source, cp_signer, keys, cp_key, _tip = _store(tmp_path, 4)
    anchor = store.checkpoint(checkpoint_id="checkpoint:a", signer=cp_signer)
    other, *_ = _store(tmp_path / "other", 2) if (tmp_path / "other").mkdir() is None else (None,)
    with pytest.raises(LedgerVerificationError):
        other.verify(source_public_keys=keys, anchor=dict(anchor), checkpoint_key=cp_key)


def test_reordered_rows_are_rejected_with_an_anchor(tmp_path):
    store, _source, cp_signer, keys, cp_key, _tip = _store(tmp_path, 8)
    anchor = store.checkpoint(checkpoint_id="checkpoint:a", signer=cp_signer)
    raw = sqlite3.connect(tmp_path / "ledger.sqlite3")
    raw.execute("UPDATE ledger_events SET ledger_sequence = 1000 WHERE ledger_sequence = 3")
    raw.execute("UPDATE ledger_events SET ledger_sequence = 3 WHERE ledger_sequence = 4")
    raw.execute("UPDATE ledger_events SET ledger_sequence = 4 WHERE ledger_sequence = 1000")
    raw.commit()
    raw.close()
    reopened = LedgerStore(tmp_path / "ledger.sqlite3", tenant_id=TENANT, ledger_id=LEDGER)
    with pytest.raises(LedgerVerificationError):
        reopened.verify(source_public_keys=keys, anchor=anchor, checkpoint_key=cp_key)


def test_anchored_path_reports_the_same_root_and_size_as_a_full_verify(tmp_path):
    store, source, cp_signer, keys, cp_key, tip = _store(tmp_path, 12)
    anchor = store.checkpoint(checkpoint_id="checkpoint:a", signer=cp_signer)
    tip = _append(store, source, 12, tip)
    _append(store, source, 13, tip)
    final = store.checkpoint(checkpoint_id="checkpoint:b", signer=cp_signer)
    full = store.verify(source_public_keys=keys, checkpoint=final, checkpoint_key=cp_key)
    fresh = LedgerStore(tmp_path / "ledger.sqlite3", tenant_id=TENANT, ledger_id=LEDGER)
    anchored = fresh.verify(source_public_keys=keys, anchor=anchor, checkpoint=final, checkpoint_key=cp_key)
    assert anchored == full and anchored["tree_size"] == 14
    assert ledger_module.merkle_root(fresh.event_digests()) == final["root_digest"]
