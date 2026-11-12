"""Scheduled full custody verification: records pass/fail; a fail blocks admission."""

from __future__ import annotations

import json
import os
import sqlite3

import pytest

from integrity_guardian import medor_architecture as a
from integrity_guardian.signing import Ed25519Signer

pytestmark = pytest.mark.skipif(os.name != "posix", reason="custody root requires POSIX modes")


def _service(tmp_path):
    root = tmp_path / "arch"
    keys = a.MedorArchitectureKeys(
        source_signer=Ed25519Signer.generate("key:medor-architecture-source"),
        checkpoint_signer=Ed25519Signer.generate("key:medor-architecture-checkpoint"),
    )
    return a.PersistentMedorArchitectureService(root, keys=keys)


def _record(service, n):
    for index in range(n):
        service._record_admission_custody(payload_digest="sha256:" + f"{index:064x}",
                                          observed_at="2026-11-06T00:00:00Z")


def test_full_verify_passes_and_reports_the_checkpointed_root(tmp_path):
    service = _service(tmp_path)
    _record(service, 5)
    status = service.full_verify()
    assert status["result"] == "pass" and status["tree_size"] == 5
    assert status["root_digest"] == status["checkpoint_root_digest"]
    stored = json.loads(service.full_verify_status_path.read_text())
    assert stored == status
    _record(service, 1)  # admission still works after a pass


def test_failed_full_verify_blocks_admission_until_repaired(tmp_path):
    service = _service(tmp_path)
    _record(service, 4)
    raw = sqlite3.connect(service.ledger_path)
    row = raw.execute("SELECT event_json FROM ledger_events WHERE ledger_sequence = 2").fetchone()[0]
    raw.execute("UPDATE ledger_events SET event_json = ? WHERE ledger_sequence = 2",
                (row.replace(b"observation", b"observatioN") if isinstance(row, bytes)
                 else row.replace("observation", "observatioN"),))
    raw.commit()
    raw.close()
    status = service.full_verify()
    assert status["result"] == "fail"
    with pytest.raises(a.MedorArchitectureError, match="full verification failed"):
        _record(service, 1)


def test_stale_full_verify_status_blocks_admission(tmp_path):
    service = _service(tmp_path)
    _record(service, 2)
    service.full_verify(observed_at="2020-01-01T00:00:00Z")
    with pytest.raises(a.MedorArchitectureError, match="stale"):
        _record(service, 1)
    service.full_verify()  # a fresh run clears the block
    _record(service, 1)


def test_deleted_status_after_a_completed_run_blocks_admission(tmp_path):
    service = _service(tmp_path)
    _record(service, 2)          # bootstrap: no status yet, admission allowed
    service.full_verify()
    service.full_verify_status_path.unlink()
    with pytest.raises(a.MedorArchitectureError, match="missing after a completed run"):
        _record(service, 1)
    assert service._full_verify_marker_present()
    service.full_verify()        # a fresh run restores the status and admission
    _record(service, 1)


def test_server_entrypoint_accepts_the_full_verify_flag():
    import inspect

    from integrity_guardian import memory_synapse_mcp_protocol as protocol

    assert "--custody-full-verify" in inspect.getsource(protocol.main)
