from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_recovery as recovery_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs import (
    ToolzRouteMemoryOutcome,
    build_toolz_route_memory_receipt,
    toolz_route_memory_digest,
)
from integrity_guardian.uroboros_toolzs_recovery import (
    ToolzAdmissionRecoveryError,
    ToolzAdmissionRecoveryPolicy,
    recover_toolz_admission_install,
    toolz_admission_recovery_identity,
    verify_toolz_admission_recovery_receipt,
)
from integrity_guardian.uroboros_toolzs_store import (
    STORE_DATABASE_NAME,
    ToolzRouteMemoryStore,
    ToolzRouteStoreError,
    ToolzStoreLifecycle,
    ToolzStoreRecoveryStatus,
)
from tests.test_uroboros_toolzs import (
    MEMORY_EXPIRES,
    _trusted,
)
from tests.test_uroboros_toolzs_admission import (
    _AdmissionFixture,
    _admit,
    _fixture,
)
from tests.test_uroboros_toolzs_install import (
    EVALUATED,
    RECORDED,
    _install,
    _policy,
    _store,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")

RECOVERY_EVALUATED = "2026-07-29T04:23:00Z"
RECOVERED = "2026-07-29T04:24:00Z"


def _recovery_policy(
    fixture: _AdmissionFixture,
) -> ToolzAdmissionRecoveryPolicy:
    return ToolzAdmissionRecoveryPolicy(
        policy_id="policy:synthetic-toolz-admission-recovery",
        install_policy=_policy(fixture),
        max_evaluation_to_recovery_seconds=60,
    )


def _recover(
    fixture: _AdmissionFixture,
    admission: Any,
    root: Path,
    store_signer: Ed25519Signer,
    *,
    retained_cursor: Any,
    memory_receipt: dict[str, Any] | None = None,
    store_key: Any = None,
    policy: ToolzAdmissionRecoveryPolicy | None = None,
    evaluated_at: str = RECOVERY_EVALUATED,
    recovered_at: str = RECOVERED,
):
    return recover_toolz_admission_install(
        policy=policy or _recovery_policy(fixture),
        admission_receipt=admission.receipt,
        trace=fixture.trace,
        observer_key=_trusted(fixture.observer_signer),
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        memory_receipt=memory_receipt or admission.memory_receipt,
        memory_key=_trusted(fixture.memory_signer),
        admission_key=_trusted(fixture.admission_signer),
        store_root=root,
        store_key=store_key or _trusted(store_signer),
        store_signer=store_signer,
        retained_cursor=retained_cursor,
        evaluated_at=evaluated_at,
        recovered_at=recovered_at,
    )


def _database_digest(root: Path) -> str:
    return hashlib.sha256((root / STORE_DATABASE_NAME).read_bytes()).hexdigest()


def _conflicting_memory(
    fixture: _AdmissionFixture,
) -> dict[str, Any]:
    return build_toolz_route_memory_receipt(
        policy=fixture.memory_policy,
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        observed_at=None,
        observation_evidence_digest=None,
        created_at="2026-07-29T04:19:00Z",
        expires_at=MEMORY_EXPIRES,
        memory_signer=fixture.memory_signer,
    )


def test_unchanged_retained_head_is_safe_to_retry_without_a_write(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-retained")
    with _store(root, store_signer) as store:
        retained = store.cursor
    before_digest = _database_digest(root)

    result = _recover(
        fixture,
        admission,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        assert result.status is ToolzStoreRecoveryStatus.RETAINED_HEAD
        assert result.store_cursor == retained
        assert result.storage_performed is False
        assert result.execution_authority is False
        assert result.receipt["store"]["status"] == "retained-head"
        assert result.receipt["authority_boundary"]["local_storage"] is True
        assert all(
            not value
            for name, value in result.receipt["authority_boundary"].items()
            if name != "local_storage"
        )
        assert result.store.entries(expected_cursor=retained) == []
    finally:
        result.store.close()

    assert _database_digest(root) == before_digest


def test_lost_install_cursor_recovers_only_the_exact_immediate_child(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-crash")
    with _store(root, store_signer) as store:
        retained = store.cursor
        installed = _install(
            fixture,
            admission,
            store,
            store_signer,
            expected_cursor=retained,
        )
        installed_cursor = installed.store_cursor
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzRouteStoreError,
        match="rollback or concurrent head change",
    ):
        ToolzRouteMemoryStore.open(
            root,
            store_id=_policy(fixture).store_id,
            tenant_id=SYNTHETIC_TENANT,
            authority_key=_trusted(store_signer),
            expected_cursor=retained,
        )

    result = _recover(
        fixture,
        admission,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        assert result.status is ToolzStoreRecoveryStatus.RECOVERED_INSTALL
        assert result.store_cursor == installed_cursor
        assert result.store_cursor.sequence == retained.sequence + 1
        assert result.receipt["store"]["status"] == "recovered-install"
        assert result.receipt["store"]["recovered_manifest_created_at"] == (RECORDED)
        assert result.receipt["authority_boundary"]["historical_install_invocation"] is False
        assert result.receipt["authority_boundary"]["install_receipt_reconstruction"] is False
        entries = result.store.entries(
            expected_cursor=result.store_cursor,
        )
        assert len(entries) == 1
        assert entries[0]["generation"] == 1
        assert entries[0]["lifecycle"] == ToolzStoreLifecycle.THEORETICAL
        assert entries[0]["receipt_digest"] == toolz_route_memory_digest(admission.memory_receipt)
    finally:
        result.store.close()

    assert _database_digest(root) == before_digest


def test_one_unrelated_child_is_rejected_without_database_mutation(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-unrelated")
    conflicting = _conflicting_memory(fixture)
    with _store(root, store_signer) as store:
        retained = store.cursor
        child = store.put(
            conflicting,
            expected_cursor=retained,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_key=_trusted(fixture.memory_signer),
            evaluated_at="2026-07-29T04:19:30Z",
            recorded_at="2026-07-29T04:20:00Z",
            store_signer=store_signer,
        )
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzAdmissionRecoveryError,
        match="store proof",
    ):
        _recover(
            fixture,
            admission,
            root,
            store_signer,
            retained_cursor=retained,
        )

    assert _database_digest(root) == before_digest
    with ToolzRouteMemoryStore.open(
        root,
        store_id=_policy(fixture).store_id,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=child,
    ) as store:
        assert store.cursor == child


def test_two_descendants_remain_rollback_or_concurrency_ambiguous(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-two-steps")
    with _store(root, store_signer) as store:
        retained = store.cursor
        first = store.put(
            _conflicting_memory(fixture),
            expected_cursor=retained,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_key=_trusted(fixture.memory_signer),
            evaluated_at="2026-07-29T04:19:30Z",
            recorded_at="2026-07-29T04:20:00Z",
            store_signer=store_signer,
        )
        second = store.put(
            admission.memory_receipt,
            expected_cursor=first,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_key=_trusted(fixture.memory_signer),
            evaluated_at=EVALUATED,
            recorded_at=RECORDED,
            store_signer=store_signer,
        )

    with pytest.raises(
        ToolzAdmissionRecoveryError,
        match="store proof",
    ):
        _recover(
            fixture,
            admission,
            root,
            store_signer,
            retained_cursor=retained,
        )

    with ToolzRouteMemoryStore.open(
        root,
        store_id=_policy(fixture).store_id,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=second,
    ) as store:
        assert store.cursor.sequence == retained.sequence + 2


def test_exact_child_created_after_recovery_observation_is_rejected(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-future-child")
    with _store(root, store_signer) as store:
        retained = store.cursor
        future_child = store.put(
            admission.memory_receipt,
            expected_cursor=retained,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_key=_trusted(fixture.memory_signer),
            evaluated_at=EVALUATED,
            recorded_at="2026-07-29T04:26:00Z",
            store_signer=store_signer,
        )

    with pytest.raises(
        ToolzAdmissionRecoveryError,
        match="store proof",
    ):
        _recover(
            fixture,
            admission,
            root,
            store_signer,
            retained_cursor=retained,
        )

    with ToolzRouteMemoryStore.open(
        root,
        store_id=_policy(fixture).store_id,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=future_child,
    ) as store:
        assert store.cursor == future_child


def test_store_level_recovery_rejects_an_unchanged_future_head(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-recovery-future-head"
    )
    with ToolzRouteMemoryStore.initialize(
        root,
        store_id=_policy(fixture).store_id,
        tenant_id=SYNTHETIC_TENANT,
        store_signer=store_signer,
        created_at="2026-07-29T04:26:00Z",
    ) as store:
        retained = store.cursor

    with pytest.raises(
        ToolzRouteStoreError,
        match="manifest timing",
    ):
        ToolzRouteMemoryStore.recover_one_step_install(
            root,
            store_id=_policy(fixture).store_id,
            tenant_id=SYNTHETIC_TENANT,
            authority_key=_trusted(store_signer),
            retained_cursor=retained,
            receipt=admission.memory_receipt,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_key=_trusted(fixture.memory_signer),
            evaluated_at=RECOVERY_EVALUATED,
        )


def test_substitution_signer_and_recovery_window_fail_before_open(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-bindings")
    wrong_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-wrong-store")
    with _store(root, store_signer) as store:
        retained = store.cursor

    with pytest.raises(
        ToolzAdmissionRecoveryError,
        match="admission",
    ):
        _recover(
            fixture,
            admission,
            root,
            store_signer,
            retained_cursor=retained,
            memory_receipt=_conflicting_memory(fixture),
        )
    with pytest.raises(
        ToolzAdmissionRecoveryError,
        match="signer mismatch",
    ):
        _recover(
            fixture,
            admission,
            root,
            wrong_signer,
            retained_cursor=retained,
            store_key=_trusted(store_signer),
        )
    with pytest.raises(
        ToolzAdmissionRecoveryError,
        match="evaluation lag",
    ):
        _recover(
            fixture,
            admission,
            root,
            store_signer,
            retained_cursor=retained,
            recovered_at="2026-07-29T04:25:01Z",
        )


def test_signed_recovery_receipt_rejects_forged_transition_and_raw_secret(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-recovery-receipt")
    with _store(root, store_signer) as store:
        retained = store.cursor
        _install(
            fixture,
            admission,
            store,
            store_signer,
            expected_cursor=retained,
        )
    result = _recover(
        fixture,
        admission,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        verified = verify_toolz_admission_recovery_receipt(
            result.receipt,
            expected_policy=_recovery_policy(fixture),
            admission_receipt=admission.receipt,
            trace=fixture.trace,
            observer_key=_trusted(fixture.observer_signer),
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_receipt=admission.memory_receipt,
            memory_key=_trusted(fixture.memory_signer),
            admission_key=_trusted(fixture.admission_signer),
            store_key=_trusted(store_signer),
            retained_cursor=retained,
            recovered_cursor=result.store_cursor,
        )
        assert verified == result.receipt

        forged = copy.deepcopy(result.receipt)
        forged["store"]["status"] = "retained-head"
        forged.pop("signature")
        forged["receipt_id"] = toolz_admission_recovery_identity(forged)
        forged = store_signer.sign(forged)
        with pytest.raises(
            ToolzAdmissionRecoveryError,
            match="retained cursor mismatch",
        ):
            verify_toolz_admission_recovery_receipt(
                forged,
                expected_policy=_recovery_policy(fixture),
                admission_receipt=admission.receipt,
                trace=fixture.trace,
                observer_key=_trusted(fixture.observer_signer),
                fog_evidence=fixture.fog,
                cyber_evidence=fixture.cyber,
                memory_receipt=admission.memory_receipt,
                memory_key=_trusted(fixture.memory_signer),
                admission_key=_trusted(fixture.admission_signer),
                store_key=_trusted(store_signer),
                retained_cursor=retained,
                recovered_cursor=result.store_cursor,
            )

        raw_secret = copy.deepcopy(result.receipt)
        raw_secret["token"] = "forbidden"
        raw_secret.pop("signature")
        raw_secret["receipt_id"] = toolz_admission_recovery_identity(raw_secret)
        raw_secret = store_signer.sign(raw_secret)
        with pytest.raises(
            ToolzAdmissionRecoveryError,
            match="schema",
        ):
            verify_toolz_admission_recovery_receipt(
                raw_secret,
                expected_policy=_recovery_policy(fixture),
                admission_receipt=admission.receipt,
                trace=fixture.trace,
                observer_key=_trusted(fixture.observer_signer),
                fog_evidence=fixture.fog,
                cyber_evidence=fixture.cyber,
                memory_receipt=admission.memory_receipt,
                memory_key=_trusted(fixture.memory_signer),
                admission_key=_trusted(fixture.admission_signer),
                store_key=_trusted(store_signer),
                retained_cursor=retained,
                recovered_cursor=result.store_cursor,
            )
    finally:
        result.store.close()


def test_recovery_module_has_no_external_or_execution_capability() -> None:
    tree = ast.parse(inspect.getsource(recovery_module))
    blocked_import_roots = {
        "http",
        "importlib",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None
    )
    blocked_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    } & {
        "__import__",
        "compile",
        "eval",
        "exec",
        "open",
    }

    assert not (imported_roots & blocked_import_roots)
    assert not blocked_calls
