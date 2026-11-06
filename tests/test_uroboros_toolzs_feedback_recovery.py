from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_feedback_recovery as recovery_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs import (
    ToolzRouteMemoryOutcome,
    build_toolz_route_memory_receipt,
    toolz_route_memory_digest,
)
from integrity_guardian.uroboros_toolzs_feedback_recovery import (
    ToolzFeedbackRecoveryError,
    ToolzFeedbackRecoveryPolicy,
    recover_toolz_feedback_install,
    toolz_feedback_recovery_identity,
    verify_toolz_feedback_recovery_receipt,
)
from integrity_guardian.uroboros_toolzs_store import (
    STORE_DATABASE_NAME,
    ToolzRouteMemoryStore,
    ToolzStoreLifecycle,
    ToolzStoreRecoveryStatus,
)
from tests.test_uroboros_toolzs import MEMORY_EXPIRES, _trusted
from tests.test_uroboros_toolzs_feedback_install import (
    FEEDBACK_EVALUATED,
    FEEDBACK_RECORDED,
    _feedback_fixture,
    _install,
    _policy,
    _seed_theoretical,
    _store,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")

RECOVERY_EVALUATED = "2026-07-29T04:33:00Z"
RECOVERED = "2026-07-29T04:34:00Z"


def _recovery_policy(case: Any) -> ToolzFeedbackRecoveryPolicy:
    return ToolzFeedbackRecoveryPolicy(
        policy_id="policy:synthetic-toolz-feedback-recovery",
        install_policy=_policy(case),
        max_evaluation_to_recovery_seconds=60,
    )


def _recover(
    case: Any,
    root: Path,
    store_signer: Ed25519Signer,
    *,
    retained_cursor: Any,
    observed_memory: dict[str, Any] | None = None,
    store_key: Any = None,
    policy: ToolzFeedbackRecoveryPolicy | None = None,
    evaluated_at: str = RECOVERY_EVALUATED,
    recovered_at: str = RECOVERED,
):
    return recover_toolz_feedback_install(
        policy=policy or _recovery_policy(case),
        feedback_receipt=case.feedback.receipt,
        theoretical_memory=case.admission.memory_receipt,
        trace=case.trace,
        observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        observed_memory=observed_memory or case.feedback.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        feedback_key=_trusted(case.feedback_signer),
        store_root=root,
        store_key=store_key or _trusted(store_signer),
        store_signer=store_signer,
        retained_cursor=retained_cursor,
        evaluated_at=evaluated_at,
        recovered_at=recovered_at,
    )


def _verify(
    case: Any,
    result: Any,
    store_signer: Ed25519Signer,
    *,
    receipt: dict[str, Any] | None = None,
    retained_cursor: Any,
    recovered_cursor: Any,
):
    return verify_toolz_feedback_recovery_receipt(
        receipt or result.receipt,
        expected_policy=_recovery_policy(case),
        feedback_receipt=case.feedback.receipt,
        theoretical_memory=case.admission.memory_receipt,
        trace=case.trace,
        observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        observed_memory=case.feedback.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        feedback_key=_trusted(case.feedback_signer),
        store_key=_trusted(store_signer),
        retained_cursor=retained_cursor,
        recovered_cursor=recovered_cursor,
    )


def _database_digest(root: Path) -> str:
    return hashlib.sha256((root / STORE_DATABASE_NAME).read_bytes()).hexdigest()


def _later_theoretical(case: Any) -> dict[str, Any]:
    return build_toolz_route_memory_receipt(
        policy=case.fixture.memory_policy,
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        observed_at=None,
        observation_evidence_digest=None,
        created_at="2026-07-29T04:30:30Z",
        expires_at=MEMORY_EXPIRES,
        memory_signer=case.fixture.memory_signer,
    )


def test_unchanged_exact_predecessor_is_safe_to_retry_without_write(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-retained")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
    before_digest = _database_digest(root)

    result = _recover(
        case,
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
        entry = result.store.entries(expected_cursor=result.store_cursor)[0]
        assert entry["generation"] == 1
        assert entry["lifecycle"] == ToolzStoreLifecycle.THEORETICAL
        assert entry["receipt_digest"] == toolz_route_memory_digest(case.admission.memory_receipt)
    finally:
        result.store.close()

    assert _database_digest(root) == before_digest


def test_lost_feedback_cursor_recovers_only_exact_immediate_promotion(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-crash")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
        installed = _install(
            case,
            store,
            store_signer,
            expected_cursor=retained,
        )
        installed_cursor = installed.store_cursor
    before_digest = _database_digest(root)

    result = _recover(
        case,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        assert result.status is ToolzStoreRecoveryStatus.RECOVERED_FEEDBACK_INSTALL
        assert result.store_cursor == installed_cursor
        assert result.store_cursor.sequence == retained.sequence + 1
        assert result.receipt["store"]["status"] == ("recovered-feedback-install")
        assert result.receipt["store"]["recovered_manifest_created_at"] == FEEDBACK_RECORDED
        assert (
            result.receipt["authority_boundary"]["historical_feedback_install_invocation"] is False
        )
        assert (
            result.receipt["authority_boundary"]["feedback_install_receipt_reconstruction"] is False
        )
        entry = result.store.entries(expected_cursor=result.store_cursor)[0]
        assert entry["generation"] == 2
        assert entry["lifecycle"] == ToolzStoreLifecycle.REUSABLE
        assert entry["receipt_digest"] == toolz_route_memory_digest(case.feedback.memory_receipt)
        assert (
            _verify(
                case,
                result,
                store_signer,
                retained_cursor=retained,
                recovered_cursor=installed_cursor,
            )
            == result.receipt
        )
    finally:
        result.store.close()

    assert _database_digest(root) == before_digest


def test_wrong_one_step_generation_is_rejected_without_mutation(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-wrong-child")
    wrong = _later_theoretical(case)
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
        child = store.put(
            wrong,
            expected_cursor=retained,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            memory_key=_trusted(case.fixture.memory_signer),
            evaluated_at="2026-07-29T04:31:00Z",
            recorded_at=FEEDBACK_RECORDED,
            store_signer=store_signer,
        )
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="store proof",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
        )

    assert _database_digest(root) == before_digest
    with ToolzRouteMemoryStore.open(
        root,
        store_id=_policy(case).store_id,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=child,
    ) as store:
        assert store.cursor == child


def test_direct_observed_generation_one_is_predecessor_bypass(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-bypass")
    with _store(root, store_signer) as store:
        retained = store.cursor
        child = store.put(
            case.feedback.memory_receipt,
            expected_cursor=retained,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            memory_key=_trusted(case.fixture.memory_signer),
            evaluated_at=FEEDBACK_EVALUATED,
            recorded_at=FEEDBACK_RECORDED,
            store_signer=store_signer,
        )
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="store proof",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
        )

    assert _database_digest(root) == before_digest
    with ToolzRouteMemoryStore.open(
        root,
        store_id=_policy(case).store_id,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=child,
    ) as store:
        assert store.entries(expected_cursor=child)[0]["generation"] == 1


def test_two_descendants_remain_rollback_or_concurrency_ambiguous(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-distance")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
        promoted = _install(
            case,
            store,
            store_signer,
            expected_cursor=retained,
        )
        latest = store.put(
            _later_theoretical(case),
            expected_cursor=promoted.store_cursor,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            memory_key=_trusted(case.fixture.memory_signer),
            evaluated_at="2026-07-29T04:32:15Z",
            recorded_at="2026-07-29T04:32:30Z",
            store_signer=store_signer,
        )
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="store proof",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
        )

    assert _database_digest(root) == before_digest
    with ToolzRouteMemoryStore.open(
        root,
        store_id=_policy(case).store_id,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=latest,
    ) as store:
        assert store.cursor.sequence == retained.sequence + 2


def test_child_created_after_recovery_observation_is_rejected(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-future")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
        future = _install(
            case,
            store,
            store_signer,
            expected_cursor=retained,
            evaluated_at="2026-07-29T04:34:30Z",
            recorded_at="2026-07-29T04:35:00Z",
        ).store_cursor
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="store proof",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
        )

    assert _database_digest(root) == before_digest
    with ToolzRouteMemoryStore.open(
        root,
        store_id=_policy(case).store_id,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=future,
    ) as store:
        assert store.cursor == future


def test_substitution_anchor_and_signer_fail_closed(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-binding")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor

    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="feedback rejected",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            observed_memory=case.admission.memory_receipt,
        )

    forged_anchor = replace(
        retained,
        manifest_digest=f"sha256:{'0' * 64}",
    )
    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="store proof",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=forged_anchor,
        )

    wrong_key = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-wrong")
    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="signer mismatch",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            store_key=_trusted(wrong_key),
        )


def test_recovery_window_and_expiry_are_fail_closed(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-window")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor

    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="evaluation lag",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            recovered_at="2026-07-29T04:35:00Z",
        )
    with pytest.raises(
        ToolzFeedbackRecoveryError,
        match="causal timing",
    ):
        _recover(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            evaluated_at=MEMORY_EXPIRES,
            recovered_at=MEMORY_EXPIRES,
        )


def test_signed_receipt_rejects_forged_status_and_raw_secret(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-recovery-receipt")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
        recovered = _install(
            case,
            store,
            store_signer,
            expected_cursor=retained,
        ).store_cursor
    result = _recover(
        case,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        forged = copy.deepcopy(result.receipt)
        forged["store"]["status"] = "retained-head"
        forged["receipt_id"] = toolz_feedback_recovery_identity(forged)
        forged = store_signer.sign(forged)
        with pytest.raises(
            ToolzFeedbackRecoveryError,
            match="retained cursor",
        ):
            _verify(
                case,
                result,
                store_signer,
                receipt=forged,
                retained_cursor=retained,
                recovered_cursor=recovered,
            )

        raw_secret = copy.deepcopy(result.receipt)
        raw_secret["token"] = "forbidden"
        raw_secret["receipt_id"] = toolz_feedback_recovery_identity(raw_secret)
        raw_secret = store_signer.sign(raw_secret)
        with pytest.raises(
            ToolzFeedbackRecoveryError,
            match="schema",
        ):
            _verify(
                case,
                result,
                store_signer,
                receipt=raw_secret,
                retained_cursor=retained,
                recovered_cursor=recovered,
            )
    finally:
        result.store.close()


def test_feedback_recovery_has_no_external_or_write_capability() -> None:
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
    blocked_store_methods = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    } & {
        "apply_feedback_delta",
        "initialize",
        "put",
        "recover_one_step_install",
    }

    assert not (imported_roots & blocked_import_roots)
    assert not blocked_calls
    assert not blocked_store_methods

    store_source = inspect.getsource(
        ToolzRouteMemoryStore.recover_one_step_feedback_install
    ).upper()
    assert "BEGIN IMMEDIATE" not in store_source
    assert "INSERT " not in store_source
    assert "UPDATE " not in store_source
    assert "DELETE " not in store_source
    assert "REPLACE " not in store_source
