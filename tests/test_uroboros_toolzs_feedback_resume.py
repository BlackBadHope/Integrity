from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_feedback_resume as resume_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs_feedback_resume import (
    ToolzFeedbackResumeError,
    ToolzFeedbackResumePolicy,
    ToolzFeedbackResumeStatus,
    resume_toolz_feedback_install,
    toolz_feedback_resume_identity,
    verify_toolz_feedback_resume_receipt,
)
from integrity_guardian.uroboros_toolzs_store import (
    STORE_DATABASE_NAME,
    ToolzRouteMemoryStore,
    ToolzStoreLifecycle,
)
from tests.test_uroboros_toolzs import MEMORY_EXPIRES, _trusted
from tests.test_uroboros_toolzs_feedback_install import (
    _feedback_fixture,
    _install,
    _policy,
    _seed_theoretical,
    _store,
)
from tests.test_uroboros_toolzs_feedback_recovery import (
    _later_theoretical,
    _recovery_policy,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")

RECOVERY_EVALUATED = "2026-07-29T04:33:00Z"
RESUME_STARTED = "2026-07-29T04:34:00Z"
RESUME_COMPLETED = "2026-07-29T04:35:00Z"


def _resume_policy(case: Any) -> ToolzFeedbackResumePolicy:
    return ToolzFeedbackResumePolicy(
        policy_id="policy:synthetic-toolz-feedback-resume",
        recovery_policy=_recovery_policy(case),
        max_resume_seconds=120,
    )


def _resume(
    case: Any,
    root: Path,
    store_signer: Ed25519Signer,
    *,
    retained_cursor: Any,
    observed_memory: dict[str, Any] | None = None,
    store_key: Any = None,
    policy: ToolzFeedbackResumePolicy | None = None,
    recovery_evaluated_at: str = RECOVERY_EVALUATED,
    resume_started_at: str = RESUME_STARTED,
    resume_completed_at: str = RESUME_COMPLETED,
):
    return resume_toolz_feedback_install(
        policy=policy or _resume_policy(case),
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
        recovery_evaluated_at=recovery_evaluated_at,
        resume_started_at=resume_started_at,
        resume_completed_at=resume_completed_at,
    )


def _verify(
    case: Any,
    result: Any,
    store_signer: Ed25519Signer,
    *,
    receipt: dict[str, Any] | None = None,
    recovery_receipt: dict[str, Any] | None = None,
    install_receipt: dict[str, Any] | None | object = ...,
    retained_cursor: Any,
    final_cursor: Any,
):
    effective_install = result.install_receipt if install_receipt is ... else install_receipt
    return verify_toolz_feedback_resume_receipt(
        receipt or result.receipt,
        expected_policy=_resume_policy(case),
        recovery_receipt=recovery_receipt or result.recovery_receipt,
        install_receipt=effective_install,
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
        final_cursor=final_cursor,
    )


def _database_digest(root: Path) -> str:
    return hashlib.sha256((root / STORE_DATABASE_NAME).read_bytes()).hexdigest()


def test_retained_predecessor_performs_one_exact_a8_install(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-install")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
    before_digest = _database_digest(root)

    result = _resume(
        case,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        assert result.status is ToolzFeedbackResumeStatus.INSTALLED
        assert result.storage_performed is True
        assert result.execution_authority is False
        assert result.store_cursor.sequence == retained.sequence + 1
        assert result.install_receipt is not None
        assert result.receipt["recovery"]["status"] == "retained-head"
        assert result.receipt["installation"]["performed"] is True
        assert result.receipt["installation"]["transition"] == "promoted"
        assert result.receipt["authority_boundary"]["store_write"] is True
        assert result.receipt["authority_boundary"]["execution"] is False
        entry = result.store.entries(expected_cursor=result.store_cursor)[0]
        assert entry["generation"] == 2
        assert entry["lifecycle"] == ToolzStoreLifecycle.REUSABLE
        assert (
            _verify(
                case,
                result,
                store_signer,
                retained_cursor=retained,
                final_cursor=result.store_cursor,
            )
            == result.receipt
        )
    finally:
        result.store.close()

    assert _database_digest(root) != before_digest


def test_already_committed_exact_child_recovers_without_write(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-recovered")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
        committed = _install(
            case,
            store,
            store_signer,
            expected_cursor=retained,
        ).store_cursor
    before_digest = _database_digest(root)

    result = _resume(
        case,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        assert result.status is ToolzFeedbackResumeStatus.RECOVERED
        assert result.storage_performed is False
        assert result.store_cursor == committed
        assert result.install_receipt is None
        assert result.receipt["recovery"]["status"] == ("recovered-feedback-install")
        assert result.receipt["installation"] == {
            "performed": False,
            "receipt_id": None,
            "receipt_digest": None,
            "transition": None,
        }
        assert (
            _verify(
                case,
                result,
                store_signer,
                retained_cursor=retained,
                final_cursor=committed,
            )
            == result.receipt
        )
    finally:
        result.store.close()

    assert _database_digest(root) == before_digest


def test_same_retained_cursor_is_crash_idempotent_across_retry(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-retry")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor

    first = _resume(
        case,
        root,
        store_signer,
        retained_cursor=retained,
    )
    committed = first.store_cursor
    first.store.close()
    after_first = _database_digest(root)

    second = _resume(
        case,
        root,
        store_signer,
        retained_cursor=retained,
        recovery_evaluated_at="2026-07-29T04:36:00Z",
        resume_started_at="2026-07-29T04:37:00Z",
        resume_completed_at="2026-07-29T04:38:00Z",
    )
    try:
        assert first.status is ToolzFeedbackResumeStatus.INSTALLED
        assert second.status is ToolzFeedbackResumeStatus.RECOVERED
        assert second.store_cursor == committed
        assert second.install_receipt is None
    finally:
        second.store.close()

    assert _database_digest(root) == after_first


def test_failure_after_commit_recovers_on_next_identical_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-post-commit")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
    before_digest = _database_digest(root)
    original_verify = resume_module.verify_toolz_feedback_resume_receipt

    def _lost_receipt(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("synthetic post-commit receipt loss")

    monkeypatch.setattr(
        resume_module,
        "verify_toolz_feedback_resume_receipt",
        _lost_receipt,
    )
    with pytest.raises(
        RuntimeError,
        match="post-commit receipt loss",
    ):
        _resume(
            case,
            root,
            store_signer,
            retained_cursor=retained,
        )
    assert _database_digest(root) != before_digest

    monkeypatch.setattr(
        resume_module,
        "verify_toolz_feedback_resume_receipt",
        original_verify,
    )
    recovered = _resume(
        case,
        root,
        store_signer,
        retained_cursor=retained,
        recovery_evaluated_at="2026-07-29T04:36:00Z",
        resume_started_at="2026-07-29T04:37:00Z",
        resume_completed_at="2026-07-29T04:38:00Z",
    )
    try:
        assert recovered.status is ToolzFeedbackResumeStatus.RECOVERED
        assert recovered.install_receipt is None
    finally:
        recovered.store.close()


def test_install_failure_before_commit_preserves_predecessor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-pre-commit")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
    before_digest = _database_digest(root)

    def _reject_install(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("synthetic pre-commit stop")

    monkeypatch.setattr(
        resume_module,
        "install_toolz_post_route_feedback",
        _reject_install,
    )
    with pytest.raises(
        ToolzFeedbackResumeError,
        match="install rejected",
    ):
        _resume(
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
        expected_cursor=retained,
    ) as store:
        entry = store.entries(expected_cursor=retained)[0]
        assert entry["generation"] == 1


def test_different_one_step_child_is_not_resumed(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-wrong-child")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
        wrong_child = store.put(
            _later_theoretical(case),
            expected_cursor=retained,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            memory_key=_trusted(case.fixture.memory_signer),
            evaluated_at="2026-07-29T04:31:00Z",
            recorded_at="2026-07-29T04:32:00Z",
            store_signer=store_signer,
        )
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzFeedbackResumeError,
        match="recovery rejected",
    ):
        _resume(
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
        expected_cursor=wrong_child,
    ) as store:
        assert store.cursor == wrong_child


def test_second_descendant_remains_concurrency_ambiguous(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-distance")
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
        ).store_cursor
        latest = store.put(
            _later_theoretical(case),
            expected_cursor=promoted,
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
        ToolzFeedbackResumeError,
        match="recovery rejected",
    ):
        _resume(
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


def test_substitution_anchor_signer_and_timing_fail_closed(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-binding")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
    before_digest = _database_digest(root)

    with pytest.raises(
        ToolzFeedbackResumeError,
        match="recovery rejected",
    ):
        _resume(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            observed_memory=case.admission.memory_receipt,
        )

    with pytest.raises(
        ToolzFeedbackResumeError,
        match="timing input",
    ):
        _resume(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            observed_memory={"malformed": True},
        )

    forged_anchor = replace(
        retained,
        manifest_digest=f"sha256:{'0' * 64}",
    )
    with pytest.raises(
        ToolzFeedbackResumeError,
        match="recovery rejected",
    ):
        _resume(
            case,
            root,
            store_signer,
            retained_cursor=forged_anchor,
        )

    wrong_key = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-wrong")
    with pytest.raises(
        ToolzFeedbackResumeError,
        match="signer mismatch",
    ):
        _resume(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            store_key=_trusted(wrong_key),
        )

    with pytest.raises(
        ToolzFeedbackResumeError,
        match="completion window",
    ):
        _resume(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            resume_completed_at="2026-07-29T04:36:00Z",
        )
    with pytest.raises(
        ToolzFeedbackResumeError,
        match="causal timing",
    ):
        _resume(
            case,
            root,
            store_signer,
            retained_cursor=retained,
            recovery_evaluated_at=MEMORY_EXPIRES,
            resume_started_at=MEMORY_EXPIRES,
            resume_completed_at=MEMORY_EXPIRES,
        )

    assert _database_digest(root) == before_digest


def test_signed_receipt_rejects_outcome_forgery_and_raw_secret(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-resume-receipt")
    with _store(root, store_signer) as store:
        retained = _seed_theoretical(
            case,
            store,
            store_signer,
        ).store_cursor
    result = _resume(
        case,
        root,
        store_signer,
        retained_cursor=retained,
    )
    try:
        forged = copy.deepcopy(result.receipt)
        forged["store"]["status"] = "recovered"
        forged["receipt_id"] = toolz_feedback_resume_identity(forged)
        forged = store_signer.sign(forged)
        with pytest.raises(
            ToolzFeedbackResumeError,
            match="schema",
        ):
            _verify(
                case,
                result,
                store_signer,
                receipt=forged,
                retained_cursor=retained,
                final_cursor=result.store_cursor,
            )

        raw_secret = copy.deepcopy(result.receipt)
        raw_secret["token"] = "forbidden"
        raw_secret["receipt_id"] = toolz_feedback_resume_identity(raw_secret)
        raw_secret = store_signer.sign(raw_secret)
        with pytest.raises(
            ToolzFeedbackResumeError,
            match="schema",
        ):
            _verify(
                case,
                result,
                store_signer,
                receipt=raw_secret,
                retained_cursor=retained,
                final_cursor=result.store_cursor,
            )

        with pytest.raises(
            ToolzFeedbackResumeError,
            match="install proof is absent",
        ):
            _verify(
                case,
                result,
                store_signer,
                install_receipt=None,
                retained_cursor=retained,
                final_cursor=result.store_cursor,
            )
    finally:
        result.store.close()


def test_resume_module_only_composes_approved_store_boundaries() -> None:
    tree = ast.parse(inspect.getsource(resume_module))
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
        "recover_one_step_feedback_install",
        "recover_one_step_install",
    }
    composed_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    } & {
        "install_toolz_post_route_feedback",
        "recover_toolz_feedback_install",
    }

    assert not (imported_roots & blocked_import_roots)
    assert not blocked_calls
    assert not blocked_store_methods
    assert composed_calls == {
        "install_toolz_post_route_feedback",
        "recover_toolz_feedback_install",
    }
