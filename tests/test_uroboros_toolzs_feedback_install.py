from __future__ import annotations

import ast
import copy
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_feedback_install as feedback_install_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs import (
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryOutcome,
    build_toolz_route_memory_receipt,
    toolz_route_memory_digest,
)
from integrity_guardian.uroboros_toolzs_feedback import (
    ToolzPostRouteFeedback,
    ToolzPostRouteFeedbackPolicy,
    build_toolz_post_route_feedback,
)
from integrity_guardian.uroboros_toolzs_feedback_install import (
    ToolzFeedbackInstallError,
    ToolzFeedbackInstallPolicy,
    ToolzFeedbackInstallStatus,
    install_toolz_post_route_feedback,
    toolz_feedback_install_identity,
    verify_toolz_feedback_install_receipt,
)
from integrity_guardian.uroboros_toolzs_install import (
    ToolzAdmissionInstallPolicy,
    install_toolz_trace_admission,
)
from integrity_guardian.uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzStoreLifecycle,
)
from tests.test_uroboros_toolzs import (
    MEMORY_EXPIRES,
    _trusted,
)
from tests.test_uroboros_toolzs_admission import (
    _AdmissionFixture,
    _admit,
    _fixture,
    _trace,
)
from tests.test_uroboros_toolzs_feedback import (
    FEEDBACK_COMPLETED,
    FEEDBACK_CREATED,
    FEEDBACK_STARTED,
    OBSERVED_MEMORY_CREATED,
    _feedback_policy,
    _later_steps,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")

STORE_ID = "toolz-store:local-synthetic-feedback-install"
STORE_CREATED = "2026-07-29T04:18:00Z"
ADMISSION_EVALUATED = "2026-07-29T04:21:00Z"
ADMISSION_RECORDED = "2026-07-29T04:22:00Z"
FEEDBACK_EVALUATED = "2026-07-29T04:31:00Z"
FEEDBACK_RECORDED = "2026-07-29T04:32:00Z"


@dataclass(frozen=True)
class _FeedbackInstallFixture:
    fixture: _AdmissionFixture
    admission: Any
    trace: dict[str, Any]
    feedback_policy: ToolzPostRouteFeedbackPolicy
    feedback_signer: Ed25519Signer
    feedback: ToolzPostRouteFeedback


def _feedback_fixture() -> _FeedbackInstallFixture:
    fixture = _fixture()
    admission = _admit(fixture)
    trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=_later_steps(),
        started_at=FEEDBACK_STARTED,
        completed_at=FEEDBACK_COMPLETED,
    )
    feedback_policy = _feedback_policy(fixture)
    feedback_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-observer")
    feedback = build_toolz_post_route_feedback(
        policy=feedback_policy,
        theoretical_memory=admission.memory_receipt,
        trace=trace,
        observer_key=_trusted(fixture.observer_signer),
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        memory_key=_trusted(fixture.memory_signer),
        memory_created_at=OBSERVED_MEMORY_CREATED,
        expires_at=MEMORY_EXPIRES,
        feedback_created_at=FEEDBACK_CREATED,
        memory_signer=fixture.memory_signer,
        feedback_signer=feedback_signer,
    )
    return _FeedbackInstallFixture(
        fixture=fixture,
        admission=admission,
        trace=trace,
        feedback_policy=feedback_policy,
        feedback_signer=feedback_signer,
        feedback=feedback,
    )


def _policy(
    case: _FeedbackInstallFixture,
) -> ToolzFeedbackInstallPolicy:
    return ToolzFeedbackInstallPolicy(
        policy_id="policy:synthetic-toolz-feedback-install",
        feedback_policy=case.feedback_policy,
        store_id=STORE_ID,
        max_evaluation_to_record_seconds=60,
    )


def _store(
    root: Path,
    store_signer: Ed25519Signer,
) -> ToolzRouteMemoryStore:
    return ToolzRouteMemoryStore.initialize(
        root,
        store_id=STORE_ID,
        tenant_id=SYNTHETIC_TENANT,
        store_signer=store_signer,
        created_at=STORE_CREATED,
    )


def _seed_theoretical(
    case: _FeedbackInstallFixture,
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
):
    admission_policy = ToolzAdmissionInstallPolicy(
        policy_id="policy:synthetic-toolz-feedback-predecessor-install",
        admission_policy=case.fixture.admission_policy,
        store_id=STORE_ID,
    )
    return install_toolz_trace_admission(
        policy=admission_policy,
        admission_receipt=case.admission.receipt,
        trace=case.fixture.trace,
        observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        memory_receipt=case.admission.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        admission_key=_trusted(case.fixture.admission_signer),
        store=store,
        expected_cursor=store.cursor,
        evaluated_at=ADMISSION_EVALUATED,
        recorded_at=ADMISSION_RECORDED,
        store_signer=store_signer,
    )


def _install(
    case: _FeedbackInstallFixture,
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
    *,
    expected_cursor: Any,
    observed_memory: dict[str, Any] | None = None,
    evaluated_at: str = FEEDBACK_EVALUATED,
    recorded_at: str = FEEDBACK_RECORDED,
    policy: ToolzFeedbackInstallPolicy | None = None,
):
    return install_toolz_post_route_feedback(
        policy=policy or _policy(case),
        feedback_receipt=case.feedback.receipt,
        theoretical_memory=case.admission.memory_receipt,
        trace=case.trace,
        observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        observed_memory=observed_memory or case.feedback.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        feedback_key=_trusted(case.feedback_signer),
        store=store,
        expected_cursor=expected_cursor,
        evaluated_at=evaluated_at,
        recorded_at=recorded_at,
        store_signer=store_signer,
    )


def _verify(
    case: _FeedbackInstallFixture,
    result: Any,
    store_signer: Ed25519Signer,
    *,
    receipt: dict[str, Any] | None = None,
    before_cursor: Any,
    after_cursor: Any,
):
    return verify_toolz_feedback_install_receipt(
        receipt or result.receipt,
        expected_policy=_policy(case),
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
        before_cursor=before_cursor,
        after_cursor=after_cursor,
    )


def test_exact_feedback_promotes_only_the_exact_theoretical_predecessor(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-store")
    with _store(tmp_path / "toolz", store_signer) as store:
        predecessor = _seed_theoretical(case, store, store_signer)
        before = predecessor.store_cursor
        result = _install(
            case,
            store,
            store_signer,
            expected_cursor=before,
        )

        assert result.status is ToolzFeedbackInstallStatus.PROMOTED
        assert result.storage_performed is True
        assert result.execution_authority is False
        assert result.store_cursor.sequence == before.sequence + 1
        assert result.receipt["store"]["transition"] == "promoted"
        assert result.receipt["authority_boundary"]["store_write"] is True
        assert result.receipt["authority_boundary"]["execution"] is False
        entry = store.entries(expected_cursor=result.store_cursor)[0]
        assert entry["generation"] == 2
        assert entry["receipt_digest"] == toolz_route_memory_digest(case.feedback.memory_receipt)
        assert entry["previous_receipt_digest"] == toolz_route_memory_digest(
            case.admission.memory_receipt
        )
        assert entry["lifecycle"] == ToolzStoreLifecycle.REUSABLE.value
        assert entry["decision"] == ToolzRouteMemoryDecision.REUSE_CANDIDATE.value
        verified = _verify(
            case,
            result,
            store_signer,
            before_cursor=before,
            after_cursor=result.store_cursor,
        )
        assert verified.receipt == result.receipt


def test_exact_generation_two_feedback_is_idempotent(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-idempotent")
    with _store(tmp_path / "toolz", store_signer) as store:
        _seed_theoretical(case, store, store_signer)
        first = _install(
            case,
            store,
            store_signer,
            expected_cursor=store.cursor,
        )
        second = _install(
            case,
            store,
            store_signer,
            expected_cursor=first.store_cursor,
            evaluated_at="2026-07-29T04:33:00Z",
            recorded_at="2026-07-29T04:34:00Z",
        )

        assert second.status is ToolzFeedbackInstallStatus.ALREADY_PRESENT
        assert second.storage_performed is False
        assert second.store_cursor == first.store_cursor
        assert second.receipt["store"]["before_cursor"] == second.receipt["store"]["after_cursor"]
        entry = store.entries(expected_cursor=second.store_cursor)[0]
        assert entry["generation"] == 2


def test_feedback_cannot_install_without_theoretical_predecessor(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-absent")
    with _store(tmp_path / "toolz", store_signer) as store:
        before = store.cursor
        with pytest.raises(
            ToolzFeedbackInstallError,
            match="predecessor is absent",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=before,
            )
        assert store.cursor == before
        assert store.entries(expected_cursor=before) == []


def test_direct_generation_one_observed_memory_is_predecessor_bypass(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-bypass")
    with _store(tmp_path / "toolz", store_signer) as store:
        direct = store.put(
            case.feedback.memory_receipt,
            expected_cursor=store.cursor,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            memory_key=_trusted(case.fixture.memory_signer),
            evaluated_at=FEEDBACK_EVALUATED,
            recorded_at=FEEDBACK_RECORDED,
            store_signer=store_signer,
        )
        before_entry = store.entries(expected_cursor=direct)[0]
        assert before_entry["generation"] == 1

        with pytest.raises(
            ToolzFeedbackInstallError,
            match="predecessor chain conflict",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=direct,
                evaluated_at="2026-07-29T04:33:00Z",
                recorded_at="2026-07-29T04:34:00Z",
            )
        assert store.cursor == direct


def test_different_theoretical_generation_cannot_be_replaced(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-conflict")
    conflicting = build_toolz_route_memory_receipt(
        policy=case.fixture.memory_policy,
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        observed_at=None,
        observation_evidence_digest=None,
        created_at="2026-07-29T04:19:00Z",
        expires_at=MEMORY_EXPIRES,
        memory_signer=case.fixture.memory_signer,
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        occupied = store.put(
            conflicting,
            expected_cursor=store.cursor,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            memory_key=_trusted(case.fixture.memory_signer),
            evaluated_at="2026-07-29T04:19:30Z",
            recorded_at="2026-07-29T04:20:00Z",
            store_signer=store_signer,
        )

        with pytest.raises(
            ToolzFeedbackInstallError,
            match="predecessor chain conflict",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=occupied,
            )
        assert store.cursor == occupied
        entry = store.entries(expected_cursor=occupied)[0]
        assert entry["receipt_digest"] == toolz_route_memory_digest(conflicting)


def test_stale_cursor_and_wrong_store_signer_fail_without_mutation(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-cursor")
    wrong_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-wrong-store")
    with _store(tmp_path / "toolz", store_signer) as store:
        stale = store.cursor
        predecessor = _seed_theoretical(case, store, store_signer)
        with pytest.raises(
            ToolzFeedbackInstallError,
            match="store pre-check",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=stale,
            )
        assert store.cursor == predecessor.store_cursor

        with pytest.raises(
            ToolzFeedbackInstallError,
            match="store transition",
        ):
            _install(
                case,
                store,
                wrong_signer,
                expected_cursor=predecessor.store_cursor,
            )
        assert store.cursor == predecessor.store_cursor


def test_store_scope_and_causal_window_are_fail_closed(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-policy")
    other_store_policy = ToolzFeedbackInstallPolicy(
        policy_id="policy:synthetic-toolz-feedback-install",
        feedback_policy=case.feedback_policy,
        store_id="toolz-store:other-synthetic-feedback-install",
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        predecessor = _seed_theoretical(case, store, store_signer)
        before = predecessor.store_cursor
        with pytest.raises(
            ToolzFeedbackInstallError,
            match="store scope",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=before,
                policy=other_store_policy,
            )
        with pytest.raises(
            ToolzFeedbackInstallError,
            match="causal timing",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=before,
                evaluated_at=MEMORY_EXPIRES,
                recorded_at=MEMORY_EXPIRES,
            )
        assert store.cursor == before


def test_non_reusable_pre_evaluation_cannot_reach_store_put(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-pre-evaluation")
    with _store(tmp_path / "toolz", store_signer) as store:
        predecessor = _seed_theoretical(case, store, store_signer)
        before = predecessor.store_cursor
        monkeypatch.setattr(
            feedback_install_module,
            "evaluate_toolz_route_memory",
            lambda *args, **kwargs: ToolzRouteMemoryDecision.REDISCOVER,
        )
        with pytest.raises(
            ToolzFeedbackInstallError,
            match="non-reusable decision",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=before,
            )
        assert store.cursor == before
        entry = store.entries(expected_cursor=before)[0]
        assert entry["generation"] == 1


def test_substituted_observed_memory_is_rejected_before_mutation(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-substitution")
    with _store(tmp_path / "toolz", store_signer) as store:
        predecessor = _seed_theoretical(case, store, store_signer)
        before = predecessor.store_cursor
        with pytest.raises(
            ToolzFeedbackInstallError,
            match="feedback rejected",
        ):
            _install(
                case,
                store,
                store_signer,
                expected_cursor=before,
                observed_memory=case.admission.memory_receipt,
            )
        assert store.cursor == before


def test_forged_transition_and_raw_secret_fields_are_rejected(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-feedback-install-forgery")
    with _store(tmp_path / "toolz", store_signer) as store:
        _seed_theoretical(case, store, store_signer)
        before = store.cursor
        result = _install(
            case,
            store,
            store_signer,
            expected_cursor=before,
        )

        forged_transition = copy.deepcopy(result.receipt)
        forged_transition["store"]["transition"] = "already-present"
        forged_transition["receipt_id"] = toolz_feedback_install_identity(forged_transition)
        forged_transition = store_signer.sign(forged_transition)
        with pytest.raises(
            ToolzFeedbackInstallError,
            match="idempotent cursor",
        ):
            _verify(
                case,
                result,
                store_signer,
                receipt=forged_transition,
                before_cursor=before,
                after_cursor=result.store_cursor,
            )

        raw_secret = copy.deepcopy(result.receipt)
        raw_secret["token"] = "forbidden"
        raw_secret["receipt_id"] = toolz_feedback_install_identity(raw_secret)
        raw_secret = store_signer.sign(raw_secret)
        with pytest.raises(ToolzFeedbackInstallError, match="schema"):
            _verify(
                case,
                result,
                store_signer,
                receipt=raw_secret,
                before_cursor=before,
                after_cursor=result.store_cursor,
            )


def test_feedback_install_module_has_no_external_or_execution_capability() -> None:
    tree = ast.parse(inspect.getsource(feedback_install_module))
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
        "recover_one_step_install",
    }

    assert not (imported_roots & blocked_import_roots)
    assert not blocked_calls
    assert not blocked_store_methods
