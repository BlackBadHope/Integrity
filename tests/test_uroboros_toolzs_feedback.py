from __future__ import annotations

import ast
import copy
import inspect
from dataclasses import dataclass, replace
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_feedback as feedback_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs import (
    ToolzRouteMemoryDecision,
    evaluate_toolz_route_memory,
)
from integrity_guardian.uroboros_toolzs_feedback import (
    ToolzPostRouteFeedback,
    ToolzPostRouteFeedbackDecision,
    ToolzPostRouteFeedbackError,
    ToolzPostRouteFeedbackPolicy,
    build_toolz_post_route_feedback,
    toolz_post_route_feedback_identity,
    verify_toolz_post_route_feedback_receipt,
)
from integrity_guardian.uroboros_toolzs_trace import (
    ToolzActionStep,
    toolz_action_trace_digest,
)
from tests.test_uroboros_toolzs import (
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    DIGEST_E,
    MEMORY_CREATED,
    MEMORY_EXPIRES,
    _trusted,
)
from tests.test_uroboros_toolzs_admission import (
    _admit,
    _fixture,
    _steps,
    _trace,
)

FEEDBACK_STARTED = "2026-07-29T04:25:00Z"
FEEDBACK_STEP_1 = "2026-07-29T04:26:00Z"
FEEDBACK_STEP_2 = "2026-07-29T04:27:00Z"
FEEDBACK_COMPLETED = "2026-07-29T04:28:00Z"
OBSERVED_MEMORY_CREATED = "2026-07-29T04:29:00Z"
FEEDBACK_CREATED = "2026-07-29T04:30:00Z"


@dataclass(frozen=True)
class _FeedbackCase:
    fixture: Any
    theoretical_memory: dict[str, Any]
    trace: dict[str, Any]
    policy: ToolzPostRouteFeedbackPolicy
    feedback_signer: Ed25519Signer
    feedback: ToolzPostRouteFeedback


def _later_steps() -> tuple[ToolzActionStep, ...]:
    first, second = _steps(
        first_at=FEEDBACK_STEP_1,
        second_at=FEEDBACK_STEP_2,
    )
    return (
        replace(
            first,
            evidence_digest=DIGEST_A,
            confidence_ppm=950_000,
        ),
        replace(
            second,
            evidence_digest=DIGEST_B,
            confidence_ppm=940_000,
        ),
    )


def _feedback_policy(fixture: Any) -> ToolzPostRouteFeedbackPolicy:
    return ToolzPostRouteFeedbackPolicy(
        policy_id="policy:synthetic-toolz-post-route-feedback",
        trace_policy=fixture.trace_policy,
        memory_policy=fixture.memory_policy,
        max_memory_to_trace_seconds=600,
        max_trace_to_feedback_seconds=600,
    )


def _build_case() -> _FeedbackCase:
    fixture = _fixture()
    theoretical_memory = _admit(fixture).memory_receipt
    trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=_later_steps(),
        started_at=FEEDBACK_STARTED,
        completed_at=FEEDBACK_COMPLETED,
    )
    policy = _feedback_policy(fixture)
    feedback_signer = Ed25519Signer.generate("key:synthetic-toolz-post-route-feedback")
    feedback = build_toolz_post_route_feedback(
        policy=policy,
        theoretical_memory=theoretical_memory,
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
    return _FeedbackCase(
        fixture=fixture,
        theoretical_memory=theoretical_memory,
        trace=trace,
        policy=policy,
        feedback_signer=feedback_signer,
        feedback=feedback,
    )


def _build_with_trace(
    fixture: Any,
    theoretical_memory: dict[str, Any],
    trace: dict[str, Any],
    *,
    expires_at: str = MEMORY_EXPIRES,
    memory_signer: Ed25519Signer | None = None,
) -> ToolzPostRouteFeedback:
    return build_toolz_post_route_feedback(
        policy=_feedback_policy(fixture),
        theoretical_memory=theoretical_memory,
        trace=trace,
        observer_key=_trusted(fixture.observer_signer),
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        memory_key=_trusted(fixture.memory_signer),
        memory_created_at=OBSERVED_MEMORY_CREATED,
        expires_at=expires_at,
        feedback_created_at=FEEDBACK_CREATED,
        memory_signer=memory_signer or fixture.memory_signer,
        feedback_signer=Ed25519Signer.generate("key:synthetic-toolz-post-route-feedback"),
    )


def test_later_exact_route_trace_promotes_only_to_reuse_candidate() -> None:
    case = _build_case()
    feedback = case.feedback

    assert feedback.decision is ToolzPostRouteFeedbackDecision.ADMIT_OBSERVED_SUCCESS
    assert feedback.execution_authority is False
    assert feedback.storage_performed is False
    assert feedback.receipt["authority_boundary"]["store_write"] is False
    assert feedback.receipt["authority_boundary"]["execution"] is False
    assert feedback.memory_receipt["observation"] == {
        "outcome": "observed-success",
        "observed_at": FEEDBACK_COMPLETED,
        "evidence_digest": toolz_action_trace_digest(case.trace),
    }
    assert feedback.memory_receipt["expires_at"] == MEMORY_EXPIRES
    assert feedback.receipt["feedback_trace"]["hops"][0]["evidence_digest"] == DIGEST_A
    assert feedback.receipt["feedback_trace"]["hops"][1]["evidence_digest"] == DIGEST_B
    assert (
        evaluate_toolz_route_memory(
            feedback.memory_receipt,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            authority_key=_trusted(case.fixture.memory_signer),
            evaluated_at=FEEDBACK_CREATED,
        )
        is ToolzRouteMemoryDecision.REUSE_CANDIDATE
    )

    verified = verify_toolz_post_route_feedback_receipt(
        feedback.receipt,
        expected_policy=case.policy,
        theoretical_memory=case.theoretical_memory,
        trace=case.trace,
        observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        observed_memory=feedback.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        feedback_key=_trusted(case.feedback_signer),
    )
    assert verified.receipt == feedback.receipt


def test_feedback_trace_must_start_strictly_after_theoretical_memory() -> None:
    fixture = _fixture()
    theoretical = _admit(fixture).memory_receipt
    trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=_steps(
            first_at="2026-07-29T04:21:00Z",
            second_at="2026-07-29T04:22:00Z",
        ),
        started_at=MEMORY_CREATED,
        completed_at="2026-07-29T04:23:00Z",
    )

    with pytest.raises(
        ToolzPostRouteFeedbackError,
        match="causal ordering",
    ):
        _build_with_trace(fixture, theoretical, trace)


def test_same_endpoints_with_changed_operation_do_not_match_route() -> None:
    fixture = _fixture()
    theoretical = _admit(fixture).memory_receipt
    first, second = _later_steps()
    trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=(replace(first, operation_digest=DIGEST_C), second),
        started_at=FEEDBACK_STARTED,
        completed_at=FEEDBACK_COMPLETED,
    )

    with pytest.raises(
        ToolzPostRouteFeedbackError,
        match="route hop mismatch",
    ):
        _build_with_trace(fixture, theoretical, trace)


def test_observed_memory_cannot_substitute_for_theoretical_input() -> None:
    case = _build_case()

    with pytest.raises(
        ToolzPostRouteFeedbackError,
        match="non-theoretical input",
    ):
        _build_with_trace(
            case.fixture,
            case.feedback.memory_receipt,
            case.trace,
        )


def test_feedback_cannot_extend_theoretical_expiry() -> None:
    fixture = _fixture()
    theoretical = _admit(fixture).memory_receipt
    trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=_later_steps(),
        started_at=FEEDBACK_STARTED,
        completed_at=FEEDBACK_COMPLETED,
    )

    with pytest.raises(
        ToolzPostRouteFeedbackError,
        match="expiry extension",
    ):
        _build_with_trace(
            fixture,
            theoretical,
            trace,
            expires_at="2026-07-29T05:01:00Z",
        )


def test_trace_after_theoretical_expiry_requires_rediscovery() -> None:
    fixture = _fixture()
    theoretical = _admit(fixture).memory_receipt
    trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=_steps(
            first_at="2026-07-29T05:00:10Z",
            second_at="2026-07-29T05:00:20Z",
        ),
        started_at="2026-07-29T05:00:01Z",
        completed_at="2026-07-29T05:00:30Z",
    )

    with pytest.raises(
        ToolzPostRouteFeedbackError,
        match="theoretical state",
    ):
        _build_with_trace(fixture, theoretical, trace)


def test_memory_signer_must_equal_theoretical_memory_authority() -> None:
    fixture = _fixture()
    theoretical = _admit(fixture).memory_receipt
    trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=_later_steps(),
        started_at=FEEDBACK_STARTED,
        completed_at=FEEDBACK_COMPLETED,
    )

    with pytest.raises(
        ToolzPostRouteFeedbackError,
        match="memory signer mismatch",
    ):
        _build_with_trace(
            fixture,
            theoretical,
            trace,
            memory_signer=Ed25519Signer.generate("key:synthetic-toolz-wrong-memory"),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("decision", "execute-route"),
        ("token", "forbidden-secret"),
    ],
)
def test_feedback_schema_rejects_authority_and_secret_injection(
    field: str,
    value: str,
) -> None:
    case = _build_case()
    forged = copy.deepcopy(case.feedback.receipt)
    forged[field] = value
    forged["receipt_id"] = toolz_post_route_feedback_identity(forged)
    forged = case.feedback_signer.sign(forged)

    with pytest.raises(ToolzPostRouteFeedbackError, match="schema"):
        verify_toolz_post_route_feedback_receipt(
            forged,
            expected_policy=case.policy,
            theoretical_memory=case.theoretical_memory,
            trace=case.trace,
            observer_key=_trusted(case.fixture.observer_signer),
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            observed_memory=case.feedback.memory_receipt,
            memory_key=_trusted(case.fixture.memory_signer),
            feedback_key=_trusted(case.feedback_signer),
        )


def test_feedback_policy_contexts_must_be_identical() -> None:
    fixture = _fixture()
    mismatched_trace_policy = replace(
        fixture.trace_policy,
        ui_context_digest=DIGEST_E,
    )

    with pytest.raises(
        ToolzPostRouteFeedbackError,
        match="context mismatch",
    ):
        ToolzPostRouteFeedbackPolicy(
            policy_id="policy:synthetic-toolz-post-route-feedback",
            trace_policy=mismatched_trace_policy,
            memory_policy=fixture.memory_policy,
        )


def test_feedback_module_has_no_active_io_or_dynamic_execution() -> None:
    tree = ast.parse(inspect.getsource(feedback_module))
    blocked_import_roots = {
        "http",
        "importlib",
        "os",
        "pathlib",
        "requests",
        "socket",
        "sqlite3",
        "subprocess",
        "urllib",
    }
    blocked_local_modules = {
        "uroboros_toolzs_install",
        "uroboros_toolzs_recovery",
        "uroboros_toolzs_store",
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
    assert (
        not {
            node.module.rsplit(".", 1)[-1]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        & blocked_local_modules
    )
    assert not blocked_calls
