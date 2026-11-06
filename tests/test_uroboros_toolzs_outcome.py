from __future__ import annotations

import ast
import contextlib
import copy
import inspect
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_outcome as outcome_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs_outcome import (
    ToolzActionOutcome,
    ToolzActionOutcomeError,
    ToolzActionOutcomePolicy,
    ToolzActionOutcomeReason,
    build_toolz_action_outcome_observation,
    toolz_action_outcome_identity,
    verify_toolz_action_outcome_observation,
)
from tests.test_uroboros_toolzs import DIGEST_A, DIGEST_B, DIGEST_C, _trusted
from tests.test_uroboros_toolzs_authority import (
    CONSUMED_AT,
    _case,
    _decide,
    _initialize,
)
from tests.test_uroboros_toolzs_authority import (
    _policy as _authority_policy,
)

OBSERVATION_STARTED = "2026-07-29T04:40:11Z"
STATE_OBSERVED = "2026-07-29T04:40:12Z"
OBSERVATION_COMPLETED = "2026-07-29T04:40:13Z"
OBSERVATION_CREATED = "2026-07-29T04:40:14Z"


@contextlib.contextmanager
def _consumed(
    tmp_path: Path,
    label: str,
) -> Iterator[tuple[Any, Any, Any, Any, Any, Any, Any, Any]]:
    with _case(tmp_path, label) as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            label,
        )
        with ledger:
            decision = _decide(
                ledger,
                evidence,
                decision_signer,
                ledger_signer,
                ledger.checkpoint,
            )
            consumption = ledger.consume(
                evidence=evidence,
                decision=decision.decision,
                decision_key=_trusted(decision_signer),
                consumed_at=CONSUMED_AT,
                ledger_signer=ledger_signer,
                expected_checkpoint=decision.checkpoint,
            )
            observer_signer = Ed25519Signer.generate(
                f"key:synthetic-a14-{label}-observer"
            )
            policy = ToolzActionOutcomePolicy(
                policy_id=f"policy:synthetic-a14-{label}",
                authority_policy=_authority_policy(case),
                observer_id=f"observer:synthetic-a14-{label}",
                observer_artifact_digest=DIGEST_A,
            )
            yield (
                case,
                evidence,
                ledger,
                decision_signer,
                decision,
                consumption,
                observer_signer,
                policy,
            )


def _build(
    case: Any,
    evidence: Any,
    ledger: Any,
    decision_signer: Ed25519Signer,
    decision: Any,
    consumption: Any,
    observer_signer: Ed25519Signer,
    policy: ToolzActionOutcomePolicy,
    *,
    outcome: ToolzActionOutcome = ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED,
    reason: ToolzActionOutcomeReason = ToolzActionOutcomeReason.EXPECTED_TRANSITION,
    after_state_digest: str | None = None,
    after_zone_id: str | None = None,
    after_evidence_digest: str | None = DIGEST_B,
    gap_evidence_digest: str | None = None,
):
    step = case.trace["steps"][0]
    if outcome is ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED:
        after_state_digest = after_state_digest or step["after_state_digest"]
        after_zone_id = after_zone_id or step["after_zone_id"]
    elif outcome is ToolzActionOutcome.PRE_STATE_RETAINED:
        before = evidence.witness["observation"]
        after_state_digest = after_state_digest or before["state_digest"]
        after_zone_id = after_zone_id or before["zone_id"]
    elif outcome is ToolzActionOutcome.UNEXPECTED_STATE_OBSERVED:
        after_state_digest = after_state_digest or DIGEST_C
        after_zone_id = after_zone_id or step["after_zone_id"]
    else:
        after_evidence_digest = None
        gap_evidence_digest = gap_evidence_digest or DIGEST_C
    return build_toolz_action_outcome_observation(
        policy=policy,
        evidence=evidence,
        decision=decision.decision,
        consumption=consumption.consumption,
        consumption_event=consumption.ledger_event,
        decision_key=_trusted(decision_signer),
        authority_ledger=ledger,
        expected_authority_checkpoint=consumption.checkpoint,
        outcome=outcome,
        reason=reason,
        observation_started_at=OBSERVATION_STARTED,
        observation_completed_at=OBSERVATION_COMPLETED,
        created_at=OBSERVATION_CREATED,
        observer_key=_trusted(observer_signer),
        observer_signer=observer_signer,
        after_state_digest=after_state_digest,
        after_zone_id=after_zone_id,
        after_evidence_digest=after_evidence_digest,
        after_observed_at=(
            None if outcome is ToolzActionOutcome.OUTCOME_UNKNOWN else STATE_OBSERVED
        ),
        gap_evidence_digest=gap_evidence_digest,
    )


def test_expected_transition_is_observed_without_execution_or_causality_claim(
    tmp_path: Path,
) -> None:
    with _consumed(tmp_path, "expected") as values:
        result = _build(*values)
        assert result.outcome is ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED
        assert result.execution_performed is False
        assert result.external_action_causality_proven is False
        assert result.production_authority is False
        assert result.observation["authority_boundary"] == {
            "authorization_granted": True,
            "browser_control": False,
            "credentials": False,
            "execution_performed": False,
            "external_action_attempt_proven": False,
            "external_action_causality_proven": False,
            "feedback_promotion": False,
            "grant_consumption_proven": True,
            "independent_observation": True,
            "model_sdk": False,
            "network": False,
            "production_authority": False,
            "raw_ui_data": False,
            "route_memory_store_write": False,
            "state_change_observed": True,
            "tool_invocation": False,
        }
        assert result.observation["intent"] == values[1].request["intent"]
        assert (
            result.observation["after_observation"]["state_entity_id"]
            == values[1].request["intent"]["to_entity_id"]
        )


@pytest.mark.parametrize(
    ("outcome", "reason", "state_change"),
    (
        (
            ToolzActionOutcome.PRE_STATE_RETAINED,
            ToolzActionOutcomeReason.PRE_STATE_RETAINED,
            False,
        ),
        (
            ToolzActionOutcome.UNEXPECTED_STATE_OBSERVED,
            ToolzActionOutcomeReason.UNEXPECTED_STATE,
            True,
        ),
        (
            ToolzActionOutcome.OUTCOME_UNKNOWN,
            ToolzActionOutcomeReason.EXECUTOR_CRASH_REPORTED,
            None,
        ),
    ),
)
def test_closed_non_success_outcomes_preserve_epistemic_state(
    tmp_path: Path,
    outcome: ToolzActionOutcome,
    reason: ToolzActionOutcomeReason,
    state_change: bool | None,
) -> None:
    with _consumed(tmp_path, outcome.value) as values:
        result = _build(*values, outcome=outcome, reason=reason)
        assert result.outcome is outcome
        assert (
            result.observation["authority_boundary"]["state_change_observed"]
            is state_change
        )
        if outcome is ToolzActionOutcome.OUTCOME_UNKNOWN:
            assert result.observation["after_observation"] is None
            assert result.observation["gap_evidence_digest"] == DIGEST_C
        else:
            assert result.observation["after_observation"] is not None
            assert result.observation["gap_evidence_digest"] is None


def test_resigned_state_substitution_and_stale_checkpoint_fail_closed(
    tmp_path: Path,
) -> None:
    with _consumed(tmp_path, "tamper") as values:
        (
            _,
            evidence,
            ledger,
            decision_signer,
            decision,
            consumption,
            observer_signer,
            policy,
        ) = values
        result = _build(*values)
        substituted = copy.deepcopy(result.observation)
        substituted["after_observation"]["state_digest"] = DIGEST_C
        substituted.pop("signature")
        substituted["observation_id"] = toolz_action_outcome_identity(substituted)
        substituted = observer_signer.sign(substituted)
        with pytest.raises(
            ToolzActionOutcomeError,
            match="state identity mismatch|expected transition observation rejected",
        ):
            verify_toolz_action_outcome_observation(
                substituted,
                policy=policy,
                evidence=evidence,
                decision=decision.decision,
                consumption=consumption.consumption,
                consumption_event=consumption.ledger_event,
                decision_key=_trusted(decision_signer),
                authority_ledger=ledger,
                expected_authority_checkpoint=consumption.checkpoint,
                observer_key=_trusted(observer_signer),
            )
        with pytest.raises(
            ToolzActionOutcomeError,
            match="grant consumption proof rejected",
        ):
            verify_toolz_action_outcome_observation(
                result.observation,
                policy=policy,
                evidence=evidence,
                decision=decision.decision,
                consumption=consumption.consumption,
                consumption_event=consumption.ledger_event,
                decision_key=_trusted(decision_signer),
                authority_ledger=ledger,
                expected_authority_checkpoint=decision.checkpoint,
                observer_key=_trusted(observer_signer),
            )


def test_outcome_observer_must_be_distinct_from_authority_and_requester(
    tmp_path: Path,
) -> None:
    with _consumed(tmp_path, "independence") as values:
        (
            case,
            evidence,
            ledger,
            decision_signer,
            decision,
            consumption,
            _,
            policy,
        ) = values
        with pytest.raises(
            ToolzActionOutcomeError,
            match="not independently anchored",
        ):
            _build(
                case,
                evidence,
                ledger,
                decision_signer,
                decision,
                consumption,
                decision_signer,
                policy,
            )


def test_outcome_module_has_no_browser_network_or_tool_execution() -> None:
    tree = ast.parse(inspect.getsource(outcome_module))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert imported_roots.isdisjoint(
        {
            "http",
            "requests",
            "selenium",
            "socket",
            "subprocess",
            "urllib",
        }
    )
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert calls.isdisjoint(
        {
            "click",
            "execute_tool",
            "invoke",
            "navigate",
            "send",
        }
    )
