from __future__ import annotations

import contextlib
import copy
import inspect
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import integrity_guardian.adapter_sdk as sdk_module
from integrity_guardian.adapter_conformance import (
    build_adapter_conformance_evidence,
    build_adapter_conformance_receipt,
    build_adapter_proof_profile,
)
from integrity_guardian.adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterReportedOutcome,
    AdapterSdkError,
    AdapterTransitionOutcome,
    build_adapter_action_proposal,
    build_adapter_capability_manifest,
    build_adapter_execution_envelope,
    build_adapter_operation_binding,
    build_adapter_transition_receipt,
    classify_adapter_transition,
    verify_adapter_capability_manifest,
    verify_adapter_execution_envelope,
    verify_adapter_operation_binding,
    verify_adapter_transition_receipt,
    verify_toolz_grant_for_adapter,
    verify_toolz_outcome_for_adapter,
)
from integrity_guardian.capabilities import integrity_capabilities
from integrity_guardian.operation_audit import build_readonly_operation_manifest
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs_outcome import (
    ToolzActionOutcome,
    ToolzActionOutcomeReason,
)
from tests.test_uroboros_toolzs import DIGEST_A, DIGEST_B, DIGEST_C, _trusted
from tests.test_uroboros_toolzs_outcome import _build, _consumed
import os
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")
_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX executor fixture (/usr/bin/printf)")

PROPOSED_AT = "2026-07-29T04:40:09Z"
ENVELOPE_AT = "2026-07-29T04:40:11Z"
RECEIPT_AT = "2026-07-29T04:40:15Z"
EXPIRES_AT = "2026-07-29T04:40:17Z"


@contextlib.contextmanager
def _sdk_case(tmp_path: Path, label: str) -> Iterator[dict[str, Any]]:
    with _consumed(tmp_path, label) as values:
        (
            case,
            evidence,
            ledger,
            decision_signer,
            decision,
            consumption,
            observer_signer,
            outcome_policy,
        ) = values
        adapter_signer = Ed25519Signer.generate(f"key:synthetic-sdk-{label}-adapter")
        proposer_signer = Ed25519Signer.generate(f"key:synthetic-sdk-{label}-proposer")
        coordinator_signer = Ed25519Signer.generate(f"key:synthetic-sdk-{label}-coordinator")
        executor_private_key = Ed25519PrivateKey.generate()
        executor_signer = Ed25519Signer(
            f"key:synthetic-sdk-{label}-executor",
            executor_private_key,
        )
        executor_alias_signer = Ed25519Signer(
            f"key:synthetic-sdk-{label}-witness-alias",
            executor_private_key,
        )
        profile_signer = Ed25519Signer.generate(f"key:synthetic-sdk-{label}-profile")
        assessor_signer = Ed25519Signer.generate(f"key:synthetic-sdk-{label}-assessor")
        conformance_signer = Ed25519Signer.generate(f"key:synthetic-sdk-{label}-conformance")
        intent = evidence.request["intent"]
        manifest = build_adapter_capability_manifest(
            adapter_id=f"adapter:synthetic-sdk-{label}",
            adapter_version=ADAPTER_SDK_VERSION,
            adapter_artifact_digest=DIGEST_A,
            roles=["executor"],
            action_classes=[intent["action_class"]],
            declared_channels={
                "api": False,
                "browser_control": False,
                "computer_use": False,
                "credentials": False,
                "network": False,
                "service_control": False,
                "shell": False,
            },
            request_schema_digest=DIGEST_B,
            observation_schema_digest=DIGEST_C,
            result_schema_digest=DIGEST_B,
            max_timeout_seconds=30,
            max_output_bytes=4096,
            credential_delivery="none",
            created_at=PROPOSED_AT,
            signer=adapter_signer,
        )
        proposal = build_adapter_action_proposal(
            manifest=manifest,
            adapter_key=_trusted(adapter_signer),
            intent=intent,
            expected_after_state_digest=case.trace["steps"][0]["after_state_digest"],
            required_channels={
                "api": False,
                "browser_control": False,
                "computer_use": False,
                "credentials": False,
                "network": False,
                "service_control": False,
                "shell": False,
            },
            proposed_at=PROPOSED_AT,
            expires_at=EXPIRES_AT,
            proposer_id=f"planner:synthetic-sdk-{label}",
            proposer_artifact_digest=DIGEST_B,
            signer=proposer_signer,
        )
        grant = verify_toolz_grant_for_adapter(
            evidence=evidence,
            decision=decision.decision,
            consumption=consumption.consumption,
            consumption_event=consumption.ledger_event,
            decision_key=_trusted(decision_signer),
            authority_ledger=ledger,
            expected_authority_checkpoint=consumption.checkpoint,
        )
        operation_manifest = build_readonly_operation_manifest(
            tenant_id=SYNTHETIC_TENANT,
            adapter_id=manifest["adapter_id"],
            target_node_id=intent["to_entity_id"],
            created_at=PROPOSED_AT,
            operations=[
                {
                    "operation_id": f"operation:sdk-{label}",
                    "purpose": "bind one synthetic read-only operation",
                    "argv": [
                        str(Path("/usr/bin/printf").resolve(strict=True)),
                        "adapter-sdk-binding-fixture",
                    ],
                    "credential_reference": None,
                    "timeout_seconds": 5,
                    "max_output_bytes": 1024,
                }
            ],
        )
        conformance_profile = build_adapter_proof_profile(
            manifest=manifest,
            adapter_key=_trusted(adapter_signer),
            created_at=PROPOSED_AT,
            signer=profile_signer,
        )
        source_proof_ids = [
            requirement["proof_id"]
            for requirement in conformance_profile["requirements"]
            if requirement["tier"] == "source" and requirement["applicability"] == "required"
        ]
        conformance_evidence = build_adapter_conformance_evidence(
            profile=conformance_profile,
            profile_key=_trusted(profile_signer),
            manifest=manifest,
            adapter_key=_trusted(adapter_signer),
            suite_id=f"suite:synthetic-sdk-{label}",
            scope="synthetic-local",
            artifact_digest=DIGEST_A,
            environment_digest=DIGEST_B,
            command_digest=DIGEST_C,
            proof_ids=source_proof_ids,
            test_count=len(source_proof_ids),
            created_at=PROPOSED_AT,
            signer=assessor_signer,
        )
        conformance_receipt = build_adapter_conformance_receipt(
            profile=conformance_profile,
            profile_key=_trusted(profile_signer),
            manifest=manifest,
            adapter_key=_trusted(adapter_signer),
            evidence_documents=[conformance_evidence],
            evidence_keys={assessor_signer.key_id: _trusted(assessor_signer)},
            created_at=PROPOSED_AT,
            signer=conformance_signer,
        )
        operation_binding = build_adapter_operation_binding(
            manifest=manifest,
            adapter_key=_trusted(adapter_signer),
            proposal=proposal,
            proposer_key=_trusted(proposer_signer),
            conformance_receipt=conformance_receipt,
            operation_manifest=operation_manifest,
            executor_id=f"executor:synthetic-sdk-{label}",
            executor_artifact_digest=DIGEST_C,
            executor_key_id=executor_signer.key_id,
            created_at=ENVELOPE_AT,
            signer=coordinator_signer,
        )
        envelope = build_adapter_execution_envelope(
            manifest=manifest,
            adapter_key=_trusted(adapter_signer),
            proposal=proposal,
            proposer_key=_trusted(proposer_signer),
            operation_binding=operation_binding,
            operation_manifest=operation_manifest,
            binding_key=_trusted(coordinator_signer),
            verified_grant=grant,
            created_at=ENVELOPE_AT,
            signer=coordinator_signer,
        )
        yield {
            "values": values,
            "case": case,
            "evidence": evidence,
            "ledger": ledger,
            "decision_signer": decision_signer,
            "decision": decision,
            "consumption": consumption,
            "observer_signer": observer_signer,
            "outcome_policy": outcome_policy,
            "adapter_signer": adapter_signer,
            "proposer_signer": proposer_signer,
            "coordinator_signer": coordinator_signer,
            "executor_signer": executor_signer,
            "executor_alias_signer": executor_alias_signer,
            "profile_signer": profile_signer,
            "assessor_signer": assessor_signer,
            "conformance_signer": conformance_signer,
            "manifest": manifest,
            "proposal": proposal,
            "grant": grant,
            "operation_manifest": operation_manifest,
            "operation_binding": operation_binding,
            "conformance_profile": conformance_profile,
            "conformance_evidence": conformance_evidence,
            "conformance_receipt": conformance_receipt,
            "envelope": envelope,
        }


def _witness(
    context: dict[str, Any],
    *,
    outcome: ToolzActionOutcome,
    reason: ToolzActionOutcomeReason,
):
    return _witness_with_signer(
        context,
        context["observer_signer"],
        outcome=outcome,
        reason=reason,
    )


def _witness_with_signer(
    context: dict[str, Any],
    observer_signer: Ed25519Signer,
    *,
    outcome: ToolzActionOutcome,
    reason: ToolzActionOutcomeReason,
):
    observation = _build(
        *context["values"][:6],
        observer_signer,
        context["outcome_policy"],
        outcome=outcome,
        reason=reason,
    )
    return verify_toolz_outcome_for_adapter(
        observation.observation,
        policy=context["outcome_policy"],
        evidence=context["evidence"],
        decision=context["decision"].decision,
        consumption=context["consumption"].consumption,
        consumption_event=context["consumption"].ledger_event,
        decision_key=_trusted(context["decision_signer"]),
        authority_ledger=context["ledger"],
        expected_authority_checkpoint=context["consumption"].checkpoint,
        observer_key=_trusted(observer_signer),
    )


def _receipt(context: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    arguments = {
        "manifest": context["manifest"],
        "adapter_key": _trusted(context["adapter_signer"]),
        "proposal": context["proposal"],
        "proposer_key": _trusted(context["proposer_signer"]),
        "envelope": context["envelope"],
        "operation_binding": context["operation_binding"],
        "operation_manifest": context["operation_manifest"],
        "binding_key": _trusted(context["coordinator_signer"]),
        "coordinator_key": _trusted(context["coordinator_signer"]),
        "verified_grant": context["grant"],
        "grant_consumed": True,
        "invocation_started": True,
        "executor": {
            "executor_id": context["operation_binding"]["executor"]["executor_id"],
            "executor_artifact_digest": context["operation_binding"]["executor"][
                "executor_artifact_digest"
            ],
            "key_id": context["operation_binding"]["executor"]["key_id"],
        },
        "executor_key": _trusted(context["executor_signer"]),
        "adapter_reported_outcome": AdapterReportedOutcome.REPORTED_SUCCESS,
        "adapter_evidence_digest": DIGEST_C,
        "witness": None,
        "recorded_at": RECEIPT_AT,
        "signer": context["coordinator_signer"],
    }
    arguments.update(overrides)
    return build_adapter_transition_receipt(**arguments)


def test_manifest_is_signed_capability_not_authority() -> None:
    signer = Ed25519Signer.generate("key:synthetic-sdk-manifest")
    manifest = build_adapter_capability_manifest(
        adapter_id="adapter:synthetic-universal",
        adapter_version=ADAPTER_SDK_VERSION,
        adapter_artifact_digest=DIGEST_A,
        roles=["observer", "executor", "witness"],
        action_classes=["external-call", "observe"],
        declared_channels={
            "api": True,
            "browser_control": True,
            "computer_use": True,
            "credentials": True,
            "network": True,
            "service_control": True,
            "shell": True,
        },
        request_schema_digest=DIGEST_B,
        observation_schema_digest=DIGEST_C,
        result_schema_digest=DIGEST_B,
        max_timeout_seconds=60,
        max_output_bytes=8192,
        credential_delivery="reference-only",
        created_at=PROPOSED_AT,
        signer=signer,
    )
    verified = verify_adapter_capability_manifest(manifest, adapter_key=_trusted(signer))
    assert verified["limits"] == {
        "max_transitions_per_grant": 1,
        "replay_allowed": False,
        "automatic_retry_after_unknown": False,
        "route_memory_write": False,
        "production_authority": False,
    }
    assert verified["interface_contract"] == {
        "request_schema_digest": DIGEST_B,
        "observation_schema_digest": DIGEST_C,
        "result_schema_digest": DIGEST_B,
        "max_timeout_seconds": 60,
        "max_output_bytes": 8192,
        "credential_delivery": "reference-only",
    }
    with pytest.raises(AdapterSdkError, match="credential declaration mismatch"):
        build_adapter_capability_manifest(
            adapter_id="adapter:invalid-credential-declaration",
            adapter_version=ADAPTER_SDK_VERSION,
            adapter_artifact_digest=DIGEST_A,
            roles=["executor"],
            action_classes=["external-call"],
            declared_channels={
                "api": False,
                "browser_control": False,
                "computer_use": False,
                "credentials": False,
                "network": False,
                "service_control": False,
                "shell": False,
            },
            request_schema_digest=DIGEST_B,
            observation_schema_digest=DIGEST_C,
            result_schema_digest=DIGEST_B,
            max_timeout_seconds=30,
            max_output_bytes=4096,
            credential_delivery="reference-only",
            created_at=PROPOSED_AT,
            signer=signer,
        )


def test_machine_readable_capability_is_honest_target_candidate() -> None:
    capabilities = integrity_capabilities("5.5.1rc8")
    module = next(item for item in capabilities["modules"] if item["module"] == "adapter-sdk")
    assert module["status"] == "1.0.0a2-target-adapter-candidate"
    assert module["execution"] is False
    assert capabilities["authority_boundary"]["adapter_sdk_issues_or_consumes_grants"] is False
    assert capabilities["authority_boundary"]["adapter_sdk_live_adapters_bundled"] is True
    assert capabilities["authority_boundary"]["adapter_sdk_workspace_patch_only"] is False
    assert (
        capabilities["authority_boundary"]["adapter_sdk_target_readiness_is_production_authority"]
        is False
    )
    assert (
        capabilities["authority_boundary"]["adapter_sdk_conformance_is_execution_authority"]
        is False
    )
    assert (
        capabilities["authority_boundary"]["adapter_sdk_source_ready_required_before_dispatch"]
        is True
    )
    assert (
        capabilities["authority_boundary"]["adapter_sdk_signed_operation_binding_required"] is True
    )
    assert (
        capabilities["authority_boundary"]["adapter_sdk_executor_witness_identity_separation"]
        is True
    )
    assert (
        capabilities["authority_boundary"]["adapter_sdk_requires_independent_witness_for_success"]
        is True
    )


@_POSIX_ONLY
def test_execution_envelope_binds_exact_a13_consumption_and_first_intent(
    tmp_path: Path,
) -> None:
    with _sdk_case(tmp_path, "binding") as context:
        verified = verify_adapter_execution_envelope(
            context["envelope"],
            manifest=context["manifest"],
            adapter_key=_trusted(context["adapter_signer"]),
            proposal=context["proposal"],
            proposer_key=_trusted(context["proposer_signer"]),
            operation_binding=context["operation_binding"],
            operation_manifest=context["operation_manifest"],
            binding_key=_trusted(context["coordinator_signer"]),
            coordinator_key=_trusted(context["coordinator_signer"]),
            verified_grant=context["grant"],
            used_at=ENVELOPE_AT,
        )
        assert (
            verified["authorization"]["consumption_id"]
            == context["consumption"].consumption["consumption_id"]
        )
        assert verified["intent"] == context["evidence"].request["intent"]
        assert verified["controls"]["max_invocations"] == 1
        assert verified["controls"]["production_authority"] is False
        binding = verify_adapter_operation_binding(
            context["operation_binding"],
            manifest=context["manifest"],
            adapter_key=_trusted(context["adapter_signer"]),
            proposal=context["proposal"],
            proposer_key=_trusted(context["proposer_signer"]),
            operation_manifest=context["operation_manifest"],
            binding_key=_trusted(context["coordinator_signer"]),
            used_at=ENVELOPE_AT,
        )
        assert verified["operation_binding"]["binding_id"] == binding["binding_id"]
        assert verified["operation_binding"]["executor_key_id"] == context["executor_signer"].key_id

        mismatched = copy.deepcopy(context["grant"])
        mismatched.intent["operation_digest"] = DIGEST_C
        with pytest.raises(AdapterSdkError, match="intent mismatch"):
            build_adapter_execution_envelope(
                manifest=context["manifest"],
                adapter_key=_trusted(context["adapter_signer"]),
                proposal=context["proposal"],
                proposer_key=_trusted(context["proposer_signer"]),
                operation_binding=context["operation_binding"],
                operation_manifest=context["operation_manifest"],
                binding_key=_trusted(context["coordinator_signer"]),
                verified_grant=mismatched,
                created_at=ENVELOPE_AT,
                signer=context["coordinator_signer"],
            )


@_POSIX_ONLY
def test_envelope_rejects_a_different_valid_binding_for_the_same_intent(
    tmp_path: Path,
) -> None:
    with _sdk_case(tmp_path, "binding-substitution") as context:
        foreign_executor = Ed25519Signer.generate("key:foreign-binding-executor")
        foreign = build_adapter_operation_binding(
            manifest=context["manifest"],
            adapter_key=_trusted(context["adapter_signer"]),
            proposal=context["proposal"],
            proposer_key=_trusted(context["proposer_signer"]),
            conformance_receipt=context["conformance_receipt"],
            operation_manifest=context["operation_manifest"],
            executor_id="executor:foreign-binding",
            executor_artifact_digest=DIGEST_B,
            executor_key_id=foreign_executor.key_id,
            created_at=ENVELOPE_AT,
            signer=context["coordinator_signer"],
        )
        with pytest.raises(AdapterSdkError, match="envelope binding mismatch"):
            verify_adapter_execution_envelope(
                context["envelope"],
                manifest=context["manifest"],
                adapter_key=_trusted(context["adapter_signer"]),
                proposal=context["proposal"],
                proposer_key=_trusted(context["proposer_signer"]),
                operation_binding=foreign,
                operation_manifest=context["operation_manifest"],
                binding_key=_trusted(context["coordinator_signer"]),
                coordinator_key=_trusted(context["coordinator_signer"]),
                verified_grant=context["grant"],
                used_at=ENVELOPE_AT,
            )


@pytest.mark.parametrize(
    (
        "name",
        "grant_consumed",
        "started",
        "reported",
        "witness_outcome",
        "witness_reason",
        "expected",
        "retry",
    ),
    (
        ("not-started", False, False, None, None, None, AdapterTransitionOutcome.NOT_STARTED, True),
        (
            "consumed-not-started",
            True,
            False,
            None,
            None,
            None,
            AdapterTransitionOutcome.GRANT_CONSUMED_ACTION_NOT_STARTED,
            False,
        ),
        (
            "success",
            True,
            True,
            AdapterReportedOutcome.REPORTED_SUCCESS,
            ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED,
            ToolzActionOutcomeReason.EXPECTED_TRANSITION,
            AdapterTransitionOutcome.CONFIRMED_SUCCESS,
            False,
        ),
        (
            "failure",
            True,
            True,
            AdapterReportedOutcome.REPORTED_SUCCESS,
            ToolzActionOutcome.PRE_STATE_RETAINED,
            ToolzActionOutcomeReason.PRE_STATE_RETAINED,
            AdapterTransitionOutcome.CONFIRMED_FAILURE,
            False,
        ),
        (
            "unknown",
            True,
            True,
            AdapterReportedOutcome.OUTCOME_UNKNOWN,
            ToolzActionOutcome.OUTCOME_UNKNOWN,
            ToolzActionOutcomeReason.EXECUTOR_CRASH_REPORTED,
            AdapterTransitionOutcome.UNKNOWN_OUTCOME,
            False,
        ),
    ),
)
@_POSIX_ONLY
def test_five_state_crash_matrix_and_no_replay(
    tmp_path: Path,
    name: str,
    grant_consumed: bool,
    started: bool,
    reported: AdapterReportedOutcome | None,
    witness_outcome: ToolzActionOutcome | None,
    witness_reason: ToolzActionOutcomeReason | None,
    expected: AdapterTransitionOutcome,
    retry: bool,
) -> None:
    with _sdk_case(tmp_path, name) as context:
        witness = None
        if witness_outcome is not None and witness_reason is not None:
            witness = _witness(context, outcome=witness_outcome, reason=witness_reason)
        receipt = _receipt(
            context,
            envelope=context["envelope"] if grant_consumed else None,
            verified_grant=context["grant"] if grant_consumed else None,
            grant_consumed=grant_consumed,
            invocation_started=started,
            adapter_reported_outcome=reported,
            adapter_evidence_digest=DIGEST_C if started else None,
            executor=(
                {
                    "executor_id": context["operation_binding"]["executor"]["executor_id"],
                    "executor_artifact_digest": context["operation_binding"]["executor"][
                        "executor_artifact_digest"
                    ],
                    "key_id": context["operation_binding"]["executor"]["key_id"],
                }
                if started
                else None
            ),
            operation_binding=context["operation_binding"] if grant_consumed else None,
            operation_manifest=context["operation_manifest"] if grant_consumed else None,
            binding_key=(_trusted(context["coordinator_signer"]) if grant_consumed else None),
            witness=witness,
        )
        verified = verify_adapter_transition_receipt(
            receipt,
            receipt_key=_trusted(context["coordinator_signer"]),
            executor_key=_trusted(context["executor_signer"]),
        )
        assert verified["result"]["outcome"] == expected.value
        assert verified["result"]["automatic_retry_allowed"] is retry
        assert verified["result"]["action_replayed"] is False
        assert verified["memory"]["route_memory_write_performed"] is False
        assert verified["authority_boundary"]["production_authority"] is False


@_POSIX_ONLY
def test_executor_witness_disagreement_is_unknown_not_green(tmp_path: Path) -> None:
    with _sdk_case(tmp_path, "disagree") as context:
        witness = _witness(
            context,
            outcome=ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED,
            reason=ToolzActionOutcomeReason.EXPECTED_TRANSITION,
        )
        outcome, reason, retry = classify_adapter_transition(
            grant_consumed=True,
            invocation_started=True,
            adapter_reported_outcome=AdapterReportedOutcome.REPORTED_FAILURE,
            witness=witness,
        )
        assert outcome is AdapterTransitionOutcome.UNKNOWN_OUTCOME
        assert reason == "executor-witness-disagree"
        assert retry is False


@_POSIX_ONLY
def test_terminal_builder_reverifies_a14_witness_instead_of_summary(
    tmp_path: Path,
) -> None:
    with _sdk_case(tmp_path, "witness-summary-forgery") as context:
        observed = _witness(
            context,
            outcome=ToolzActionOutcome.PRE_STATE_RETAINED,
            reason=ToolzActionOutcomeReason.PRE_STATE_RETAINED,
        )
        forged = replace(
            observed,
            outcome=ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED,
            reason_code=ToolzActionOutcomeReason.EXPECTED_TRANSITION.value,
        )
        with pytest.raises(AdapterSdkError, match="witness proof mismatch"):
            _receipt(context, witness=forged)


@_POSIX_ONLY
def test_executor_cannot_be_its_own_independent_witness(tmp_path: Path) -> None:
    with _sdk_case(tmp_path, "same-executor-witness") as context:
        witness = _witness(
            context,
            outcome=ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED,
            reason=ToolzActionOutcomeReason.EXPECTED_TRANSITION,
        )
        forged_identity = replace(
            witness,
            observer_id=context["operation_binding"]["executor"]["executor_id"],
        )
        with pytest.raises(AdapterSdkError, match="executor/witness separation rejected"):
            _receipt(context, witness=forged_identity)


@_POSIX_ONLY
def test_executor_key_alias_cannot_be_independent_witness(tmp_path: Path) -> None:
    with _sdk_case(tmp_path, "executor-witness-key-alias") as context:
        witness = _witness_with_signer(
            context,
            context["executor_alias_signer"],
            outcome=ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED,
            reason=ToolzActionOutcomeReason.EXPECTED_TRANSITION,
        )
        with pytest.raises(AdapterSdkError, match="executor/witness separation rejected"):
            _receipt(context, witness=witness)


@_POSIX_ONLY
def test_transition_verifier_rejects_signed_executor_witness_key_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _sdk_case(tmp_path, "signed-executor-witness-key-alias") as context:
        witness = _witness_with_signer(
            context,
            context["executor_alias_signer"],
            outcome=ToolzActionOutcome.EXPECTED_TRANSITION_OBSERVED,
            reason=ToolzActionOutcomeReason.EXPECTED_TRANSITION,
        )
        separation = sdk_module._require_independent_witness
        monkeypatch.setattr(
            sdk_module,
            "_require_independent_witness",
            lambda **_: None,
        )
        malicious_receipt = _receipt(context, witness=witness)
        monkeypatch.setattr(
            sdk_module,
            "_require_independent_witness",
            separation,
        )
        with pytest.raises(AdapterSdkError, match="executor/witness separation rejected"):
            verify_adapter_transition_receipt(
                malicious_receipt,
                receipt_key=_trusted(context["coordinator_signer"]),
                executor_key=_trusted(context["executor_signer"]),
            )


def test_sdk_has_no_live_actuator_or_parallel_memory_writer() -> None:
    source = inspect.getsource(sdk_module)
    assert "subprocess" not in source
    assert "socket" not in source
    assert 'route_memory_write_performed": False' in source
    assert "verify_toolz_action_outcome_observation" in source
    assert "verify_consumption_record" in source
