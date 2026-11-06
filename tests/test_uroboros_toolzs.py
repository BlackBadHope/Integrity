from __future__ import annotations

import ast
import inspect
from copy import deepcopy
from dataclasses import replace
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs as toolzs_module
from integrity_guardian.discovery import (
    CoverageState,
    DiscoveryCursor,
    DiscoveryEmitter,
    TrustedDiscoverySource,
    ZonedDiscoveryIndex,
    build_entity_assertion,
    build_relation_assertion,
)
from integrity_guardian.discovery_feedback import (
    DiscoveryFeedbackPolicy,
    TrustedDiscoveryFeedback,
    build_discovery_feedback_overlay,
    synthesize_discovery_theory_route_with_feedback,
)
from integrity_guardian.discovery_theory import (
    DiscoveryFeedbackOutcome,
    DiscoveryTheoryPolicy,
    build_discovery_theory_feedback,
    synthesize_discovery_theory_route,
)
from integrity_guardian.security_admission import (
    ProjectSecurityAdmissionPolicy,
    SecurityArtifact,
    SecurityEnvironment,
    SecurityHarness,
    build_artifact_provenance_receipt,
    build_execution_containment_receipt,
    build_security_assessment_receipt,
    evaluate_project_security_admission,
)
from integrity_guardian.signing import Ed25519Signer, TrustedKey
from integrity_guardian.uroboros_toolzs import (
    ToolzCyberEvidence,
    ToolzFogRouteEvidence,
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryError,
    ToolzRouteMemoryOutcome,
    ToolzRouteMemoryPolicy,
    build_toolz_route_memory_receipt,
    evaluate_toolz_route_memory,
    verify_toolz_route_memory_receipt,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64
DIGEST_F = "sha256:" + "f" * 64
CYBER_CREATED = "2026-07-29T03:30:00Z"
CYBER_EVALUATED = "2026-07-29T04:00:00Z"
CYBER_DECISION_EXPIRES = "2026-07-29T05:30:00Z"
CYBER_INPUT_EXPIRES = "2026-07-29T06:00:00Z"
OBSERVED = "2026-07-29T04:15:00Z"
MEMORY_CREATED = "2026-07-29T04:20:00Z"
MEMORY_EXPIRES = "2026-07-29T05:00:00Z"


def _trusted(signer: Ed25519Signer) -> TrustedKey:
    return TrustedKey(signer.key_id, signer.public_key)


def _fog_evidence(
    *,
    unresolved: bool = False,
    feedback_ranked: bool = False,
) -> ToolzFogRouteEvidence:
    source_signer = Ed25519Signer.generate("key:synthetic-toolz-source")
    snapshot_signer = Ed25519Signer.generate("key:synthetic-toolz-snapshot")
    theory_signer = Ed25519Signer.generate("key:synthetic-toolz-theory")
    emitter = DiscoveryEmitter(
        tenant_id=SYNTHETIC_TENANT,
        cursor=DiscoveryCursor(
            source_id="source:synthetic-toolz",
            source_epoch="epoch:synthetic-toolz-1",
        ),
        signer=source_signer,
    )
    records = [
        emitter.emit(
            assertion=build_entity_assertion(
                entity_id="entity:synthetic-toolz-start",
                entity_type="entity-type:synthetic-ui-state",
            ),
            observed_at="2026-07-29T03:10:00Z",
            zone_id="zone:synthetic-toolz-start",
            source_artifact_digest=DIGEST_A,
            coverage_digest=DIGEST_B,
            confidence_ppm=1_000_000,
            content_digest=DIGEST_C,
            coverage=CoverageState.COMPLETE,
        ),
        emitter.emit(
            assertion=build_entity_assertion(
                entity_id="entity:synthetic-toolz-finish",
                entity_type="entity-type:synthetic-ui-state",
            ),
            observed_at="2026-07-29T03:11:00Z",
            zone_id="zone:synthetic-toolz-finish",
            source_artifact_digest=DIGEST_A,
            coverage_digest=DIGEST_B,
            confidence_ppm=1_000_000,
            content_digest=DIGEST_C,
            coverage=CoverageState.COMPLETE,
        ),
        emitter.emit(
            assertion=build_relation_assertion(
                relation_id="relation:synthetic-toolz-next",
                relation_type="relation-type:synthetic-ui-transition",
                from_entity_id="entity:synthetic-toolz-start",
                to_entity_id="entity:synthetic-toolz-finish",
                from_zone_id="zone:synthetic-toolz-start",
                to_zone_id="zone:synthetic-toolz-finish",
            ),
            observed_at="2026-07-29T03:12:00Z",
            zone_id="zone:synthetic-toolz-start",
            source_artifact_digest=DIGEST_A,
            coverage_digest=DIGEST_B,
            confidence_ppm=900_000,
            content_digest=DIGEST_C,
            coverage=CoverageState.COMPLETE,
        ),
    ]
    trusted_sources = (
        TrustedDiscoverySource(
            source_id="source:synthetic-toolz",
            source_epoch="epoch:synthetic-toolz-1",
            source_artifact_digest=DIGEST_A,
            trusted_key=_trusted(source_signer),
        ),
    )
    index = ZonedDiscoveryIndex(
        tenant_id=SYNTHETIC_TENANT,
        trusted_sources=trusted_sources,
        receipt_signer=snapshot_signer,
    )
    index.apply(records)
    snapshot = index.export_snapshot(created_at="2026-07-29T03:15:00Z")
    theory_policy = DiscoveryTheoryPolicy(
        policy_id="policy:synthetic-toolz-theory",
        allowed_relation_types=("relation-type:synthetic-ui-transition",),
        min_confidence_ppm=(950_000 if unresolved else 0),
        max_hops=4,
        max_expansions=16,
    )
    base_route = synthesize_discovery_theory_route(
        snapshot,
        trusted_snapshot_key=_trusted(snapshot_signer),
        trusted_sources=trusted_sources,
        expected_snapshot_id=snapshot["snapshot_id"],
        expected_tenant_id=SYNTHETIC_TENANT,
        policy=theory_policy,
        from_entity_id="entity:synthetic-toolz-start",
        to_entity_id="entity:synthetic-toolz-finish",
        created_at="2026-07-29T03:20:00Z",
        theory_signer=theory_signer,
    )
    if not feedback_ranked:
        return ToolzFogRouteEvidence(
            snapshot=snapshot,
            route=base_route,
            trusted_snapshot_key=_trusted(snapshot_signer),
            trusted_sources=trusted_sources,
            trusted_theory_key=_trusted(theory_signer),
            expected_snapshot_id=snapshot["snapshot_id"],
            expected_tenant_id=SYNTHETIC_TENANT,
            expected_policy=theory_policy,
        )

    feedback_signer = Ed25519Signer.generate("key:synthetic-toolz-observer")
    feedback_receipt = build_discovery_theory_feedback(
        base_route,
        observer_id="observer:synthetic-toolz-local",
        observed_at="2026-07-29T03:21:00Z",
        outcome=DiscoveryFeedbackOutcome.CONFIRMED,
        evidence_digest=DIGEST_D,
        affected_record_ids=(base_route["hops"][0]["record_id"],),
        invalidated_zone_ids=(),
        feedback_signer=feedback_signer,
        trusted_theory_key=_trusted(theory_signer),
    )
    feedback_evidence = (
        TrustedDiscoveryFeedback(
            proposal=base_route,
            receipt=feedback_receipt,
            proposal_policy=theory_policy,
            trusted_theory_key=_trusted(theory_signer),
            trusted_feedback_key=_trusted(feedback_signer),
            expected_observer_id="observer:synthetic-toolz-local",
        ),
    )
    feedback_policy = DiscoveryFeedbackPolicy(
        policy_id="policy:synthetic-toolz-feedback",
    )
    overlay_signer = Ed25519Signer.generate("key:synthetic-toolz-overlay")
    overlay = build_discovery_feedback_overlay(
        snapshot,
        trusted_snapshot_key=_trusted(snapshot_signer),
        trusted_sources=trusted_sources,
        expected_snapshot_id=snapshot["snapshot_id"],
        expected_tenant_id=SYNTHETIC_TENANT,
        expected_policy=theory_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
        created_at="2026-07-29T03:22:00Z",
        overlay_signer=overlay_signer,
    )
    ranked_route = synthesize_discovery_theory_route_with_feedback(
        snapshot,
        overlay,
        trusted_snapshot_key=_trusted(snapshot_signer),
        trusted_sources=trusted_sources,
        trusted_overlay_key=_trusted(overlay_signer),
        expected_snapshot_id=snapshot["snapshot_id"],
        expected_tenant_id=SYNTHETIC_TENANT,
        expected_policy=theory_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
        from_entity_id="entity:synthetic-toolz-start",
        to_entity_id="entity:synthetic-toolz-finish",
        created_at="2026-07-29T03:23:00Z",
        theory_signer=theory_signer,
    )
    return ToolzFogRouteEvidence(
        snapshot=snapshot,
        route=ranked_route,
        trusted_snapshot_key=_trusted(snapshot_signer),
        trusted_sources=trusted_sources,
        trusted_theory_key=_trusted(theory_signer),
        expected_snapshot_id=snapshot["snapshot_id"],
        expected_tenant_id=SYNTHETIC_TENANT,
        expected_policy=theory_policy,
        overlay=overlay,
        trusted_overlay_key=_trusted(overlay_signer),
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
    )


def _cyber_evidence(
    *,
    unresolved_high: int = 0,
    subject: SecurityArtifact | None = None,
    environment: SecurityEnvironment | None = None,
    requested_channel: str = "stable",
) -> tuple[ProjectSecurityAdmissionPolicy, ToolzCyberEvidence]:
    subject = subject or SecurityArtifact(
        tenant_id=SYNTHETIC_TENANT,
        artifact_id="toolz:synthetic-browser-route",
        artifact_digest=DIGEST_A,
    )
    environment = environment or SecurityEnvironment(
        profile_id="environment:synthetic-linux",
        fingerprint_digest=DIGEST_B,
    )
    provenance_harness = SecurityHarness(
        harness_id="harness:synthetic-toolz-provenance",
        revision="1" * 40,
        artifact_digest=DIGEST_C,
    )
    assessment_harness = SecurityHarness(
        harness_id="harness:synthetic-toolz-assessment",
        revision="2" * 40,
        artifact_digest=DIGEST_D,
    )
    containment_harness = SecurityHarness(
        harness_id="harness:synthetic-toolz-containment",
        revision="3" * 40,
        artifact_digest=DIGEST_E,
    )
    provenance_signer = Ed25519Signer.generate("key:synthetic-toolz-provenance")
    assessment_signer = Ed25519Signer.generate("key:synthetic-toolz-assessment")
    containment_signer = Ed25519Signer.generate("key:synthetic-toolz-containment")
    promotion_signer = Ed25519Signer.generate("key:synthetic-toolz-promotion")
    policy = ProjectSecurityAdmissionPolicy(
        policy_id=f"policy:synthetic-toolz-{requested_channel}",
        product_id="product:synthetic-toolzs",
        subject=subject,
        environment=environment,
        provenance_policy_digest=DIGEST_C,
        assessment_policy_digest=DIGEST_D,
        containment_policy_digest=DIGEST_E,
        provenance_harness=provenance_harness,
        assessment_harness=assessment_harness,
        containment_harness=containment_harness,
        requested_channel=requested_channel,
        require_reproducible_provenance=True,
        required_assessment_mode="full",
        require_complete_coverage=True,
        require_validated_findings=True,
        max_unresolved_critical=0,
        max_unresolved_high=0,
        max_unresolved_medium=0,
        max_unresolved_low=0,
        containment_required=True,
        required_containment_assurance="protected",
    )
    provenance = build_artifact_provenance_receipt(
        subject,
        policy_digest=DIGEST_C,
        environment=environment,
        harness=provenance_harness,
        source_revision="4" * 40,
        source_tree_digest=DIGEST_D,
        dependency_lock_digest=DIGEST_E,
        build_digest=DIGEST_F,
        state="exact",
        reproducible=True,
        artifact_count=4,
        created_at=CYBER_CREATED,
        expires_at=CYBER_INPUT_EXPIRES,
        authority_signer=provenance_signer,
    )
    unresolved = {
        "critical": 0,
        "high": unresolved_high,
        "medium": 0,
        "low": 0,
    }
    assessment = build_security_assessment_receipt(
        subject,
        policy_digest=DIGEST_D,
        environment=environment,
        harness=assessment_harness,
        scope_mode="full",
        selectors=(".",),
        exclusions=(),
        threat_model_digest=DIGEST_E,
        knowledge_base_digests=(DIGEST_F,),
        coverage_state="complete",
        examined_count=42,
        omitted_count=0,
        termination_reason="completed",
        sealed_finding_set_digest=DIGEST_F,
        total_findings=unresolved_high,
        unresolved=unresolved,
        validation_state="validated-complete",
        previous_receipt_id=None,
        history_counts={
            "new": unresolved_high,
            "persisting": 0,
            "reopened": 0,
            "resolved": 0,
            "unknown": 0,
        },
        tool_calls=3,
        model_calls=1,
        elapsed_ms=2_500,
        private_evidence_reference="private-evidence:synthetic/toolzs-assessment",
        private_evidence_retained_until=CYBER_INPUT_EXPIRES,
        created_at=CYBER_CREATED,
        expires_at=CYBER_INPUT_EXPIRES,
        authority_signer=assessment_signer,
    )
    containment = build_execution_containment_receipt(
        subject,
        policy_digest=DIGEST_E,
        environment=environment,
        environment_supported=True,
        harness=containment_harness,
        assurance_class="protected",
        ready_before_untrusted_work=True,
        policy_frozen=True,
        controls={
            "egress": "bounded",
            "privilege": "removed",
            "container_control": "disabled",
            "secrets": "absent",
        },
        resident_monitor=True,
        continuous_monitor=True,
        post_run_drift="none",
        allowed_channels=("results:synthetic",),
        exceptions=(),
        created_at=CYBER_CREATED,
        expires_at=CYBER_INPUT_EXPIRES,
        authority_signer=containment_signer,
    )
    decision = evaluate_project_security_admission(
        policy,
        provenance,
        assessment,
        containment,
        provenance_key=_trusted(provenance_signer),
        assessment_key=_trusted(assessment_signer),
        containment_key=_trusted(containment_signer),
        evaluated_at=CYBER_EVALUATED,
        expires_at=CYBER_DECISION_EXPIRES,
        authority_signer=promotion_signer,
    )
    evidence = ToolzCyberEvidence(
        decision_receipt=decision,
        expected_policy=policy,
        provenance_receipt=provenance,
        assessment_receipt=assessment,
        containment_receipt=containment,
        provenance_key=_trusted(provenance_signer),
        assessment_key=_trusted(assessment_signer),
        containment_key=_trusted(containment_signer),
        authority_key=_trusted(promotion_signer),
    )
    return policy, evidence


def _memory_policy(
    cyber_policy: ProjectSecurityAdmissionPolicy,
    *,
    require_feedback_ranked: bool = False,
    required_cyber_channel: str | None = None,
    environment: SecurityEnvironment | None = None,
) -> ToolzRouteMemoryPolicy:
    return ToolzRouteMemoryPolicy(
        policy_id="policy:synthetic-uroboros-toolzs-v1",
        subject=cyber_policy.subject,
        environment=environment or cyber_policy.environment,
        ui_context_digest=DIGEST_F,
        required_cyber_channel=(required_cyber_channel or cyber_policy.requested_channel),
        require_feedback_ranked=require_feedback_ranked,
        max_validity_seconds=3_600,
    )


def _memory(
    policy: ToolzRouteMemoryPolicy,
    fog: ToolzFogRouteEvidence,
    cyber: ToolzCyberEvidence,
    signer: Ed25519Signer,
    *,
    outcome: ToolzRouteMemoryOutcome = ToolzRouteMemoryOutcome.OBSERVED_SUCCESS,
    observed_at: str | None = OBSERVED,
    evidence_digest: str | None = DIGEST_E,
    created_at: str = MEMORY_CREATED,
    expires_at: str = MEMORY_EXPIRES,
) -> dict[str, Any]:
    return build_toolz_route_memory_receipt(
        policy=policy,
        fog_evidence=fog,
        cyber_evidence=cyber,
        outcome=outcome,
        observed_at=observed_at,
        observation_evidence_digest=evidence_digest,
        created_at=created_at,
        expires_at=expires_at,
        memory_signer=signer,
    )


def test_observed_success_is_reuse_candidate_without_execution_authority() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")

    receipt = _memory(policy, fog, cyber, memory_signer)
    decision = evaluate_toolz_route_memory(
        receipt,
        expected_policy=policy,
        fog_evidence=fog,
        cyber_evidence=cyber,
        authority_key=_trusted(memory_signer),
        evaluated_at="2026-07-29T04:30:00Z",
    )

    assert decision is ToolzRouteMemoryDecision.REUSE_CANDIDATE
    assert receipt["fog_route"]["proposal_id"] == fog.route["proposal_id"]
    assert receipt["cyber_admission"]["decision"] == "stable-eligible"
    assert not any(receipt["authority_boundary"].values())


def test_theoretical_route_requires_exploration() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(
        policy,
        fog,
        cyber,
        memory_signer,
        outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        observed_at=None,
        evidence_digest=None,
    )

    assert (
        evaluate_toolz_route_memory(
            receipt,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:30:00Z",
        )
        is ToolzRouteMemoryDecision.EXPLORE
    )


@pytest.mark.parametrize(
    "outcome",
    [
        ToolzRouteMemoryOutcome.OBSERVED_FAILURE,
        ToolzRouteMemoryOutcome.STALE,
        ToolzRouteMemoryOutcome.INVALIDATED,
    ],
)
def test_non_reusable_outcomes_force_rediscovery(
    outcome: ToolzRouteMemoryOutcome,
) -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(
        policy,
        fog,
        cyber,
        memory_signer,
        outcome=outcome,
    )

    assert (
        evaluate_toolz_route_memory(
            receipt,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:30:00Z",
        )
        is ToolzRouteMemoryDecision.REDISCOVER
    )


def test_expired_memory_forces_rediscovery() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)

    assert (
        evaluate_toolz_route_memory(
            receipt,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T05:00:01Z",
        )
        is ToolzRouteMemoryDecision.REDISCOVER
    )


def test_unresolved_fog_route_blocks_and_cannot_claim_success() -> None:
    fog = _fog_evidence(unresolved=True)
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")

    with pytest.raises(
        ToolzRouteMemoryError,
        match="successful unresolved route rejected",
    ):
        _memory(policy, fog, cyber, memory_signer)

    receipt = _memory(
        policy,
        fog,
        cyber,
        memory_signer,
        outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        observed_at=None,
        evidence_digest=None,
    )
    assert (
        evaluate_toolz_route_memory(
            receipt,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:30:00Z",
        )
        is ToolzRouteMemoryDecision.BLOCKED
    )


def test_ineligible_local_cyber_chain_blocks_reuse() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence(unresolved_high=1)
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)

    assert receipt["cyber_admission"]["decision"] == "ineligible"
    assert (
        evaluate_toolz_route_memory(
            receipt,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:30:00Z",
        )
        is ToolzRouteMemoryDecision.BLOCKED
    )


def test_feedback_ranked_route_is_exactly_bound_when_required() -> None:
    fog = _fog_evidence(feedback_ranked=True)
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy, require_feedback_ranked=True)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)

    assert receipt["fog_route"]["route_kind"] == "feedback-ranked"
    assert receipt["fog_route"]["feedback_overlay_id"] == fog.overlay["overlay_id"]
    assert (
        evaluate_toolz_route_memory(
            receipt,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:30:00Z",
        )
        is ToolzRouteMemoryDecision.REUSE_CANDIDATE
    )


def test_feedback_requirement_rejects_base_route() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy, require_feedback_ranked=True)

    with pytest.raises(
        ToolzRouteMemoryError,
        match="feedback-ranked route required",
    ):
        _memory(
            policy,
            fog,
            cyber,
            Ed25519Signer.generate("key:synthetic-toolz-memory"),
        )


def test_exact_local_context_and_channel_cannot_be_substituted() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")

    wrong_environment = SecurityEnvironment(
        profile_id="environment:synthetic-other",
        fingerprint_digest=DIGEST_C,
    )
    with pytest.raises(ToolzRouteMemoryError, match="cyber context mismatch"):
        _memory(
            _memory_policy(cyber_policy, environment=wrong_environment),
            fog,
            cyber,
            memory_signer,
        )
    with pytest.raises(ToolzRouteMemoryError, match="cyber channel mismatch"):
        _memory(
            _memory_policy(cyber_policy, required_cyber_channel="rc"),
            fog,
            cyber,
            memory_signer,
        )


def test_receipt_fog_context_and_memory_key_tampering_are_rejected() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)

    tampered = deepcopy(receipt)
    tampered["tool_context"]["ui_context_digest"] = DIGEST_A
    with pytest.raises(ToolzRouteMemoryError, match="identity mismatch"):
        verify_toolz_route_memory_receipt(
            tampered,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
        )
    with pytest.raises(ToolzRouteMemoryError, match="signature rejected"):
        verify_toolz_route_memory_receipt(
            receipt,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(Ed25519Signer.generate("key:synthetic-toolz-memory-other")),
        )

    alternate_fog = _fog_evidence(feedback_ranked=True)
    with pytest.raises(ToolzRouteMemoryError, match="fog_route mismatch"):
        verify_toolz_route_memory_receipt(
            receipt,
            expected_policy=policy,
            fog_evidence=alternate_fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
        )


@pytest.mark.parametrize("raw_field", ["screenshot", "dom", "cookie", "token"])
def test_schema_rejects_raw_ui_and_secret_fields(raw_field: str) -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)
    tampered = deepcopy(receipt)
    tampered["tool_context"][raw_field] = "must-not-enter-receipt"

    with pytest.raises(ToolzRouteMemoryError, match="schema rejected"):
        verify_toolz_route_memory_receipt(
            tampered,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            authority_key=_trusted(memory_signer),
        )


def test_observation_semantics_and_validity_windows_fail_closed() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")

    with pytest.raises(ToolzRouteMemoryError, match="theoretical observation rejected"):
        _memory(
            policy,
            fog,
            cyber,
            memory_signer,
            outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        )
    with pytest.raises(ToolzRouteMemoryError, match="observation evidence rejected"):
        _memory(
            policy,
            fog,
            cyber,
            memory_signer,
            outcome=ToolzRouteMemoryOutcome.OBSERVED_FAILURE,
            evidence_digest=None,
        )
    with pytest.raises(ToolzRouteMemoryError, match="validity window rejected"):
        _memory(
            policy,
            fog,
            cyber,
            memory_signer,
            expires_at=CYBER_INPUT_EXPIRES,
        )
    with pytest.raises(ToolzRouteMemoryError, match="validity window rejected"):
        _memory(
            policy,
            fog,
            cyber,
            memory_signer,
            outcome=ToolzRouteMemoryOutcome.THEORETICAL,
            observed_at=None,
            evidence_digest=None,
            created_at="2026-07-29T03:19:00Z",
            expires_at="2026-07-29T04:00:00Z",
        )


def test_imported_memory_cannot_bypass_a_different_local_cyber_subject() -> None:
    fog = _fog_evidence()
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)

    other_subject = SecurityArtifact(
        tenant_id=SYNTHETIC_TENANT,
        artifact_id="toolz:synthetic-other-browser-route",
        artifact_digest=DIGEST_C,
    )
    other_cyber_policy, other_cyber = _cyber_evidence(subject=other_subject)
    other_policy = replace(
        _memory_policy(other_cyber_policy),
        ui_context_digest=policy.ui_context_digest,
    )
    with pytest.raises(ToolzRouteMemoryError, match="policy_digest mismatch"):
        verify_toolz_route_memory_receipt(
            receipt,
            expected_policy=other_policy,
            fog_evidence=fog,
            cyber_evidence=other_cyber,
            authority_key=_trusted(memory_signer),
        )


def test_protocol_module_has_no_active_io_or_dynamic_execution() -> None:
    tree = ast.parse(inspect.getsource(toolzs_module))
    blocked_import_roots = {
        "http",
        "importlib",
        "os",
        "pathlib",
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
