from __future__ import annotations

import ast
import copy
import inspect
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_admission as admission_module
from integrity_guardian.discovery import (
    CoverageState,
    DiscoveryCursor,
    DiscoveryEmitter,
    DiscoveryProvenance,
    TrustedDiscoverySource,
    ZonedDiscoveryIndex,
    build_relation_assertion,
)
from integrity_guardian.discovery_theory import (
    DiscoveryTheoryPolicy,
    synthesize_discovery_theory_route,
)
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs import (
    ToolzFogRouteEvidence,
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryOutcome,
    build_toolz_route_memory_receipt,
    evaluate_toolz_route_memory,
)
from integrity_guardian.uroboros_toolzs_admission import (
    ToolzTraceAdmissionDecision,
    ToolzTraceAdmissionError,
    ToolzTraceAdmissionPolicy,
    build_toolz_trace_admission,
    toolz_trace_admission_identity,
    verify_toolz_trace_admission_receipt,
)
from integrity_guardian.uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzStoreLifecycle,
    toolz_store_context_identity,
)
from integrity_guardian.uroboros_toolzs_trace import (
    TOOLZ_TRACE_RELATION_TYPE,
    ToolzActionClass,
    ToolzActionStep,
    ToolzActionTracePolicy,
    build_toolz_action_trace_receipt,
    compile_toolz_action_trace,
    describe_toolz_action_trace_path,
)
from tests.test_uroboros_toolzs import (
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    DIGEST_D,
    DIGEST_E,
    DIGEST_F,
    MEMORY_CREATED,
    MEMORY_EXPIRES,
    OBSERVED,
    _cyber_evidence,
    _memory_policy,
    _trusted,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")

TRACE_STARTED = "2026-07-29T04:05:00Z"
TRACE_STEP_1 = "2026-07-29T04:06:00Z"
TRACE_STEP_2 = "2026-07-29T04:07:00Z"
TRACE_COMPLETED = "2026-07-29T04:08:00Z"
SNAPSHOT_CREATED = "2026-07-29T04:09:00Z"
ROUTE_CREATED = "2026-07-29T04:10:00Z"


@dataclass(frozen=True)
class _AdmissionFixture:
    trace_policy: ToolzActionTracePolicy
    trace: dict[str, Any]
    observer_signer: Ed25519Signer
    source_signer: Ed25519Signer
    trusted_source: TrustedDiscoverySource
    fog: ToolzFogRouteEvidence
    cyber: Any
    memory_policy: Any
    admission_policy: ToolzTraceAdmissionPolicy
    memory_signer: Ed25519Signer
    admission_signer: Ed25519Signer


def _steps(
    *,
    first_at: str = TRACE_STEP_1,
    second_at: str = TRACE_STEP_2,
) -> tuple[ToolzActionStep, ...]:
    return (
        ToolzActionStep(
            action_class=ToolzActionClass.ACTIVATE,
            operation_digest=DIGEST_A,
            before_state_digest=DIGEST_C,
            after_state_digest=DIGEST_D,
            before_zone_id="zone:synthetic-admission-start",
            after_zone_id="zone:synthetic-admission-middle",
            observed_at=first_at,
            evidence_digest=DIGEST_E,
            confidence_ppm=980_000,
        ),
        ToolzActionStep(
            action_class=ToolzActionClass.SUBMIT,
            operation_digest=DIGEST_B,
            before_state_digest=DIGEST_D,
            after_state_digest=DIGEST_E,
            before_zone_id="zone:synthetic-admission-middle",
            after_zone_id="zone:synthetic-admission-finish",
            observed_at=second_at,
            evidence_digest=DIGEST_F,
            confidence_ppm=970_000,
        ),
    )


def _trace_policy(cyber_policy: Any) -> ToolzActionTracePolicy:
    return ToolzActionTracePolicy(
        policy_id="policy:synthetic-toolz-admission-trace",
        subject=cyber_policy.subject,
        environment=cyber_policy.environment,
        ui_context_digest=DIGEST_F,
        observer_id="observer:synthetic-toolz-admission",
        observer_artifact_digest=DIGEST_C,
        discovery_source_id="source:synthetic-toolz-admission",
        discovery_source_epoch="epoch:synthetic-toolz-admission-1",
        discovery_source_artifact_digest=DIGEST_D,
        max_steps=8,
        max_duration_seconds=600,
    )


def _trace(
    policy: ToolzActionTracePolicy,
    signer: Ed25519Signer,
    *,
    steps: tuple[ToolzActionStep, ...] | None = None,
    started_at: str = TRACE_STARTED,
    completed_at: str = TRACE_COMPLETED,
) -> dict[str, Any]:
    return build_toolz_action_trace_receipt(
        policy=policy,
        steps=steps or _steps(),
        coverage_digest=DIGEST_D,
        started_at=started_at,
        completed_at=completed_at,
        observer_signer=signer,
    )


def _fixture(
    *,
    route_created_at: str = ROUTE_CREATED,
    shortcut: bool = False,
    rewire: bool = False,
    wrong_evidence: bool = False,
) -> _AdmissionFixture:
    cyber_policy, cyber = _cyber_evidence()
    memory_policy = _memory_policy(cyber_policy)
    trace_policy = _trace_policy(cyber_policy)
    observer_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-admission-observer"
    )
    source_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-admission-source"
    )
    trace = _trace(trace_policy, observer_signer)
    projection = compile_toolz_action_trace(
        trace,
        expected_policy=trace_policy,
        observer_key=_trusted(observer_signer),
        discovery_cursor=DiscoveryCursor(
            source_id=trace_policy.discovery_source_id,
            source_epoch=trace_policy.discovery_source_epoch,
        ),
        discovery_signer=source_signer,
    )
    path = describe_toolz_action_trace_path(
        trace,
        expected_policy=trace_policy,
        observer_key=_trusted(observer_signer),
    )
    if rewire or wrong_evidence:
        if rewire:
            malicious_middle = "entity:synthetic-toolz-state-" + "0" * 64
            emitted_hops = (
                replace(path.hops[0], to_entity_id=malicious_middle),
                replace(path.hops[1], from_entity_id=malicious_middle),
            )
        else:
            emitted_hops = path.hops
        evidence_digests = (
            (DIGEST_A, DIGEST_F)
            if wrong_evidence
            else (DIGEST_E, DIGEST_F)
        )
        emitter = DiscoveryEmitter(
            tenant_id=SYNTHETIC_TENANT,
            cursor=DiscoveryCursor(
                source_id=trace_policy.discovery_source_id,
                source_epoch=trace_policy.discovery_source_epoch,
            ),
            signer=source_signer,
        )
        records = [
            emitter.emit(
                assertion=build_relation_assertion(
                    relation_id=hop.relation_id,
                    relation_type=TOOLZ_TRACE_RELATION_TYPE,
                    from_entity_id=hop.from_entity_id,
                    to_entity_id=hop.to_entity_id,
                    from_zone_id=hop.from_zone_id,
                    to_zone_id=hop.to_zone_id,
                ),
                observed_at=(TRACE_STEP_1, TRACE_STEP_2)[sequence],
                zone_id=hop.from_zone_id,
                source_artifact_digest=(
                    trace_policy.discovery_source_artifact_digest
                ),
                coverage_digest=projection.projection_digest,
                provenance=DiscoveryProvenance.LEARNED,
                coverage=CoverageState.PARTIAL,
                confidence_ppm=hop.confidence_ppm,
                content_digest=evidence_digests[sequence],
            )
            for sequence, hop in enumerate(emitted_hops)
        ]
    else:
        records = list(projection.records)
    if shortcut:
        emitter = DiscoveryEmitter(
            tenant_id=SYNTHETIC_TENANT,
            cursor=projection.next_cursor,
            signer=source_signer,
        )
        records.append(
            emitter.emit(
                assertion=build_relation_assertion(
                    relation_id="relation:synthetic-000-shortcut",
                    relation_type=TOOLZ_TRACE_RELATION_TYPE,
                    from_entity_id=projection.from_entity_id,
                    to_entity_id=projection.to_entity_id,
                    from_zone_id="zone:synthetic-admission-start",
                    to_zone_id="zone:synthetic-admission-finish",
                ),
                observed_at="2026-07-29T04:08:30Z",
                zone_id="zone:synthetic-admission-start",
                source_artifact_digest=(
                    trace_policy.discovery_source_artifact_digest
                ),
                coverage_digest=projection.projection_digest,
                provenance=DiscoveryProvenance.LEARNED,
                coverage=CoverageState.PARTIAL,
                confidence_ppm=990_000,
                content_digest=DIGEST_E,
            )
        )
    trusted_source = TrustedDiscoverySource(
        source_id=trace_policy.discovery_source_id,
        source_epoch=trace_policy.discovery_source_epoch,
        source_artifact_digest=trace_policy.discovery_source_artifact_digest,
        trusted_key=_trusted(source_signer),
    )
    index_signer = Ed25519Signer.generate("key:synthetic-toolz-admission-index")
    index = ZonedDiscoveryIndex(
        tenant_id=SYNTHETIC_TENANT,
        trusted_sources=(trusted_source,),
        receipt_signer=index_signer,
    )
    index.apply(records)
    snapshot = index.export_snapshot(created_at=SNAPSHOT_CREATED)
    theory_policy = DiscoveryTheoryPolicy(
        policy_id="policy:synthetic-toolz-admission-route",
        allowed_relation_types=(TOOLZ_TRACE_RELATION_TYPE,),
        allowed_provenance=(DiscoveryProvenance.LEARNED,),
        min_confidence_ppm=900_000,
        max_hops=8,
    )
    theory_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-admission-theory"
    )
    route = synthesize_discovery_theory_route(
        snapshot,
        trusted_snapshot_key=_trusted(index_signer),
        trusted_sources=(trusted_source,),
        expected_snapshot_id=snapshot["snapshot_id"],
        expected_tenant_id=SYNTHETIC_TENANT,
        policy=theory_policy,
        from_entity_id=projection.from_entity_id,
        to_entity_id=projection.to_entity_id,
        created_at=route_created_at,
        theory_signer=theory_signer,
    )
    fog = ToolzFogRouteEvidence(
        snapshot=snapshot,
        route=route,
        trusted_snapshot_key=_trusted(index_signer),
        trusted_sources=(trusted_source,),
        trusted_theory_key=_trusted(theory_signer),
        expected_snapshot_id=snapshot["snapshot_id"],
        expected_tenant_id=SYNTHETIC_TENANT,
        expected_policy=theory_policy,
    )
    admission_policy = ToolzTraceAdmissionPolicy(
        policy_id="policy:synthetic-toolz-trace-admission",
        trace_policy=trace_policy,
        memory_policy=memory_policy,
        max_trace_to_route_seconds=600,
        max_route_to_admission_seconds=600,
    )
    return _AdmissionFixture(
        trace_policy=trace_policy,
        trace=trace,
        observer_signer=observer_signer,
        source_signer=source_signer,
        trusted_source=trusted_source,
        fog=fog,
        cyber=cyber,
        memory_policy=memory_policy,
        admission_policy=admission_policy,
        memory_signer=Ed25519Signer.generate(
            "key:synthetic-toolz-admission-memory"
        ),
        admission_signer=Ed25519Signer.generate(
            "key:synthetic-toolz-admission-authority"
        ),
    )


def _admit(fixture: _AdmissionFixture):
    return build_toolz_trace_admission(
        policy=fixture.admission_policy,
        trace=fixture.trace,
        observer_key=_trusted(fixture.observer_signer),
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        created_at=MEMORY_CREATED,
        expires_at=MEMORY_EXPIRES,
        memory_signer=fixture.memory_signer,
        admission_signer=fixture.admission_signer,
    )


def test_exact_completed_trace_is_admitted_only_as_theoretical_memory(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)

    assert admission.decision is ToolzTraceAdmissionDecision.ADMIT_THEORETICAL
    assert admission.execution_authority is False
    assert admission.storage_performed is False
    assert admission.receipt["decision"] == "admit-theoretical"
    assert admission.receipt["authority_boundary"]["retroactive_success"] is False
    assert admission.memory_receipt["observation"] == {
        "outcome": "theoretical",
        "observed_at": None,
        "evidence_digest": None,
    }
    assert (
        evaluate_toolz_route_memory(
            admission.memory_receipt,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            authority_key=_trusted(fixture.memory_signer),
            evaluated_at="2026-07-29T04:21:00Z",
        )
        is ToolzRouteMemoryDecision.EXPLORE
    )

    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-admission-store"
    )
    store = ToolzRouteMemoryStore.initialize(
        tmp_path / "toolz",
        store_id="toolz-store:synthetic-admission",
        tenant_id=SYNTHETIC_TENANT,
        store_signer=store_signer,
        created_at="2026-07-29T04:18:00Z",
    )
    cursor = store.put(
        admission.memory_receipt,
        expected_cursor=store.cursor,
        expected_policy=fixture.memory_policy,
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        memory_key=_trusted(fixture.memory_signer),
        evaluated_at="2026-07-29T04:21:00Z",
        recorded_at="2026-07-29T04:22:00Z",
        store_signer=store_signer,
    )
    context_lookup = store.lookup(
        toolz_store_context_identity(admission.memory_receipt),
        expected_cursor=cursor,
        expected_policy=fixture.memory_policy,
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        memory_key=_trusted(fixture.memory_signer),
        evaluated_at="2026-07-29T04:23:00Z",
    )
    assert context_lookup is not None
    assert context_lookup.lifecycle is ToolzStoreLifecycle.THEORETICAL
    assert context_lookup.decision is ToolzRouteMemoryDecision.EXPLORE


def test_route_must_equal_trace_hops_not_a_shorter_graph_path() -> None:
    fixture = _fixture(shortcut=True)

    with pytest.raises(ToolzTraceAdmissionError, match="route path mismatch"):
        _admit(fixture)


def test_reused_relation_ids_cannot_rewire_the_intermediate_state() -> None:
    fixture = _fixture(rewire=True)

    with pytest.raises(ToolzTraceAdmissionError, match="route path mismatch"):
        _admit(fixture)


def test_route_record_must_retain_the_trace_step_evidence_digest() -> None:
    fixture = _fixture(wrong_evidence=True)

    with pytest.raises(ToolzTraceAdmissionError, match="route evidence mismatch"):
        _admit(fixture)


def test_equivalent_old_projection_cannot_admit_a_new_trace() -> None:
    fixture = _fixture()
    later_trace = _trace(
        fixture.trace_policy,
        fixture.observer_signer,
        steps=_steps(
            first_at="2026-07-29T04:06:30Z",
            second_at="2026-07-29T04:07:30Z",
        ),
        started_at="2026-07-29T04:05:30Z",
        completed_at="2026-07-29T04:08:30Z",
    )
    old_path = describe_toolz_action_trace_path(
        fixture.trace,
        expected_policy=fixture.trace_policy,
        observer_key=_trusted(fixture.observer_signer),
    )
    later_path = describe_toolz_action_trace_path(
        later_trace,
        expected_policy=fixture.trace_policy,
        observer_key=_trusted(fixture.observer_signer),
    )
    assert old_path.relation_ids == later_path.relation_ids
    assert old_path.projection_digest != later_path.projection_digest

    with pytest.raises(ToolzTraceAdmissionError, match="route evidence mismatch"):
        build_toolz_trace_admission(
            policy=fixture.admission_policy,
            trace=later_trace,
            observer_key=_trusted(fixture.observer_signer),
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            created_at=MEMORY_CREATED,
            expires_at=MEMORY_EXPIRES,
            memory_signer=fixture.memory_signer,
            admission_signer=fixture.admission_signer,
        )


def test_causal_order_and_lag_fail_closed() -> None:
    route_before_trace = _fixture(
        route_created_at="2026-07-29T04:07:30Z"
    )
    with pytest.raises(ToolzTraceAdmissionError, match="causal ordering"):
        _admit(route_before_trace)

    fixture = _fixture()
    strict_policy = replace(
        fixture.admission_policy,
        max_trace_to_route_seconds=30,
    )
    with pytest.raises(ToolzTraceAdmissionError, match="trace-to-route lag"):
        build_toolz_trace_admission(
            policy=strict_policy,
            trace=fixture.trace,
            observer_key=_trusted(fixture.observer_signer),
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            created_at=MEMORY_CREATED,
            expires_at=MEMORY_EXPIRES,
            memory_signer=fixture.memory_signer,
            admission_signer=fixture.admission_signer,
        )


def test_observed_success_cannot_substitute_for_theoretical_admission() -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    success_memory = build_toolz_route_memory_receipt(
        policy=fixture.memory_policy,
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        outcome=ToolzRouteMemoryOutcome.OBSERVED_SUCCESS,
        observed_at=OBSERVED,
        observation_evidence_digest=DIGEST_E,
        created_at=MEMORY_CREATED,
        expires_at=MEMORY_EXPIRES,
        memory_signer=fixture.memory_signer,
    )

    with pytest.raises(ToolzTraceAdmissionError, match="retroactive success"):
        verify_toolz_trace_admission_receipt(
            admission.receipt,
            expected_policy=fixture.admission_policy,
            trace=fixture.trace,
            observer_key=_trusted(fixture.observer_signer),
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_receipt=success_memory,
            memory_key=_trusted(fixture.memory_signer),
            admission_key=_trusted(fixture.admission_signer),
        )


def test_memory_created_after_admission_breaks_causal_order() -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    future_memory = build_toolz_route_memory_receipt(
        policy=fixture.memory_policy,
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        observed_at=None,
        observation_evidence_digest=None,
        created_at="2026-07-29T04:21:00Z",
        expires_at=MEMORY_EXPIRES,
        memory_signer=fixture.memory_signer,
    )

    with pytest.raises(ToolzTraceAdmissionError, match="causal ordering"):
        verify_toolz_trace_admission_receipt(
            admission.receipt,
            expected_policy=fixture.admission_policy,
            trace=fixture.trace,
            observer_key=_trusted(fixture.observer_signer),
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_receipt=future_memory,
            memory_key=_trusted(fixture.memory_signer),
            admission_key=_trusted(fixture.admission_signer),
        )


@pytest.mark.parametrize(
    "raw_field",
    ["url", "selector", "dom", "screenshot", "form_value", "cookie", "token"],
)
def test_admission_schema_rejects_raw_ui_and_secret_fields(
    raw_field: str,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    forged = copy.deepcopy(admission.receipt)
    forged[raw_field] = "forbidden"
    forged["receipt_id"] = toolz_trace_admission_identity(forged)
    forged = fixture.admission_signer.sign(forged)

    with pytest.raises(ToolzTraceAdmissionError, match="schema"):
        verify_toolz_trace_admission_receipt(
            forged,
            expected_policy=fixture.admission_policy,
            trace=fixture.trace,
            observer_key=_trusted(fixture.observer_signer),
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_receipt=admission.memory_receipt,
            memory_key=_trusted(fixture.memory_signer),
            admission_key=_trusted(fixture.admission_signer),
        )


def test_admission_contexts_must_be_identical() -> None:
    cyber_policy, _ = _cyber_evidence()
    memory_policy = _memory_policy(cyber_policy)
    other_trace_policy = replace(
        _trace_policy(cyber_policy),
        ui_context_digest=DIGEST_E,
    )

    with pytest.raises(ToolzTraceAdmissionError, match="context mismatch"):
        ToolzTraceAdmissionPolicy(
            policy_id="policy:synthetic-toolz-trace-admission",
            trace_policy=other_trace_policy,
            memory_policy=memory_policy,
        )


def test_admission_module_has_no_active_io_or_dynamic_execution() -> None:
    tree = ast.parse(inspect.getsource(admission_module))
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
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.level == 0
        and node.module is not None
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
