from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from dataclasses import replace

import pytest

import integrity_guardian.uroboros_toolzs_trace as trace_module
from integrity_guardian.discovery import (
    DiscoveryCursor,
    DiscoveryProvenance,
    TrustedDiscoverySource,
    ZonedDiscoveryIndex,
)
from integrity_guardian.discovery_theory import (
    DiscoveryTheoryPolicy,
    synthesize_discovery_theory_route,
)
from integrity_guardian.security_admission import (
    SecurityArtifact,
    SecurityEnvironment,
)
from integrity_guardian.signing import Ed25519Signer, TrustedKey
from integrity_guardian.uroboros_toolzs_trace import (
    TOOLZ_TRACE_ENTITY_TYPE,
    TOOLZ_TRACE_RELATION_TYPE,
    ToolzActionClass,
    ToolzActionStep,
    ToolzActionTraceError,
    ToolzActionTracePolicy,
    build_toolz_action_trace_receipt,
    compile_toolz_action_trace,
    toolz_action_trace_identity,
    verify_toolz_action_trace_receipt,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode('utf-8')).hexdigest()}"


def _trusted(signer: Ed25519Signer) -> TrustedKey:
    return TrustedKey(key_id=signer.key_id, public_key=signer.public_key)


def _policy(*, max_steps: int = 16) -> ToolzActionTracePolicy:
    return ToolzActionTracePolicy(
        policy_id="policy:synthetic-toolz-trace",
        subject=SecurityArtifact(
            tenant_id=SYNTHETIC_TENANT,
            artifact_id="toolz:synthetic-browser-route",
            artifact_digest=_digest("toolz-artifact"),
        ),
        environment=SecurityEnvironment(
            profile_id="environment:synthetic-desktop",
            fingerprint_digest=_digest("environment"),
        ),
        ui_context_digest=_digest("ui-context"),
        observer_id="observer:synthetic-computer-use",
        observer_artifact_digest=_digest("observer-artifact"),
        discovery_source_id="source:synthetic-toolz-trace",
        discovery_source_epoch="epoch:synthetic-toolz-trace-1",
        discovery_source_artifact_digest=_digest("trace-compiler-artifact"),
        max_steps=max_steps,
        max_duration_seconds=600,
    )


def _steps(
    *,
    first_observed_at: str = "2026-07-29T10:01:00Z",
    second_observed_at: str = "2026-07-29T10:02:00Z",
) -> tuple[ToolzActionStep, ...]:
    return (
        ToolzActionStep(
            action_class=ToolzActionClass.ACTIVATE,
            operation_digest=_digest("open-dialog-operation"),
            before_state_digest=_digest("state-home"),
            after_state_digest=_digest("state-dialog"),
            before_zone_id="zone:synthetic-home-window",
            after_zone_id="zone:synthetic-dialog",
            observed_at=first_observed_at,
            evidence_digest=_digest("dialog-observation"),
            confidence_ppm=970_000,
        ),
        ToolzActionStep(
            action_class=ToolzActionClass.SUBMIT,
            operation_digest=_digest("submit-operation"),
            before_state_digest=_digest("state-dialog"),
            after_state_digest=_digest("state-result"),
            before_zone_id="zone:synthetic-dialog",
            after_zone_id="zone:synthetic-result",
            observed_at=second_observed_at,
            evidence_digest=_digest("result-observation"),
            confidence_ppm=960_000,
        ),
    )


def _trace(
    observer_signer: Ed25519Signer,
    *,
    policy: ToolzActionTracePolicy | None = None,
    steps: tuple[ToolzActionStep, ...] | None = None,
    started_at: str = "2026-07-29T10:00:00Z",
    completed_at: str = "2026-07-29T10:03:00Z",
) -> dict:
    return build_toolz_action_trace_receipt(
        policy=policy or _policy(),
        steps=steps or _steps(),
        coverage_digest=_digest("observer-coverage"),
        started_at=started_at,
        completed_at=completed_at,
        observer_signer=observer_signer,
    )


def _compile(
    trace: dict,
    *,
    policy: ToolzActionTracePolicy,
    observer_signer: Ed25519Signer,
    source_signer: Ed25519Signer,
    cursor: DiscoveryCursor | None = None,
):
    return compile_toolz_action_trace(
        trace,
        expected_policy=policy,
        observer_key=_trusted(observer_signer),
        discovery_cursor=cursor
        or DiscoveryCursor(
            source_id=policy.discovery_source_id,
            source_epoch=policy.discovery_source_epoch,
        ),
        discovery_signer=source_signer,
    )


def test_completed_trace_compiles_into_existing_fog_route() -> None:
    policy = _policy()
    observer_signer = Ed25519Signer.generate("key:synthetic-toolz-observer")
    source_signer = Ed25519Signer.generate("key:synthetic-toolz-source")
    index_signer = Ed25519Signer.generate("key:synthetic-toolz-index")
    theory_signer = Ed25519Signer.generate("key:synthetic-toolz-theory")
    trace = _trace(observer_signer, policy=policy)

    projection = _compile(
        trace,
        policy=policy,
        observer_signer=observer_signer,
        source_signer=source_signer,
    )

    assert projection.execution_authority is False
    assert "execution_authority" not in inspect.signature(type(projection)).parameters
    assert projection.relation_type == TOOLZ_TRACE_RELATION_TYPE
    assert all(
        record["evidence"]["coverage"]["scope_digest"]
        == projection.projection_digest
        for record in projection.records
    )
    assert len(projection.records) == 5
    assert projection.next_cursor.next_sequence == 5
    assert projection.invalidation_zone_ids == (
        "zone:synthetic-dialog",
        "zone:synthetic-home-window",
        "zone:synthetic-result",
    )
    entity_records = [
        record
        for record in projection.records
        if record["assertion"]["kind"] == "entity"
    ]
    relation_records = [
        record
        for record in projection.records
        if record["assertion"]["kind"] == "relation"
    ]
    assert len(entity_records) == 3
    assert all(
        record["assertion"]["entity_type"] == TOOLZ_TRACE_ENTITY_TYPE
        for record in entity_records
    )
    assert len(relation_records) == 2
    assert all(
        record["assertion"]["relation_type"] == TOOLZ_TRACE_RELATION_TYPE
        and record["evidence"]["provenance"] == "LEARNED"
        for record in relation_records
    )

    trusted_source = TrustedDiscoverySource(
        source_id=policy.discovery_source_id,
        source_epoch=policy.discovery_source_epoch,
        source_artifact_digest=policy.discovery_source_artifact_digest,
        trusted_key=_trusted(source_signer),
    )
    index = ZonedDiscoveryIndex(
        tenant_id=SYNTHETIC_TENANT,
        trusted_sources=(trusted_source,),
        receipt_signer=index_signer,
    )
    delta = index.apply(projection.records)
    assert delta["inserted_count"] == 5
    snapshot = index.export_snapshot(created_at="2026-07-29T10:04:00Z")
    route = synthesize_discovery_theory_route(
        snapshot,
        trusted_snapshot_key=_trusted(index_signer),
        trusted_sources=(trusted_source,),
        expected_snapshot_id=snapshot["snapshot_id"],
        expected_tenant_id=SYNTHETIC_TENANT,
        policy=DiscoveryTheoryPolicy(
            policy_id="policy:synthetic-toolz-trace-route",
            allowed_relation_types=(TOOLZ_TRACE_RELATION_TYPE,),
            allowed_provenance=(DiscoveryProvenance.LEARNED,),
            min_confidence_ppm=900_000,
            max_hops=4,
        ),
        from_entity_id=projection.from_entity_id,
        to_entity_id=projection.to_entity_id,
        created_at="2026-07-29T10:05:00Z",
        theory_signer=theory_signer,
    )
    assert route["status"] == "candidate"
    assert [hop["relation_id"] for hop in route["hops"]] == [
        record["assertion"]["relation_id"] for record in relation_records
    ]
    assert route["theory_boundary"]["execution"] is False


def test_same_minimized_path_has_stable_graph_identity() -> None:
    policy = _policy()
    observer_signer = Ed25519Signer.generate("key:synthetic-toolz-observer")
    source_signer = Ed25519Signer.generate("key:synthetic-toolz-source")
    first = _compile(
        _trace(observer_signer, policy=policy),
        policy=policy,
        observer_signer=observer_signer,
        source_signer=source_signer,
    )
    later = _compile(
        _trace(
            observer_signer,
            policy=policy,
            steps=_steps(
                first_observed_at="2026-07-29T11:01:00Z",
                second_observed_at="2026-07-29T11:02:00Z",
            ),
            started_at="2026-07-29T11:00:00Z",
            completed_at="2026-07-29T11:03:00Z",
        ),
        policy=policy,
        observer_signer=observer_signer,
        source_signer=source_signer,
    )

    def graph_ids(projection) -> tuple[list[str], list[str]]:
        entities = [
            record["assertion"]["entity_id"]
            for record in projection.records
            if record["assertion"]["kind"] == "entity"
        ]
        relations = [
            record["assertion"]["relation_id"]
            for record in projection.records
            if record["assertion"]["kind"] == "relation"
        ]
        return entities, relations

    assert first.trace_id != later.trace_id
    assert first.projection_digest != later.projection_digest
    assert graph_ids(first) == graph_ids(later)


def test_trace_is_bound_to_exact_observer_and_local_context() -> None:
    policy = _policy()
    observer_signer = Ed25519Signer.generate("key:synthetic-toolz-observer")
    trace = _trace(observer_signer, policy=policy)

    with pytest.raises(ToolzActionTraceError, match="signature"):
        verify_toolz_action_trace_receipt(
            trace,
            expected_policy=policy,
            observer_key=_trusted(
                Ed25519Signer.generate("key:synthetic-other-observer")
            ),
        )

    other_policy = replace(policy, ui_context_digest=_digest("other-ui-context"))
    with pytest.raises(ToolzActionTraceError, match="policy_digest mismatch"):
        verify_toolz_action_trace_receipt(
            trace,
            expected_policy=other_policy,
            observer_key=_trusted(observer_signer),
        )


@pytest.mark.parametrize(
    "raw_field",
    ["cookie", "dom", "form_value", "free_text", "screenshot", "selector", "url"],
)
def test_closed_trace_schema_rejects_raw_ui_and_secret_fields(raw_field: str) -> None:
    policy = _policy()
    observer_signer = Ed25519Signer.generate("key:synthetic-toolz-observer")
    forged = copy.deepcopy(_trace(observer_signer, policy=policy))
    forged[raw_field] = "forbidden"
    forged["trace_id"] = toolz_action_trace_identity(forged)
    forged = observer_signer.sign(forged)

    with pytest.raises(ToolzActionTraceError, match="schema"):
        verify_toolz_action_trace_receipt(
            forged,
            expected_policy=policy,
            observer_key=_trusted(observer_signer),
        )


def test_trace_continuity_time_bounds_and_cycles_fail_closed() -> None:
    observer_signer = Ed25519Signer.generate("key:synthetic-toolz-observer")
    broken_chain = (
        _steps()[0],
        replace(
            _steps()[1],
            before_state_digest=_digest("unrelated-state"),
        ),
    )
    with pytest.raises(ToolzActionTraceError, match="state chain"):
        _trace(observer_signer, steps=broken_chain)

    cyclic = (
        _steps()[0],
        replace(
            _steps()[1],
            after_state_digest=_digest("state-home"),
            after_zone_id="zone:synthetic-home-window",
        ),
    )
    with pytest.raises(ToolzActionTraceError, match="cyclic"):
        _trace(observer_signer, steps=cyclic)

    out_of_order = _steps(
        first_observed_at="2026-07-29T10:02:00Z",
        second_observed_at="2026-07-29T10:01:00Z",
    )
    with pytest.raises(ToolzActionTraceError, match="observation order"):
        _trace(observer_signer, steps=out_of_order)

    with pytest.raises(ToolzActionTraceError, match="step count"):
        _trace(observer_signer, policy=_policy(max_steps=1))


def test_projection_source_cursor_is_exact_and_caller_cursor_is_not_mutated() -> None:
    policy = _policy()
    observer_signer = Ed25519Signer.generate("key:synthetic-toolz-observer")
    source_signer = Ed25519Signer.generate("key:synthetic-toolz-source")
    trace = _trace(observer_signer, policy=policy)
    original = DiscoveryCursor(
        source_id=policy.discovery_source_id,
        source_epoch=policy.discovery_source_epoch,
    )

    projection = _compile(
        trace,
        policy=policy,
        observer_signer=observer_signer,
        source_signer=source_signer,
        cursor=original,
    )
    assert original.next_sequence == 0
    assert projection.next_cursor.next_sequence == 5

    with pytest.raises(ToolzActionTraceError, match="cursor mismatch"):
        _compile(
            trace,
            policy=policy,
            observer_signer=observer_signer,
            source_signer=source_signer,
            cursor=DiscoveryCursor(
                source_id="source:synthetic-wrong",
                source_epoch=policy.discovery_source_epoch,
            ),
        )


def test_trace_ingress_module_has_no_active_io_or_dynamic_execution() -> None:
    tree = ast.parse(inspect.getsource(trace_module))
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
