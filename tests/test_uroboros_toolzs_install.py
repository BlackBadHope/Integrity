from __future__ import annotations

import ast
import copy
import inspect
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_install as install_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs import (
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryOutcome,
    build_toolz_route_memory_receipt,
    toolz_route_memory_digest,
)
from integrity_guardian.uroboros_toolzs_install import (
    ToolzAdmissionInstallError,
    ToolzAdmissionInstallPolicy,
    ToolzAdmissionInstallStatus,
    install_toolz_trace_admission,
    toolz_admission_install_identity,
    verify_toolz_admission_install_receipt,
)
from integrity_guardian.uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzStoreLifecycle,
)
from tests.test_uroboros_toolzs import (
    DIGEST_E,
    MEMORY_CREATED,
    MEMORY_EXPIRES,
    OBSERVED,
    _trusted,
)
from tests.test_uroboros_toolzs_admission import (
    _AdmissionFixture,
    _admit,
    _fixture,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")

STORE_ID = "toolz-store:local-synthetic-admission-install"
STORE_CREATED = "2026-07-29T04:18:00Z"
EVALUATED = "2026-07-29T04:21:00Z"
RECORDED = "2026-07-29T04:22:00Z"


def _policy(fixture: _AdmissionFixture) -> ToolzAdmissionInstallPolicy:
    return ToolzAdmissionInstallPolicy(
        policy_id="policy:synthetic-toolz-admission-install",
        admission_policy=fixture.admission_policy,
        store_id=STORE_ID,
        max_evaluation_to_record_seconds=60,
    )


def _store(
    root: Path,
    signer: Ed25519Signer,
) -> ToolzRouteMemoryStore:
    return ToolzRouteMemoryStore.initialize(
        root,
        store_id=STORE_ID,
        tenant_id=SYNTHETIC_TENANT,
        store_signer=signer,
        created_at=STORE_CREATED,
    )


def _install(
    fixture: _AdmissionFixture,
    admission: Any,
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
    *,
    expected_cursor: Any,
    memory_receipt: dict[str, Any] | None = None,
    evaluated_at: str = EVALUATED,
    recorded_at: str = RECORDED,
    policy: ToolzAdmissionInstallPolicy | None = None,
):
    return install_toolz_trace_admission(
        policy=policy or _policy(fixture),
        admission_receipt=admission.receipt,
        trace=fixture.trace,
        observer_key=_trusted(fixture.observer_signer),
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        memory_receipt=memory_receipt or admission.memory_receipt,
        memory_key=_trusted(fixture.memory_signer),
        admission_key=_trusted(fixture.admission_signer),
        store=store,
        expected_cursor=expected_cursor,
        evaluated_at=evaluated_at,
        recorded_at=recorded_at,
        store_signer=store_signer,
    )


def _verify(
    fixture: _AdmissionFixture,
    admission: Any,
    result: Any,
    store_signer: Ed25519Signer,
    *,
    receipt: dict[str, Any] | None = None,
    before_cursor: Any,
    after_cursor: Any,
):
    return verify_toolz_admission_install_receipt(
        receipt or result.receipt,
        expected_policy=_policy(fixture),
        admission_receipt=admission.receipt,
        trace=fixture.trace,
        observer_key=_trusted(fixture.observer_signer),
        fog_evidence=fixture.fog,
        cyber_evidence=fixture.cyber,
        memory_receipt=admission.memory_receipt,
        memory_key=_trusted(fixture.memory_signer),
        admission_key=_trusted(fixture.admission_signer),
        store_key=_trusted(store_signer),
        before_cursor=before_cursor,
        after_cursor=after_cursor,
    )


def test_exact_admission_is_installed_as_one_theoretical_generation(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-store"
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        before = store.cursor
        result = _install(
            fixture,
            admission,
            store,
            store_signer,
            expected_cursor=before,
        )

        assert result.status is ToolzAdmissionInstallStatus.INSTALLED
        assert result.storage_performed is True
        assert result.execution_authority is False
        assert result.store_cursor.sequence == before.sequence + 1
        assert result.receipt["store"]["transition"] == "installed"
        assert result.receipt["authority_boundary"]["local_storage"] is True
        assert result.receipt["authority_boundary"]["execution"] is False
        entries = store.entries(expected_cursor=result.store_cursor)
        assert len(entries) == 1
        assert entries[0]["lifecycle"] == ToolzStoreLifecycle.THEORETICAL.value
        assert entries[0]["receipt_digest"] == toolz_route_memory_digest(
            admission.memory_receipt
        )
        verified = _verify(
            fixture,
            admission,
            result,
            store_signer,
            before_cursor=before,
            after_cursor=result.store_cursor,
        )
        assert verified.receipt == result.receipt


def test_identical_admission_is_idempotent_at_the_current_cursor(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-idempotent"
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        first = _install(
            fixture,
            admission,
            store,
            store_signer,
            expected_cursor=store.cursor,
        )
        second = _install(
            fixture,
            admission,
            store,
            store_signer,
            expected_cursor=first.store_cursor,
            evaluated_at="2026-07-29T04:23:00Z",
            recorded_at="2026-07-29T04:24:00Z",
        )

        assert second.status is ToolzAdmissionInstallStatus.ALREADY_PRESENT
        assert second.storage_performed is False
        assert second.store_cursor == first.store_cursor
        assert second.receipt["store"]["before_cursor"] == second.receipt[
            "store"
        ]["after_cursor"]
        assert len(store.entries(expected_cursor=second.store_cursor)) == 1


def test_existing_different_generation_cannot_be_downgraded(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-conflict"
    )
    conflicting = build_toolz_route_memory_receipt(
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
    with _store(tmp_path / "toolz", store_signer) as store:
        occupied = store.put(
            conflicting,
            expected_cursor=store.cursor,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_key=_trusted(fixture.memory_signer),
            evaluated_at="2026-07-29T04:19:30Z",
            recorded_at="2026-07-29T04:20:00Z",
            store_signer=store_signer,
        )

        with pytest.raises(ToolzAdmissionInstallError, match="context conflict"):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=occupied,
            )

        assert store.cursor == occupied
        entries = store.entries(expected_cursor=occupied)
        assert entries[0]["receipt_digest"] == toolz_route_memory_digest(
            conflicting
        )


def test_existing_reuse_candidate_cannot_be_downgraded(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-reusable"
    )
    observed_success = build_toolz_route_memory_receipt(
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
    with _store(tmp_path / "toolz", store_signer) as store:
        reusable = store.put(
            observed_success,
            expected_cursor=store.cursor,
            expected_policy=fixture.memory_policy,
            fog_evidence=fixture.fog,
            cyber_evidence=fixture.cyber,
            memory_key=_trusted(fixture.memory_signer),
            evaluated_at=EVALUATED,
            recorded_at=RECORDED,
            store_signer=store_signer,
        )

        with pytest.raises(ToolzAdmissionInstallError, match="context conflict"):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=reusable,
                evaluated_at="2026-07-29T04:23:00Z",
                recorded_at="2026-07-29T04:24:00Z",
            )

        assert store.cursor == reusable
        entries = store.entries(expected_cursor=reusable)
        assert entries[0]["lifecycle"] == ToolzStoreLifecycle.REUSABLE.value
        assert entries[0]["receipt_digest"] == toolz_route_memory_digest(
            observed_success
        )


def test_substituted_memory_is_rejected_before_store_mutation(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    substituted = build_toolz_route_memory_receipt(
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
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-substitution"
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        before = store.cursor
        with pytest.raises(ToolzAdmissionInstallError, match="admission"):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=before,
                memory_receipt=substituted,
            )
        assert store.cursor == before


def test_stale_cursor_and_wrong_store_signer_fail_without_mutation(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-cursor"
    )
    wrong_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-wrong-store"
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        initial = store.cursor
        installed = _install(
            fixture,
            admission,
            store,
            store_signer,
            expected_cursor=initial,
        )
        with pytest.raises(ToolzAdmissionInstallError, match="store"):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=initial,
            )
        assert store.cursor == installed.store_cursor

    with _store(tmp_path / "toolz-wrong-key", store_signer) as store:
        before = store.cursor
        with pytest.raises(ToolzAdmissionInstallError, match="store"):
            _install(
                fixture,
                admission,
                store,
                wrong_signer,
                expected_cursor=before,
            )
        assert store.cursor == before


def test_policy_store_scope_and_causal_window_are_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-policy"
    )
    other_store_policy = ToolzAdmissionInstallPolicy(
        policy_id="policy:synthetic-toolz-admission-install",
        admission_policy=fixture.admission_policy,
        store_id="toolz-store:other-synthetic-install",
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        before = store.cursor
        with pytest.raises(ToolzAdmissionInstallError, match="store scope"):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=before,
                policy=other_store_policy,
            )
        with pytest.raises(ToolzAdmissionInstallError, match="causal timing"):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=before,
                recorded_at="2026-07-29T05:01:00Z",
            )
        with pytest.raises(ToolzAdmissionInstallError, match="causal timing"):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=before,
                evaluated_at=MEMORY_EXPIRES,
                recorded_at=MEMORY_EXPIRES,
            )
        assert store.cursor == before


def test_non_explore_pre_evaluation_cannot_reach_the_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-pre-evaluation"
    )
    monkeypatch.setattr(
        install_module,
        "evaluate_toolz_route_memory",
        lambda *args, **kwargs: ToolzRouteMemoryDecision.REDISCOVER,
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        before = store.cursor
        with pytest.raises(
            ToolzAdmissionInstallError,
            match="non-theoretical decision",
        ):
            _install(
                fixture,
                admission,
                store,
                store_signer,
                expected_cursor=before,
            )
        assert store.cursor == before
        assert store.entries(expected_cursor=before) == []


def test_forged_transition_and_raw_secret_fields_are_rejected(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    admission = _admit(fixture)
    store_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-install-forgery"
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        before = store.cursor
        result = _install(
            fixture,
            admission,
            store,
            store_signer,
            expected_cursor=before,
        )

        forged_transition = copy.deepcopy(result.receipt)
        forged_transition["store"]["transition"] = "already-present"
        forged_transition["receipt_id"] = toolz_admission_install_identity(
            forged_transition
        )
        forged_transition = store_signer.sign(forged_transition)
        with pytest.raises(
            ToolzAdmissionInstallError,
            match="idempotent cursor",
        ):
            _verify(
                fixture,
                admission,
                result,
                store_signer,
                receipt=forged_transition,
                before_cursor=before,
                after_cursor=result.store_cursor,
            )

        raw_secret = copy.deepcopy(result.receipt)
        raw_secret["token"] = "forbidden"
        raw_secret["receipt_id"] = toolz_admission_install_identity(raw_secret)
        raw_secret = store_signer.sign(raw_secret)
        with pytest.raises(ToolzAdmissionInstallError, match="schema"):
            _verify(
                fixture,
                admission,
                result,
                store_signer,
                receipt=raw_secret,
                before_cursor=before,
                after_cursor=result.store_cursor,
            )


def test_install_module_has_no_external_or_execution_capability() -> None:
    tree = ast.parse(inspect.getsource(install_module))
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
