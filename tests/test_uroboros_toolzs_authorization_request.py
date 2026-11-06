from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_authorization_request as request_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs_authorization_request import (
    ToolzAuthorizationRequestError,
    ToolzAuthorizationRequestPolicy,
    ToolzAuthorizationRequestStatus,
    build_toolz_authorization_request,
    toolz_authorization_request_identity,
    verify_toolz_authorization_request,
)
from integrity_guardian.uroboros_toolzs_store import (
    STORE_DATABASE_NAME,
    ToolzRouteMemoryStore,
)
from tests.test_uroboros_toolzs import DIGEST_A, DIGEST_B, DIGEST_C, _trusted
from tests.test_uroboros_toolzs_feedback_install import (
    _feedback_fixture,
    _install,
    _seed_theoretical,
    _store,
)
from tests.test_uroboros_toolzs_readiness import (
    _installed_store,
    _ready,
)
from tests.test_uroboros_toolzs_readiness import (
    _policy as _readiness_policy,
)

REQUESTED_AT = "2026-07-29T04:40:05Z"
REQUEST_CREATED = "2026-07-29T04:40:06Z"
REQUEST_EXPIRES = "2026-07-29T04:40:20Z"


def _policy(case: Any) -> ToolzAuthorizationRequestPolicy:
    return ToolzAuthorizationRequestPolicy(
        policy_id="policy:synthetic-toolz-authorization-request",
        readiness_policy=_readiness_policy(case),
        requester_id="requester:synthetic-toolz-agent",
        requester_artifact_digest=DIGEST_A,
        decision_authority_id="authority:synthetic-toolz-owner",
        decision_authority_artifact_digest=DIGEST_B,
        max_request_seconds=15,
        max_signing_delay_seconds=5,
    )


def _request(
    case: Any,
    readiness: Any,
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
    readiness_signer: Ed25519Signer,
    requester_signer: Ed25519Signer,
    *,
    expected_cursor: Any = None,
    requested_at: str = REQUESTED_AT,
    created_at: str = REQUEST_CREATED,
    requester_key: Any = None,
):
    return build_toolz_authorization_request(
        policy=_policy(case),
        readiness_receipt=readiness.receipt,
        witness=readiness.witness,
        witness_observer_key=_trusted(case.fixture.observer_signer),
        feedback_receipt=case.feedback.receipt,
        theoretical_memory=case.admission.memory_receipt,
        trace=case.trace,
        trace_observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        observed_memory=case.feedback.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        feedback_key=_trusted(case.feedback_signer),
        store=store,
        expected_cursor=expected_cursor or readiness.lookup.cursor,
        store_key=_trusted(store_signer),
        readiness_key=_trusted(readiness_signer),
        requested_at=requested_at,
        created_at=created_at,
        requester_key=requester_key or _trusted(requester_signer),
        requester_signer=requester_signer,
    )


def _verify(
    case: Any,
    readiness: Any,
    result: Any,
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
    readiness_signer: Ed25519Signer,
    requester_signer: Ed25519Signer,
    *,
    request: dict[str, Any] | None = None,
    used_at: str = REQUEST_CREATED,
):
    return verify_toolz_authorization_request(
        request or result.request,
        expected_policy=_policy(case),
        readiness_receipt=readiness.receipt,
        witness=readiness.witness,
        witness_observer_key=_trusted(case.fixture.observer_signer),
        feedback_receipt=case.feedback.receipt,
        theoretical_memory=case.admission.memory_receipt,
        trace=case.trace,
        trace_observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        observed_memory=case.feedback.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        feedback_key=_trusted(case.feedback_signer),
        store=store,
        expected_cursor=readiness.lookup.cursor,
        store_key=_trusted(store_signer),
        readiness_key=_trusted(readiness_signer),
        requester_key=_trusted(requester_signer),
        used_at=used_at,
    )


def _database_digest(root: Path) -> str:
    return hashlib.sha256((root / STORE_DATABASE_NAME).read_bytes()).hexdigest()


def test_exact_first_transition_creates_only_a_pending_request(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-request-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-request-readiness")
    requester_signer = Ed25519Signer.generate("key:synthetic-toolz-request-requester")
    with _installed_store(case, root, store_signer) as store:
        readiness = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        before = _database_digest(root)
        result = _request(
            case,
            readiness,
            store,
            store_signer,
            readiness_signer,
            requester_signer,
        )

        assert result.status is ToolzAuthorizationRequestStatus.PENDING_AUTHORITY_DECISION
        assert result.authorization_granted is False
        assert result.execution_authority is False
        assert result.transport_performed is False
        assert result.storage_performed is False
        assert result.request["status"] == "pending-authority-decision"
        assert result.request["intent"]["hop_index"] == 0
        assert result.request["intent"]["action_class"] == case.trace["steps"][0]["action_class"]
        assert (
            result.request["intent"]["operation_digest"]
            == case.trace["steps"][0]["operation_digest"]
        )
        assert result.request["scope"] == {
            "requested_capability": "single-toolz-transition",
            "max_transitions": 1,
            "replay_allowed": False,
            "route_continuation_allowed": False,
            "production_authority_requested": False,
        }
        assert result.request["timing"]["expires_at"] == REQUEST_EXPIRES
        assert result.request["authority_boundary"]["execution"] is False
        assert (
            _verify(
                case,
                readiness,
                result,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
            )
            == result.request
        )
        assert _database_digest(root) == before


def test_operation_substitution_is_rejected_after_valid_signature(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-request-operation-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-request-operation-readiness")
    requester_signer = Ed25519Signer.generate("key:synthetic-toolz-request-operation-requester")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        readiness = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        result = _request(
            case,
            readiness,
            store,
            store_signer,
            readiness_signer,
            requester_signer,
        )
        substituted = copy.deepcopy(result.request)
        substituted["intent"]["operation_digest"] = DIGEST_C
        substituted.pop("signature")
        substituted["request_id"] = toolz_authorization_request_identity(substituted)
        substituted = requester_signer.sign(substituted)

        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="recomputation mismatch",
        ):
            _verify(
                case,
                readiness,
                result,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
                request=substituted,
            )


def test_request_cannot_expand_scope_or_carry_raw_selector(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-request-scope-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-request-scope-readiness")
    requester_signer = Ed25519Signer.generate("key:synthetic-toolz-request-scope-requester")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        readiness = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        result = _request(
            case,
            readiness,
            store,
            store_signer,
            readiness_signer,
            requester_signer,
        )
        expanded = copy.deepcopy(result.request)
        expanded["scope"]["max_transitions"] = 2
        expanded["scope"]["route_continuation_allowed"] = True
        expanded.pop("signature")
        expanded["request_id"] = toolz_authorization_request_identity(expanded)
        expanded = requester_signer.sign(expanded)
        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="schema rejected",
        ):
            _verify(
                case,
                readiness,
                result,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
                request=expanded,
            )

        raw_selector = copy.deepcopy(result.request)
        raw_selector["intent"]["selector"] = "#confirm"
        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="schema rejected",
        ):
            _verify(
                case,
                readiness,
                result,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
                request=raw_selector,
            )


def test_expired_request_and_expired_readiness_fail_closed(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-request-expiry-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-request-expiry-readiness")
    requester_signer = Ed25519Signer.generate("key:synthetic-toolz-request-expiry-requester")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        readiness = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        result = _request(
            case,
            readiness,
            store,
            store_signer,
            readiness_signer,
            requester_signer,
        )
        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="causal timing rejected",
        ):
            _verify(
                case,
                readiness,
                result,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
                used_at=REQUEST_EXPIRES,
            )

        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="readiness proof rejected",
        ):
            _request(
                case,
                readiness,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
                requested_at="2026-07-29T04:40:31Z",
                created_at="2026-07-29T04:40:32Z",
            )


def test_stale_store_cursor_cannot_create_request(tmp_path: Path) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-request-cursor-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-request-cursor-readiness")
    requester_signer = Ed25519Signer.generate("key:synthetic-toolz-request-cursor-requester")
    with _store(tmp_path / "toolz", store_signer) as store:
        predecessor = _seed_theoretical(case, store, store_signer)
        _install(
            case,
            store,
            store_signer,
            expected_cursor=predecessor.store_cursor,
        )
        readiness = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="readiness proof rejected",
        ):
            _request(
                case,
                readiness,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
                expected_cursor=predecessor.store_cursor,
            )


def test_readiness_and_requester_signatures_are_both_required(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-request-signatures-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-request-signatures-readiness")
    requester_signer = Ed25519Signer.generate("key:synthetic-toolz-request-signatures-requester")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        readiness = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        wrong_readiness = Ed25519Signer.generate("key:synthetic-toolz-request-wrong-readiness")
        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="readiness proof rejected",
        ):
            build_toolz_authorization_request(
                policy=_policy(case),
                readiness_receipt=readiness.receipt,
                witness=readiness.witness,
                witness_observer_key=_trusted(case.fixture.observer_signer),
                feedback_receipt=case.feedback.receipt,
                theoretical_memory=case.admission.memory_receipt,
                trace=case.trace,
                trace_observer_key=_trusted(case.fixture.observer_signer),
                fog_evidence=case.fixture.fog,
                cyber_evidence=case.fixture.cyber,
                observed_memory=case.feedback.memory_receipt,
                memory_key=_trusted(case.fixture.memory_signer),
                feedback_key=_trusted(case.feedback_signer),
                store=store,
                expected_cursor=readiness.lookup.cursor,
                store_key=_trusted(store_signer),
                readiness_key=_trusted(wrong_readiness),
                requested_at=REQUESTED_AT,
                created_at=REQUEST_CREATED,
                requester_key=_trusted(requester_signer),
                requester_signer=requester_signer,
            )

        wrong_requester = Ed25519Signer.generate("key:synthetic-toolz-request-wrong-requester")
        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="signer rejected",
        ):
            _request(
                case,
                readiness,
                store,
                store_signer,
                readiness_signer,
                requester_signer,
                requester_key=_trusted(wrong_requester),
            )

        result = _request(
            case,
            readiness,
            store,
            store_signer,
            readiness_signer,
            requester_signer,
        )
        with pytest.raises(
            ToolzAuthorizationRequestError,
            match="signature rejected",
        ):
            verify_toolz_authorization_request(
                result.request,
                expected_policy=_policy(case),
                readiness_receipt=readiness.receipt,
                witness=readiness.witness,
                witness_observer_key=_trusted(case.fixture.observer_signer),
                feedback_receipt=case.feedback.receipt,
                theoretical_memory=case.admission.memory_receipt,
                trace=case.trace,
                trace_observer_key=_trusted(case.fixture.observer_signer),
                fog_evidence=case.fixture.fog,
                cyber_evidence=case.fixture.cyber,
                observed_memory=case.feedback.memory_receipt,
                memory_key=_trusted(case.fixture.memory_signer),
                feedback_key=_trusted(case.feedback_signer),
                store=store,
                expected_cursor=readiness.lookup.cursor,
                store_key=_trusted(store_signer),
                readiness_key=_trusted(readiness_signer),
                requester_key=_trusted(wrong_requester),
                used_at=REQUEST_CREATED,
            )


def test_module_has_no_transport_browser_execution_or_write_primitive() -> None:
    source = inspect.getsource(request_module)
    tree = ast.parse(source)
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
            "execute",
            "executemany",
            "executescript",
            "put",
            "send",
            "write_bytes",
            "write_text",
        }
    )
