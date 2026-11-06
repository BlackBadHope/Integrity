from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_readiness as readiness_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs_readiness import (
    ToolzReuseReadinessError,
    ToolzReuseReadinessPolicy,
    ToolzReuseReadinessStatus,
    build_toolz_reuse_readiness,
    build_toolz_start_state_witness,
    toolz_reuse_readiness_identity,
    toolz_start_state_witness_identity,
    verify_toolz_reuse_readiness_receipt,
    verify_toolz_start_state_witness,
)
from integrity_guardian.uroboros_toolzs_store import (
    STORE_DATABASE_NAME,
    ToolzRouteMemoryStore,
)
from tests.test_uroboros_toolzs import DIGEST_A, DIGEST_B, DIGEST_C, _trusted
from tests.test_uroboros_toolzs_feedback_install import (
    STORE_ID,
    _feedback_fixture,
    _install,
    _seed_theoretical,
    _store,
)

WITNESS_OBSERVED = "2026-07-29T04:40:00Z"
WITNESS_CREATED = "2026-07-29T04:40:02Z"
READINESS_EVALUATED = "2026-07-29T04:40:03Z"
READINESS_CREATED = "2026-07-29T04:40:04Z"
READINESS_EXPIRES = "2026-07-29T04:40:30Z"


def _policy(case: Any) -> ToolzReuseReadinessPolicy:
    return ToolzReuseReadinessPolicy(
        policy_id="policy:synthetic-toolz-reuse-readiness",
        feedback_policy=case.feedback_policy,
        store_id=STORE_ID,
        evaluator_id="evaluator:synthetic-toolz-reuse-readiness",
        evaluator_artifact_digest=DIGEST_C,
        max_observation_age_seconds=30,
        max_witness_signing_delay_seconds=10,
        max_readiness_signing_delay_seconds=5,
    )


def _witness(
    case: Any,
    *,
    policy: ToolzReuseReadinessPolicy | None = None,
    state_digest: str | None = None,
    zone_id: str | None = None,
    observed_at: str = WITNESS_OBSERVED,
    created_at: str = WITNESS_CREATED,
    observer_signer: Ed25519Signer | None = None,
) -> dict[str, Any]:
    return build_toolz_start_state_witness(
        policy=policy or _policy(case),
        state_digest=state_digest or case.trace["initial_state"]["state_digest"],
        zone_id=zone_id or case.trace["initial_state"]["zone_id"],
        evidence_digest=DIGEST_A,
        observed_at=observed_at,
        created_at=created_at,
        observer_signer=observer_signer or case.fixture.observer_signer,
    )


def _ready(
    case: Any,
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
    readiness_signer: Ed25519Signer,
    *,
    witness: dict[str, Any] | None = None,
    expected_cursor: Any = None,
    policy: ToolzReuseReadinessPolicy | None = None,
    trace: dict[str, Any] | None = None,
    evaluated_at: str = READINESS_EVALUATED,
    created_at: str = READINESS_CREATED,
):
    return build_toolz_reuse_readiness(
        policy=policy or _policy(case),
        witness=witness or _witness(case),
        witness_observer_key=_trusted(case.fixture.observer_signer),
        feedback_receipt=case.feedback.receipt,
        theoretical_memory=case.admission.memory_receipt,
        trace=trace or case.trace,
        trace_observer_key=_trusted(case.fixture.observer_signer),
        fog_evidence=case.fixture.fog,
        cyber_evidence=case.fixture.cyber,
        observed_memory=case.feedback.memory_receipt,
        memory_key=_trusted(case.fixture.memory_signer),
        feedback_key=_trusted(case.feedback_signer),
        store=store,
        expected_cursor=expected_cursor or store.cursor,
        store_key=_trusted(store_signer),
        evaluated_at=evaluated_at,
        created_at=created_at,
        readiness_signer=readiness_signer,
    )


def _verify(
    case: Any,
    result: Any,
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
    readiness_signer: Ed25519Signer,
    *,
    receipt: dict[str, Any] | None = None,
    witness: dict[str, Any] | None = None,
    used_at: str = READINESS_CREATED,
):
    return verify_toolz_reuse_readiness_receipt(
        receipt or result.receipt,
        expected_policy=_policy(case),
        witness=witness or result.witness,
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
        expected_cursor=result.lookup.cursor,
        store_key=_trusted(store_signer),
        readiness_key=_trusted(readiness_signer),
        used_at=used_at,
    )


def _installed_store(
    case: Any,
    root: Path,
    store_signer: Ed25519Signer,
) -> ToolzRouteMemoryStore:
    store = _store(root, store_signer)
    predecessor = _seed_theoretical(case, store, store_signer)
    _install(
        case,
        store,
        store_signer,
        expected_cursor=predecessor.store_cursor,
    )
    return store


def _database_digest(root: Path) -> str:
    return hashlib.sha256((root / STORE_DATABASE_NAME).read_bytes()).hexdigest()


def test_exact_fresh_start_and_generation_two_are_ready_only_to_request(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    root = tmp_path / "toolz"
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-authority")
    with _installed_store(case, root, store_signer) as store:
        before = _database_digest(root)
        result = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )

        assert result.status is ToolzReuseReadinessStatus.READY_TO_REQUEST_AUTHORIZATION
        assert result.execution_authority is False
        assert result.authorization_granted is False
        assert result.storage_performed is False
        assert result.lookup.generation == 2
        assert result.receipt["status"] == "ready-to-request-authorization"
        assert result.receipt["store"]["generation"] == 2
        assert result.receipt["timing"]["expires_at"] == READINESS_EXPIRES
        assert result.receipt["authority_boundary"]["store_write"] is False
        assert result.receipt["authority_boundary"]["execution"] is False
        assert (
            _verify(
                case,
                result,
                store,
                store_signer,
                readiness_signer,
            )
            == result.receipt
        )
        assert _database_digest(root) == before


def test_wrong_current_state_or_zone_cannot_reuse_route(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-wrong-start-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-wrong-start-authority")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        wrong_state = _witness(case, state_digest=DIGEST_B)
        with pytest.raises(
            ToolzReuseReadinessError,
            match="current route start mismatch",
        ):
            _ready(
                case,
                store,
                store_signer,
                readiness_signer,
                witness=wrong_state,
            )

        wrong_zone = _witness(
            case,
            zone_id="zone:synthetic-readiness-wrong-start",
        )
        with pytest.raises(
            ToolzReuseReadinessError,
            match="current route start mismatch",
        ):
            _ready(
                case,
                store,
                store_signer,
                readiness_signer,
                witness=wrong_zone,
            )


def test_stale_witness_and_expired_use_fail_closed(tmp_path: Path) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-stale-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-stale-authority")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        stale = _witness(
            case,
            observed_at="2026-07-29T04:39:00Z",
            created_at="2026-07-29T04:39:05Z",
        )
        with pytest.raises(
            ToolzReuseReadinessError,
            match="timing rejected",
        ):
            _ready(
                case,
                store,
                store_signer,
                readiness_signer,
                witness=stale,
            )

        result = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        with pytest.raises(
            ToolzReuseReadinessError,
            match="timing rejected",
        ):
            _verify(
                case,
                result,
                store,
                store_signer,
                readiness_signer,
                used_at="2026-07-29T04:40:31Z",
            )


def test_generation_one_observed_bypass_is_not_ready(tmp_path: Path) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-generation-one-store")
    readiness_signer = Ed25519Signer.generate(
        "key:synthetic-toolz-readiness-generation-one-authority"
    )
    with _store(tmp_path / "toolz", store_signer) as store:
        cursor = store.put(
            case.feedback.memory_receipt,
            expected_cursor=store.cursor,
            expected_policy=case.fixture.memory_policy,
            fog_evidence=case.fixture.fog,
            cyber_evidence=case.fixture.cyber,
            memory_key=_trusted(case.fixture.memory_signer),
            evaluated_at="2026-07-29T04:31:00Z",
            recorded_at="2026-07-29T04:32:00Z",
            store_signer=store_signer,
        )
        with pytest.raises(
            ToolzReuseReadinessError,
            match="generation-two state rejected",
        ):
            _ready(
                case,
                store,
                store_signer,
                readiness_signer,
                expected_cursor=cursor,
            )


def test_theoretical_predecessor_without_promotion_is_not_ready(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-theoretical-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-theoretical-authority")
    with _store(tmp_path / "toolz", store_signer) as store:
        predecessor = _seed_theoretical(case, store, store_signer)
        with pytest.raises(
            ToolzReuseReadinessError,
            match="generation-two state rejected",
        ):
            _ready(
                case,
                store,
                store_signer,
                readiness_signer,
                expected_cursor=predecessor.store_cursor,
            )


def test_stale_external_cursor_and_wrong_store_key_fail_closed(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-cursor-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-cursor-authority")
    with _store(tmp_path / "toolz", store_signer) as store:
        predecessor = _seed_theoretical(case, store, store_signer)
        _install(
            case,
            store,
            store_signer,
            expected_cursor=predecessor.store_cursor,
        )
        with pytest.raises(
            ToolzReuseReadinessError,
            match="store verification rejected",
        ):
            _ready(
                case,
                store,
                store_signer,
                readiness_signer,
                expected_cursor=predecessor.store_cursor,
            )

        wrong_key = Ed25519Signer.generate("key:synthetic-toolz-readiness-wrong-store")
        with pytest.raises(
            ToolzReuseReadinessError,
            match="store trust rejected",
        ):
            build_toolz_reuse_readiness(
                policy=_policy(case),
                witness=_witness(case),
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
                expected_cursor=store.cursor,
                store_key=_trusted(wrong_key),
                evaluated_at=READINESS_EVALUATED,
                created_at=READINESS_CREATED,
                readiness_signer=readiness_signer,
            )


def test_witness_signature_feedback_chain_and_readiness_signature_are_bound(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    other = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-signatures-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-signatures-authority")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        witness = _witness(case)
        with pytest.raises(
            ToolzReuseReadinessError,
            match="witness signature rejected",
        ):
            verify_toolz_start_state_witness(
                witness,
                expected_policy=_policy(case),
                observer_key=_trusted(other.fixture.observer_signer),
            )

        with pytest.raises(
            ToolzReuseReadinessError,
            match="feedback proof rejected",
        ):
            _ready(
                case,
                store,
                store_signer,
                readiness_signer,
                trace=other.trace,
            )

        result = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        with pytest.raises(
            ToolzReuseReadinessError,
            match="receipt signature rejected",
        ):
            verify_toolz_reuse_readiness_receipt(
                result.receipt,
                expected_policy=_policy(case),
                witness=result.witness,
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
                expected_cursor=result.lookup.cursor,
                store_key=_trusted(store_signer),
                readiness_key=_trusted(
                    Ed25519Signer.generate("key:synthetic-toolz-readiness-wrong-authority")
                ),
                used_at=READINESS_CREATED,
            )


def test_closed_schemas_reject_raw_ui_and_authority_escalation(
    tmp_path: Path,
) -> None:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-schema-store")
    readiness_signer = Ed25519Signer.generate("key:synthetic-toolz-readiness-schema-authority")
    with _installed_store(case, tmp_path / "toolz", store_signer) as store:
        witness = _witness(case)
        raw_witness = copy.deepcopy(witness)
        raw_witness["observation"]["selector"] = "#submit"
        with pytest.raises(
            ToolzReuseReadinessError,
            match="witness schema rejected",
        ):
            verify_toolz_start_state_witness(
                raw_witness,
                expected_policy=_policy(case),
                observer_key=_trusted(case.fixture.observer_signer),
            )

        malformed_zone = copy.deepcopy(witness)
        malformed_zone["observation"]["zone_id"] = "zone:unclassified"
        malformed_zone.pop("signature")
        malformed_zone["witness_id"] = toolz_start_state_witness_identity(malformed_zone)
        malformed_zone = case.fixture.observer_signer.sign(malformed_zone)
        with pytest.raises(
            ToolzReuseReadinessError,
            match="witness state identity rejected",
        ):
            verify_toolz_start_state_witness(
                malformed_zone,
                expected_policy=_policy(case),
                observer_key=_trusted(case.fixture.observer_signer),
            )

        result = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        escalated = copy.deepcopy(result.receipt)
        escalated["authority_boundary"]["execution"] = True
        unsigned = copy.deepcopy(escalated)
        unsigned.pop("signature")
        unsigned["receipt_id"] = toolz_reuse_readiness_identity(unsigned)
        escalated = readiness_signer.sign(unsigned)
        with pytest.raises(
            ToolzReuseReadinessError,
            match="receipt schema rejected",
        ):
            _verify(
                case,
                result,
                store,
                store_signer,
                readiness_signer,
                receipt=escalated,
            )


def test_module_has_no_browser_network_subprocess_or_write_primitive() -> None:
    source = inspect.getsource(readiness_module)
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
            "write_bytes",
            "write_text",
        }
    )
