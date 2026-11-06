from __future__ import annotations

import ast
import contextlib
import copy
import inspect
import os
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_authority as authority_module
import integrity_guardian.uroboros_toolzs_authority_ledger as ledger_module
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.uroboros_toolzs_authority import (
    ToolzAuthorityDecisionOutcome,
    ToolzAuthorityDecisionReason,
    ToolzAuthorityError,
    ToolzAuthorityPolicy,
    ToolzAuthorizationEvidence,
    ToolzGrantConsumptionStatus,
    toolz_authority_decision_identity,
)
from integrity_guardian.uroboros_toolzs_authority_ledger import (
    AUTHORITY_LEDGER_DATABASE_NAME,
    ToolzAuthorityLedger,
)
from tests.test_uroboros_toolzs import DIGEST_A, _trusted
from tests.test_uroboros_toolzs_authorization_request import (
    _policy as _request_policy,
)
from tests.test_uroboros_toolzs_authorization_request import (
    _request as _authorization_request,
)
from tests.test_uroboros_toolzs_feedback_install import _feedback_fixture
from tests.test_uroboros_toolzs_readiness import (
    _installed_store,
    _ready,
)
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")
_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and symlinks")

LEDGER_CREATED = "2026-07-29T04:40:07Z"
DECIDED_AT = "2026-07-29T04:40:08Z"
DECISION_CREATED = "2026-07-29T04:40:09Z"
GRANT_EXPIRES = "2026-07-29T04:40:18Z"
CONSUMED_AT = "2026-07-29T04:40:10Z"


def _policy(case: Any) -> ToolzAuthorityPolicy:
    return ToolzAuthorityPolicy(
        policy_id="policy:synthetic-toolz-authority",
        request_policy=_request_policy(case),
        ledger_id="ledger:synthetic-toolz-authority",
        ledger_authority_id="authority:synthetic-toolz-ledger",
        ledger_authority_artifact_digest=DIGEST_A,
        max_decision_signing_delay_seconds=5,
        max_grant_seconds=10,
    )


@contextlib.contextmanager
def _case(
    tmp_path: Path,
    label: str,
) -> Iterator[
    tuple[
        Any,
        ToolzAuthorizationEvidence,
        Ed25519Signer,
        Ed25519Signer,
    ]
]:
    case = _feedback_fixture()
    store_signer = Ed25519Signer.generate(f"key:synthetic-a13-{label}-store")
    readiness_signer = Ed25519Signer.generate(f"key:synthetic-a13-{label}-readiness")
    requester_signer = Ed25519Signer.generate(f"key:synthetic-a13-{label}-requester")
    with _installed_store(
        case,
        tmp_path / f"{label}-route-memory",
        store_signer,
    ) as store:
        readiness = _ready(
            case,
            store,
            store_signer,
            readiness_signer,
        )
        request = _authorization_request(
            case,
            readiness,
            store,
            store_signer,
            readiness_signer,
            requester_signer,
        )
        evidence = ToolzAuthorizationEvidence(
            request=request.request,
            request_policy=_request_policy(case),
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
        )
        yield case, evidence, store_signer, readiness_signer


def _initialize(
    tmp_path: Path,
    case: Any,
    label: str,
) -> tuple[ToolzAuthorityLedger, Ed25519Signer, Ed25519Signer]:
    decision_signer = Ed25519Signer.generate(f"key:synthetic-a13-{label}-decision")
    ledger_signer = Ed25519Signer.generate(f"key:synthetic-a13-{label}-ledger")
    ledger = ToolzAuthorityLedger.initialize(
        tmp_path / f"{label}-authority",
        policy=_policy(case),
        ledger_key=_trusted(ledger_signer),
        ledger_signer=ledger_signer,
        created_at=LEDGER_CREATED,
    )
    return ledger, decision_signer, ledger_signer


def _decide(
    ledger: ToolzAuthorityLedger,
    evidence: ToolzAuthorizationEvidence,
    decision_signer: Ed25519Signer,
    ledger_signer: Ed25519Signer,
    checkpoint: dict[str, Any],
    *,
    outcome: ToolzAuthorityDecisionOutcome = ToolzAuthorityDecisionOutcome.APPROVED,
    reason: ToolzAuthorityDecisionReason = ToolzAuthorityDecisionReason.OWNER_APPROVED,
):
    return ledger.decide(
        evidence=evidence,
        outcome=outcome,
        reason=reason,
        decided_at=DECIDED_AT,
        created_at=DECISION_CREATED,
        decision_key=_trusted(decision_signer),
        decision_signer=decision_signer,
        ledger_signer=ledger_signer,
        expected_checkpoint=checkpoint,
    )


@_POSIX_ONLY
def test_approved_decision_and_consumption_are_exactly_one_ledger_chain(
    tmp_path: Path,
) -> None:
    with _case(tmp_path, "approved") as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            "approved",
        )
        with ledger:
            initial = ledger.checkpoint
            decision = _decide(
                ledger,
                evidence,
                decision_signer,
                ledger_signer,
                initial,
            )
            assert decision.decision["outcome"] == "approved"
            assert decision.decision["grant"]["max_transitions"] == 1
            assert decision.decision["grant"]["single_use"] is True
            assert decision.decision["grant"]["expires_at"] == GRANT_EXPIRES
            assert decision.execution_performed is False
            assert decision.ledger_event["source_sequence"] == 0
            assert decision.checkpoint["tree_size"] == 2
            assert (
                ledger.verify_decision_record(
                    evidence=evidence,
                    decision=decision.decision,
                    decision_key=_trusted(decision_signer),
                    expected_checkpoint=decision.checkpoint,
                    used_at=DECISION_CREATED,
                )
                == decision.decision
            )

            consumption = ledger.consume(
                evidence=evidence,
                decision=decision.decision,
                decision_key=_trusted(decision_signer),
                consumed_at=CONSUMED_AT,
                ledger_signer=ledger_signer,
                expected_checkpoint=decision.checkpoint,
            )
            assert (
                consumption.consumption["status"]
                == ToolzGrantConsumptionStatus.PENDING_LEDGER_RECORD
            )
            assert consumption.ledger_event["source_sequence"] == 1
            assert consumption.checkpoint["tree_size"] == 3
            assert consumption.execution_performed is False
            assert consumption.external_effect_performed is False
            assert consumption.consumption_recorded is True
            assert consumption.consumption["authority_boundary"]["consumption_recorded"] is False
            assert (
                ledger.verify_consumption_record(
                    evidence=evidence,
                    decision=decision.decision,
                    consumption=consumption.consumption,
                    decision_key=_trusted(decision_signer),
                    expected_checkpoint=consumption.checkpoint,
                    used_at=CONSUMED_AT,
                )
                == consumption.consumption
            )
            verification = ledger.verify(expected_checkpoint=consumption.checkpoint)
            assert verification["tree_size"] == 3
            assert verification["request_count"] == 1
            assert verification["authority_boundary"]["execution"] is False

            root_mode = stat.S_IMODE(os.stat(ledger.root).st_mode)
            database_mode = stat.S_IMODE(os.stat(ledger.database_path).st_mode)
            assert root_mode == 0o700
            assert database_mode == 0o600


def test_second_decision_stale_checkpoint_and_second_consumption_fail_closed(
    tmp_path: Path,
) -> None:
    with _case(tmp_path, "replay") as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            "replay",
        )
        with ledger:
            initial = ledger.checkpoint
            decision = _decide(
                ledger,
                evidence,
                decision_signer,
                ledger_signer,
                initial,
            )
            with pytest.raises(ToolzAuthorityError, match="checkpoint rejected"):
                ledger.verify(expected_checkpoint=initial)
            with pytest.raises(ToolzAuthorityError, match="already has a decision"):
                _decide(
                    ledger,
                    evidence,
                    decision_signer,
                    ledger_signer,
                    decision.checkpoint,
                )
            consumption = ledger.consume(
                evidence=evidence,
                decision=decision.decision,
                decision_key=_trusted(decision_signer),
                consumed_at=CONSUMED_AT,
                ledger_signer=ledger_signer,
                expected_checkpoint=decision.checkpoint,
            )
            with pytest.raises(
                ToolzAuthorityError,
                match="decision ledger proof rejected",
            ):
                ledger.consume(
                    evidence=evidence,
                    decision=decision.decision,
                    decision_key=_trusted(decision_signer),
                    consumed_at="2026-07-29T04:40:11Z",
                    ledger_signer=ledger_signer,
                    expected_checkpoint=consumption.checkpoint,
                )


def test_clock_rollback_is_rejected_before_authority_append_commits(
    tmp_path: Path,
) -> None:
    with _case(tmp_path, "append-clock") as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            "append-clock",
        )
        with ledger:
            decision = _decide(
                ledger,
                evidence,
                decision_signer,
                ledger_signer,
                ledger.checkpoint,
            )
            rollback_event = ledger_module.build_ledger_event(
                tenant_id=SYNTHETIC_TENANT,
                source_id="toolz-authorization-request:" + "f" * 64,
                source_sequence=0,
                event_type="toolz-authorization-decision",
                payload_digest=DIGEST_A,
                previous_event_digest=None,
                signer=ledger_signer,
                recorded_at="2026-07-29T04:40:08Z",
            )

            with pytest.raises(ToolzAuthorityError, match="clock rollback"):
                ledger._append_at_checkpoint(
                    event=rollback_event,
                    expected_checkpoint=decision.checkpoint,
                    ledger_signer=ledger_signer,
                    checkpoint_created_at="2026-07-29T04:40:08Z",
                )

            verification = ledger.verify(expected_checkpoint=decision.checkpoint)
            assert verification["tree_size"] == 2


def test_denial_is_recorded_but_cannot_be_consumed(tmp_path: Path) -> None:
    with _case(tmp_path, "denied") as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            "denied",
        )
        with ledger:
            decision = _decide(
                ledger,
                evidence,
                decision_signer,
                ledger_signer,
                ledger.checkpoint,
                outcome=ToolzAuthorityDecisionOutcome.DENIED,
                reason=ToolzAuthorityDecisionReason.OWNER_DENIED,
            )
            assert decision.decision["grant"] is None
            assert decision.decision["authority_boundary"]["authorization_granted"] is False
            with pytest.raises(ToolzAuthorityError, match="denied grant"):
                ledger.consume(
                    evidence=evidence,
                    decision=decision.decision,
                    decision_key=_trusted(decision_signer),
                    consumed_at=CONSUMED_AT,
                    ledger_signer=ledger_signer,
                    expected_checkpoint=decision.checkpoint,
                )


def test_resigned_scope_expansion_and_raw_selector_are_rejected(
    tmp_path: Path,
) -> None:
    with _case(tmp_path, "scope") as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            "scope",
        )
        with ledger:
            decision = _decide(
                ledger,
                evidence,
                decision_signer,
                ledger_signer,
                ledger.checkpoint,
            )
            expanded = copy.deepcopy(decision.decision)
            expanded["grant"]["max_transitions"] = 2
            expanded.pop("signature")
            expanded["decision_id"] = toolz_authority_decision_identity(expanded)
            expanded = decision_signer.sign(expanded)
            with pytest.raises(ToolzAuthorityError, match="schema rejected"):
                ledger.verify_decision_record(
                    evidence=evidence,
                    decision=expanded,
                    decision_key=_trusted(decision_signer),
                    expected_checkpoint=decision.checkpoint,
                    used_at=DECISION_CREATED,
                )

            selector = copy.deepcopy(decision.decision)
            selector["grant"]["selector"] = "#confirm"
            with pytest.raises(ToolzAuthorityError, match="schema rejected"):
                ledger.verify_decision_record(
                    evidence=evidence,
                    decision=selector,
                    decision_key=_trusted(decision_signer),
                    expected_checkpoint=decision.checkpoint,
                    used_at=DECISION_CREATED,
                )


def test_wrong_authority_keys_and_expired_grant_fail_closed(
    tmp_path: Path,
) -> None:
    with _case(tmp_path, "keys") as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            "keys",
        )
        with ledger:
            wrong_decision = Ed25519Signer.generate("key:synthetic-a13-wrong-decision")
            with pytest.raises(ToolzAuthorityError, match="decision signer rejected"):
                ledger.decide(
                    evidence=evidence,
                    outcome=ToolzAuthorityDecisionOutcome.APPROVED,
                    reason=ToolzAuthorityDecisionReason.OWNER_APPROVED,
                    decided_at=DECIDED_AT,
                    created_at=DECISION_CREATED,
                    decision_key=_trusted(wrong_decision),
                    decision_signer=decision_signer,
                    ledger_signer=ledger_signer,
                    expected_checkpoint=ledger.checkpoint,
                )
            decision = _decide(
                ledger,
                evidence,
                decision_signer,
                ledger_signer,
                ledger.checkpoint,
            )
            with pytest.raises(ToolzAuthorityError, match="decision timing rejected"):
                ledger.consume(
                    evidence=evidence,
                    decision=decision.decision,
                    decision_key=_trusted(decision_signer),
                    consumed_at=GRANT_EXPIRES,
                    ledger_signer=ledger_signer,
                    expected_checkpoint=decision.checkpoint,
                )
            wrong_ledger = Ed25519Signer.generate("key:synthetic-a13-wrong-ledger")
            with pytest.raises(ToolzAuthorityError, match="ledger signer rejected"):
                ledger.consume(
                    evidence=evidence,
                    decision=decision.decision,
                    decision_key=_trusted(decision_signer),
                    consumed_at=CONSUMED_AT,
                    ledger_signer=wrong_ledger,
                    expected_checkpoint=decision.checkpoint,
                )


def test_database_tamper_and_signed_prefix_rollback_fail_closed(
    tmp_path: Path,
) -> None:
    with _case(tmp_path, "tamper") as (case, evidence, _, _):
        ledger, decision_signer, ledger_signer = _initialize(
            tmp_path,
            case,
            "tamper",
        )
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
        root = ledger.root
        ledger.close()

        database = root / AUTHORITY_LEDGER_DATABASE_NAME
        connection = sqlite3.connect(database)
        connection.execute("DELETE FROM ledger_events WHERE source_sequence = 1")
        connection.commit()
        connection.close()
        with pytest.raises(ToolzAuthorityError, match="checkpoint rejected"):
            ToolzAuthorityLedger.open(
                root,
                policy=_policy(case),
                ledger_key=_trusted(ledger_signer),
                expected_checkpoint=consumption.checkpoint,
            )


@_POSIX_ONLY
def test_symlinked_authority_root_and_database_are_rejected(
    tmp_path: Path,
) -> None:
    with _case(tmp_path, "symlink") as (case, _, _, _):
        ledger_signer = Ed25519Signer.generate("key:synthetic-a13-symlink-ledger")
        outside = tmp_path / "outside-authority"
        outside.mkdir(mode=0o700)
        initialize_link = tmp_path / "initialize-authority-link"
        initialize_link.symlink_to(outside, target_is_directory=True)
        with pytest.raises(ToolzAuthorityError, match="root rejected|root is unsafe"):
            ToolzAuthorityLedger.initialize(
                initialize_link,
                policy=_policy(case),
                ledger_key=_trusted(ledger_signer),
                ledger_signer=ledger_signer,
                created_at=LEDGER_CREATED,
            )

        ledger = ToolzAuthorityLedger.initialize(
            tmp_path / "real-authority",
            policy=_policy(case),
            ledger_key=_trusted(ledger_signer),
            ledger_signer=ledger_signer,
            created_at=LEDGER_CREATED,
        )
        checkpoint = ledger.checkpoint
        root = ledger.root
        ledger.close()

        open_link = tmp_path / "open-authority-link"
        open_link.symlink_to(root, target_is_directory=True)
        with pytest.raises(ToolzAuthorityError, match="root is unsafe"):
            ToolzAuthorityLedger.open(
                open_link,
                policy=_policy(case),
                ledger_key=_trusted(ledger_signer),
                expected_checkpoint=checkpoint,
            )

        database = root / AUTHORITY_LEDGER_DATABASE_NAME
        replacement = tmp_path / "replacement-authority.sqlite3"
        database.replace(replacement)
        database.symlink_to(replacement)
        with pytest.raises(
            ToolzAuthorityError,
            match="database rejected|database is unsafe",
        ):
            ToolzAuthorityLedger.open(
                root,
                policy=_policy(case),
                ledger_key=_trusted(ledger_signer),
                expected_checkpoint=checkpoint,
            )


def test_authority_modules_have_no_browser_network_or_tool_execution() -> None:
    for module in (authority_module, ledger_module):
        tree = ast.parse(inspect.getsource(module))
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
