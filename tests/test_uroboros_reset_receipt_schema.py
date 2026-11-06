from __future__ import annotations

import copy

import pytest
from jsonschema import ValidationError

from integrity_guardian.schemas import validate

ATTEMPT_UID = "a" * 32
DIGEST = "sha256:" + "b" * 64


def _receipt() -> dict[str, object]:
    return {
        "protocol": (
            "integrity-guardian/uroboros-winops-zero-day-reset-receipt/v2"
        ),
        "outcome": "confirmed-success",
        "attempt_uid": ATTEMPT_UID,
        "started_at": "2026-08-02T12:00:00Z",
        "finished_at": "2026-08-02T12:00:01Z",
        "plan_digest": DIGEST,
        "task_name": "IntegrityZeroDaySeedRuntime",
        "contained_processes": [
            {
                "process_id": 4321,
                "parent_process_id": 1234,
                "creation_date": "20260802120000.000000+000",
                "executable_path": "D:\\Integrity-Guardian\\python.exe",
            }
        ],
        "self_process_excluded_count": 1,
        "controller_process_excluded_count": 3,
        "deletions": [
            {
                "path": "D:\\Integrity-Guardian",
                "result": "confirmed-absent",
                "exit_code": 0,
                "elapsed_ms": 11,
            },
            {
                "path": "D:\\Integrity-Workspace",
                "result": "already-absent",
                "elapsed_ms": 0,
            },
            {
                "path": "D:\\Integrity-Codex",
                "result": "already-absent",
                "elapsed_ms": 0,
            },
        ],
        "reservation_digest": "sha256:" + "c" * 64,
        "target_absence": [True, True, True],
        "task_absent": True,
        "credentials_deleted": True,
        "failure": None,
        "automatic_retry_allowed": False,
        "action_replayed": False,
        "local_destructive_action": True,
        "owner_authorization_proven": False,
        "imports_remote_memory": False,
        "production_authority": False,
        "path_identity_held_during_delete": False,
        "hostile_same_principal_race_proven": False,
        "receipt_guard_held_until_atomic_commit": True,
        "receipt_guard_release": (
            "after-final-create-flush-acl-and-byte-readback-before-"
            "write-through-reservation-archive"
        ),
        "same_principal_precommit_swap_window": False,
    }


def test_reset_receipt_v2_accepts_closed_confirmed_success() -> None:
    validate("uroboros-winops-zero-day-reset-receipt", _receipt())


@pytest.mark.parametrize("outcome", ["confirmed-failure", "unknown-outcome"])
def test_reset_receipt_v2_accepts_other_terminal_outcomes(outcome: str) -> None:
    receipt = _receipt()
    receipt["outcome"] = outcome
    receipt["target_absence"] = [True, False, True]
    receipt["task_absent"] = False
    receipt["failure"] = "bounded terminal diagnostic"
    validate("uroboros-winops-zero-day-reset-receipt", receipt)


def test_reset_receipt_v2_accepts_pre_deletion_confirmed_failure() -> None:
    receipt = _receipt()
    receipt["outcome"] = "confirmed-failure"
    receipt["contained_processes"] = []
    receipt["deletions"] = []
    receipt["failure"] = "bounded pre-deletion failure"
    validate("uroboros-winops-zero-day-reset-receipt", receipt)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("outcome",), "not-started"),
        (("self_process_excluded_count",), 0),
        (("controller_process_excluded_count",), 0),
        (("automatic_retry_allowed",), True),
        (("action_replayed",), True),
        (("local_destructive_action",), False),
        (("owner_authorization_proven",), True),
        (("imports_remote_memory",), True),
        (("production_authority",), True),
        (("path_identity_held_during_delete",), True),
        (("hostile_same_principal_race_proven",), True),
        (("receipt_guard_held_until_atomic_commit",), False),
        (("same_principal_precommit_swap_window",), True),
    ],
)
def test_reset_receipt_v2_rejects_nonterminal_replay_authority_or_guard_drift(
    path: tuple[object, ...], value: object
) -> None:
    receipt = copy.deepcopy(_receipt())
    target: object = receipt
    for component in path[:-1]:
        target = target[component]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", receipt)


def test_reset_receipt_v2_requires_confirmed_success_postconditions() -> None:
    receipt = _receipt()
    receipt["target_absence"] = [True, False, True]
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", receipt)

    receipt = _receipt()
    receipt["task_absent"] = False
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", receipt)


def test_reset_receipt_v2_closes_nested_witnesses_and_deletion_variants() -> None:
    receipt = _receipt()
    receipt["contained_processes"][0]["command_line"] = "secret"  # type: ignore[index]
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", receipt)

    receipt = _receipt()
    receipt["deletions"][1]["exit_code"] = 0  # type: ignore[index]
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", receipt)


def test_reset_receipt_v2_rejects_unknown_or_missing_fields() -> None:
    unknown = _receipt()
    unknown["silent_authority_expansion"] = True
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", unknown)

    missing = _receipt()
    del missing["self_process_excluded_count"]
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", missing)

    missing = _receipt()
    del missing["controller_process_excluded_count"]
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-receipt", missing)
