from __future__ import annotations

import copy

import pytest
from jsonschema import ValidationError

from integrity_guardian.schemas import validate

DIGEST = "sha256:" + "a" * 64


def _receipt() -> dict[str, object]:
    return {
        "protocol": (
            "integrity-guardian/"
            "uroboros-winops-zero-day-reset-reconciliation/v2"
        ),
        "reconciliation_uid": "1" * 32,
        "reconciliation_id": (
            "uroboros-winops-zero-day-reset-reconciliation:" + "b" * 64
        ),
        "reconciled_at": "2026-08-02T12:00:00Z",
        "host": "EXAMPLE-WINOPS",
        "attempt_uid": "winops-reset:20260802T090000Z:a2ae6bf0",
        "source_attempt_id": "winops-reset:20260802T090000Z:a2ae6bf0",
        "source_reservation": {
            "protocol": (
                "integrity-guardian/"
                "uroboros-winops-zero-day-reset-reservation/v1"
            ),
            "digest": "sha256:" + "c" * 64,
            "location_at_open": "active",
            "name_digest": "sha256:" + "1" * 64,
        },
        "original_terminal": {
            "state": "absent",
            "name_digest": "sha256:" + "2" * 64,
            "content_digest": None,
            "recorded_outcome": None,
            "trusted_for_outcome": False,
        },
        "bound_preexisting_artifacts": [
            {
                "role": "top-level",
                "name_digest": "sha256:" + "1" * 64,
                "content_digest": "sha256:" + "c" * 64,
                "size": 412,
                "validation": "json-valid",
            }
        ],
        "artifact_inventory_digest": "sha256:" + "3" * 64,
        "original_action_outcome": "unknown-outcome",
        "reconciliation_outcome": "confirmed-success",
        "postconditions_status": "confirmed-absent",
        "plan_digest": DIGEST,
        "reservation_digest": "sha256:" + "c" * 64,
        "original_plan_provenance": (
            "reconstructed-from-captured-terminal-output"
        ),
        "postconditions": {
            "targets": [
                {"path_digest": "sha256:" + "d" * 64, "absent": True},
                {"path_digest": "sha256:" + "e" * 64, "absent": True},
            ],
            "task": {"name_digest": "sha256:" + "f" * 64, "absent": True},
            "inspected_process_count": 137,
            "self_process_excluded_count": 1,
            "controller_process_excluded_count": 3,
            "matching_process_count": 0,
            "uninspectable_process_count": 0,
            "protected_os_process_count": 7,
            "inspected_listener_ports": [8765, 8775],
            "matching_tcp_listener_count": 0,
            "matching_udp_listener_count": 0,
        },
        "limitations": [
            "original_action_outcome_remains_unknown",
            "original_plan_reconstructed_from_captured_terminal_output",
        ],
        "reconciliation_only": True,
        "reconciliation_required": False,
        "action_replayed": False,
        "automatic_retry_allowed": False,
        "destructive_write_performed": False,
        "event_write_performed": False,
        "evidence_write_scope": "reconciliation-receipt-only",
        "local_destructive_authority": False,
        "imports_remote_memory": False,
        "production_authority": False,
    }


def test_reconciliation_schema_accepts_closed_unknown_outcome_receipt() -> None:
    validate("uroboros-winops-zero-day-reset-reconciliation", _receipt())


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("original_action_outcome",), "confirmed-success"),
        (("action_replayed",), True),
        (("automatic_retry_allowed",), True),
        (("destructive_write_performed",), True),
        (("event_write_performed",), True),
        (("local_destructive_authority",), True),
        (("production_authority",), True),
        (("postconditions", "targets", 0, "absent"), False),
        (("postconditions", "self_process_excluded_count"), 0),
        (("postconditions", "controller_process_excluded_count"), 0),
        (("postconditions", "matching_process_count"), 1),
        (("postconditions", "uninspectable_process_count"), 1),
        (("postconditions", "matching_tcp_listener_count"), 1),
        (("postconditions", "matching_udp_listener_count"), 1),
        (("postconditions", "inspected_listener_ports"), []),
    ],
)
def test_reconciliation_schema_rejects_replay_write_authority_or_gap(
    path: tuple[object, ...], value: object
) -> None:
    receipt = copy.deepcopy(_receipt())
    target: object = receipt
    for component in path[:-1]:
        target = target[component]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-reconciliation", receipt)


def test_reconstructed_plan_requires_explicit_provenance_limitation() -> None:
    receipt = _receipt()
    receipt["limitations"] = [
        "original_action_outcome_remains_unknown",
    ]

    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-reconciliation", receipt)


def test_retained_plan_rejects_false_reconstruction_limitation() -> None:
    receipt = _receipt()
    receipt["original_plan_provenance"] = "retained-before-action"

    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-reconciliation", receipt)


def test_reconciliation_schema_rejects_unknown_fields() -> None:
    receipt = _receipt()
    receipt["silent_authority_expansion"] = True

    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-reconciliation", receipt)
