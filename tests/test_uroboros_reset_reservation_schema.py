from __future__ import annotations

import copy

import pytest
from jsonschema import ValidationError

from integrity_guardian.schemas import validate

ATTEMPT_UID = "a" * 32
DIGEST = "sha256:" + "b" * 64


def _reservation() -> dict[str, object]:
    return {
        "protocol": (
            "integrity-guardian/"
            "uroboros-winops-zero-day-reset-reservation/v2"
        ),
        "outcome": "unknown-outcome",
        "receipt_state": "reserved-before-mutation",
        "started_at": "2026-08-02T12:00:00Z",
        "attempt_uid": ATTEMPT_UID,
        "plan_digest": DIGEST,
        "final_receipt_name": (
            f"uroboros-winops-zero-day-reset-{ATTEMPT_UID}.json"
        ),
        "archive_receipt_name": (
            "uroboros-winops-zero-day-reset-reservation-"
            f"{ATTEMPT_UID}.json"
        ),
        "reconciliation_required": True,
        "automatic_retry_allowed": False,
        "action_replayed": False,
        "production_authority": False,
    }


def test_reset_reservation_v2_accepts_closed_unknown_outcome() -> None:
    validate("uroboros-winops-zero-day-reset-reservation", _reservation())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("outcome", "confirmed-success"),
        ("receipt_state", "committed"),
        ("reconciliation_required", False),
        ("automatic_retry_allowed", True),
        ("action_replayed", True),
        ("production_authority", True),
        ("attempt_uid", "not-an-attempt-uid"),
        ("plan_digest", "sha256:short"),
    ],
)
def test_reset_reservation_v2_rejects_state_replay_authority_or_identity_drift(
    field: str, value: object
) -> None:
    reservation = copy.deepcopy(_reservation())
    reservation[field] = value

    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-reservation", reservation)


def test_reset_reservation_v2_rejects_unknown_or_missing_fields() -> None:
    unknown = _reservation()
    unknown["local_destructive_authority"] = True
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-reservation", unknown)

    missing = _reservation()
    del missing["automatic_retry_allowed"]
    with pytest.raises(ValidationError):
        validate("uroboros-winops-zero-day-reset-reservation", missing)
