from __future__ import annotations

import ast
import inspect
import sqlite3
from collections.abc import Iterator, Mapping
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import integrity_guardian.uroboros_toolzs_store as store_module
from integrity_guardian.discovery_feedback import (
    TrustedDiscoveryFeedback,
    build_discovery_feedback_overlay,
)
from integrity_guardian.discovery_feedback_delta import (
    DiscoveryFeedbackDeltaCursor,
    build_discovery_feedback_delta,
)
from integrity_guardian.discovery_theory import (
    DiscoveryFeedbackOutcome,
    build_discovery_theory_feedback,
)
from integrity_guardian.signing import Ed25519Signer, TrustedKey
from integrity_guardian.uroboros_toolzs import (
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryOutcome,
)
from integrity_guardian.uroboros_toolzs_store import (
    STORE_DATABASE_NAME,
    ToolzFeedbackDeltaEvidence,
    ToolzRouteMemoryStore,
    ToolzRouteStoreError,
    ToolzStoreLifecycle,
    toolz_store_context_identity,
)
from tests.test_uroboros_toolzs import (
    DIGEST_A,
    DIGEST_E,
    _cyber_evidence,
    _fog_evidence,
    _memory,
    _memory_policy,
    _trusted,
)
import os
from integrity_guardian import deployment_profile as _deployment_profile


SYNTHETIC_TENANT = _deployment_profile.identity("synthetic_tenant_id")
_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and symlinks")

STORE_ID = "toolz-store:synthetic-home"
INITIALIZED = "2026-07-29T04:25:00Z"
INGRESS_EVALUATED = "2026-07-29T04:30:00Z"
INGRESS_RECORDED = "2026-07-29T04:31:00Z"


def _initialized(
    tmp_path: Path,
) -> tuple[ToolzRouteMemoryStore, Ed25519Signer]:
    signer = Ed25519Signer.generate("key:synthetic-toolz-store")
    store = ToolzRouteMemoryStore.initialize(
        tmp_path / "toolz",
        store_id=STORE_ID,
        tenant_id=SYNTHETIC_TENANT,
        store_signer=signer,
        created_at=INITIALIZED,
    )
    return store, signer


def _put_success(
    store: ToolzRouteMemoryStore,
    store_signer: Ed25519Signer,
) -> tuple[
    dict[str, Any],
    Any,
    Any,
    Any,
    Ed25519Signer,
]:
    fog = _fog_evidence(feedback_ranked=True)
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy, require_feedback_ranked=True)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)
    cursor = store.put(
        receipt,
        expected_cursor=store.cursor,
        expected_policy=policy,
        fog_evidence=fog,
        cyber_evidence=cyber,
        memory_key=_trusted(memory_signer),
        evaluated_at=INGRESS_EVALUATED,
        recorded_at=INGRESS_RECORDED,
        store_signer=store_signer,
    )
    assert cursor.sequence == 1
    return receipt, policy, fog, cyber, memory_signer


def _build_delta(
    fog: Any,
    *,
    previous_overlay: dict[str, Any],
    previous_overlay_key: TrustedKey,
    previous_feedback: tuple[TrustedDiscoveryFeedback, ...],
    cursor: DiscoveryFeedbackDeltaCursor,
    observer_number: int,
    outcome: DiscoveryFeedbackOutcome,
    invalidate_zone: bool,
) -> tuple[
    ToolzFeedbackDeltaEvidence,
    dict[str, Any],
    TrustedKey,
    tuple[TrustedDiscoveryFeedback, ...],
    DiscoveryFeedbackDeltaCursor,
]:
    base_proposal = fog.feedback_evidence[0].proposal
    record_id = base_proposal["hops"][0]["record_id"]
    zones = (
        (base_proposal["invalidation_zone_ids"][0],)
        if invalidate_zone
        else ()
    )
    feedback_signer = Ed25519Signer.generate(
        f"key:synthetic-toolz-observer-{observer_number}"
    )
    observed_minute = 30 + (5 * observer_number)
    feedback = build_discovery_theory_feedback(
        base_proposal,
        observer_id=f"observer:synthetic-toolz-{observer_number}",
        observed_at=f"2026-07-29T04:{observed_minute:02d}:00Z",
        outcome=outcome,
        evidence_digest=DIGEST_A,
        affected_record_ids=(record_id,),
        invalidated_zone_ids=zones,
        feedback_signer=feedback_signer,
        trusted_theory_key=fog.trusted_theory_key,
    )
    trusted_feedback = TrustedDiscoveryFeedback(
        proposal=base_proposal,
        receipt=feedback,
        proposal_policy=fog.expected_policy,
        trusted_theory_key=fog.trusted_theory_key,
        trusted_feedback_key=_trusted(feedback_signer),
        expected_observer_id=f"observer:synthetic-toolz-{observer_number}",
    )
    next_feedback = (*previous_feedback, trusted_feedback)
    overlay_signer = Ed25519Signer.generate(
        f"key:synthetic-toolz-overlay-{observer_number}"
    )
    overlay_minute = 31 + (5 * observer_number)
    next_overlay = build_discovery_feedback_overlay(
        fog.snapshot,
        trusted_snapshot_key=fog.trusted_snapshot_key,
        trusted_sources=fog.trusted_sources,
        expected_snapshot_id=fog.expected_snapshot_id,
        expected_tenant_id=fog.expected_tenant_id,
        expected_policy=fog.expected_policy,
        feedback_policy=fog.feedback_policy,
        feedback_evidence=next_feedback,
        created_at=f"2026-07-29T04:{overlay_minute:02d}:00Z",
        overlay_signer=overlay_signer,
    )
    delta_signer = Ed25519Signer.generate(
        f"key:synthetic-toolz-delta-{observer_number}"
    )
    delta_minute = 32 + (5 * observer_number)
    delta, next_cursor = build_discovery_feedback_delta(
        previous_overlay,
        next_overlay,
        fog.snapshot,
        trusted_snapshot_key=fog.trusted_snapshot_key,
        trusted_sources=fog.trusted_sources,
        trusted_previous_overlay_key=previous_overlay_key,
        trusted_next_overlay_key=_trusted(overlay_signer),
        expected_snapshot_id=fog.expected_snapshot_id,
        expected_tenant_id=fog.expected_tenant_id,
        expected_policy=fog.expected_policy,
        feedback_policy=fog.feedback_policy,
        previous_feedback_evidence=previous_feedback,
        next_feedback_evidence=next_feedback,
        cursor=cursor,
        created_at=f"2026-07-29T04:{delta_minute:02d}:00Z",
        delta_signer=delta_signer,
    )
    evidence = ToolzFeedbackDeltaEvidence(
        delta=delta,
        previous_overlay=previous_overlay,
        next_overlay=next_overlay,
        snapshot=fog.snapshot,
        trusted_snapshot_key=fog.trusted_snapshot_key,
        trusted_sources=fog.trusted_sources,
        trusted_previous_overlay_key=previous_overlay_key,
        trusted_next_overlay_key=_trusted(overlay_signer),
        trusted_delta_key=_trusted(delta_signer),
        expected_snapshot_id=fog.expected_snapshot_id,
        expected_tenant_id=fog.expected_tenant_id,
        expected_policy=fog.expected_policy,
        feedback_policy=fog.feedback_policy,
        previous_feedback_evidence=previous_feedback,
        next_feedback_evidence=next_feedback,
        cursor=cursor,
    )
    return (
        evidence,
        next_overlay,
        _trusted(overlay_signer),
        next_feedback,
        next_cursor,
    )


@_POSIX_ONLY
def test_private_store_survives_restart_and_returns_guidance_only(
    tmp_path: Path,
) -> None:
    store, store_signer = _initialized(tmp_path)
    receipt, policy, fog, cyber, memory_signer = _put_success(
        store,
        store_signer,
    )
    context_id = toolz_store_context_identity(receipt)
    cursor = store.cursor
    result = store.verify(expected_cursor=cursor)
    assert result == {
        "ok": True,
        "store_id": STORE_ID,
        "tenant_id": SYNTHETIC_TENANT,
        "sequence": 1,
        "entry_count": 1,
        "object_count": 1,
        "rollback_cursor_verified": True,
        "authority_boundary": {
            "browser_control": False,
            "credentials": False,
            "execution": False,
            "global_publish": False,
            "local_storage": True,
            "model_sdk": False,
            "network": False,
            "production_authority": False,
            "raw_ui_data": False,
            "tool_invocation": False,
        },
    }
    assert store.root.stat().st_mode & 0o777 == 0o700
    assert store.database_path.stat().st_mode & 0o777 == 0o600
    store.close()

    with ToolzRouteMemoryStore.open(
        tmp_path / "toolz",
        store_id=STORE_ID,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=cursor,
    ) as reopened:
        lookup = reopened.lookup(
            context_id,
            expected_cursor=cursor,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            memory_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:32:00Z",
        )
        assert lookup is not None
        assert lookup.lifecycle is ToolzStoreLifecycle.REUSABLE
        assert lookup.decision is ToolzRouteMemoryDecision.REUSE_CANDIDATE
        assert lookup.receipt == receipt
        assert lookup.generation == 1


def test_same_receipt_is_idempotent_and_new_receipt_supersedes_generation(
    tmp_path: Path,
) -> None:
    store, store_signer = _initialized(tmp_path)
    receipt, policy, fog, cyber, memory_signer = _put_success(
        store,
        store_signer,
    )
    first_cursor = store.cursor
    same_cursor = store.put(
        receipt,
        expected_cursor=first_cursor,
        expected_policy=policy,
        fog_evidence=fog,
        cyber_evidence=cyber,
        memory_key=_trusted(memory_signer),
        evaluated_at="2026-07-29T04:32:00Z",
        recorded_at="2026-07-29T04:33:00Z",
        store_signer=store_signer,
    )
    assert same_cursor == first_cursor

    replacement = _memory(
        policy,
        fog,
        cyber,
        memory_signer,
        outcome=ToolzRouteMemoryOutcome.OBSERVED_FAILURE,
        observed_at="2026-07-29T04:34:00Z",
        evidence_digest=DIGEST_E,
        created_at="2026-07-29T04:35:00Z",
        expires_at="2026-07-29T05:10:00Z",
    )
    second_cursor = store.put(
        replacement,
        expected_cursor=first_cursor,
        expected_policy=policy,
        fog_evidence=fog,
        cyber_evidence=cyber,
        memory_key=_trusted(memory_signer),
        evaluated_at="2026-07-29T04:36:00Z",
        recorded_at="2026-07-29T04:37:00Z",
        store_signer=store_signer,
    )
    entry = store.entries(expected_cursor=second_cursor)[0]
    assert entry["generation"] == 2
    assert entry["previous_receipt_digest"] != entry["receipt_digest"]
    assert entry["lifecycle"] == "rediscover"
    assert store.verify(expected_cursor=second_cursor)["object_count"] == 2


@_POSIX_ONLY
def test_external_cursor_detects_valid_database_rollback(tmp_path: Path) -> None:
    store, store_signer = _initialized(tmp_path)
    initial_cursor = store.cursor
    store.close()
    database = tmp_path / "toolz" / STORE_DATABASE_NAME
    initial_bytes = database.read_bytes()

    with ToolzRouteMemoryStore.open(
        tmp_path / "toolz",
        store_id=STORE_ID,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=initial_cursor,
    ) as advanced:
        _put_success(advanced, store_signer)
        advanced_cursor = advanced.cursor

    database.write_bytes(initial_bytes)
    assert database.stat().st_mode & 0o777 == 0o600
    with pytest.raises(
        ToolzRouteStoreError,
        match="rollback or concurrent head change",
    ):
        ToolzRouteMemoryStore.open(
            tmp_path / "toolz",
            store_id=STORE_ID,
            tenant_id=SYNTHETIC_TENANT,
            authority_key=_trusted(store_signer),
            expected_cursor=advanced_cursor,
        )


def test_receipt_or_manifest_database_tamper_fails_closed(tmp_path: Path) -> None:
    store, store_signer = _initialized(tmp_path)
    _put_success(store, store_signer)
    cursor = store.cursor
    store.close()
    database = tmp_path / "toolz" / STORE_DATABASE_NAME

    connection = sqlite3.connect(database)
    payload = connection.execute(
        "SELECT payload FROM receipt_objects"
    ).fetchone()[0]
    receipt = deepcopy(__import__("json").loads(payload))
    receipt["tool_context"]["ui_context_digest"] = "sha256:" + "0" * 64
    connection.execute(
        "UPDATE receipt_objects SET payload = ?",
        (
            __import__("json").dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
        ),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ToolzRouteStoreError, match="content address mismatch"):
        ToolzRouteMemoryStore.open(
            tmp_path / "toolz",
            store_id=STORE_ID,
            tenant_id=SYNTHETIC_TENANT,
            authority_key=_trusted(store_signer),
            expected_cursor=cursor,
        )


def test_atomic_transition_rolls_back_object_manifest_and_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, store_signer = _initialized(tmp_path)
    cursor = store.cursor
    fog = _fog_evidence(feedback_ranked=True)
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy, require_feedback_ranked=True)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory")
    receipt = _memory(policy, fog, cyber, memory_signer)

    def crash_before_head(*_: object) -> None:
        raise RuntimeError("synthetic crash before head")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_set_head", crash_before_head)
        with pytest.raises(RuntimeError, match="synthetic crash"):
            store.put(
                receipt,
                expected_cursor=cursor,
                expected_policy=policy,
                fog_evidence=fog,
                cyber_evidence=cyber,
                memory_key=_trusted(memory_signer),
                evaluated_at=INGRESS_EVALUATED,
                recorded_at=INGRESS_RECORDED,
                store_signer=store_signer,
            )
    assert store.verify(expected_cursor=cursor)["object_count"] == 0
    connection = sqlite3.connect(store.database_path)
    assert connection.execute("SELECT COUNT(*) FROM manifests").fetchone()[0] == 1
    assert connection.execute("SELECT sequence FROM store_head").fetchone()[0] == 0
    connection.close()


def test_stale_concurrent_writer_is_rejected(tmp_path: Path) -> None:
    primary, store_signer = _initialized(tmp_path)
    initial = primary.cursor
    secondary = ToolzRouteMemoryStore.open(
        tmp_path / "toolz",
        store_id=STORE_ID,
        tenant_id=SYNTHETIC_TENANT,
        authority_key=_trusted(store_signer),
        expected_cursor=initial,
    )
    _put_success(primary, store_signer)

    fog = _fog_evidence(feedback_ranked=True)
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy, require_feedback_ranked=True)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory-other")
    receipt = _memory(policy, fog, cyber, memory_signer)
    with pytest.raises(
        ToolzRouteStoreError,
        match="rollback or concurrent head change",
    ):
        secondary.put(
            receipt,
            expected_cursor=initial,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            memory_key=_trusted(memory_signer),
            evaluated_at=INGRESS_EVALUATED,
            recorded_at=INGRESS_RECORDED,
            store_signer=store_signer,
        )
    secondary.close()
    primary.close()


def test_verified_delta_retains_unaffected_then_invalidates_affected_route(
    tmp_path: Path,
) -> None:
    store, store_signer = _initialized(tmp_path)
    receipt, policy, fog, cyber, memory_signer = _put_success(
        store,
        store_signer,
    )
    context_id = toolz_store_context_identity(receipt)
    delta_cursor = DiscoveryFeedbackDeltaCursor.from_overlay(fog.overlay)

    (
        neutral_evidence,
        neutral_overlay,
        neutral_overlay_key,
        neutral_feedback,
        next_delta_cursor,
    ) = _build_delta(
        fog,
        previous_overlay=fog.overlay,
        previous_overlay_key=fog.trusted_overlay_key,
        previous_feedback=fog.feedback_evidence,
        cursor=delta_cursor,
        observer_number=1,
        outcome=DiscoveryFeedbackOutcome.INCONCLUSIVE,
        invalidate_zone=False,
    )
    neutral = store.apply_feedback_delta(
        neutral_evidence,
        expected_cursor=store.cursor,
        applied_at="2026-07-29T04:38:00Z",
        store_signer=store_signer,
    )
    assert neutral.matched_entries == 1
    assert neutral.retained_entries == 1
    assert neutral.invalidated_entries == 0
    lookup = store.lookup(
        context_id,
        expected_cursor=neutral.store_cursor,
        expected_policy=policy,
        fog_evidence=fog,
        cyber_evidence=cyber,
        memory_key=_trusted(memory_signer),
        evaluated_at="2026-07-29T04:39:00Z",
    )
    assert lookup is not None
    assert lookup.lifecycle is ToolzStoreLifecycle.REUSABLE
    assert lookup.decision is ToolzRouteMemoryDecision.REUSE_CANDIDATE

    (
        invalidating_evidence,
        _,
        _,
        _,
        _,
    ) = _build_delta(
        fog,
        previous_overlay=neutral_overlay,
        previous_overlay_key=neutral_overlay_key,
        previous_feedback=neutral_feedback,
        cursor=next_delta_cursor,
        observer_number=2,
        outcome=DiscoveryFeedbackOutcome.REFUTED,
        invalidate_zone=True,
    )
    invalidated = store.apply_feedback_delta(
        invalidating_evidence,
        expected_cursor=neutral.store_cursor,
        applied_at="2026-07-29T04:45:00Z",
        store_signer=store_signer,
    )
    assert invalidated.matched_entries == 1
    assert invalidated.invalidated_entries == 1
    lookup = store.lookup(
        context_id,
        expected_cursor=invalidated.store_cursor,
        expected_policy=policy,
        fog_evidence=fog,
        cyber_evidence=cyber,
        memory_key=_trusted(memory_signer),
        evaluated_at="2026-07-29T04:46:00Z",
    )
    assert lookup is not None
    assert lookup.lifecycle is ToolzStoreLifecycle.INVALIDATED
    assert lookup.decision is ToolzRouteMemoryDecision.REDISCOVER
    assert not any(
        value
        for key, value in invalidated.authority_boundary.items()
        if key != "local_storage"
    )


def test_empty_store_persists_feedback_head_and_rejects_stale_ingress(
    tmp_path: Path,
) -> None:
    store, store_signer = _initialized(tmp_path)
    fog = _fog_evidence(feedback_ranked=True)
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy, require_feedback_ranked=True)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory-stale")
    stale_receipt = _memory(policy, fog, cyber, memory_signer)
    evidence, *_ = _build_delta(
        fog,
        previous_overlay=fog.overlay,
        previous_overlay_key=fog.trusted_overlay_key,
        previous_feedback=fog.feedback_evidence,
        cursor=DiscoveryFeedbackDeltaCursor.from_overlay(fog.overlay),
        observer_number=1,
        outcome=DiscoveryFeedbackOutcome.REFUTED,
        invalidate_zone=True,
    )

    application = store.apply_feedback_delta(
        evidence,
        expected_cursor=store.cursor,
        applied_at="2026-07-29T04:38:00Z",
        store_signer=store_signer,
    )
    assert application.matched_entries == 0
    assert application.store_cursor.sequence == 1
    with pytest.raises(ToolzRouteStoreError, match="feedback head mismatch"):
        store.put(
            stale_receipt,
            expected_cursor=application.store_cursor,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            memory_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:39:00Z",
            recorded_at="2026-07-29T04:40:00Z",
            store_signer=store_signer,
        )
    assert store.cursor == application.store_cursor


def test_pre_delta_receipt_cannot_supersede_invalidated_generation(
    tmp_path: Path,
) -> None:
    store, store_signer = _initialized(tmp_path)
    first, policy, fog, cyber, memory_signer = _put_success(
        store,
        store_signer,
    )
    replay = _memory(
        policy,
        fog,
        cyber,
        memory_signer,
        outcome=ToolzRouteMemoryOutcome.OBSERVED_SUCCESS,
        observed_at="2026-07-29T04:16:00Z",
        evidence_digest=DIGEST_A,
        created_at="2026-07-29T04:21:00Z",
        expires_at="2026-07-29T05:00:00Z",
    )
    assert replay != first
    evidence, *_ = _build_delta(
        fog,
        previous_overlay=fog.overlay,
        previous_overlay_key=fog.trusted_overlay_key,
        previous_feedback=fog.feedback_evidence,
        cursor=DiscoveryFeedbackDeltaCursor.from_overlay(fog.overlay),
        observer_number=1,
        outcome=DiscoveryFeedbackOutcome.REFUTED,
        invalidate_zone=True,
    )
    application = store.apply_feedback_delta(
        evidence,
        expected_cursor=store.cursor,
        applied_at="2026-07-29T04:38:00Z",
        store_signer=store_signer,
    )

    with pytest.raises(ToolzRouteStoreError, match="feedback head mismatch"):
        store.put(
            replay,
            expected_cursor=application.store_cursor,
            expected_policy=policy,
            fog_evidence=fog,
            cyber_evidence=cyber,
            memory_key=_trusted(memory_signer),
            evaluated_at="2026-07-29T04:39:00Z",
            recorded_at="2026-07-29T04:40:00Z",
            store_signer=store_signer,
        )
    entry = store.entries(expected_cursor=application.store_cursor)[0]
    assert entry["generation"] == 1
    assert entry["lifecycle"] == ToolzStoreLifecycle.INVALIDATED.value
    assert entry["last_delta_sequence"] == 0


class _ThirdReadDropsHops(Mapping[str, Any]):
    def __init__(self, route: Mapping[str, Any]) -> None:
        self._route = dict(route)
        self._hop_reads = 0

    def __getitem__(self, key: str) -> Any:
        if key == "hops":
            self._hop_reads += 1
            if self._hop_reads >= 3:
                return []
        return self._route[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._route)

    def __len__(self) -> int:
        return len(self._route)


def test_dependencies_are_derived_from_frozen_verified_fog_input(
    tmp_path: Path,
) -> None:
    store, store_signer = _initialized(tmp_path)
    fog = _fog_evidence(feedback_ranked=True)
    cyber_policy, cyber = _cyber_evidence()
    policy = _memory_policy(cyber_policy, require_feedback_ranked=True)
    memory_signer = Ed25519Signer.generate("key:synthetic-toolz-memory-frozen")
    receipt = _memory(policy, fog, cyber, memory_signer)
    stateful_fog = replace(fog, route=_ThirdReadDropsHops(fog.route))
    expected_record_ids = sorted(
        hop["record_id"] for hop in fog.route["hops"]
    )

    cursor = store.put(
        receipt,
        expected_cursor=store.cursor,
        expected_policy=policy,
        fog_evidence=stateful_fog,
        cyber_evidence=cyber,
        memory_key=_trusted(memory_signer),
        evaluated_at=INGRESS_EVALUATED,
        recorded_at=INGRESS_RECORDED,
        store_signer=store_signer,
    )
    entry = store.entries(expected_cursor=cursor)[0]
    assert entry["dependency_record_ids"] == expected_record_ids

    evidence, *_ = _build_delta(
        fog,
        previous_overlay=fog.overlay,
        previous_overlay_key=fog.trusted_overlay_key,
        previous_feedback=fog.feedback_evidence,
        cursor=DiscoveryFeedbackDeltaCursor.from_overlay(fog.overlay),
        observer_number=1,
        outcome=DiscoveryFeedbackOutcome.CONFIRMED,
        invalidate_zone=False,
    )
    application = store.apply_feedback_delta(
        evidence,
        expected_cursor=cursor,
        applied_at="2026-07-29T04:38:00Z",
        store_signer=store_signer,
    )
    assert application.invalidated_entries == 1
    assert application.retained_entries == 0


def test_forged_delta_and_stale_store_signer_leave_head_unchanged(
    tmp_path: Path,
) -> None:
    store, store_signer = _initialized(tmp_path)
    _, _, fog, _, _ = _put_success(store, store_signer)
    cursor = store.cursor
    delta_cursor = DiscoveryFeedbackDeltaCursor.from_overlay(fog.overlay)
    evidence, *_ = _build_delta(
        fog,
        previous_overlay=fog.overlay,
        previous_overlay_key=fog.trusted_overlay_key,
        previous_feedback=fog.feedback_evidence,
        cursor=delta_cursor,
        observer_number=1,
        outcome=DiscoveryFeedbackOutcome.REFUTED,
        invalidate_zone=True,
    )
    forged = deepcopy(evidence.delta)
    forged["recheck_zone_ids"] = []
    forged_evidence = ToolzFeedbackDeltaEvidence(
        **{
            **evidence.__dict__,
            "delta": forged,
        }
    )
    with pytest.raises(ToolzRouteStoreError, match="verification rejected"):
        store.apply_feedback_delta(
            forged_evidence,
            expected_cursor=cursor,
            applied_at="2026-07-29T04:40:00Z",
            store_signer=store_signer,
        )
    with pytest.raises(ToolzRouteStoreError, match="signer mismatch"):
        store.apply_feedback_delta(
            evidence,
            expected_cursor=cursor,
            applied_at="2026-07-29T04:40:00Z",
            store_signer=Ed25519Signer.generate(
                "key:synthetic-toolz-store-other"
            ),
        )
    assert store.verify(expected_cursor=cursor)["sequence"] == cursor.sequence


@_POSIX_ONLY
def test_symlinked_root_and_database_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    root_link = tmp_path / "toolz-link"
    root_link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ToolzRouteStoreError, match="new private directory"):
        ToolzRouteMemoryStore.initialize(
            root_link,
            store_id=STORE_ID,
            tenant_id=SYNTHETIC_TENANT,
            store_signer=Ed25519Signer.generate("key:synthetic-toolz-store"),
            created_at=INITIALIZED,
        )

    store, signer = _initialized(tmp_path)
    cursor = store.cursor
    store.close()
    database = tmp_path / "toolz" / STORE_DATABASE_NAME
    replacement = tmp_path / "replacement.sqlite3"
    replacement.write_bytes(database.read_bytes())
    replacement.chmod(0o600)
    database.unlink()
    database.symlink_to(replacement)
    with pytest.raises(ToolzRouteStoreError, match="database is unsafe"):
        ToolzRouteMemoryStore.open(
            tmp_path / "toolz",
            store_id=STORE_ID,
            tenant_id=SYNTHETIC_TENANT,
            authority_key=_trusted(signer),
            expected_cursor=cursor,
        )


def test_store_module_has_only_private_local_storage_authority() -> None:
    tree = ast.parse(inspect.getsource(store_module))
    blocked_import_roots = {
        "http",
        "importlib",
        "requests",
        "selenium",
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
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not (imported_roots & blocked_import_roots)
    assert not (called_names & {"__import__", "compile", "eval", "exec"})
    assert "sqlite3" in imported_roots
    assert "os" in imported_roots
