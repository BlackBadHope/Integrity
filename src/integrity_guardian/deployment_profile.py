"""Deployment identity profile: host-owned identity values for one deployment.

The public distribution carries only public identity values. A deployment that
must keep reading state created under its own tenant identifiers and Action Log
protocol labels supplies them in one owner-provisioned JSON document on the
host. The server receives its path and a pinned SHA-256 digest
(``--deployment-profile`` and ``--expected-deployment-profile-digest``), the
same byte-binding used for the TTT path catalogue. Nothing is searched for and
no default path exists: without a profile every value below keeps its public
default.

The profile is identity configuration, never authority. It cannot grant
production authority, widen tool surfaces or relax any verification. A process
activates at most one profile, before the first identity value is read; a
second, different profile or a late activation is refused so that one process
never mixes identities.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .canonical import parse_json_strict

PROTOCOL = "integrity-guardian/deployment-profile/v1"
MAX_PROFILE_BYTES = 65536

# Public defaults. These are the values the public distribution has always
# shipped; a profile may replace any of them for one deployment.
PUBLIC_IDENTITIES: Mapping[str, str] = MappingProxyType({
    "architecture_tenant_id": "tenant:public-f3351a94ab708c31",
    "security_tenant_id": "tenant:public-b9d53e60dea942e6",
    "security_environment_profile_id": "environment:local-client-forced-stdio",
    "synthetic_tenant_id": "tenant:public-6e3cdbebaafc8efa",
    "readonly_canary_tenant_id": "tenant:public-19b422cdda7a5502",
    "canary_tenant_id": "tenant:public-a0d3e830ed127ef0",
    "canary_foreign_tenant_id": "tenant:public-adc098318f62fb10",
    "cross_agent_acceptance_tenant_id": "tenant:public-0660f95c17ebc298",
})
PUBLIC_ACTION_LOG_DIALECT: Mapping[str, str] = MappingProxyType({
    "mind_projection": "legacy.action-log.mind-projection/v1",
    "concept_recovery": "legacy.action-log.concept-recovery/v1",
    "coordination_projection": "legacy.action-log.coordination-projection/v1",
})
PUBLIC_SESSION_RECOVERY_MAX_RECORDS = 128

# Identity values that also appear as JSON Schema constants. Schemas are
# rewritten value-for-value when a profile replaces one of these.
SCHEMA_REWRITABLE = (
    "security_tenant_id",
    "security_environment_profile_id",
    "synthetic_tenant_id",
)

_TENANT = re.compile(r"tenant:[a-z0-9][a-z0-9._-]{0,63}")
_ENVIRONMENT = re.compile(r"environment:[a-z0-9][a-z0-9._-]{0,127}")
_PROFILE_ID = re.compile(r"deployment:[a-z0-9][a-z0-9._-]{0,63}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_DIALECT_PREFIX = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_EVENT_UID = re.compile(r"client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}")
_ACTION = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_TERM = re.compile(r"\S{1,64}")
_TOP_LEVEL = frozenset({
    "protocol", "profile_id", "production_authority", "identities",
    "action_log_dialect", "archive_policy", "seed_catalog", "session_recovery",
    "replay_catalog_pool", "append_response_compaction", "facade_identity",
})
# Facade labels that describe the same memory-synapse LTS contract and the same
# capability shape. The private and public release lines diverged only in this
# label (2.10.0 vs 2.11.0); installed clients pin one of them exactly.
FACADE_SERVER_VERSIONS = ("2.11.0", "2.10.0")


class DeploymentProfileError(ValueError):
    """Raised when a deployment profile is absent, altered or not acceptable."""


@dataclass(frozen=True)
class RecallDemotion:
    """Rank one bulk action below ordinary events unless a term asks for it."""

    action: str
    unless_terms: tuple[str, ...]


@dataclass(frozen=True)
class DeploymentProfile:
    profile_id: str
    digest: str
    identities: Mapping[str, str]
    action_log_dialect: Mapping[str, str]
    archive_policy: Mapping[str, Any] | None = None
    seed_required_event_ids: tuple[int, ...] = ()
    recall_demotions: tuple[RecallDemotion, ...] = ()
    session_recovery_max_records: int = PUBLIC_SESSION_RECOVERY_MAX_RECORDS
    replay_catalog_pool: bool = False
    append_response_compaction: bool = False
    facade_default_server_version: str | None = None
    _schema_rewrites: Mapping[str, str] = field(default_factory=dict, repr=False)

    def schema_rewrites(self) -> Mapping[str, str]:
        return self._schema_rewrites


def _public_profile() -> DeploymentProfile:
    return DeploymentProfile(
        profile_id="deployment:public",
        digest="",
        identities=PUBLIC_IDENTITIES,
        action_log_dialect=PUBLIC_ACTION_LOG_DIALECT,
    )


_PUBLIC = _public_profile()
_lock = threading.Lock()
_active: DeploymentProfile | None = None
_sealed = False


def _require(condition: object, message: str) -> None:
    if not condition:
        raise DeploymentProfileError(message)


def _read_profile_bytes(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DeploymentProfileError("deployment profile could not be opened") from exc
    try:
        details = os.fstat(descriptor)
        _require(stat.S_ISREG(details.st_mode), "deployment profile is not a regular file")
        if hasattr(os, "geteuid"):
            # Owner-provisioned: owned by root or by the serving principal, and
            # never writable by group or others.
            _require(
                details.st_uid in {0, os.geteuid()},
                "deployment profile owner is not trusted",
            )
            _require(
                not stat.S_IMODE(details.st_mode) & 0o022,
                "deployment profile is writable by group or others",
            )
        chunks = []
        remaining = MAX_PROFILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    _require(len(raw) <= MAX_PROFILE_BYTES, "deployment profile exceeds 65536 bytes")
    return raw


def _string_map(
    value: object, allowed: Mapping[str, str], label: str, check
) -> dict[str, str]:
    _require(isinstance(value, dict), f"{label} must be an object")
    unknown = set(value) - set(allowed)
    _require(not unknown, f"{label} has unknown keys")
    result = {}
    for key, item in value.items():
        _require(isinstance(item, str) and check(key, item), f"{label}.{key} is invalid")
        result[key] = item
    return result


def _identity_valid(key: str, value: str) -> bool:
    pattern = _ENVIRONMENT if key == "security_environment_profile_id" else _TENANT
    return pattern.fullmatch(value) is not None


def _dialect_valid(key: str, value: str) -> bool:
    suffix = ".action-log." + key.replace("_", "-") + "/v1"
    if not value.endswith(suffix):
        return False
    return _DIALECT_PREFIX.fullmatch(value[: -len(suffix)]) is not None


def _archive_policy(value: object) -> dict[str, Any]:
    _require(
        isinstance(value, dict)
        and set(value) == {"source_sha256", "manifest_event_uid", "message_count", "part_count"},
        "archive_policy keys are invalid",
    )
    _require(
        isinstance(value["source_sha256"], str)
        and re.fullmatch(r"[a-f0-9]{64}", value["source_sha256"]) is not None,
        "archive_policy.source_sha256 is invalid",
    )
    _require(
        isinstance(value["manifest_event_uid"], str)
        and _EVENT_UID.fullmatch(value["manifest_event_uid"]) is not None,
        "archive_policy.manifest_event_uid is invalid",
    )
    for key, maximum in (("message_count", 1_000_000), ("part_count", 4096)):
        _require(
            type(value[key]) is int and 1 <= value[key] <= maximum,
            f"archive_policy.{key} is invalid",
        )
    _require(value["part_count"] <= value["message_count"], "archive_policy counts are invalid")
    return dict(value)


def _seed_catalog(value: object) -> tuple[tuple[int, ...], tuple[RecallDemotion, ...]]:
    _require(isinstance(value, dict), "seed_catalog must be an object")
    _require(
        not set(value) - {"required_event_ids", "recall_demotions"},
        "seed_catalog has unknown keys",
    )
    ids = value.get("required_event_ids", [])
    _require(
        isinstance(ids, list) and len(ids) <= 64
        and all(type(item) is int and item >= 1 for item in ids)
        and len(set(ids)) == len(ids),
        "seed_catalog.required_event_ids is invalid",
    )
    demotions = value.get("recall_demotions", [])
    _require(isinstance(demotions, list) and len(demotions) <= 16, "recall_demotions is invalid")
    parsed = []
    for row in demotions:
        _require(
            isinstance(row, dict) and set(row) == {"action", "unless_terms"}
            and isinstance(row["action"], str) and _ACTION.fullmatch(row["action"]) is not None
            and isinstance(row["unless_terms"], list) and len(row["unless_terms"]) <= 16
            and all(
                isinstance(term, str) and _TERM.fullmatch(term) is not None
                for term in row["unless_terms"]
            ),
            "recall_demotions entry is invalid",
        )
        parsed.append(RecallDemotion(row["action"], tuple(term.casefold() for term in row["unless_terms"])))
    return tuple(sorted(ids)), tuple(parsed)


def parse_profile(raw: bytes, expected_digest: str) -> DeploymentProfile:
    """Validate exact profile bytes against a pinned digest."""

    _require(
        isinstance(expected_digest, str) and _DIGEST.fullmatch(expected_digest) is not None,
        "expected deployment profile digest must be sha256:<64 hex>",
    )
    observed = "sha256:" + hashlib.sha256(raw).hexdigest()
    _require(
        observed == expected_digest,
        f"deployment profile digest mismatch: expected {expected_digest}, observed {observed}",
    )
    try:
        document = parse_json_strict(raw)
    except ValueError as exc:
        raise DeploymentProfileError("deployment profile is not strict JSON") from exc
    _require(isinstance(document, dict), "deployment profile must be a JSON object")
    _require(not set(document) - _TOP_LEVEL, "deployment profile has unknown keys")
    _require(document.get("protocol") == PROTOCOL, "deployment profile protocol is not supported")
    _require(
        isinstance(document.get("profile_id"), str)
        and _PROFILE_ID.fullmatch(document["profile_id"]) is not None
        and document["profile_id"] != "deployment:public",
        "deployment profile id is invalid",
    )
    _require(
        document.get("production_authority", False) is False,
        "deployment profile cannot claim production authority",
    )
    identities = dict(PUBLIC_IDENTITIES)
    identities.update(_string_map(
        document.get("identities", {}), PUBLIC_IDENTITIES, "identities", _identity_valid,
    ))
    dialect = dict(PUBLIC_ACTION_LOG_DIALECT)
    dialect.update(_string_map(
        document.get("action_log_dialect", {}), PUBLIC_ACTION_LOG_DIALECT,
        "action_log_dialect", _dialect_valid,
    ))
    archive = document.get("archive_policy")
    archive_policy = None if archive is None else _archive_policy(archive)
    required_ids, demotions = _seed_catalog(document.get("seed_catalog", {}))
    recovery = document.get("session_recovery", {})
    _require(
        isinstance(recovery, dict) and not set(recovery) - {"max_records"},
        "session_recovery is invalid",
    )
    max_records = recovery.get("max_records", PUBLIC_SESSION_RECOVERY_MAX_RECORDS)
    _require(
        type(max_records) is int and 1 <= max_records <= 4096,
        "session_recovery.max_records is invalid",
    )
    pool = document.get("replay_catalog_pool", False)
    _require(type(pool) is bool, "replay_catalog_pool must be a boolean")
    compaction = document.get("append_response_compaction", False)
    _require(type(compaction) is bool, "append_response_compaction must be a boolean")
    facade = document.get("facade_identity", {})
    _require(isinstance(facade, dict) and set(facade) <= {"default_server_version"},
             "facade_identity keys are invalid")
    facade_default = facade.get("default_server_version")
    _require(facade_default is None or facade_default in FACADE_SERVER_VERSIONS,
             "facade_identity.default_server_version is not supported")
    rewrites = {
        PUBLIC_IDENTITIES[key]: identities[key]
        for key in SCHEMA_REWRITABLE
        if identities[key] != PUBLIC_IDENTITIES[key]
    }
    return DeploymentProfile(
        profile_id=document["profile_id"],
        digest=observed,
        identities=MappingProxyType(identities),
        action_log_dialect=MappingProxyType(dialect),
        archive_policy=None if archive_policy is None else MappingProxyType(archive_policy),
        seed_required_event_ids=required_ids,
        recall_demotions=demotions,
        session_recovery_max_records=max_records,
        replay_catalog_pool=pool,
        append_response_compaction=compaction,
        facade_default_server_version=facade_default,
        _schema_rewrites=MappingProxyType(rewrites),
    )


def load_profile(path: Path | None, expected_digest: str | None) -> DeploymentProfile | None:
    """Load one explicit byte-bound host profile; never search for defaults."""

    if path is None:
        _require(expected_digest is None, "expected digest requires a deployment profile")
        return None
    _require(expected_digest is not None, "deployment profile requires an expected digest")
    return parse_profile(_read_profile_bytes(Path(path)), expected_digest)


def activate(profile: DeploymentProfile | None) -> None:
    """Install ``profile`` for this process before any identity value is read."""

    global _active
    if profile is None:
        return
    _require(isinstance(profile, DeploymentProfile), "deployment profile is invalid")
    with _lock:
        if _active is not None:
            _require(_active.digest == profile.digest, "a different deployment profile is active")
            return
        _require(not _sealed, "deployment profile must be activated before identities are read")
        _active = profile
    from . import schemas

    schemas.reset_schema_cache()


def current() -> DeploymentProfile:
    """Return the active profile and seal the process against later activation."""

    global _sealed
    profile = _active
    if profile is None:
        _sealed = True
        return _PUBLIC
    return profile


def identity(key: str) -> str:
    if key not in PUBLIC_IDENTITIES:
        raise KeyError(f"unknown deployment identity: {key}")
    return current().identities[key]


def action_log_dialect() -> Mapping[str, str]:
    return current().action_log_dialect


def schema_value(value: str) -> str:
    """Map one public schema constant to this deployment's value."""

    return current().schema_rewrites().get(value, value)


def describe() -> dict[str, Any]:
    """Content-free description: which profile, never its values."""

    profile = current()
    return {
        "protocol": PROTOCOL,
        "profile_id": profile.profile_id,
        "digest": profile.digest or None,
        "production_authority": False,
    }
