"""Verified agent identity for work claims: signed requests, one core, no replay.

An agent holds an Ed25519 key. The core operator enrolls the public key under
an agent id (optionally bound to the SSH device ids that may carry it). Every
claim operation the agent sends is a signed request:

    {protocol, core_id, agent_id, key_id, operation, arguments,
     nonce, issued_at, expires_at, signature}

``SignedClaimGate`` accepts a request only when

* it names this core (``core_id``), so it cannot be replayed at another core;
* ``key_id`` is enrolled, active, and enrolled for exactly this ``agent_id``;
* the transport device, when the enrollment names devices, is one of them;
* the signature covers every field above with that key;
* the validity window is short (at most ``MAX_REQUEST_LIFETIME_SECONDS``),
  has started (with ``CLOCK_SKEW_SECONDS`` tolerance) and has not ended;
* ``(key_id, nonce)`` was never accepted before. The request is stored with
  its outcome in the same database, so a replay is refused for as long as the
  database exists, including from another session or after a restart.

The claim operation then runs inside the same write transaction as the nonce
insert, in a savepoint, under the enrolled agent id, and every event it
appends carries the request digest and key id. A refused operation (for
example a stale fence) is rolled back to the savepoint; the nonce stays
consumed and a ``claim-request-failed`` record is written in that same
transaction, so the request cannot be replayed in between.

In ``strict`` mode an unsigned request is refused. In ``declared`` mode an
unsigned request is executed under the agent id it names and its events say
``"requested_by": {"mode": "declared"}``, unless a key was ever enrolled for
that agent id (active or revoked): such an agent must sign
(``enrolled-agent-must-sign``). A
signed request is verified the same way in both modes. Identity is not authority: nothing here grants
permission to act on any system.
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    public_key_value,
    trusted_key_from_value,
    verify_trusted_signature,
)
from .work_claims import (
    IDENTITY_STRICT,
    ClaimDecision,
    WorkClaimError,
    WorkClaimRegistry,
)

REQUEST_PROTOCOL = "integrity-guardian/work-claim-request/v1"
REQUEST_DOMAIN = "work-claim-request-v1"
MAX_REQUEST_LIFETIME_SECONDS = 300
DEFAULT_REQUEST_LIFETIME_SECONDS = 60
CLOCK_SKEW_SECONDS = 60
MAX_DEVICES = 16
OPERATIONS = (
    "claim",
    "poll",
    "renew",
    "release",
    "cancel",
    "handoff",
    "record",
    "assert_fence",
    "status",
    "events",
)
_SIGNED_FIELDS = frozenset(
    {
        "protocol",
        "core_id",
        "agent_id",
        "key_id",
        "operation",
        "arguments",
        "nonce",
        "issued_at",
        "expires_at",
        "signature",
    }
)
_UNSIGNED_FIELDS = frozenset({"protocol", "agent_id", "operation", "arguments"})
_NONCE = re.compile(r"[a-f0-9]{32,128}")
_KEY_ID = re.compile(r"sha256:[a-f0-9]{64}")
_CORE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DEVICE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
_AGENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")


class ClaimRequestRejected(WorkClaimError):
    """A request was refused before any claim operation ran."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# -- agent keys ---------------------------------------------------------------


class AgentKey:
    """An agent's Ed25519 private key; it stays in caller-owned memory or file."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self.key_id = public_key_fingerprint(private_key.public_key())
        self.public_value = public_key_value(private_key.public_key())

    @classmethod
    def generate(cls) -> AgentKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path) -> AgentKey:
        key = load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise WorkClaimError("agent key file must hold an Ed25519 private key")
        return cls(key)

    def save(self, path: Path) -> None:
        """Write the private key once, as PEM, readable only by its owner on POSIX."""

        data = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(Path(path), flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)

    def signer(self) -> Ed25519Signer:
        return Ed25519Signer(self.key_id, self._private_key)


def _render(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ClaimRequestRejected("malformed", f"{field} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ClaimRequestRejected("malformed", f"{field} is not a timestamp") from exc
    return parsed


def _now(value: datetime | None) -> datetime:
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None:
        raise WorkClaimError("time must include a timezone")
    return current.astimezone(UTC)


def sign_request(
    key: AgentKey,
    *,
    core_id: str,
    agent_id: str,
    operation: str,
    arguments: Mapping[str, Any],
    now: datetime | None = None,
    lifetime_seconds: int = DEFAULT_REQUEST_LIFETIME_SECONDS,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Build one signed, single-use claim request."""

    if operation not in OPERATIONS:
        raise WorkClaimError(f"unknown claim operation {operation!r}")
    if not 1 <= lifetime_seconds <= MAX_REQUEST_LIFETIME_SECONDS:
        raise WorkClaimError("request lifetime is outside the accepted window")
    issued = _now(now)
    request = {
        "protocol": REQUEST_PROTOCOL,
        "core_id": core_id,
        "agent_id": agent_id,
        "key_id": key.key_id,
        "operation": operation,
        "arguments": dict(arguments),
        "nonce": nonce or secrets.token_hex(16),
        "issued_at": _render(issued),
        "expires_at": _render(issued + timedelta(seconds=lifetime_seconds)),
    }
    canonical_bytes(request)  # reject floats and other non-canonical values early
    return key.signer().sign(request)


def request_digest(request: Mapping[str, Any]) -> str:
    return digest_object(dict(request), domain=REQUEST_DOMAIN)


# -- enrolled keys and the gate -------------------------------------------------


@dataclass(frozen=True)
class EnrolledKey:
    key_id: str
    agent_id: str
    public_key: str
    devices: tuple[str, ...]
    status: str
    enrolled_at: str
    revoked_at: str | None

    def public(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "devices": list(self.devices),
            "status": self.status,
            "enrolled_at": self.enrolled_at,
            "revoked_at": self.revoked_at,
        }


def _decision(decision: ClaimDecision, identity: str) -> dict[str, Any]:
    return {
        "status": decision.status.value,
        "claim_id": decision.claim_id,
        "agent_id": decision.agent_id,
        "resources": list(decision.resources),
        "fence_token": decision.fence_token,
        "expires_at": decision.expires_at,
        "blocked_by": list(decision.blocked_by),
        "reason": decision.reason,
        "identity": identity,
    }


def _arguments(arguments: Any, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(arguments, dict):
        raise ClaimRequestRejected("bad-arguments", "arguments must be an object")
    keys = set(arguments)
    if not required <= keys or not keys <= required | optional:
        expected = ", ".join(sorted(required | optional))
        raise ClaimRequestRejected("bad-arguments", f"arguments must be exactly: {expected}")
    for field in ("claim_id", "outcome", "result", "successor_id"):
        if field in arguments and not isinstance(arguments[field], str):
            raise ClaimRequestRejected("bad-arguments", f"{field} must be a string")
    return arguments


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ClaimRequestRejected("bad-arguments", f"{field} must be an integer")
    return value


class SignedClaimGate:
    """Verify signed requests and run them against one claim registry."""

    def __init__(self, registry: WorkClaimRegistry, *, core_id: str) -> None:
        if not isinstance(core_id, str) or _CORE_ID.fullmatch(core_id) is None:
            raise WorkClaimError("core_id must be a short safe token")
        self.registry = registry
        self.core_id = core_id
        self._db = registry._connection
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS work_claim_agent_keys (
                key_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                devices_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
                enrolled_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS work_claim_requests (
                request_digest TEXT PRIMARY KEY,
                key_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                device_id TEXT,
                received_at TEXT NOT NULL,
                outcome TEXT NOT NULL,
                request_json BLOB NOT NULL,
                UNIQUE (key_id, nonce)
            );
            """
        )

    @property
    def identity_mode(self) -> str:
        return self.registry.identity_mode

    # -- enrollment (operator side, on the core) -------------------------

    def enroll(
        self,
        *,
        agent_id: str,
        public_key: str,
        devices: tuple[str, ...] | list[str] = (),
        now: datetime | None = None,
    ) -> EnrolledKey:
        if not isinstance(agent_id, str) or _AGENT.fullmatch(agent_id) is None:
            raise WorkClaimError("agent_id must be a token of 1..256 safe characters")
        try:
            trusted = trusted_key_from_value("pending", public_key)
        except ValueError as exc:
            raise WorkClaimError("public_key must be a raw Ed25519 key in base64url") from exc
        key_id = public_key_fingerprint(trusted.public_key)
        device_list = sorted(set(devices))
        if len(device_list) > MAX_DEVICES or any(
            not isinstance(item, str) or _DEVICE.fullmatch(item) is None for item in device_list
        ):
            raise WorkClaimError("devices must be integrity-remote device ids")
        current = _now(now)
        with self.registry._transaction():
            if self._db.execute(
                "SELECT 1 FROM work_claim_agent_keys WHERE key_id = ?", (key_id,)
            ).fetchone():
                raise WorkClaimError("this key is already enrolled; a revoked key stays revoked")
            self._db.execute(
                "INSERT INTO work_claim_agent_keys VALUES (?, ?, ?, ?, 'active', ?, NULL)",
                (key_id, agent_id, public_key, canonical_bytes(device_list).decode(),
                 _render(current)),
            )
            self.registry.append_record(
                "agent-key-enrolled",
                {"agent_id": agent_id, "key_id": key_id, "public_key": public_key,
                 "devices": device_list},
                now=current,
            )
        return self.key(key_id)

    def revoke(self, key_id: str, *, now: datetime | None = None) -> EnrolledKey:
        current = _now(now)
        with self.registry._transaction():
            enrolled = self.key(key_id)
            if enrolled.status == "revoked":
                return enrolled
            self._db.execute(
                "UPDATE work_claim_agent_keys SET status = 'revoked', revoked_at = ? "
                "WHERE key_id = ?",
                (_render(current), key_id),
            )
            self.registry.append_record(
                "agent-key-revoked",
                {"agent_id": enrolled.agent_id, "key_id": key_id},
                now=current,
            )
        return self.key(key_id)

    def key(self, key_id: str) -> EnrolledKey:
        row = self._db.execute(
            "SELECT * FROM work_claim_agent_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None:
            raise ClaimRequestRejected("unknown-key", "this key is not enrolled at this core")
        return EnrolledKey(
            key_id=row["key_id"],
            agent_id=row["agent_id"],
            public_key=row["public_key"],
            devices=tuple(parse_json_strict(row["devices_json"])),
            status=row["status"],
            enrolled_at=row["enrolled_at"],
            revoked_at=row["revoked_at"],
        )

    def enrolled_keys(self) -> list[EnrolledKey]:
        rows = self._db.execute(
            "SELECT key_id FROM work_claim_agent_keys ORDER BY enrolled_at, key_id"
        ).fetchall()
        return [self.key(row["key_id"]) for row in rows]

    def _active_agent(self, agent_id: str) -> bool:
        return (
            self._db.execute(
                "SELECT 1 FROM work_claim_agent_keys WHERE agent_id = ? AND status = 'active'",
                (agent_id,),
            ).fetchone()
            is not None
        )

    def _enrolled_agent(self, agent_id: str) -> bool:
        return (
            self._db.execute(
                "SELECT 1 FROM work_claim_agent_keys WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            is not None
        )

    # -- requests ----------------------------------------------------------

    def execute(
        self,
        request: Any,
        *,
        device_id: str = "",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Verify one request and run it. Raises ``ClaimRequestRejected`` or
        ``WorkClaimError``; returns the operation's result."""

        current = _now(now)
        if not isinstance(request, dict) or request.get("protocol") != REQUEST_PROTOCOL:
            raise ClaimRequestRejected("malformed", "not a work-claim request")
        if "signature" not in request:
            return self._execute_declared(request, current)
        enrolled, digest = self._verify(request, device_id, current)
        requested_by = {
            "mode": "verified",
            "agent_id": enrolled.agent_id,
            "key_id": enrolled.key_id,
            "request_digest": digest,
            "device_id": device_id or None,
        }
        record = (
            digest, enrolled.key_id, request["nonce"], enrolled.agent_id, device_id or None,
            _render(current),
        )
        refusal: WorkClaimError | None = None
        with self.registry._transaction():
            # A replay raises here and the whole transaction rolls back.
            self._consume(record, "accepted", request)
            # The operation runs inside a savepoint: a refusal undoes only the
            # operation, and the nonce stays consumed in the same transaction
            # as the failure record, so no second copy can slip in between.
            self._db.execute("SAVEPOINT claim_operation")
            try:
                if self.key(enrolled.key_id).status != "active":
                    # Revoked after the signature check: the write lock now holds.
                    raise ClaimRequestRejected("key-revoked", "this key was revoked at this core")
                with self.registry.verified_request(requested_by):
                    result = self._dispatch(
                        request["operation"], request["arguments"], enrolled.agent_id, current
                    )
            except WorkClaimError as exc:
                self._db.execute("ROLLBACK TO claim_operation")
                self._db.execute("RELEASE claim_operation")
                self._record_failure(digest, request, requested_by, exc, current)
                refusal = exc
            else:
                self._db.execute("RELEASE claim_operation")
        if refusal is not None:
            raise refusal
        return {**result, "request_digest": digest}

    def _verify(
        self, request: dict[str, Any], device_id: str, current: datetime
    ) -> tuple[EnrolledKey, str]:
        if set(request) != _SIGNED_FIELDS:
            raise ClaimRequestRejected("malformed", "signed request fields do not match v1")
        if request["core_id"] != self.core_id:
            raise ClaimRequestRejected("wrong-core", "the request names another core")
        if request["operation"] not in OPERATIONS:
            raise ClaimRequestRejected("malformed", "unknown operation")
        if not isinstance(request["nonce"], str) or _NONCE.fullmatch(request["nonce"]) is None:
            raise ClaimRequestRejected("malformed", "nonce must be 32..128 lowercase hex")
        if not isinstance(request["key_id"], str) or _KEY_ID.fullmatch(request["key_id"]) is None:
            raise ClaimRequestRejected("malformed", "key_id must be a sha256 key fingerprint")
        try:
            canonical_bytes(request)
        except ValueError as exc:
            raise ClaimRequestRejected("malformed", "request is not canonical JSON") from exc
        enrolled = self.key(request["key_id"])
        trusted = TrustedKey(
            key_id=enrolled.key_id,
            public_key=trusted_key_from_value(enrolled.key_id, enrolled.public_key).public_key,
        )
        if not verify_trusted_signature(request, trusted):
            raise ClaimRequestRejected("bad-signature", "the signature does not verify")
        if enrolled.status != "active":
            raise ClaimRequestRejected("key-revoked", "this key was revoked at this core")
        if request["agent_id"] != enrolled.agent_id:
            raise ClaimRequestRejected("agent-mismatch", "this key is enrolled for another agent")
        if enrolled.devices and device_id not in enrolled.devices:
            raise ClaimRequestRejected(
                "device-mismatch", "this key is not enrolled for the connecting device"
            )
        issued = _parse_time(request["issued_at"], "issued_at")
        expires = _parse_time(request["expires_at"], "expires_at")
        lifetime = (expires - issued).total_seconds()
        if not 0 < lifetime <= MAX_REQUEST_LIFETIME_SECONDS:
            raise ClaimRequestRejected("bad-window", "request lifetime is outside the window")
        if issued > current + timedelta(seconds=CLOCK_SKEW_SECONDS):
            raise ClaimRequestRejected("not-yet-valid", "the request is issued in the future")
        if expires <= current:
            raise ClaimRequestRejected("expired", "the request has expired")
        return enrolled, request_digest(request)

    def _consume(self, record: tuple, outcome: str, request: dict[str, Any]) -> None:
        try:
            self._db.execute(
                "INSERT INTO work_claim_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (*record, outcome, canonical_bytes(request)),
            )
        except sqlite3.IntegrityError as exc:
            raise ClaimRequestRejected(
                "replay", "this request (key and nonce) was already used at this core"
            ) from exc

    def _record_failure(
        self,
        digest: str,
        request: dict[str, Any],
        requested_by: dict[str, Any],
        error: WorkClaimError,
        current: datetime,
    ) -> None:
        """Mark a consumed request as refused; runs inside the caller's transaction."""

        code = getattr(error, "code", None) or type(error).__name__
        self._db.execute(
            "UPDATE work_claim_requests SET outcome = 'refused' WHERE request_digest = ?",
            (digest,),
        )
        self.registry.append_record(
            "claim-request-failed",
            {"operation": request["operation"], "requested_by": requested_by, "error": code},
            now=current,
        )

    def _execute_declared(self, request: dict[str, Any], current: datetime) -> dict[str, Any]:
        if self.identity_mode == IDENTITY_STRICT:
            raise ClaimRequestRejected(
                "unsigned-refused", "this core is strict: requests must be signed"
            )
        if set(request) != _UNSIGNED_FIELDS:
            raise ClaimRequestRejected("malformed", "unsigned request fields do not match v1")
        agent = request["agent_id"]
        if not isinstance(agent, str) or _AGENT.fullmatch(agent) is None:
            raise ClaimRequestRejected("malformed", "agent_id is not a safe token")
        if request["operation"] not in OPERATIONS:
            raise ClaimRequestRejected("malformed", "unknown operation")
        with self.registry._transaction():
            if self._enrolled_agent(agent):
                # A name with an enrolled key, active or revoked, is only
                # accepted signed; otherwise anyone could act as that agent
                # unsigned, for example cancel its verified claims.
                raise ClaimRequestRejected(
                    "enrolled-agent-must-sign",
                    "this agent has an enrolled key: its requests must be signed",
                )
            return self._dispatch(request["operation"], request["arguments"], agent, current,
                                  identity="declared")

    def _owned(self, claim_id: Any, agent: str) -> str:
        if not isinstance(claim_id, str):
            raise ClaimRequestRejected("bad-arguments", "claim_id must be a string")
        if self.registry.status(claim_id).agent_id != agent:
            raise WorkClaimError("this claim belongs to another agent")
        return claim_id

    def _dispatch(
        self,
        operation: str,
        arguments: Any,
        agent: str,
        current: datetime,
        *,
        identity: str = "verified",
    ) -> dict[str, Any]:
        registry = self.registry
        if operation == "claim":
            args = _arguments(arguments, {"resources"}, {"ttl_seconds", "reference"})
            resources = args["resources"]
            if not isinstance(resources, list) or not all(isinstance(r, str) for r in resources):
                raise ClaimRequestRejected("bad-arguments", "resources must be a list of strings")
            decision = registry.claim(
                agent_id=agent, resources=resources,
                ttl_seconds=_integer(args.get("ttl_seconds", 300), "ttl_seconds"),
                reference=args.get("reference"), now=current,
            )
            return _decision(decision, identity)
        if operation == "poll":
            args = _arguments(arguments, {"claim_id"})
            return _decision(registry.poll(self._owned(args["claim_id"], agent), now=current),
                             identity)
        if operation == "status":
            args = _arguments(arguments, {"claim_id"})
            if not isinstance(args["claim_id"], str):
                raise ClaimRequestRejected("bad-arguments", "claim_id must be a string")
            return _decision(registry.status(args["claim_id"]), identity)
        if operation == "events":
            args = _arguments(arguments, set(), {"after", "limit"})
            events = registry.events(after=_integer(args.get("after", 0), "after"),
                                     limit=_integer(args.get("limit", 200), "limit"))
            return {"events": events, "identity": identity}
        if operation == "cancel":
            args = _arguments(arguments, {"claim_id"})
            claim_id = self._owned(args["claim_id"], agent)
            registry.cancel(claim_id, agent_id=agent, now=current)
            return _decision(registry.status(claim_id), identity)
        if operation == "renew":
            args = _arguments(arguments, {"claim_id", "fence_token"}, {"ttl_seconds"})
            ttl = args.get("ttl_seconds")
            decision = registry.renew(
                args["claim_id"], agent_id=agent,
                fence_token=_integer(args["fence_token"], "fence_token"),
                ttl_seconds=None if ttl is None else _integer(ttl, "ttl_seconds"), now=current,
            )
            return _decision(decision, identity)
        if operation == "assert_fence":
            args = _arguments(arguments, {"claim_id", "fence_token"})
            decision = registry.assert_fence(
                args["claim_id"], agent_id=agent,
                fence_token=_integer(args["fence_token"], "fence_token"), now=current,
            )
            return _decision(decision, identity)
        if operation == "release":
            args = _arguments(arguments, {"claim_id", "fence_token", "outcome"})
            receipt = registry.release(
                args["claim_id"], agent_id=agent,
                fence_token=_integer(args["fence_token"], "fence_token"),
                outcome=args["outcome"], now=current,
            )
            return {"receipt": receipt, "identity": identity}
        if operation == "record":
            args = _arguments(arguments, {"claim_id", "fence_token", "result"})
            receipt = registry.record_result(
                args["claim_id"], agent_id=agent,
                fence_token=_integer(args["fence_token"], "fence_token"),
                result=args["result"], now=current,
            )
            return {"receipt": receipt, "identity": identity}
        if operation == "handoff":
            args = _arguments(arguments, {"claim_id", "fence_token", "successor_id"}, {"note"})
            successor = args["successor_id"]
            if identity == "verified" and not (
                isinstance(successor, str) and self._active_agent(successor)
            ):
                raise ClaimRequestRejected(
                    "unknown-successor", "the successor has no active enrolled key at this core"
                )
            note = args.get("note", "")
            if not isinstance(note, str):
                raise ClaimRequestRejected("bad-arguments", "note must be a string")
            decision = registry.handoff(
                args["claim_id"], agent_id=agent,
                fence_token=_integer(args["fence_token"], "fence_token"),
                successor_id=successor, note=note, now=current,
            )
            return _decision(decision, identity)
        raise ClaimRequestRejected("malformed", "unknown operation")

    # -- audit -------------------------------------------------------------

    def verify_log(self) -> dict[str, int]:
        """Recheck the event chain and every stored signed request.

        Every event that names a verified request must point at a stored
        request whose signature still verifies with the key enrolled for it.
        """

        chained = self.registry.verify_events()
        checked = 0
        for row in self._db.execute("SELECT request_digest, request_json FROM work_claim_requests"):
            request = parse_json_strict(row["request_json"])
            if request_digest(request) != row["request_digest"]:
                raise WorkClaimError("stored request digest mismatch")
            enrolled = self.key(request["key_id"])
            trusted = trusted_key_from_value(enrolled.key_id, enrolled.public_key)
            if not verify_trusted_signature(deepcopy(request), trusted):
                raise WorkClaimError("stored request signature does not verify")
            checked += 1
        referenced = 0
        after = 0
        while True:
            page = self.registry.events(after=after, limit=1000)
            if not page:
                break
            for event in page:
                requested_by = event.get("requested_by") or {}
                if requested_by.get("mode") == "verified":
                    found = self._db.execute(
                        "SELECT key_id FROM work_claim_requests WHERE request_digest = ?",
                        (requested_by.get("request_digest"),),
                    ).fetchone()
                    if found is None or found["key_id"] != requested_by.get("key_id"):
                        raise WorkClaimError("an event names a request the core never stored")
                    referenced += 1
                after = event["event_seq"]
        return {"events": chained, "signed_requests": checked, "verified_events": referenced}
