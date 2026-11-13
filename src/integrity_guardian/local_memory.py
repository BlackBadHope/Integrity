"""Local memory profile: one machine, three plain stores, one MCP server on stdio.

This is the first install stage of Integrity memory, for one user with their
own agents on one machine. It joins three stores that already exist in this
package:

* a Seed catalog holds the events the agents write;
* a Turn Memory store holds a signed registration for every turn and a signed
  receipt that says how the turn ended;
* a work-claim registry holds who claimed which task, in a hash-chained log.

It is NOT the core write path. There is no Action Log, no custody ledger, no
admission of actions and no production authority. Agent, client and machine
names are whatever the caller declares; nothing here authenticates them. The
signing key lives next to the stores, so a signature proves that a record was
written by this instance and not changed afterwards, not who the writer was.
Claims are not signed at all. A shared core on a server is a different stage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, ValidationError

from . import __version__
from .canonical import canonical_bytes
from .seed_catalog import SeedCatalog, SeedCatalogError, open_catalog_readonly
from .signing import Ed25519Signer, public_key_fingerprint
from .turn_memory import TurnMemoryError, TurnMemoryStore, namespace_fingerprint
from .work_claims import WorkClaimError, WorkClaimRegistry, normalize_resource

PROFILE = "integrity-local-memory/v1"
SERVER_NAME = "integrity-local-memory"
ENV_HOME = "INTEGRITY_LOCAL_MEMORY_HOME"
SOURCE_NAMESPACE = "seed://project/local-memory"
MARKER = "_integrity_local"
DEFAULT_MCP_VERSION = "2025-06-18"
SUPPORTED_MCP_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MAX_FRAME_BYTES = 1_048_576
CLIENTS = ("claude-code", "codex", "antigravity")
KINDS = ("task", "thought", "concept")
_NAME = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$"
_EVENT_UID = r"^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$"
_DIGEST = r"^sha256:[a-f0-9]{64}$"
_TASK = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"

LIMITS = (
    "one machine: every agent must reach the same folder on this computer",
    "agent, client and machine names are declared by the caller and are not verified",
    "signatures come from a key stored beside the data: they show a record was not changed, not who wrote it",
    "work claims are hash-chained but not signed",
    "no Action Log, no custody ledger, no admission of actions, no production authority",
)


class LocalMemoryError(ValueError):
    """A request that the local profile refuses."""


def default_home() -> Path:
    """Per-user folder outside any clone; nothing here names a particular machine."""
    configured = os.environ.get(ENV_HOME)
    if configured:
        return Path(configured)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "integrity-local-memory"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _private_folder(path: Path) -> None:
    if os.name == "nt":
        from ._windows_files import create_private_directory_tree

        create_private_directory_tree(path)
    else:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)


def _write_private(path: Path, payload: bytes) -> None:
    if os.name == "nt":
        from .windows_private_state import write_private_once

        write_private_once(path, payload)
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


class LocalMemory:
    """The three stores of one local instance, opened from its home folder."""

    def __init__(self, home: Path) -> None:
        self.home = Path(home).absolute()
        instance_file = self.home / "instance.json"
        if not instance_file.is_file():
            raise LocalMemoryError(f"no local memory instance in {self.home}; run: guardian-local-memory init")
        self.instance = json.loads(instance_file.read_text(encoding="utf-8"))
        if self.instance.get("profile") != PROFILE:
            raise LocalMemoryError("instance.json does not describe a local memory instance")
        key = serialization.load_pem_private_key((self.home / "turn-signing-key.pem").read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise LocalMemoryError("the turn signing key is not an Ed25519 key")
        signer = Ed25519Signer(self.instance["key_id"], key)
        if public_key_fingerprint(signer.public_key) != self.instance["public_key_fingerprint"]:
            raise LocalMemoryError("the turn signing key does not match instance.json")
        self.catalog = SeedCatalog(self.home / "seed" / "catalog.sqlite")
        self.turns = TurnMemoryStore(
            self.home / "turns.sqlite",
            namespace=namespace_fingerprint(
                source_namespace=SOURCE_NAMESPACE,
                trust_fingerprint=self.instance["public_key_fingerprint"],
            ),
            signer=signer,
        )
        self.claims = WorkClaimRegistry(self.home / "claims.sqlite")
        self._index = sqlite3.connect(self.home / "index.sqlite", timeout=5.0, isolation_level=None)
        self._index.execute("PRAGMA busy_timeout = 5000")
        self._index.executescript(
            """
            CREATE TABLE IF NOT EXISTS turn_authors (
                registration_id TEXT PRIMARY KEY, declared_agent TEXT NOT NULL,
                declared_client TEXT NOT NULL, declared_machine TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS turn_events (
                event_uid TEXT PRIMARY KEY, registration_id TEXT NOT NULL,
                event_id INTEGER NOT NULL, request_sha256 TEXT NOT NULL);
            """
        )

    def close(self) -> None:
        self.claims.close()
        self._index.close()

    # -- setup ---------------------------------------------------------------

    @classmethod
    def create(cls, home: Path) -> LocalMemory:
        """Create a new instance in an empty or missing folder."""
        home = Path(home).absolute()
        if home.exists() and (not home.is_dir() or any(home.iterdir())):
            raise LocalMemoryError(f"{home} exists and is not an empty folder; nothing was changed")
        _private_folder(home)
        key = Ed25519PrivateKey.generate()
        fingerprint = public_key_fingerprint(key.public_key())
        instance = {
            "profile": PROFILE,
            "source_namespace": SOURCE_NAMESPACE,
            "key_id": "key:local-memory:" + fingerprint.split(":", 1)[1][:16],
            "public_key_fingerprint": fingerprint,
            "created_at": _now(),
        }
        _write_private(
            home / "turn-signing-key.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        (home / "instance.json").write_text(json.dumps(instance, indent=2) + "\n", encoding="utf-8")
        memory = cls(home)
        memory.catalog.import_events(
            [{
                "id": 1,
                "event_uid": "client:local-instance-" + uuid.uuid4().hex,
                "ts_utc": instance["created_at"],
                "actor": SERVER_NAME,
                "action": "local_instance_create",
                "level": "info",
                "summary": "Local memory instance created.",
                "details": {MARKER: {"profile": PROFILE}},
                "tags": ["local-memory"],
            }],
            source_namespace=SOURCE_NAMESPACE,
        )
        return memory

    # -- turns ---------------------------------------------------------------

    def open_turn(self, *, declared_agent: str, declared_client: str = "unknown",
                  declared_machine: str = "local-machine", intent: str = "",
                  thread_id: str | None = None, turn_id: str | None = None) -> dict[str, Any]:
        opened = self.turns.open_turn(
            machine_id=declared_machine,
            thread_id=thread_id or declared_agent,
            turn_id=turn_id or "turn-" + uuid.uuid4().hex,
            prompt_sha256=hashlib.sha256(intent.encode("utf-8")).hexdigest(),
        )
        receipt = opened["receipt"]
        self._index.execute(
            "INSERT OR IGNORE INTO turn_authors VALUES (?, ?, ?, ?)",
            (receipt["receipt_id"], declared_agent, declared_client, declared_machine),
        )
        return {
            "registration_id": receipt["receipt_id"],
            "turn_id": receipt["identity"]["turn_id"],
            "opened_at": receipt["opened_at"],
            "replayed": opened["replayed"],
            "terminal_required": True,
            "production_authority": False,
        }

    def _author(self, registration_id: str) -> dict[str, str]:
        row = self._index.execute(
            "SELECT declared_agent, declared_client, declared_machine FROM turn_authors WHERE registration_id = ?",
            (registration_id,),
        ).fetchone()
        if row is None or self.turns.find_registration(registration_id) is None:
            raise LocalMemoryError("unknown registration_id: open a turn first")
        return {"declared_agent": row[0], "declared_client": row[1], "declared_machine": row[2]}

    def _open_author(self, registration_id: str) -> dict[str, str]:
        author = self._author(registration_id)
        if self.turns.find_terminal(registration_id) is not None:
            raise LocalMemoryError("this turn is already closed; open a new turn to write again")
        return author

    def close_turn(self, *, registration_id: str, outcome: str | None = None,
                   no_event_reason: str | None = None) -> dict[str, Any]:
        self._author(registration_id)
        events = [
            {"event_uid": row[0], "event_id": row[1], "request_sha256": row[2]}
            for row in self._index.execute(
                "SELECT event_uid, event_id, request_sha256 FROM turn_events "
                "WHERE registration_id = ? ORDER BY event_id", (registration_id,))
        ]
        outcome = outcome or ("events" if events else "no-event")
        if outcome == "events":
            closed = self.turns.close_turn(registration_id=registration_id, outcome="events", events=events)
        else:
            if events:
                raise LocalMemoryError("this turn wrote events; it cannot be closed as no-event")
            closed = self.turns.close_turn(
                registration_id=registration_id, outcome="no-event",
                no_event_reason=no_event_reason or "no-durable-state-change")
        return {"receipt": closed["receipt"], "replayed": closed["replayed"], "production_authority": False}

    def observe_gap(self, *, registration_id: str) -> dict[str, Any]:
        """Record, signed, that a turn had no closing receipt when someone looked."""
        return self.turns.observe_gap(registration_id=registration_id, stage="reconciliation")

    def coverage(self, *, limit: int = 50) -> dict[str, Any]:
        report = self.turns.coverage(limit=limit)
        return {"counts": report["counts"], "unresolved": report["unresolved"], "production_authority": False}

    # -- events --------------------------------------------------------------

    def _event_by_uid(self, event_uid: str) -> dict[str, Any] | None:
        with open_catalog_readonly(self.catalog.path) as connection:
            row = connection.execute(
                "SELECT canonical_json FROM seed_events WHERE event_uid = ?", (event_uid,)).fetchone()
        return None if row is None else json.loads(row[0])

    def append_event(self, *, registration_id: str, kind: str, summary: str,
                     details: dict[str, Any] | None = None, tags: list[str] | None = None,
                     task: str | None = None, event_uid: str | None = None) -> dict[str, Any]:
        author = self._open_author(registration_id)
        if kind not in KINDS:
            raise LocalMemoryError("kind must be task, thought or concept")
        stored = dict(details or {})
        if MARKER in stored:
            raise LocalMemoryError(f"details may not contain the reserved key {MARKER}")
        if task is not None:
            stored["task_id"] = task
        uid = event_uid or "client:local-" + uuid.uuid4().hex
        request = {"registration_id": registration_id, "event_uid": uid, "kind": kind,
                   "summary": summary, "details": stored, "tags": list(tags or [])}
        request_sha256 = hashlib.sha256(canonical_bytes(request)).hexdigest()
        existing = self._event_by_uid(uid)
        if existing is not None:
            if existing["details"].get(MARKER, {}).get("request_sha256") != request_sha256:
                raise LocalMemoryError("event_uid already exists with different content")
            return {"event_uid": uid, "event_id": existing["id"], "request_sha256": request_sha256,
                    "ts_utc": existing["ts_utc"], "replayed": True}
        stored[MARKER] = {"profile": PROFILE, "registration_id": registration_id,
                          "request_sha256": request_sha256, **author}
        event = {"event_uid": uid, "ts_utc": _now(), "actor": author["declared_agent"],
                 "action": f"client_{kind}", "level": "info", "summary": summary,
                 "details": stored, "tags": list(tags or [])}
        for _ in range(8):
            event["id"] = self.catalog.event_cursor()[1] + 1
            try:
                self.catalog.import_events([event], source_namespace=SOURCE_NAMESPACE)
                break
            except SeedCatalogError as exc:
                # Another agent's server took this id between the read and the write.
                if "immutable Seed event conflict" not in str(exc):
                    raise
        else:
            raise LocalMemoryError("the catalog stayed busy; the event was not written")
        self._index.execute("INSERT INTO turn_events VALUES (?, ?, ?, ?)",
                            (uid, registration_id, event["id"], request_sha256))
        return {"event_uid": uid, "event_id": event["id"], "request_sha256": request_sha256,
                "ts_utc": event["ts_utc"], "replayed": False}

    def recall(self, *, query: str | None = None, task: str | None = None, limit: int = 20) -> dict[str, Any]:
        if (query is None) == (task is None):
            raise LocalMemoryError("give exactly one of query and task")
        if task is not None:
            ids = sorted(row["event_id"] for row in self.catalog.find_events(task_id=task, limit=limit))
        else:
            ids = [row["event_id"] for row in self.catalog.search(query, limit=limit)]
        return {"events": [self.catalog.event_at(event_id) for event_id in ids],
                "returned_count": len(ids), "production_authority": False}

    def receipt_by_event(self, *, event_uid: str) -> dict[str, Any]:
        """From an event alone: who declared it, under which turn, and how that turn ended."""
        event = self._event_by_uid(event_uid)
        if event is None:
            return {"outcome": "not_found", "event_uid": event_uid}
        marker = event["details"].get(MARKER, {})
        registration_id = marker.get("registration_id")
        result: dict[str, Any] = {"outcome": "found", "event": event, "production_authority": False}
        if not registration_id:
            result["turn"] = {"status": "none", "note": "this event was not written under a registered turn"}
            return result
        registration = self.turns.find_registration(registration_id)
        if registration is None:
            result["turn"] = {"status": "missing", "registration_id": registration_id,
                              "note": "the event names a turn registration that this store does not hold"}
            return result
        terminal = self.turns.find_terminal(registration_id)
        identity = registration["identity"]
        sample = self.turns.coverage(machine_id=identity["machine_id"], thread_id=identity["thread_id"],
                                     limit=500)["receipt_sample"]["receipts"]
        gap = next((item["gap_receipt"] for item in sample if item["registration_id"] == registration_id), None)
        result["author"] = {
            "declared_agent": marker.get("declared_agent"),
            "declared_client": marker.get("declared_client"),
            "declared_machine": marker.get("declared_machine"),
            "note": "declared by the writer; not verified",
        }
        result["turn"] = {
            "status": "closed" if terminal is not None else "open",
            "registration_id": registration_id,
            "identity": identity,
            "opened_at": registration["opened_at"],
            "registration_signature": "valid",
            "terminal_receipt": terminal,
            "terminal_signature": None if terminal is None else "valid",
            "event_listed_in_terminal_receipt": None if terminal is None else any(
                item["event_uid"] == event_uid for item in terminal.get("events", [])),
            "gap_receipt": gap,
            "note": ("closed with a signed receipt" if terminal is not None else
                     "no closing receipt: the writer never closed this turn"),
        }
        log = self._claim_events()
        own = {item["claim_id"] for item in log
               if item.get("reference", {}).get("registration_id") == registration_id}
        result["claims"] = [item for item in log if item["claim_id"] in own]
        return result

    # -- claims --------------------------------------------------------------

    def _claim_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        after = 0
        while True:
            page = self.claims.events(after=after, limit=1000)
            events.extend(page)
            if len(page) < 1000:
                return events
            after = page[-1]["event_seq"]

    def claim(self, *, registration_id: str, task: str | None = None, ttl_seconds: int = 900,
              claim_id: str | None = None) -> dict[str, Any]:
        author = self._open_author(registration_id)
        if (task is None) == (claim_id is None):
            raise LocalMemoryError("give task to claim it, or claim_id to ask again about a waiting claim")
        if claim_id is not None:
            decision = self.claims.poll(claim_id)
            if decision.agent_id != author["declared_agent"]:
                raise LocalMemoryError("this claim belongs to another agent")
            return self._decision(decision)
        registration = self.turns.find_registration(registration_id)
        decision = self.claims.claim(
            agent_id=author["declared_agent"],
            resources=[f"task:{task}"],
            ttl_seconds=ttl_seconds,
            reference={"registration_id": registration_id,
                       "turn_id": registration["identity"]["turn_id"],
                       "declared_client": author["declared_client"],
                       "declared_machine": author["declared_machine"]},
        )
        return self._decision(decision)

    @staticmethod
    def _decision(decision: Any) -> dict[str, Any]:
        return {"status": decision.status.value, "claim_id": decision.claim_id,
                "declared_agent": decision.agent_id, "resources": list(decision.resources),
                "fence_token": decision.fence_token, "expires_at": decision.expires_at,
                "blocked_by": list(decision.blocked_by), "reason": decision.reason,
                "signed": False, "production_authority": False}

    def release(self, *, registration_id: str, claim_id: str, fence_token: int,
                result_event_uid: str) -> dict[str, Any]:
        author = self._author(registration_id)
        event = self._event_by_uid(result_event_uid)
        if event is None or event["details"].get(MARKER, {}).get("registration_id") != registration_id:
            raise LocalMemoryError("result_event_uid must name an event written under this turn")
        receipt = self.claims.release(claim_id, agent_id=author["declared_agent"],
                                      fence_token=fence_token, outcome=result_event_uid)
        return {"release": receipt, "signed": False, "production_authority": False}

    def claim_log(self, *, task: str | None = None) -> dict[str, Any]:
        verified = self.claims.verify_events()
        events = self._claim_events()
        if task is not None:
            wanted = normalize_resource(f"task:{task}")
            events = [item for item in events if wanted in item.get("resources", [])]
        return {"events": events, "chain_events_verified": verified, "signed": False,
                "note": "agent names in claims are declared by the caller; the log is hash-chained, not signed",
                "production_authority": False}

    # -- self-check ----------------------------------------------------------

    def capabilities(self) -> dict[str, Any]:
        return {"profile": PROFILE, "server": SERVER_NAME, "version": __version__,
                "stores": ["seed catalog", "turn memory", "work claims"], "limits": list(LIMITS),
                "tools": [tool["name"] for tool in TOOLS], "production_authority": False}


def doctor_report(home: Path) -> dict[str, Any]:
    """Read-only check of one instance; creates nothing."""
    checks: list[dict[str, str]] = []

    def add(name: str, result: str, detail: str) -> None:
        checks.append({"check": name, "result": result, "detail": detail})

    version = ".".join(str(part) for part in sys.version_info[:3])
    add("package", "ok", f"integrity-guardian {__version__} on Python {version} ({sys.platform})")
    home = Path(home).absolute()
    if not (home / "instance.json").is_file():
        add("instance", "fail", f"{home}: no instance here; run: guardian-local-memory init")
        return {"profile": PROFILE, "passed": False, "checks": checks}
    try:
        memory = LocalMemory(home)
    except (LocalMemoryError, OSError, ValueError, KeyError, TurnMemoryError) as exc:
        add("instance", "fail", f"{home}: {exc}")
        return {"profile": PROFILE, "passed": False, "checks": checks}
    with closing(memory):
        add("instance", "ok", f"{home}: created {memory.instance['created_at']}")
        try:
            memory.catalog.verify()
            add("events", "ok", f"catalog verified, {memory.catalog.event_cursor()[0]} events")
        except SeedCatalogError as exc:
            add("events", "fail", f"catalog verification failed: {exc}")
        try:
            counts = memory.turns.coverage(limit=1)["counts"]
            detail = (f"{counts['registered']} turns: {counts['terminal']} closed, "
                      f"{counts['unresolved']} without a closing receipt; signatures valid")
            add("turns", "warn" if counts["unresolved"] else "ok", detail)
        except TurnMemoryError as exc:
            add("turns", "fail", f"turn store verification failed: {exc}")
        try:
            add("claims", "ok", f"hash chain verified, {memory.claims.verify_events()} claim events")
        except WorkClaimError as exc:
            add("claims", "fail", f"claim log verification failed: {exc}")
    add("scope", "ok", "local profile: " + "; ".join(LIMITS[:2]))
    failed = any(item["result"] == "fail" for item in checks)
    return {"profile": PROFILE, "passed": not failed, "checks": checks}


# --------------------------------------------------------------------------- MCP tools

def _tool(name: str, description: str, properties: dict[str, Any], required: list[str],
          read_only: bool) -> dict[str, Any]:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "properties": properties, "required": required},
            "annotations": {"readOnlyHint": read_only, "destructiveHint": False}}


_REG = {"type": "string", "pattern": _DIGEST, "description": "registration_id from integrity_turn_memory_open"}
_UID = {"type": "string", "pattern": _EVENT_UID}
_TASK_FIELD = {"type": "string", "pattern": _TASK, "description": "short task name, for example demo-task"}
_NAME_FIELD = {"type": "string", "pattern": _NAME}

TOOLS: list[dict[str, Any]] = [
    _tool("integrity_memory_capabilities",
          "What this local memory is and what it does not prove. Read this once.", {}, [], True),
    _tool("integrity_turn_memory_open",
          "Start a turn before you write. Returns a signed registration_id. The names you give are "
          "recorded as declared, not verified.",
          {"declared_agent": {**_NAME_FIELD, "description": "your name in this work, for example agent-a"},
           "declared_client": {**_NAME_FIELD, "description": "the program you run in, for example claude-code"},
           "declared_machine": _NAME_FIELD,
           "intent": {"type": "string", "maxLength": 4000, "description": "what you were asked; only its hash is kept"},
           "thread_id": _NAME_FIELD, "turn_id": _NAME_FIELD},
          ["declared_agent"], False),
    _tool("integrity_work_claim",
          "Claim a task for your open turn. Status acquired means you hold it; waiting means another "
          "agent holds it and blocked_by names that claim. To ask again about a waiting claim, give "
          "claim_id instead of task.",
          {"registration_id": _REG, "task": _TASK_FIELD,
           "claim_id": {"type": "string", "minLength": 1, "maxLength": 128},
           "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 86400}},
          ["registration_id"], False),
    _tool("integrity_append_event",
          "Write one event under your open turn. Put the task name in task so others can find it.",
          {"registration_id": _REG, "kind": {"enum": list(KINDS)},
           "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
           "details": {"type": "object"}, "task": _TASK_FIELD, "event_uid": _UID,
           "tags": {"type": "array", "maxItems": 20, "items": {"type": "string", "maxLength": 64}}},
          ["registration_id", "kind", "summary"], False),
    _tool("integrity_work_release",
          "Release your claim and name the event that is its result.",
          {"registration_id": _REG, "claim_id": {"type": "string", "minLength": 1, "maxLength": 128},
           "fence_token": {"type": "integer", "minimum": 1}, "result_event_uid": _UID},
          ["registration_id", "claim_id", "fence_token", "result_event_uid"], False),
    _tool("integrity_turn_memory_close",
          "End your turn. Returns a signed receipt that lists the events this turn wrote, or says it "
          "wrote none.",
          {"registration_id": _REG, "outcome": {"enum": ["events", "no-event"]},
           "no_event_reason": {"enum": ["no-durable-state-change", "read-only", "repetition",
                                        "social-response", "user-cancelled"]}},
          ["registration_id"], False),
    _tool("integrity_seed_recall",
          "Read events: all events of one task in the order they were written, or a text search. "
          "Give exactly one of task and query.",
          {"task": _TASK_FIELD, "query": {"type": "string", "minLength": 1, "maxLength": 400},
           "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, [], True),
    _tool("integrity_turn_receipt_by_event",
          "From one event_uid: the event as written, who declared it, the signed turn it belongs to, "
          "how that turn ended (signed receipt, recorded gap, or never closed) and the claims of that turn.",
          {"event_uid": _UID}, ["event_uid"], True),
    _tool("integrity_work_claims",
          "The claim log, optionally for one task: who claimed, who waited, who released with which "
          "result. The hash chain is verified on every call.",
          {"task": _TASK_FIELD}, [], True),
    _tool("integrity_turn_memory_coverage",
          "How many turns were opened, closed, and left without a closing receipt.",
          {"limit": {"type": "integer", "minimum": 1, "maximum": 500}}, [], True),
    _tool("integrity_turn_memory_gap",
          "Record, signed, that a turn had no closing receipt when you looked. It does not close the turn.",
          {"registration_id": _REG}, ["registration_id"], False),
]
_VALIDATORS = {tool["name"]: Draft202012Validator(tool["inputSchema"]) for tool in TOOLS}

INSTRUCTIONS = (
    "Integrity local memory. Order of work: integrity_turn_memory_open, then integrity_work_claim "
    "for the task, integrity_append_event for each result, integrity_work_release, and "
    "integrity_turn_memory_close last. To continue someone else's work, read with "
    "integrity_seed_recall and integrity_turn_receipt_by_event before you write. "
    "Names are declared, not verified; nothing here grants authority to act."
)


def call_tool(memory: LocalMemory, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    handlers = {
        "integrity_memory_capabilities": lambda: memory.capabilities(),
        "integrity_turn_memory_open": lambda: memory.open_turn(**arguments),
        "integrity_work_claim": lambda: memory.claim(**arguments),
        "integrity_append_event": lambda: memory.append_event(**arguments),
        "integrity_work_release": lambda: memory.release(**arguments),
        "integrity_turn_memory_close": lambda: memory.close_turn(**arguments),
        "integrity_seed_recall": lambda: memory.recall(**arguments),
        "integrity_turn_receipt_by_event": lambda: memory.receipt_by_event(**arguments),
        "integrity_work_claims": lambda: memory.claim_log(**arguments),
        "integrity_turn_memory_coverage": lambda: memory.coverage(**arguments),
        "integrity_turn_memory_gap": lambda: memory.observe_gap(**arguments),
    }
    if name not in handlers:
        raise LocalMemoryError(f"unknown tool: {name[:120]}")
    try:
        _VALIDATORS[name].validate(arguments)
    except ValidationError as exc:
        raise LocalMemoryError(f"invalid arguments: {exc.message[:300]}") from exc
    return handlers[name]()


def dispatch(memory: LocalMemory, message: dict[str, Any]) -> dict[str, Any] | None:
    """One JSON-RPC message of the MCP stdio transport."""
    request_id = message.get("id")
    method = message.get("method")

    def error(code: int, text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": text}}

    if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return error(-32600, "invalid request")
    if "id" not in message or method.startswith("notifications/"):
        return None
    params = message.get("params", {})
    if not isinstance(params, dict):
        return error(-32602, "params must be an object")
    if method == "initialize":
        requested = params.get("protocolVersion")
        result: dict[str, Any] = {
            "protocolVersion": requested if requested in SUPPORTED_MCP_VERSIONS else DEFAULT_MCP_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
            "instructions": INSTRUCTIONS,
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name, arguments = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return error(-32602, "invalid tool call")
        try:
            value, failed = call_tool(memory, name, arguments), False
        except (LocalMemoryError, SeedCatalogError, TurnMemoryError, WorkClaimError) as exc:
            value, failed = {"error": str(exc), "production_authority": False}, True
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        result = {"content": [{"type": "text", "text": text}], "isError": failed}
    else:
        return error(-32601, "method not found")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(memory: LocalMemory, *, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    source, sink = stdin or sys.stdin.buffer, stdout or sys.stdout.buffer
    while True:
        raw = source.readline(MAX_FRAME_BYTES + 1)
        if not raw:
            return 0
        if len(raw) > MAX_FRAME_BYTES:
            while raw and not raw.endswith(b"\n"):
                raw = source.readline(MAX_FRAME_BYTES + 1)
            response: dict[str, Any] | None = {"jsonrpc": "2.0", "id": None,
                                               "error": {"code": -32700, "message": "frame too large"}}
        else:
            try:
                message = json.loads(raw)
            except ValueError:
                message = None
            response = (dispatch(memory, message) if isinstance(message, dict) else
                        {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
        if response is not None:
            sink.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            sink.flush()


# --------------------------------------------------------------------------- command line

def client_config(client: str, home: Path) -> str:
    """The MCP block for one agent client; the command is this Python, the path is this home."""
    # Keep a virtualenv symlink: resolving it would select the base interpreter without the package.
    entry = {"command": str(Path(sys.executable).absolute()),
             "args": ["-m", "integrity_guardian.local_memory", "serve", "--home", str(Path(home).absolute())]}
    if client == "codex":
        return ("[mcp_servers.integrity_local_memory]\ncommand = " + json.dumps(entry["command"])
                + "\nargs = " + json.dumps(entry["args"]) + "\nstartup_timeout_sec = 30\ntool_timeout_sec = 60\n")
    if client in ("claude-code", "antigravity"):
        return json.dumps({"mcpServers": {"integrity_local_memory": entry}}, indent=2) + "\n"
    raise LocalMemoryError(f"no configuration block for {client!r}; known: {', '.join(CLIENTS)}")


def _print_report(report: dict[str, Any], as_json: bool) -> int:
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for item in report["checks"]:
            print(f"[{item['result']:<4}] {item['check']}: {item['detail']}")
        print("doctor: " + ("PASS" if report["passed"] else "FAIL"))
    return 0 if report["passed"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian-local-memory", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def command(name: str, text: str) -> argparse.ArgumentParser:
        item = sub.add_parser(name, help=text)
        item.add_argument("--home", type=Path, default=None,
                          help=f"instance folder (default: ${ENV_HOME} or the per-user data folder)")
        return item

    item = command("init", "create the instance and print the MCP block for your agent client")
    item.add_argument("--client", choices=CLIENTS, help="print the configuration block for this client")
    item = command("config", "print the MCP block for one agent client")
    item.add_argument("--client", choices=CLIENTS, required=True)
    command("serve", "run the MCP server on stdio (your agent client starts this)")
    item = command("doctor", "read-only check of the instance (exit 1 when a check fails)")
    item.add_argument("--json", action="store_true")
    item = command("uninstall", "remove the instance folder with all its memory (dry run without --yes)")
    item.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    home = (args.home or default_home()).absolute()
    try:
        if args.cmd == "init":
            LocalMemory.create(home).close()
            print(f"Created a local memory instance in {home}")
            if args.client:
                print(f"\nMCP block for {args.client}:\n\n{client_config(args.client, home)}")
            else:
                print("Next: guardian-local-memory config --client " + "|".join(CLIENTS))
            return 0
        if args.cmd == "config":
            print(client_config(args.client, home), end="")
            return 0
        if args.cmd == "doctor":
            return _print_report(doctor_report(home), args.json)
        if args.cmd == "uninstall":
            if not (home / "instance.json").is_file():
                print(f"No local memory instance in {home}. To remove the program: "
                      "python -m pip uninstall integrity-guardian")
                return 0
            if json.loads((home / "instance.json").read_text(encoding="utf-8")).get("profile") != PROFILE:
                raise LocalMemoryError(f"{home} is not a local memory instance; nothing was removed")
            if not args.yes:
                print(f"Dry run. --yes removes {home} with every event, receipt and claim in it.")
                return 0
            shutil.rmtree(home)
            print(f"Removed {home}. To remove the program: python -m pip uninstall integrity-guardian")
            return 0
        memory = LocalMemory(home)
        with closing(memory):
            return serve(memory)
    except (LocalMemoryError, SeedCatalogError, TurnMemoryError, WorkClaimError, OSError) as exc:
        print(f"guardian-local-memory: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
