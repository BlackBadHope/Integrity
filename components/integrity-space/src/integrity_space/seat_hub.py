"""Seat-scoped hub tools. Identity comes from SeatContext, never from tool arguments.

search and fetch stay on their existing handlers. These tools are additive.
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
PROFILES = {
    "web-seat": {"roles": ("read", "write"), "namespaces": ("team/*", "seat/<id>/*")},
    "workstation-agent": {"roles": ("read", "write"), "namespaces": ("team/*", "seat/<id>/*")},
    "core-operator": {
        "roles": ("read", "write", "go_approver", "admin"),
        "namespaces": ("team/*", "seat/<id>/*"),
    },
}
ALLOWED_UPSTREAMS = {
    "example-memory": "https://example.invalid/integrity-seats",
}
SEAT_TOOL_NAMES = ("seat_whoami", "seat_append_note", "mesh_status", "bus_post_message")


class SeatHubError(PermissionError):
    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def tool_definitions() -> list[dict]:
    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    ident = {"type": "string", "pattern": r"^[A-Za-z0-9._:-]{1,128}$"}
    return [
        {"name": "seat_whoami", "description": "Return the server-derived seat. Ignores any seat id in arguments.",
         "inputSchema": empty, "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}},
        {"name": "seat_append_note", "description": "Append a note when the seat has write. The note is untrusted data.",
         "inputSchema": {"type": "object", "properties": {"note": {"type": "string", "minLength": 1, "maxLength": 4000}},
                          "required": ["note"], "additionalProperties": False},
         "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
        {"name": "mesh_status", "description": "Read mesh status visible to this seat.",
         "inputSchema": {"type": "object", "properties": {"work_id": ident}, "required": ["work_id"], "additionalProperties": False},
         "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}},
        {"name": "bus_post_message", "description": "Post a bus pointer for a seat with write. Does not accept a URL.",
         "inputSchema": {"type": "object", "properties": {"upstream_id": ident, "body": {"type": "string", "minLength": 1, "maxLength": 4000}},
                          "required": ["upstream_id", "body"], "additionalProperties": False},
         "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}},
    ]


def resolve_upstream(upstream_id: str) -> str:
    if not isinstance(upstream_id, str) or ID_RE.fullmatch(upstream_id) is None or "://" in upstream_id:
        raise SeatHubError("upstream id invalid", 400)
    if upstream_id not in ALLOWED_UPSTREAMS:
        raise SeatHubError("upstream not allowlisted", 403)
    return ALLOWED_UPSTREAMS[upstream_id]


def wrap_peer_memory(record: dict, reader_seat: str) -> dict:
    wrapped = dict(record)
    if wrapped.get("seat_id") != reader_seat:
        wrapped["trust"] = "untrusted_peer_memory"
    return wrapped


def _reject_identity_arguments(arguments: dict) -> None:
    if not isinstance(arguments, dict):
        raise SeatHubError("arguments invalid", 400)
    if any(key in arguments for key in ("seat_id", "host_id", "roles", "url", "upstream_url")):
        raise SeatHubError("identity is server-derived", 403)


def _require(context, role: str) -> None:
    if context is None:
        raise SeatHubError("seat required", 401)
    roles = set(getattr(context, "roles", ()) or ())
    if role not in roles and "admin" not in roles:
        raise SeatHubError(role + " forbidden", 403)


def namespace_visible(patterns, namespace: str) -> bool:
    if not isinstance(namespace, str) or not namespace or len(namespace) > 128:
        return False
    parts = namespace.split("/")
    if any(not part or part == "*" for part in parts):
        return False
    for pattern in patterns:
        pattern_parts = str(pattern).split("/")
        if len(pattern_parts) != len(parts):
            continue
        if all(pat == "*" or pat == part for pat, part in zip(pattern_parts, parts)):
            return True
    return False


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SeatNoteStore:
    """Append-only notes for one seat namespace. stored=true is returned after the row is readable."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS seat_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seat_id TEXT NOT NULL,
                namespace TEXT NOT NULL,
                note TEXT NOT NULL,
                created_utc TEXT NOT NULL
            )
            """
        )
        if os.name == "posix":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def close(self) -> None:
        self._db.close()

    def append(self, context, note: str) -> dict:
        namespace = f"seat/{context.seat_id}/notes"
        created = _utc_now()
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO seat_notes (seat_id, namespace, note, created_utc) VALUES (?, ?, ?, ?)",
                (context.seat_id, namespace, note, created),
            )
            note_id = int(cursor.lastrowid)
            row = self._db.execute(
                "SELECT note FROM seat_notes WHERE id = ? AND seat_id = ? AND namespace = ?",
                (note_id, context.seat_id, namespace),
            ).fetchone()
        if row is None or row[0] != note:
            raise SeatHubError("note not stored", 500)
        return {
            "ok": True,
            "seat_id": context.seat_id,
            "namespace": namespace,
            "stored": True,
            "id": note_id,
        }

    def read(self, context) -> list[dict]:
        namespace = f"seat/{context.seat_id}/notes"
        with self._lock:
            rows = self._db.execute(
                """
                SELECT id, seat_id, namespace, note, created_utc
                  FROM seat_notes
                 WHERE seat_id = ? AND namespace = ?
                 ORDER BY id
                """,
                (context.seat_id, namespace),
            ).fetchall()
        return [
            {"id": row[0], "seat_id": row[1], "namespace": row[2], "note": row[3], "created_utc": row[4]}
            for row in rows
        ]


def _authorize(router, context, namespace: str, action: str) -> None:
    if router is None:
        return
    try:
        router.authorize(context, namespace, action)
    except PermissionError as exc:
        raise SeatHubError(getattr(exc, "code", "namespace forbidden"), getattr(exc, "status", 403)) from exc


def _mesh_state(work_id: str, context, mesh, mesh_status: dict | None) -> dict:
    if mesh_status is None:
        if mesh is None or not hasattr(mesh, "status"):
            raise SeatHubError("mesh unavailable", 503)
        try:
            mesh_status = mesh.status(work_id)
        except (ValueError, sqlite3.Error) as exc:
            code = getattr(exc, "code", None) or "mesh unavailable"
            status = 404 if code == "work unknown" else 409
            raise SeatHubError(str(code), status) from exc
    if not isinstance(mesh_status, dict):
        raise SeatHubError("mesh state unavailable", 503)
    status = dict(mesh_status)
    if status.get("work_id") not in (None, work_id):
        raise SeatHubError("work id invalid", 400)
    state = status.get("state")
    if not isinstance(state, str) or not state or state == "unknown":
        raise SeatHubError("mesh state unavailable", 503)
    status["work_id"] = work_id
    namespace = status.get("namespace")
    patterns = tuple(getattr(context, "namespaces", ()) or ())
    if isinstance(namespace, str) and not namespace_visible(patterns, namespace):
        raise SeatHubError("namespace forbidden", 403)
    return status


def _forward_bus(context, upstream_id: str, upstream: str, body: str, bus) -> dict:
    if bus is None or not hasattr(bus, "post"):
        raise SeatHubError("bus unavailable", 503)
    message = {
        "id": "hub-" + secrets.token_hex(8),
        "to": upstream_id,
        "k": "note",
        "th": "hub",
        "delivery": "steer",
        "body": body,
        "body_sha256": sha256(body.encode("utf-8")).hexdigest(),
    }
    try:
        stored = bus.post(context, message)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str) or not code:
            raise
        status = getattr(exc, "status", 400)
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 400
        raise SeatHubError(code, status) from exc
    if not isinstance(stored, dict):
        raise SeatHubError("bus payload missing", 502)
    payload = {
        "id": stored.get("id", message["id"]),
        "from": stored.get("from", context.seat_id),
        "to": stored.get("to", upstream_id),
        "reply_to": stored.get("reply_to"),
        "delivery": stored.get("delivery") or "steer",
        "body": stored.get("body", body),
        "body_sha256": stored.get("body_sha256", message["body_sha256"]),
    }
    if not isinstance(payload["body"], str) or payload["body"] != body:
        raise SeatHubError("bus payload missing", 502)
    return {
        "ok": True,
        "seat_id": context.seat_id,
        "upstream": upstream,
        "delivered": bool(stored.get("delivered", False)),
        "delivery": payload["delivery"],
        "payload": payload,
    }


def dispatch_seat_tool(
    name: str,
    arguments: dict,
    context,
    *,
    notes: SeatNoteStore | None = None,
    mesh=None,
    mesh_status: dict | None = None,
    bus=None,
    router=None,
) -> dict:
    _reject_identity_arguments(arguments or {})
    if name == "seat_whoami":
        if context is None:
            raise SeatHubError("seat required", 401)
        return {
            "seat_id": context.seat_id,
            "host_id": context.host_id,
            "roles": sorted(context.roles),
            "namespaces": list(context.namespaces),
        }
    if name == "seat_append_note":
        _require(context, "write")
        note = (arguments or {}).get("note")
        if not isinstance(note, str) or not note.strip() or len(note) > 4000:
            raise SeatHubError("note invalid", 400)
        namespace = f"seat/{context.seat_id}/notes"
        if not namespace_visible(getattr(context, "namespaces", ()) or (), namespace):
            raise SeatHubError("namespace forbidden", 403)
        _authorize(router, context, namespace, "write")
        if notes is None:
            raise SeatHubError("note store unavailable", 503)
        return notes.append(context, note)
    if name == "mesh_status":
        if context is None:
            raise SeatHubError("seat required", 401)
        work_id = (arguments or {}).get("work_id")
        if not isinstance(work_id, str) or ID_RE.fullmatch(work_id) is None:
            raise SeatHubError("work id invalid", 400)
        status = _mesh_state(work_id, context, mesh, mesh_status)
        if isinstance(status.get("namespace"), str):
            _authorize(router, context, status["namespace"], "read")
        return wrap_peer_memory(status, context.seat_id)
    if name == "bus_post_message":
        _require(context, "write")
        body = (arguments or {}).get("body")
        if not isinstance(body, str) or not body.strip() or len(body) > 4000:
            raise SeatHubError("body invalid", 400)
        upstream_id = (arguments or {}).get("upstream_id")
        upstream = resolve_upstream(upstream_id)
        return _forward_bus(context, upstream_id, upstream, body, bus)
    raise SeatHubError("unknown seat tool", 404)
