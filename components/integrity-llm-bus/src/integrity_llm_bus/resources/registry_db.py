# SPDX-License-Identifier: BUSL-1.1
"""Agent registry stored in bus.sqlite3 (r2). agents-registry.json becomes a generated read-only export.

The export is kept because other code reads the JSON path (Integrity LTS hook REGISTRY_PATH).
Tables: agents (one row per address; thread UNIQUE), registry_meta (aliases, version, migration info).
Core fields (thread, harness, topic, registered_*, session_id, ...) live in core_json and are written by
agent_registry; autoreg-owned fields live in columns and are never overwritten by agent_registry.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
import os
from pathlib import Path
import shutil
import sqlite3
import time
import uuid

EXTRA = ("auto", "wake", "vendor", "model", "source", "first_seen", "last_seen")
SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  address TEXT PRIMARY KEY, thread TEXT NOT NULL UNIQUE, harness TEXT NOT NULL, core_json TEXT NOT NULL,
  auto INTEGER, wake INTEGER, vendor TEXT, model TEXT, source TEXT, first_seen INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS registry_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def db_path(state_dir: Path) -> Path:
    return Path(state_dir) / "bus.sqlite3"


def json_path(state_dir: Path) -> Path:
    return Path(state_dir) / "agents-registry.json"


def connect(state_dir: Path, *, readonly: bool = False, timeout_ms: int = 250) -> sqlite3.Connection:
    path = db_path(state_dir)
    if readonly:
        con = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=timeout_ms / 1000,
                              isolation_level=None)
    else:
        con = sqlite3.connect(path, timeout=timeout_ms / 1000, isolation_level=None)
    con.execute(f"PRAGMA busy_timeout = {int(timeout_ms)}")
    con.row_factory = sqlite3.Row
    return con


def migrated(state_dir: Path) -> bool:
    if not db_path(state_dir).exists():
        return False
    try:
        con = connect(state_dir, readonly=True, timeout_ms=200)
        try:
            row = con.execute("SELECT value FROM registry_meta WHERE key='migrated'").fetchone()
            return row is not None
        finally:
            con.close()
    except sqlite3.Error:
        return False


def _entry(row) -> dict:
    entry = json.loads(row["core_json"])
    for key in EXTRA:
        value = row[key]
        if value is not None:
            entry[key] = bool(value) if key in ("auto", "wake") else value
    return entry


def load_doc(state_dir: Path, con: sqlite3.Connection | None = None) -> dict:
    own = con is None
    con = con or connect(state_dir, readonly=True)
    try:
        agents = {r["address"]: _entry(r) for r in con.execute("SELECT * FROM agents ORDER BY address")}
        meta = {r["key"]: r["value"] for r in con.execute("SELECT key, value FROM registry_meta")}
    finally:
        if own:
            con.close()
    doc = {"version": 2, "agents": agents}
    aliases = json.loads(meta.get("aliases", "{}"))
    if aliases:
        doc["aliases"] = aliases
    return doc


def _core(entry: dict) -> str:
    return json.dumps({k: v for k, v in entry.items() if k not in EXTRA}, ensure_ascii=False, sort_keys=True)


def _insert(con, address: str, entry: dict, *, replace_core: bool) -> None:
    extras = [entry.get(k) for k in EXTRA]
    extras = [int(v) if isinstance(v, bool) else v for v in extras]
    sql = ("INSERT INTO agents (address, thread, harness, core_json, %s) VALUES (?,?,?,?,%s) " % (
        ",".join(EXTRA), ",".join("?" * len(EXTRA))))
    sql += ("ON CONFLICT(address) DO UPDATE SET thread=excluded.thread, harness=excluded.harness, core_json=excluded.core_json"
            if replace_core else "ON CONFLICT(address) DO NOTHING")
    con.execute(sql, (address, entry["thread"], entry.get("harness", "codex"), _core(entry), *extras))


def generation(con: sqlite3.Connection) -> int:
    row = con.execute("SELECT value FROM registry_meta WHERE key='generation'").fetchone()
    return int(row["value"] if isinstance(row, sqlite3.Row) else row[0]) if row else 0


def bump_generation(con: sqlite3.Connection) -> int:
    """r3: call inside the same BEGIN IMMEDIATE transaction as every registry mutation."""
    gen = generation(con) + 1
    con.execute("INSERT OR REPLACE INTO registry_meta VALUES ('generation', ?)", (str(gen),))
    return gen


def upsert_doc(state_dir: Path, data: dict) -> None:
    """agent_registry writes: upsert core fields only; never deletes rows, never touches autoreg columns."""
    con = connect(state_dir)
    try:
        con.execute("BEGIN IMMEDIATE")
        for address, entry in data["agents"].items():
            _insert(con, address, entry, replace_core=True)
        con.execute("INSERT OR REPLACE INTO registry_meta VALUES ('aliases', ?)",
                    (json.dumps(data.get("aliases", {}), sort_keys=True),))
        bump_generation(con)
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()
    export_json(state_dir)


def _publish(path: Path, doc: dict) -> None:
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".prev"))
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with tmp.open("x", encoding="utf-8") as stream:
        json.dump(doc, stream, ensure_ascii=False, indent=1)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, path)


def export_json(state_dir: Path, timeout_ms: int = 2000) -> dict:
    """Generated read-only copy for legacy readers (atomic, previous kept as .prev).

    r3: snapshot, generation check and os.replace all happen inside one BEGIN IMMEDIATE, i.e.
    serialized with every registry mutation. A file is published only if its generation is newer
    than the last published one, so a stale snapshot can never overwrite a newer export.
    After unmigrate (tables gone) this is a no-op: the JSON file is authoritative again.
    """
    import bus_remote  # hub mode: on a replica bus_remote exports (it alone may write the replica)
    if bus_remote.active(state_dir):
        return bus_remote.export_registry(state_dir)
    path = json_path(state_dir)
    con = connect(state_dir, timeout_ms=timeout_ms)
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            gen = generation(con)
            row = con.execute("SELECT value FROM registry_meta WHERE key='exported_generation'").fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):
                return {"published": False, "reason": "not-migrated"}
            raise
        exported = int(row["value"]) if row else -1
        if exported >= gen and path.exists():
            return {"published": False, "reason": "up-to-date", "generation": gen}
        _publish(path, load_doc(state_dir, con))
        con.execute("INSERT OR REPLACE INTO registry_meta VALUES ('exported_generation', ?)", (str(gen),))
        con.execute("COMMIT")
        return {"published": True, "generation": gen}
    finally:
        if con.in_transaction:
            con.execute("ROLLBACK")
        con.close()


def backup_db(state_dir: Path, tag: str) -> Path:
    target = Path(state_dir) / f"bus.sqlite3.{tag}-{time.strftime('%Y%m%dT%H%M%S')}"
    src = sqlite3.connect(db_path(state_dir)); dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    return target


def migrate(state_dir: Path, backup: bool = True) -> dict:
    """Idempotent: imports every JSON entry not yet in the table (address, thread, wake unchanged)."""
    state_dir = Path(state_dir)
    path = json_path(state_dir)
    src = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"version": 2, "agents": {}}
    if not isinstance(src.get("agents"), dict):
        raise ValueError("invalid registry JSON")
    first = not migrated(state_dir)
    saved = str(backup_db(state_dir, "pre-registry")) if (backup and first) else None
    con = connect(state_dir, timeout_ms=2000)
    imported = 0
    try:
        con.execute("BEGIN IMMEDIATE")
        for stmt in SCHEMA.strip().split(";"):
            if stmt.strip():
                con.execute(stmt)
        for address, entry in src["agents"].items():
            before = con.total_changes
            _insert(con, address, entry, replace_core=False)
            imported += con.total_changes - before
        if first:
            con.execute("INSERT OR REPLACE INTO registry_meta VALUES ('aliases', ?)",
                        (json.dumps(src.get("aliases", {}), sort_keys=True),))
            con.execute("INSERT OR REPLACE INTO registry_meta VALUES ('migrated', ?)",
                        (json.dumps({"ts": int(time.time()), "entries": len(src["agents"])}),))
        bump_generation(con)
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()
    export_json(state_dir)
    return {"first": first, "imported": imported, "entries": len(load_doc(state_dir)["agents"]), "db_backup": saved}


def unmigrate(state_dir: Path, timeout_ms: int = 5000) -> dict:
    """Rollback in ONE BEGIN IMMEDIATE: re-read the DB registry under the write lock, publish it to JSON,
    drop the tables, commit. Every registration committed before the lock is in the JSON; a writer that
    queued behind the lock fails (no such table) instead of committing into tables that are dropped.
    If publishing fails the transaction rolls back and the DB registry stays authoritative."""
    if not migrated(state_dir):
        return {"unmigrated": False}
    con = connect(state_dir, timeout_ms=timeout_ms)
    try:
        con.execute("BEGIN IMMEDIATE")
        doc = load_doc(state_dir, con)
        _publish(json_path(state_dir), doc)
        con.execute("DROP TABLE agents"); con.execute("DROP TABLE registry_meta")
        con.execute("COMMIT")
    finally:
        if con.in_transaction:
            con.execute("ROLLBACK")
        con.close()
    return {"unmigrated": True, "entries": len(doc["agents"])}

if __name__ == "__main__":
    _integrity_require_config()
