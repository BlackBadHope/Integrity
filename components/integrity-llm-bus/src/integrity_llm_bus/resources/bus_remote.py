# SPDX-License-Identifier: BUSL-1.1
"""bus_remote - client of a bus hosted on a hub. Enabled by state/CORE.json; without it the local bus works as before.

After the switch:
  * the local state/bus.sqlite3 is a REPLICA of the hub bus. Reading it works as before (client SELECTs need no change).
  * Only this module may write to it, when it applies hub changes. The replica carries guard triggers: any
    other write (an unmigrated client, old code) fails with
    "no such function: bus_moved_to_core__use_bus_remote". A silent write to a second mailbox is impossible.
  * Writes go to the hub: send / ack / registry through the gateway SSH account (forced command, hub key of this client).
    The reply carries the changes after the replica cursor; they are applied at once (own writes are visible immediately).
  * Other writers' changes are caught up by bus_replica_sync.py (watch stream + changes operation).
No secrets here: the key path comes from CORE.json and ssh reads the key itself.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

GUARD_FN = "bus_moved_to_core__use_bus_remote"
REPL_TABLES = ("messages", "agents", "registry_meta", "owner_nonces", "mesh_edges", "mesh_meta", "mesh_msgs",
               "mesh_presence", "mesh_rejects", "mesh_resources", "mesh_work")
GIT_SSH = r"C:\Program Files\Git\usr\bin\ssh.exe"


class BusRemoteError(RuntimeError):
    pass


def active(state_dir) -> bool:
    return (Path(state_dir) / "CORE.json").is_file()


def conf(state_dir) -> dict:
    return json.loads((Path(state_dir) / "CORE.json").read_text(encoding="utf-8"))


def ssh_env(ssh: str) -> dict:
    """The profile's ProxyCommand calls plain "ssh": a watchdog process may have a reduced PATH or one leading to the
    Windows OpenSSH. Put the directory of the selected ssh first so both hops use the same client."""
    env = os.environ.copy()
    d = os.path.dirname(ssh)
    if d:
        env["PATH"] = d + os.pathsep + env.get("PATH", "")
    return env


def ssh_bin(c: dict) -> str:
    return c.get("ssh") or (GIT_SSH if os.name == "nt" and os.path.exists(GIT_SSH) else "ssh")


def call(state_dir, op: str, args: dict, key: str = "hub", timeout: int | None = None) -> dict:
    """One request to the hub bus. op is a protocol word (not a shell command), args is JSON on stdin."""
    c = conf(state_dir)
    ssh = ssh_bin(c)
    argv = [ssh, *c.get("ssh_args", []), "-o", "BatchMode=yes", "-o", f"ConnectTimeout={c.get('connect_timeout', 8)}",
            "-o", "IdentitiesOnly=yes", "-i", c["keys"][key], c["dest"], op]
    try:
        p = subprocess.run(argv, input=json.dumps(args, ensure_ascii=False).encode("utf-8"), capture_output=True,
                           timeout=timeout or c.get("timeout", 60), env=ssh_env(ssh),
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise BusRemoteError(f"bus core timeout ({op})") from exc
    try:
        doc = json.loads(p.stdout.decode("utf-8").strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise BusRemoteError(f"bus core unreachable ({op}): rc={p.returncode} {p.stderr.decode('utf-8', 'replace')[-200:]}") from exc
    if not doc.get("ok"):
        raise BusRemoteError(doc.get("error", "bus core error"))
    return doc["result"]


# ---------- replica ----------

def _connect(path: Path, writer: bool) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 10000")
    if writer:
        db.create_function(GUARD_FN, 0, lambda: 1)
    return db


def install_guard(path: Path) -> None:
    """Turn the local database into a replica: cursor + guards on every replicated table. Idempotent."""
    db = _connect(path, writer=True)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS _repl_state(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        have = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for t in REPL_TABLES:
            if t in have:
                for ev in ("INSERT", "UPDATE", "DELETE"):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS _guard_{t}_{ev.lower()} BEFORE {ev} ON {t} "
                               f"BEGIN SELECT {GUARD_FN}(); END")
        db.commit()
    finally:
        db.close()


def snapshot_and_guard(path: Path, out: Path) -> dict:
    """Switch without a loss window: under one write lock (BEGIN IMMEDIATE) take the snapshot for the hub,
    then install guards and cursor 0 and release the lock. Anything written later fails on a guard."""
    if out.exists():
        raise FileExistsError(f"{out} exists")
    db = _connect(path, writer=True)
    try:
        db.execute("BEGIN IMMEDIATE")   # hold the write lock: other writers wait or time out
        # snapshot through a SECOND, read-only connection: SQLite refuses backup from a connection holding a write (LOCKED)
        rd = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=10)
        dst = sqlite3.connect(out)
        rd.backup(dst)
        dst.close(); rd.close()
        db.execute("CREATE TABLE IF NOT EXISTS _repl_state(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        have = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        n = 0
        for t in REPL_TABLES:
            if t in have:
                for ev in ("INSERT", "UPDATE", "DELETE"):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS _guard_{t}_{ev.lower()} BEFORE {ev} ON {t} "
                               f"BEGIN SELECT {GUARD_FN}(); END")
                    n += 1
        db.execute("INSERT OR REPLACE INTO _repl_state VALUES ('cursor', '0')")
        db.execute("INSERT OR REPLACE INTO _repl_state VALUES ('moved_at', ?)", (str(int(time.time())),))
        counts = {t: db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ("messages", "agents") if t in have}
        db.execute("COMMIT")
        return {"snapshot": str(out), "guards": n, **counts}
    finally:
        if db.in_transaction:
            db.execute("ROLLBACK")
        db.close()


def remove_guard(path: Path) -> None:
    db = _connect(path, writer=True)
    try:
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '\\_guard\\_%' ESCAPE '\\'").fetchall():
            db.execute(f"DROP TRIGGER {name}")
        db.commit()
    finally:
        db.close()


def cursor(path: Path) -> int:
    db = sqlite3.connect(path, timeout=10)
    try:
        r = db.execute("SELECT v FROM _repl_state WHERE k='cursor'").fetchone()
        return int(r[0]) if r else 0
    finally:
        db.close()


def apply(path: Path, chunk: dict | None) -> int:
    """Apply hub changes. Changes with v <= the current cursor are skipped (another process already applied them,
    and the latest version of each row always has the larger v), so concurrent applies are safe."""
    if not chunk:
        return cursor(path)
    db = _connect(path, writer=True)
    try:
        db.execute("BEGIN IMMEDIATE")
        r = db.execute("SELECT v FROM _repl_state WHERE k='cursor'").fetchone()
        cur = int(r[0]) if r else 0
        cols_cache = {}
        for ch in chunk.get("changes", []):
            v, t = int(ch["v"]), ch["t"]
            if v <= cur or t not in REPL_TABLES:
                continue
            if t not in cols_cache:
                info = db.execute(f"PRAGMA table_info({t})").fetchall()
                alias = len([c for c in info if c[5]]) == 1 and [c for c in info if c[5]][0][2].upper() == "INTEGER"
                cols_cache[t] = ({c[1] for c in info}, alias)
            cols, alias = cols_cache[t]
            if ch["op"] == "d":
                db.execute(f"DELETE FROM {t} WHERE rowid = ?", (int(ch["rid"]),))
            else:
                row = {k: val for k, val in ch["row"].items() if k in cols}
                names = list(row) if alias else ["rowid", *row]
                vals = list(row.values()) if alias else [int(ch["rid"]), *row.values()]
                db.execute(f"INSERT OR REPLACE INTO {t}({','.join(names)}) VALUES({','.join('?' * len(names))})", vals)
            cur = v
        # the reply covers the continuous range (since, cursor]: since was read before the request, the cursor only grows
        new = max(cur, int(chunk.get("cursor", cur)))
        db.execute("INSERT OR REPLACE INTO _repl_state VALUES ('cursor', ?)", (str(new),))
        db.execute("INSERT OR REPLACE INTO _repl_state VALUES ('synced_at', ?)", (str(int(time.time())),))
        db.execute("COMMIT")
        return new
    finally:
        if db.in_transaction:
            db.execute("ROLLBACK")
        db.close()


def pull(state_dir, max_rounds: int = 50) -> int:
    """Catch up with the hub: changes until the end of its log."""
    path = Path(state_dir) / "bus.sqlite3"
    cur = cursor(path)
    for _ in range(max_rounds):
        chunk = call(state_dir, "changes", {"since": cur, "limit": 1000})
        cur = apply(path, chunk)
        if not chunk.get("more"):
            break
    export_registry(state_dir)
    return cur


def export_registry(state_dir) -> dict:
    """agents-registry.json - derived registry copy for older readers; on a client only this module writes it."""
    import registry_db as rdb
    path = Path(state_dir) / "bus.sqlite3"
    db = _connect(path, writer=True)
    try:
        gen = rdb.generation(db)
        r = db.execute("SELECT v FROM _repl_state WHERE k='exported_generation'").fetchone()
        if r and int(r[0]) >= gen and rdb.json_path(state_dir).exists():
            return {"published": False, "reason": "up-to-date", "generation": gen}
        rdb._publish(rdb.json_path(state_dir), rdb.load_doc(state_dir, db))
        db.execute("INSERT OR REPLACE INTO _repl_state VALUES ('exported_generation', ?)", (str(gen),))
        db.commit()
        return {"published": True, "generation": gen}
    finally:
        db.close()


# ---------- MessageStore-compatible facade ----------

class RemoteStore:
    """Same interface as bus.MessageStore (post / inbox / ack / _connection / path), but writes go to the hub."""

    def __init__(self, state_dir, ttl_seconds: int):
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "bus.sqlite3"
        self.ttl_seconds = ttl_seconds

    @contextmanager
    def _connection(self):
        db = _connect(self.path, writer=False)   # replica read; a write would hit the guards
        try:
            with db:
                yield db
        finally:
            db.close()

    def _write(self, op, args, key="hub"):
        res = call(self.state_dir, op, {**args, "since": cursor(self.path)}, key=key)
        apply(self.path, res.pop("changes", None))
        return res

    def post(self, message: dict) -> tuple[dict, bool]:
        from bus import _row
        sender = message["from"]
        args = {"to": message["to"], "id": message["id"], "body": message["body"], "reply_to": message.get("reply_to"),
                "as": sender}
        if message.get("delivery") is not None:
            args["delivery"] = message["delivery"]
        try:
            res = self._write("send", args, key="owner" if sender == "owner" else "hub")
        except BusRemoteError as exc:
            text = str(exc)
            if text.startswith("FileExistsError"):
                raise FileExistsError(text.split(": ", 1)[-1]) from exc
            if text.startswith("ValueError") or text.startswith("OwnerSignatureError"):
                raise ValueError(text.split(": ", 1)[-1]) from exc
            raise
        with self._connection() as db:
            row = db.execute("SELECT * FROM messages WHERE id = ?", (message["id"],)).fetchone()
        if row is None:  # replica not caught up (should not happen: the changes came with the reply)
            pull(self.state_dir)
            with self._connection() as db:
                row = db.execute("SELECT * FROM messages WHERE id = ?", (message["id"],)).fetchone()
        return _row(row), bool(res.get("duplicate"))

    def inbox(self, recipient: str, status: str, limit: int) -> list[dict]:
        from bus import _row
        now = int(time.time())
        with self._connection() as db:
            if status == "all":
                rows = db.execute("SELECT * FROM messages WHERE recipient = ? AND expires_at > ? ORDER BY seq LIMIT ?",
                                  (recipient, now, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM messages WHERE recipient = ? AND status = ? AND expires_at > ? "
                                  "ORDER BY seq LIMIT ?", (recipient, status, now, limit)).fetchall()
            return [_row(r) for r in rows]

    def ack(self, mid: str, recipient: str) -> dict | None:
        from bus import _row
        try:
            self._write("ack", {"id": mid, "as": recipient})
        except BusRemoteError as exc:
            if "message not found" in str(exc):
                return None
            raise
        with self._connection() as db:
            row = db.execute("SELECT * FROM messages WHERE id = ? AND recipient = ?", (mid, recipient)).fetchone()
        return _row(row) if row else None


# ---------- registry ----------

def registry(state_dir, fn: str, **args) -> dict:
    path = Path(state_dir) / "bus.sqlite3"
    keep = {k: v for k, v in args.items() if v is not None or k in ("vendor", "model", "expected")}
    res = call(state_dir, "registry", {"fn": fn, **keep, "since": cursor(path)})
    apply(path, res.pop("changes", None))
    export_registry(state_dir)
    return res["registry"]

if __name__ == "__main__":
    _integrity_require_config()
