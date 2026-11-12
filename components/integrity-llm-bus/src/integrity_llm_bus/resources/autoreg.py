# SPDX-License-Identifier: BUSL-1.1
"""Auto-registration of every local thread on the agent bus (staging, agent-bus/1).

ensure() = register + heartbeat, idempotent. Registration grants NO authority and, for auto
entries, no wake: wake=false entries are served only by the thread's own hook (pull).

Invariants (GROK_REVIEW_v1):
- fast path is lock-free and read-only when the identity is known and last_seen is fresh;
- slow path: lookup by identity, collision check and insert happen under ONE registry lock;
  the stored address is never recomputed (id8, extended to id12 on collision);
- ensure() never changes address or wake of an existing entry; it only refreshes last_seen and
  fills missing vendor/model;
- wake=true only via set_wake() (owner-run command, never from hooks);
- r2: registry rows live in bus.sqlite3 (registry_db); JSON is a generated export (+.prev);
- hooks call ensure_bounded(): hard timeout, fail-open, one log line, never blocks a turn.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import threading
import time

import agent_registry as ar
import registry_db as rdb

HEARTBEAT_S = 600
LEASE_S = 7 * 86400
HOOK_TIMEOUT_S = 0.3
LOCK_WAIT_MS = 250
SCAN_INTERVAL_S = 300
WARN_ENTRIES = 500
PREFIX = {"codex": "codex", "claude": "claude", "gemini": "ag", "antigravity": "ag"}
VENDOR = {"codex": "openai", "claude": "anthropic"}
BAD_CHARS = re.compile(r"[\ufffd\x00-\x08\x0b-\x1f]")


def is_mojibake(text: str) -> bool:
    """True if text is UTF-8 bytes mis-decoded as CP1251 or Latin-1 (decodes cleanly back to other text)."""
    if text.isascii():
        return False
    for enc in ("cp1251", "latin-1"):
        try:
            fixed = text.encode(enc).decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if fixed != text:
            return True
    return False


def _now(now):
    return time.time() if now is None else now


def valid_topic(topic: str) -> str:
    topic = (topic or "").strip()
    if len(topic) > 200 or BAD_CHARS.search(topic) or is_mojibake(topic):
        raise ValueError("topic rejected (length or invalid text)")
    return topic


def vendor_for_model(model: str | None) -> str | None:
    m = (model or "").lower()
    for key, vendor in (("claude", "anthropic"), ("gemini", "google"), ("gpt", "openai"), ("grok", "xai")):
        if key in m:
            return vendor
    return None


def by_identity(agents: dict, identity: str) -> str | None:
    hits = sorted(n for n, e in agents.items() if e.get("thread") == identity)
    return hits[0] if hits else None


def state_of(entry: dict, now=None) -> str:
    seen = entry.get("last_seen")
    if seen is None:  # v2 explicit entry: keeps today's semantics
        return "active"
    return "active" if _now(now) - seen < LEASE_S else "dormant"


def wake_of(entry: dict) -> bool:
    return bool(entry.get("wake", not entry.get("auto", False)))


def route(address: str, state_dir: Path, now=None) -> dict:
    """route = wake | pull | dormant (+ webhook for grok). Sender must not treat pull as delivered."""
    if address == "grok":
        return {"route": "webhook", "wake": True, "vendor": "xai"}
    entry = ar.load(state_dir).get(address)
    if entry is None:
        return {"route": "wake" if address in ar.BUILTIN_CODEX else "pull"}
    if state_of(entry, now) == "dormant":
        return {"route": "dormant"}
    harness = entry.get("harness", "codex")
    return {"route": "wake" if harness == "codex" and wake_of(entry) else "pull"}


def relay_excluded(state_dir: Path, now=None) -> set[str]:
    """Addresses the relay must neither wake nor poll: auto/wake=false or dormant."""
    return {n for n, e in ar.load(state_dir).items() if not wake_of(e) or state_of(e, now) == "dormant"}


def _builtin_threads(state_dir):
    return set(ar.builtin_threads(state_dir).values())


def ensure(harness: str, identity: str, *, source: str, vendor: str | None = None, model: str | None = None,
           topic: str = "", state_dir: Path | None = None, now: float | None = None) -> dict:
    """r2: registry rows in bus.sqlite3. Fast path = read-only SELECT; slow path = one BEGIN IMMEDIATE txn."""
    state_dir = Path(state_dir or ar.DEFAULT_STATE)
    if harness not in PREFIX:
        raise ValueError("unknown harness")
    identity = (identity or "").strip().lower()
    if not ar.THREAD_RE.fullmatch(identity):
        raise ValueError("identity must be a lowercase UUID")
    now = int(_now(now))
    if not rdb.migrated(state_dir):
        raise ValueError("registry not migrated to bus.sqlite3")
    con = rdb.connect(state_dir, readonly=True, timeout_ms=LOCK_WAIT_MS)
    try:
        row = con.execute("SELECT address, last_seen, model, vendor FROM agents WHERE thread=?", (identity,)).fetchone()
    finally:
        con.close()
    eff_vendor = vendor or (vendor_for_model(model) if model else None)
    model_changed = (model is not None and row is not None and row["model"] != model)
    vendor_changed = (eff_vendor is not None and row is not None and row["vendor"] != eff_vendor)
    if row and row["last_seen"] is not None and (now - row["last_seen"] < HEARTBEAT_S) and not model_changed and not vendor_changed:
        return {"address": row["address"], "created": False, "fast": True, **route(row["address"], state_dir, now)}
    import bus_remote  # hub mode: the slow path (registry write) runs on the hub
    if bus_remote.active(state_dir):
        res = bus_remote.registry(state_dir, "ensure", harness=harness, identity=identity, source=source,
                                  vendor=vendor, model=model, topic=topic)
        if res.get("created") and harness == "claude":
            ar._initialize_claude_cursor(state_dir, identity, res["address"])
        return res
    topic = valid_topic(topic)
    if identity in _builtin_threads(state_dir):
        raise ValueError("identity is a built-in address")
    con = rdb.connect(state_dir, timeout_ms=LOCK_WAIT_MS)
    created = False
    try:
        con.execute("BEGIN IMMEDIATE")  # waits <= busy_timeout, then 'database is locked' -> fail-open upstream
        row = con.execute("SELECT * FROM agents WHERE thread=?", (identity,)).fetchone()
        if row:
            name = row["address"]
            eff_vendor = vendor or (vendor_for_model(model) if model else None)
            if eff_vendor is None and row["harness"] in VENDOR:
                eff_vendor = VENDOR[row["harness"]]
            new_model = model if model is not None else row["model"]
            new_vendor = eff_vendor if eff_vendor is not None else row["vendor"]
            con.execute("UPDATE agents SET last_seen=MAX(COALESCE(last_seen,0),?), first_seen=COALESCE(first_seen,?), "
                        "vendor=?, model=? WHERE address=?",
                        (now, now, new_vendor, new_model, name))
        else:
            compact = identity.replace("-", "")
            name = f"{PREFIX[harness]}-{compact[:8]}"
            taken = lambda n: n in ar.BUILTIN or n in getattr(ar, "RESERVED", ()) or con.execute("SELECT 1 FROM agents WHERE address=?", (n,)).fetchone()
            if taken(name):
                name = f"{PREFIX[harness]}-{compact[:12]}"
                if taken(name):
                    raise ValueError("address collision at 12 chars")
            core = {"thread": identity, "harness": harness, "topic": topic, "registered_at": now,
                    "registered_local": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))}
            if harness == "claude":
                core["session_id"] = identity
            eff_vendor = vendor or (vendor_for_model(model) if model else None)
            if eff_vendor is None and harness in VENDOR:
                eff_vendor = VENDOR[harness]
            rdb._insert(con, name, {**core, "auto": True, "wake": False, "source": source, "model": model,
                                    "vendor": eff_vendor,
                                    "first_seen": now, "last_seen": now}, replace_core=False)
            created = True
        rdb.bump_generation(con)
        con.execute("COMMIT")
    except sqlite3.OperationalError as exc:
        raise ValueError("registry busy") from exc
    finally:
        if con.in_transaction:
            con.execute("ROLLBACK")
        con.close()
    if created and harness == "claude":
        ar._initialize_claude_cursor(state_dir, identity, name)
    try:
        rdb.export_json(state_dir)
    except (OSError, sqlite3.Error):
        log(state_dir, {"event": "export-failed"})
    count = len(ar.load(state_dir))
    if count > WARN_ENTRIES:
        log(state_dir, {"event": "registry-large", "entries": count})
    return {"address": name, "created": created, "fast": False, **route(name, state_dir, now)}


def set_wake(address: str, wake: bool, state_dir: Path | None = None) -> dict:
    """Owner-only (run on the owner's GO); hooks and discovery never call this."""
    state_dir = Path(state_dir or ar.DEFAULT_STATE)
    import bus_remote  # hub mode
    if bus_remote.active(state_dir):
        raise ValueError("bus moved to the hub: set-wake runs on the hub host")
    con = rdb.connect(state_dir, timeout_ms=2000)
    try:
        con.execute("BEGIN IMMEDIATE")
        if con.execute("UPDATE agents SET wake=? WHERE address=?", (int(bool(wake)), address)).rowcount != 1:
            raise ValueError("unknown address")
        rdb.bump_generation(con)
        con.execute("COMMIT")
    finally:
        if con.in_transaction:
            con.execute("ROLLBACK")
        con.close()
    rdb.export_json(state_dir)
    return {"address": address, "wake": bool(wake)}


def log(state_dir: Path, event: dict) -> None:
    try:
        with (state_dir / "autoreg.log").open("a", encoding="utf-8") as s:
            s.write(json.dumps({"ts": int(time.time()), **event}, separators=(",", ":")) + "\n")
    except OSError:
        pass


def ensure_bounded(harness: str, identity, *, state_dir: Path | None = None, timeout: float = HOOK_TIMEOUT_S,
                   **kw) -> dict | None:
    """Hook entry: never raises, never waits longer than timeout. None = skipped (fail-open)."""
    state_dir = state_dir or ar.DEFAULT_STATE
    box = {}
    def run():
        try:
            box["r"] = ensure(harness, identity, state_dir=state_dir, **kw)
        except Exception as exc:
            box["e"] = type(exc).__name__ + ":" + str(exc)[:80]
    t = threading.Thread(target=run, daemon=True); t.start(); t.join(timeout)
    if t.is_alive():
        log(state_dir, {"event": "ensure-timeout", "harness": harness}); return None
    if "e" in box:
        log(state_dir, {"event": "ensure-failed", "harness": harness, "error": box["e"]}); return None
    return box.get("r")


def interactive_codex_meta(path: Path) -> dict | None:
    """Read ONLY the first line; accept interactive Desktop/CLI threads, skip exec/subagent/one-shot."""
    try:
        with path.open("rb") as s:
            first = s.readline(65537)
        if len(first) > 65536:
            return None
        meta = json.loads(first)
    except (OSError, ValueError):
        return None
    if not isinstance(meta, dict):  # r3: a list/str/number first line is not a session header
        return None
    p = meta.get("payload")
    if meta.get("type") != "session_meta" or not isinstance(p, dict):
        return None
    if (p.get("originator") == "codex_exec" or not isinstance(p.get("source"), str) or p["source"] == "exec"
            or p.get("parent_thread_id") or p.get("forked_from_id")):
        return None
    if not isinstance(p.get("id"), str) or not ar.THREAD_RE.fullmatch(p["id"]):
        return None
    return {"id": p["id"], "cwd": p.get("cwd")}


def discover_codex(state_dir: Path | None = None, root: Path | None = None, now=None, max_age_s=LEASE_S) -> list[dict]:
    """Fallback for threads that never run a tool. Registers only; never wakes, never sends."""
    root = root or Path.home() / ".codex" / "sessions"
    out = []
    for path in sorted(root.glob("*/*/*/rollout-*.jsonl")):
        try:
            mtime = path.stat().st_mtime
            if _now(now) - mtime > max_age_s:
                continue
        except OSError:
            continue
        meta = interactive_codex_meta(path)
        if meta:
            topic = f"{Path(meta['cwd']).name if meta.get('cwd') else ''} codex".strip()
            try:
                out.append(ensure("codex", meta["id"], source="discovery", topic=topic[:200], state_dir=state_dir,
                                  now=min(_now(now), mtime)))  # lease follows real activity, never extends it
            except ValueError as exc:
                out.append({"id": meta["id"], "error": str(exc)[:80]})
    return out


def discover_antigravity(state_dir: Path | None = None, db_path: Path | None = None, now=None, max_age_s=LEASE_S) -> list[dict]:
    """Scan Antigravity conversation_summaries.db. Registers only; never wakes, never sends."""
    db_path = db_path or (Path.home() / ".gemini" / "antigravity" / "conversation_summaries.db")
    if not db_path.exists():
        return []
    out = []
    try:
        con = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        with con:
            rows = con.execute("SELECT conversation_id, title, last_modified_time FROM conversation_summaries").fetchall()
    except (sqlite3.Error, OSError) as exc:
        return [{"error": f"antigravity_db_read_failed:{str(exc)[:60]}"}]

    for row in rows:
        cid, title, last_mod = row[0], row[1], row[2]
        if not cid or not ar.THREAD_RE.fullmatch(cid):
            continue
        clean_title = (title or "Antigravity conversation").strip()
        try:
            topic = valid_topic(clean_title[:200])
        except ValueError:
            topic = "Antigravity conversation"
        try:
            out.append(ensure("antigravity", cid, source="discovery", topic=topic, vendor="google", state_dir=state_dir, now=_now(now)))
        except (ValueError, Exception) as exc:
            out.append({"id": cid, "error": str(exc)[:80]})
    return out


def periodic_scan(state_dir: Path, last_scan: float, now: float | None = None,
                  interval: float = SCAN_INTERVAL_S, root: Path | None = None) -> tuple[float, dict | None]:
    """Called from the relay loop. At most once per interval; never raises."""
    now = _now(now)
    if now - last_scan < interval:
        return last_scan, None
    try:
        out_codex = discover_codex(state_dir, root, now)
        out_ag = discover_antigravity(state_dir, now=now)
        out = out_codex + out_ag
        return now, {"event": "discovery", "seen": len(out), "created": sum(1 for o in out if o.get("created")),
                     "errors": sum(1 for o in out if "error" in o)}
    except Exception as exc:
        return now, {"event": "discovery-failed", "error_type": type(exc).__name__}


def pull_pointers(address: str, thread: str, state_dir: Path, limit: int = 20) -> list[dict]:
    """Pending ids for a wake=false Codex address; advances a per-thread cursor. Never ACKs."""
    db = state_dir / "bus.sqlite3"
    if not db.exists():
        return []
    cur_path = state_dir / "autoreg-seen" / (thread + ".json")
    try:
        seen = json.loads(cur_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        seen = {}
    last = int(seen.get(address, 0))
    con = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        rows = con.execute("SELECT seq,id,sender FROM messages WHERE recipient=? AND status='pending' AND expires_at>? "
                           "AND seq>? ORDER BY seq LIMIT ?", (address, int(time.time()), last, limit)).fetchall()
    finally:
        con.close()
    if rows:
        seen[address] = rows[-1][0]
        cur_path.parent.mkdir(exist_ok=True)
        tmp = cur_path.with_suffix(".tmp"); tmp.write_text(json.dumps(seen), encoding="utf-8"); os.replace(tmp, cur_path)
    return [{"id": r[1], "from": r[2]} for r in rows]


def status(state_dir: Path | None = None, now=None) -> list[dict]:
    return [{"address": n, "harness": e.get("harness", "codex"), "auto": bool(e.get("auto")), "wake": wake_of(e),
             "state": state_of(e, now), "last_seen": e.get("last_seen")} for n, e in sorted(ar.load(state_dir).items())]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-dir", type=Path, default=ar.DEFAULT_STATE)
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("ensure"); e.add_argument("--harness", required=True, choices=tuple(PREFIX))
    e.add_argument("--identity", required=True); e.add_argument("--source", default="cli"); e.add_argument("--topic", default="")
    e.add_argument("--model")
    sub.add_parser("status", help="lease state per address (active/dormant); never deletes")
    sub.add_parser("discover", help="Codex rollout fallback scan (first line only)")
    sub.add_parser("discover-antigravity", help="Antigravity conversation summaries scan")
    sub.add_parser("migrate", help="import agents-registry.json into bus.sqlite3 (idempotent; DB backup first)")
    sub.add_parser("unmigrate", help="ROLLBACK: export DB registry to JSON, drop registry tables")
    w = sub.add_parser("set-wake", help="OWNER ONLY (needs the owner's approval)"); w.add_argument("--address", required=True)
    w.add_argument("--wake", choices=("on", "off"), required=True)
    a = p.parse_args(argv)
    try:
        if a.cmd == "ensure":
            r = ensure(a.harness, a.identity, source=a.source, topic=a.topic, model=a.model, state_dir=a.state_dir)
        elif a.cmd == "status":
            r = status(a.state_dir)
        elif a.cmd == "discover":
            r = discover_codex(a.state_dir)
        elif a.cmd == "discover-antigravity":
            r = discover_antigravity(a.state_dir)
        elif a.cmd == "migrate":
            r = rdb.migrate(a.state_dir)
        elif a.cmd == "unmigrate":
            r = rdb.unmigrate(a.state_dir)
        else:
            r = set_wake(a.address, a.wake == "on", a.state_dir)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); return 2
    print(json.dumps(r, ensure_ascii=False, separators=(",", ":"))); return 0



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
