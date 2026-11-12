# SPDX-License-Identifier: BUSL-1.1
"""agent-mesh/1 projection: a deterministic index of data.mesh messages, derived from the bus `messages` table.

The bus is the record. The mesh_* tables are a projection applied strictly in seq order. Projection time comes
from message.created_at. Read-only freshness views may use an explicit observation time or the current clock.
Claims are decided here, so a raw `local_cli send` with a claim cannot create a second claimant.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
import math
from pathlib import Path
import sqlite3
import time

import mesh_validate as mv

SCHEMA = """
CREATE TABLE IF NOT EXISTS mesh_work (
    work TEXT PRIMARY KEY, state TEXT NOT NULL, version INTEGER NOT NULL, claimant TEXT,
    lease_until INTEGER, lease_s INTEGER, opener TEXT NOT NULL, title TEXT, owner_cite TEXT,
    candidate_sha TEXT, block_reason TEXT, prev_state TEXT, decision_seq INTEGER, decision_sha TEXT,
    last_seq INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mesh_msgs (
    msg TEXT PRIMARY KEY, seq INTEGER NOT NULL, work TEXT NOT NULL, kind TEXT NOT NULL, sender TEXT NOT NULL,
    created_at INTEGER NOT NULL, bytes INTEGER NOT NULL, eid TEXT, candidate TEXT, verdict TEXT,
    stale INTEGER NOT NULL DEFAULT 0, cite TEXT, unblock INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS mesh_msgs_sender ON mesh_msgs(sender, created_at);
CREATE INDEX IF NOT EXISTS mesh_msgs_work ON mesh_msgs(work, seq);
CREATE TABLE IF NOT EXISTS mesh_edges (child TEXT NOT NULL, parent TEXT NOT NULL, PRIMARY KEY(child, parent));
CREATE TABLE IF NOT EXISTS mesh_rejects (msg TEXT PRIMARY KEY, seq INTEGER NOT NULL, agent TEXT NOT NULL,
    work TEXT, reason TEXT NOT NULL, at INTEGER NOT NULL, eid TEXT);
CREATE TABLE IF NOT EXISTS mesh_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mesh_resources (
    work TEXT NOT NULL, resource TEXT NOT NULL, PRIMARY KEY(work, resource));
CREATE TABLE IF NOT EXISTS mesh_presence (
    agent TEXT PRIMARY KEY, presence_until INTEGER NOT NULL,
    updated_at INTEGER NOT NULL, last_seq INTEGER NOT NULL);
"""
DEFAULT_LIMITS = {"msgs_per_10min": 60, "node_msgs_per_10min": 20, "bytes_per_hour": 512 * 1024,
                  "open_claims": 5, "decisions_per_agent": 5, "stale_after_s": 1800,
                  "pm": "grok"}  # pm may cancel any node
EXEMPT = ("release", "cancel", "blocked")
HOLDING = ("claimed", "review", "blocked")
CLOSED = ("done", "cancelled")
DECISION_REF = 12  # an owner answer must quote at least this many leading hex chars of the decision sha256


def load_limits(state_dir: Path | None) -> dict:
    limits = dict(DEFAULT_LIMITS)
    path = state_dir / "mesh-limits.json" if state_dir else None
    if path and path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        for key, value in data.items():
            if key == "pm":
                if isinstance(value, str) and mv.ADDR_RE.fullmatch(value) and value != mv.OWNER:
                    limits[key] = value
            elif key in limits and isinstance(value, int) and not isinstance(value, bool) and value > 0:
                limits[key] = value
    return limits


def ensure_schema(db: sqlite3.Connection) -> None:
    # one execute per statement: executescript() would COMMIT first and drop the caller's BEGIN IMMEDIATE lock
    for statement in SCHEMA.split(";"):
        if statement.strip():
            db.execute(statement)


def _meta(db, key, default=None):
    row = db.execute("SELECT value FROM mesh_meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _set_meta(db, key, value):
    db.execute("INSERT INTO mesh_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, str(value)))


def _node(db, work):
    row = db.execute("SELECT * FROM mesh_work WHERE work=?", (work,)).fetchone()
    if row is None:
        return None
    cols = [d[0] for d in db.execute("SELECT * FROM mesh_work LIMIT 0").description]
    return dict(zip(cols, row))


def _save(db, node):
    cols = list(node)
    db.execute(f"INSERT OR REPLACE INTO mesh_work({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
               [node[c] for c in cols])


def _known(db, msg_id, fallback) -> bool:
    if db.execute("SELECT 1 FROM messages WHERE id=?", (msg_id,)).fetchone():
        return True
    if db.execute("SELECT 1 FROM mesh_msgs WHERE msg=?", (msg_id,)).fetchone():
        return True
    return bool(fallback and fallback(msg_id))


def _owner_root_known(db, root, fallback) -> bool:
    row = db.execute("SELECT 1 FROM messages WHERE sender='owner' AND (id=? OR id LIKE ? ESCAPE '\\')",
                     (root, root.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + ".%")).fetchone()
    return bool(row) or bool(fallback and fallback("owner-root:" + root))


def _data(body):
    try:
        parsed = json.loads(body or "")
    except ValueError:
        return None, None
    if not isinstance(parsed, dict) or not isinstance(parsed.get("data"), dict):
        return None, None
    return parsed, parsed["data"]


def _owner_approval(body, ref) -> bool:
    """An owner decision that approves and quotes the ref in its own text. A refusal or deferral never unblocks,
    and a ref hidden in another field does not count."""
    parsed, data = _data(body)
    return (data is not None and parsed.get("k") == "decision" and data.get("disposition") == "approve"
            and isinstance(data.get("text"), str) and ref in data["text"])


def _asked_for(db, reply_to, asker, node) -> bool:
    """The owner answered `asker`'s own request to the owner for exactly this node's current decision: a question or
    decision (need != none) posted after the decision-request, naming the node (data.work) and the decision
    (data.decision_ref, a prefix of decision_sha). Two nodes with the same decision text cannot share one answer."""
    if not reply_to or node["decision_seq"] is None:
        return False
    row = db.execute("SELECT seq, sender, recipient, body FROM messages WHERE id=?", (reply_to,)).fetchone()
    if row is None or row[1] != asker or row[2] != "owner" or row[0] <= node["decision_seq"]:
        return False
    parsed, data = _data(row[3])
    if data is None or parsed.get("k") not in ("question", "decision") or parsed.get("need") in (None, "none"):
        return False
    value = data.get("decision_ref")
    return (data.get("work") == node["work"] and isinstance(value, str) and len(value) >= DECISION_REF
            and all(c in "0123456789abcdef" for c in value) and (node["decision_sha"] or "").startswith(value))


def _owner_answer(db, root, node, msg_id, fallback, pm=None) -> bool:
    """True when `root` is the owner's approval of exactly this node's decision-request.

    It must be posted after the request, be k=decision with disposition=approve, quote the sha256 prefix in its
    text, go to the arbiter (pm) or the node's claimant, and reply to that agent's own later request to the owner
    that names this node (data.work) and this decision (data.decision_ref). A cite of any older owner message (for example the charter the node was
    opened under), a refusal, or an approval of another question never unblocks.
    """
    ref = (node["decision_sha"] or "")[:DECISION_REF]
    allowed = {a for a in (pm, node["claimant"]) if a}
    pattern = root.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + ".%"
    rows = db.execute("SELECT seq, recipient, reply_to, body FROM messages WHERE sender='owner' AND "
                      "(id=? OR id LIKE ? ESCAPE '\\')", (root, pattern)).fetchall()
    complete = bool(rows)
    for seq, recipient, reply_to, body in rows:
        own_ok = (ref and node["decision_seq"] is not None and seq > node["decision_seq"] and recipient in allowed
                  and _owner_approval(body, ref))
        if own_ok and _asked_for(db, reply_to, recipient, node):
            return True
        if own_ok and reply_to and not db.execute("SELECT 1 FROM messages WHERE id=?", (reply_to,)).fetchone():
            # The answer itself is a valid approval, only the request it answered has expired: that part cannot be
            # re-judged, so the recorded unblock decides. A refusal or a non-approval never reaches this (Codex v6).
            complete = False
    if complete:
        # Codex (v4): the owner answer and the request it answered are both still on the bus and fail the rule, so an
        # older accepted unblock recorded for this msg_id must not resurrect it on rebuild. A chain with an expired
        # part (answer or request) is judged by the recorded unblock instead (Codex v5).
        return False
    return bool(fallback and fallback("owner-answer:" + msg_id))


def _review_state(db, work, candidate, claimant) -> tuple[int, list]:
    """Latest verdict per reviewer on `candidate`: (number of PASS, reviewers whose latest is FAIL or PARTIAL)."""
    latest = {}
    for sender, verdict in db.execute("SELECT sender, verdict FROM mesh_msgs WHERE work=? AND kind='verdict' AND stale=0"
                                      " AND candidate=? AND sender<>? ORDER BY seq", (work, candidate, claimant or "")):
        latest[sender] = verdict
    return sum(v == "PASS" for v in latest.values()), sorted(s for s, v in latest.items() if v != "PASS")


def apply(db, row, limits, fallback=None) -> str | None:
    """Project one bus row. Returns None when accepted, else the reject reason (stored in mesh_rejects)."""
    seq, msg_id, sender, recipient, raw, t = row
    try:
        body = json.loads(raw)
    except ValueError:
        return None  # not JSON: not a mesh message
    raw_mesh = mv.mesh_of(body) if isinstance(body, dict) else None
    if raw_mesh is None:
        return None
    raw_mesh = raw_mesh if isinstance(raw_mesh, dict) else {}
    # eid is read before validation so that a rejected first copy still decides for its siblings
    eid = raw_mesh.get("eid") if isinstance(raw_mesh.get("eid"), str) and mv.ID_RE.fullmatch(raw_mesh["eid"]) else None
    raw_work = raw_mesh.get("work") if isinstance(raw_mesh.get("work"), str) else None

    def reject(reason, work=None):
        db.execute("INSERT OR IGNORE INTO mesh_rejects(msg, seq, agent, work, reason, at, eid) VALUES(?,?,?,?,?,?,?)",
                   (msg_id, seq, sender, work, reason, t, eid))
        return reason

    if eid:
        first = db.execute("SELECT msg FROM (SELECT msg, seq FROM mesh_msgs WHERE sender=? AND eid=?"
                           " UNION ALL SELECT msg, seq FROM mesh_rejects WHERE agent=? AND eid=?) ORDER BY seq LIMIT 1",
                           (sender, eid, sender, eid)).fetchone()
        if first:
            return reject("copy:" + first[0], raw_work)
    try:
        mesh = mv.validate(body, sender, recipient)
    except mv.MeshError as exc:
        return reject("invalid:" + str(exc)[:120], raw_work)
    kind, work = mesh["kind"], mesh["work"]
    size = len(raw.encode("utf-8"))
    if kind not in EXEMPT:
        n10 = db.execute("SELECT COUNT(*) FROM mesh_msgs WHERE sender=? AND created_at>?", (sender, t - 600)).fetchone()[0]
        if n10 >= limits["msgs_per_10min"]:
            return reject("quota:msgs", work)
        nn = db.execute("SELECT COUNT(*) FROM mesh_msgs WHERE sender=? AND work=? AND created_at>?",
                        (sender, work, t - 600)).fetchone()[0]
        if nn >= limits["node_msgs_per_10min"]:
            return reject("quota:node", work)
        used = db.execute("SELECT COALESCE(SUM(bytes),0) FROM mesh_msgs WHERE sender=? AND created_at>?",
                          (sender, t - 3600)).fetchone()[0]
        if used + size > limits["bytes_per_hour"]:
            return reject("quota:bytes", work)
    for parent in mesh.get("parents", []):
        if not _known(db, parent, fallback):
            return reject("unknown-parent:" + parent, work)
    if mesh.get("sup") and not db.execute("SELECT 1 FROM mesh_msgs WHERE msg=? AND sender=?",
                                          (mesh["sup"], sender)).fetchone():
        return reject("bad-sup", work)
    cite = (mesh.get("cite") or {}).get("owner")
    if cite and not _owner_root_known(db, cite, fallback):
        return reject("unknown-cite", work)
    candidate = next((e["sha256"] for e in mesh.get("ev", []) if e["role"] == "candidate"), None)
    payload = mesh.get("body", {})
    node = _node(db, work)
    stale = unblock = 0
    resources = None  # None leaves an existing declaration untouched; [] clears it.
    verdict = payload.get("verdict") if kind in ("review", "verdict") else None

    if kind == "open":
        if node:
            return reject("exists", work)
        node = {"work": work, "state": "open", "version": 0, "claimant": None, "lease_until": None, "lease_s": None,
                "opener": sender, "title": payload.get("title", ""), "owner_cite": cite, "candidate_sha": None,
                "block_reason": None, "prev_state": None, "decision_seq": None, "decision_sha": None,
                "last_seq": seq, "updated_at": t}
        resources = []
    else:
        if node is None:
            return reject("no-node", work)
        if node["state"] in ("claimed", "review") and node["lease_until"] is not None and node["lease_until"] < t:
            node.update(state="open", claimant=None, lease_until=None, version=node["version"] + 1)
            resources = []
        if node["state"] in CLOSED and kind != "digest":
            return reject("closed:" + node["state"], work)
        is_claimant = node["claimant"] == sender

        def renew():
            node["lease_until"] = t + (node["lease_s"] or 1800)

        if kind == "claim":
            if node["state"] != "open":
                return reject(("held-by:" + node["claimant"]) if node["claimant"] else "state:" + node["state"], work)
            if mesh["claim"]["expect"] != node["version"]:
                return reject(f"stale-expect:{node['version']}", work)
            held = db.execute("SELECT COUNT(*) FROM mesh_work WHERE claimant=? AND state IN ('claimed','review','blocked')"
                              " AND (state='blocked' OR lease_until>=?)", (sender, t)).fetchone()[0]
            if held >= limits["open_claims"]:
                return reject("quota:claims", work)
            node.update(state="claimed", claimant=sender, version=node["version"] + 1,
                        lease_s=mesh["claim"]["lease_s"], lease_until=t + mesh["claim"]["lease_s"])
            resources = mv.normalize_resources(payload.get("resources", []))
        elif kind == "release":
            if not is_claimant:
                return reject("not-claimant", work)
            node.update(state="open", claimant=None, lease_until=None, version=node["version"] + 1,
                        block_reason=None, prev_state=None, decision_seq=None, decision_sha=None)
            resources = []
        elif kind in ("assign", "digest"):
            pass  # proposals and summaries never change state
        elif kind in ("progress", "artifact"):
            if not is_claimant:
                return reject("not-claimant", work)
            if node["state"] == "blocked":
                if node["block_reason"] == "decision":
                    if not cite:
                        return reject("needs-owner-cite", work)
                    if not _owner_answer(db, cite, node, msg_id, fallback, limits["pm"]):
                        return reject("cite-not-decision-answer", work)
                    unblock = 1
                node.update(state=node["prev_state"] or "claimed", block_reason=None, prev_state=None,
                            decision_seq=None, decision_sha=None)
            if candidate:
                node["candidate_sha"] = candidate
            renew()
        elif kind == "review":
            if not is_claimant:
                return reject("not-claimant", work)
            if node["state"] == "blocked":
                return reject("blocked", work)
            node.update(state="review", candidate_sha=candidate)
            renew()
        elif kind == "verdict":
            if is_claimant:
                return reject("self-verdict", work)
            stale = int(candidate != node["candidate_sha"])
            if not stale and verdict == "FAIL" and node["state"] == "review":
                node["state"] = "claimed"
        elif kind == "done":
            if not is_claimant:
                return reject("not-claimant", work)
            if node["state"] != "review":
                return reject("state:" + node["state"], work)
            passed, objections = _review_state(db, work, node["candidate_sha"], sender)
            if objections:
                return reject("open-objection:" + ",".join(objections)[:100], work)
            if not node["candidate_sha"] or not passed:
                return reject("no-pass-verdict", work)
            node.update(state="done", lease_until=None)
            resources = []
        elif kind == "blocked":
            if not (is_claimant or node["opener"] == sender):
                return reject("not-allowed", work)
            if node["state"] != "blocked":
                node.update(prev_state=node["state"], state="blocked", block_reason="blocked")
        elif kind == "decision-request":
            if not is_claimant:
                return reject("not-claimant", work)
            if node["state"] == "blocked" and node["block_reason"] == "decision":
                return reject("decision-open-on-node", work)
            open_decisions = db.execute("SELECT COUNT(*) FROM mesh_work WHERE claimant=? AND state='blocked'"
                                        " AND block_reason='decision'", (sender,)).fetchone()[0]
            if open_decisions >= limits["decisions_per_agent"]:
                return reject("quota:decisions", work)
            node.update(prev_state=node["state"] if node["state"] != "blocked" else node["prev_state"],
                        state="blocked", block_reason="decision", decision_seq=seq, decision_sha=payload["sha256"])
        elif kind == "cancel":
            if not (node["opener"] == sender or sender == limits["pm"]):
                return reject("not-allowed", work)
            node.update(state="cancelled", lease_until=None)
            resources = []
        node.update(last_seq=seq, updated_at=t)
    _save(db, node)
    if resources is not None:
        db.execute("DELETE FROM mesh_resources WHERE work=?", (work,))
        db.executemany("INSERT INTO mesh_resources(work,resource) VALUES(?,?)",
                       [(work, resource) for resource in resources])
    if kind in ("claim", "progress") and "presence_until" in payload:
        # Only an accepted claim or holder progress reaches this point. Presence is
        # an agent declaration, never an independent claim, renewal, or authority.
        db.execute("INSERT INTO mesh_presence(agent,presence_until,updated_at,last_seq) VALUES(?,?,?,?) "
                   "ON CONFLICT(agent) DO UPDATE SET "
                   "presence_until=MAX(mesh_presence.presence_until,excluded.presence_until), "
                   "updated_at=MAX(mesh_presence.updated_at,excluded.updated_at), "
                   "last_seq=MAX(mesh_presence.last_seq,excluded.last_seq)",
                   (sender, payload["presence_until"], t, seq))
    db.execute("INSERT INTO mesh_msgs(msg, seq, work, kind, sender, created_at, bytes, eid, candidate, verdict, stale, cite,"
               " unblock) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (msg_id, seq, work, kind, sender, t, size, eid, candidate, verdict, stale, cite, unblock))
    for parent in mesh.get("parents", []):
        db.execute("INSERT OR IGNORE INTO mesh_edges(child, parent) VALUES(?, ?)", (msg_id, parent))
    return None


def project(db, limits, fallback=None) -> int:
    """Apply every bus row with seq > projected_seq, in seq order. Idempotent. Caller holds the transaction."""
    ensure_schema(db)
    done = int(_meta(db, "projected_seq", 0))
    last = done
    for row in db.execute("SELECT seq, id, sender, recipient, body, created_at FROM messages WHERE seq>? ORDER BY seq",
                          (done,)).fetchall():
        apply(db, tuple(row), limits, fallback)
        last = row[0]
    if last != done:
        _set_meta(db, "projected_seq", last)
    return last - done


def outcome(db, msg_id) -> str:
    if db.execute("SELECT 1 FROM mesh_msgs WHERE msg=?", (msg_id,)).fetchone():
        return "accepted"
    row = db.execute("SELECT reason FROM mesh_rejects WHERE msg=?", (msg_id,)).fetchone()
    return ("rejected:" + row[0]) if row else "not-projected"


def _view_time(now, stale_after_s):
    if now is None:
        now = time.time()
    if (isinstance(now, bool) or not isinstance(now, (int, float))
            or not math.isfinite(now) or now < 0):
        raise ValueError("now must be a finite non-negative epoch")
    if isinstance(stale_after_s, bool) or not isinstance(stale_after_s, int) or stale_after_s < 1:
        raise ValueError("stale_after_s must be a positive integer")
    return now


def _freshness(node, now, stale_after_s, presence=None):
    holding = node["state"] in HOLDING and node["claimant"] is not None
    expired = bool(holding and node["lease_until"] is not None and node["lease_until"] < now)
    stale = node["state"] not in CLOSED and node["updated_at"] + stale_after_s < now
    return {"as_of": now, "updated_at": node["updated_at"], "lease_until": node["lease_until"],
            "expired": expired, "stale": stale,
            "claim_active": bool(holding and node["lease_until"] is not None and not expired),
            "presence_until": presence[0] if presence else None,
            "presence_updated_at": presence[1] if presence else None,
            "presence_active": presence[0] >= now if presence else None,
            "presence_stale": presence[1] + stale_after_s < now if presence else None}


def show(db, work, *, now=None, stale_after_s=1800) -> dict | None:
    node = _node(db, work)
    if node is None:
        return None
    now = _view_time(now, stale_after_s)
    msgs = db.execute("SELECT msg, kind, sender, created_at, candidate, verdict, stale, cite FROM mesh_msgs"
                      " WHERE work=? ORDER BY seq", (work,)).fetchall()
    verdicts = {}
    for m in msgs:
        if m[1] == "verdict":
            verdicts[m[2]] = {"verdict": m[5], "candidate": m[4], "stale": bool(m[6]), "msg": m[0]}
    rejects = db.execute("SELECT msg, agent, reason FROM mesh_rejects WHERE work=? ORDER BY seq", (work,)).fetchall()
    node["owner_cite"] = (node["owner_cite"] + " (unverified until owner-verify)") if node["owner_cite"] else None
    presence = db.execute("SELECT presence_until,updated_at FROM mesh_presence WHERE agent=?",
                          (node["claimant"],)).fetchone()
    resources = [r[0] for r in db.execute("SELECT resource FROM mesh_resources WHERE work=? ORDER BY resource", (work,))]
    return {"node": node, "freshness": _freshness(node, now, stale_after_s, presence),
            "resources": resources, "verdicts": verdicts, "messages": [m[0] for m in msgs],
            "rejects": [{"msg": r[0], "agent": r[1], "reason": r[2]} for r in rejects if not r[2].startswith("copy:")]}


def _conflicts(nodes, resources, now, stale_after_s):
    result = {node["work"]: {} for node in nodes}
    by_resource, hosts, children = {}, {}, {}
    claimants = {node["work"]: node["claimant"] for node in nodes}
    for node in nodes:
        if not _freshness(node, now, stale_after_s)["claim_active"]:
            continue
        for resource in resources.get(node["work"], []):
            kind, host, _ = mv.resource_parts(resource)
            item = (node["work"], resource)
            by_resource.setdefault(resource, []).append(item)
            (hosts if kind == "host" else children).setdefault(host, []).append(item)

    def add(left, right):
        work, resource = left
        other_work, other_resource = right
        if work != other_work:
            result[work][(resource, other_work, other_resource)] = {
                "resource": resource, "other_work": other_work,
                "other_claimant": claimants[other_work], "other_resource": other_resource}

    for group in by_resource.values():
        for left in group:
            for right in group:
                add(left, right)
    for host, declarations in hosts.items():
        for left in declarations:
            for right in children.get(host, []):
                add(left, right)
                add(right, left)
    return {work: [items[key] for key in sorted(items)] for work, items in result.items()}


def digest(db, owner_root: str | None = None, *, now=None, stale_after_s=1800) -> list:
    now = _view_time(now, stale_after_s)
    query = db.execute("SELECT * FROM mesh_work ORDER BY updated_at DESC,work")
    names = [d[0] for d in query.description]
    nodes = [dict(zip(names, row)) for row in query.fetchall()]
    resources = {}
    for work, resource in db.execute("SELECT work,resource FROM mesh_resources ORDER BY work,resource"):
        resources.setdefault(work, []).append(resource)
    presence = {agent: (until, updated) for agent, until, updated in
                db.execute("SELECT agent,presence_until,updated_at FROM mesh_presence")}
    # Build conflicts globally before applying owner_root: another charter must
    # not hide a live claim on the same resource.
    conflicts = _conflicts(nodes, resources, now, stale_after_s)
    out = []
    for node in nodes:
        cite = node["owner_cite"]
        if owner_root and cite != owner_root:
            continue
        work, claimant, candidate = node["work"], node["claimant"], node["candidate_sha"]
        passes, objections = _review_state(db, work, candidate, claimant) if candidate else (0, [])
        out.append({"work": work, "state": node["state"], "claimant": claimant,
                    "candidate": candidate[:16] if candidate else None,
                    "pass_verdicts": passes, "objections": objections, "blocked_on": node["block_reason"],
                    "owner_cite": (cite + " (unverified)") if cite else None,
                    **_freshness(node, now, stale_after_s, presence.get(claimant)),
                    "resources": resources.get(work, []), "resource_conflicts": conflicts[work]})
    return out


CORE = ("work", "state", "version", "claimant", "lease_until", "candidate_sha", "block_reason", "last_seq")


def rebuild(db, limits, apply_changes: bool = False) -> dict:
    """Replay live bus rows into a scratch projection. Nodes whose messages all expired keep their stored row."""
    scratch = sqlite3.connect(":memory:")
    scratch.execute("CREATE TABLE messages (seq INTEGER PRIMARY KEY, id TEXT, sender TEXT, recipient TEXT, body TEXT,"
                    " created_at INTEGER, reply_to TEXT)")
    scratch.executemany("INSERT INTO messages VALUES(?,?,?,?,?,?,?)",
                        db.execute("SELECT seq, id, sender, recipient, body, created_at, reply_to FROM messages "
                                   "ORDER BY seq").fetchall())

    def fallback(key):
        if key.startswith("owner-root:"):
            root = key[len("owner-root:"):]
            return bool(db.execute("SELECT 1 FROM mesh_msgs WHERE cite=?", (root,)).fetchone())
        if key.startswith("owner-answer:"):  # this exact message was accepted as an unblock before its owner answer expired
            msg = key[len("owner-answer:"):]
            return bool(db.execute("SELECT 1 FROM mesh_msgs WHERE msg=? AND unblock=1", (msg,)).fetchone())
        return bool(db.execute("SELECT 1 FROM mesh_msgs WHERE msg=?", (key,)).fetchone())

    ensure_schema(db)
    project(scratch, limits, fallback)
    fresh = {r[0]: tuple(r) for r in scratch.execute(f"SELECT {','.join(CORE)} FROM mesh_work").fetchall()}
    stored = {r[0]: tuple(r) for r in db.execute(f"SELECT {','.join(CORE)} FROM mesh_work").fetchall()}
    diffs = [{"work": w, "stored": stored.get(w), "rebuilt": fresh[w]} for w in sorted(fresh) if stored.get(w) != fresh[w]]
    kept = sorted(set(stored) - set(fresh))
    resource_diffs = []
    for work in sorted(fresh):
        old = db.execute("SELECT resource FROM mesh_resources WHERE work=? ORDER BY resource", (work,)).fetchall()
        new = scratch.execute("SELECT resource FROM mesh_resources WHERE work=? ORDER BY resource", (work,)).fetchall()
        if [tuple(r) for r in old] != [tuple(r) for r in new]:
            resource_diffs.append({"work": work, "stored": [r[0] for r in old], "rebuilt": [r[0] for r in new]})
    if apply_changes and fresh:
        works = list(fresh)
        marks = ",".join("?" * len(works))
        msgs = [r[0] for r in db.execute(f"SELECT msg FROM mesh_msgs WHERE work IN ({marks})", works).fetchall()]
        db.execute(f"DELETE FROM mesh_work WHERE work IN ({marks})", works)
        db.execute(f"DELETE FROM mesh_msgs WHERE work IN ({marks})", works)
        db.execute(f"DELETE FROM mesh_rejects WHERE work IN ({marks})", works)
        db.execute(f"DELETE FROM mesh_resources WHERE work IN ({marks})", works)
        for chunk in range(0, len(msgs), 500):
            part = msgs[chunk:chunk + 500]
            db.execute(f"DELETE FROM mesh_edges WHERE child IN ({','.join('?' * len(part))})", part)
        for table in ("mesh_work", "mesh_msgs", "mesh_edges", "mesh_rejects", "mesh_resources"):
            rows = scratch.execute(f"SELECT * FROM {table}").fetchall()
            if rows:
                db.executemany(f"INSERT OR REPLACE INTO {table} VALUES({','.join('?' * len(rows[0]))})", rows)
        # A retained accepted presence may outlive its source message's TTL.
        # Merge maxima, as the incremental projection does, rather than deleting it.
        for agent, until, updated, seq in scratch.execute("SELECT * FROM mesh_presence"):
            db.execute("INSERT INTO mesh_presence VALUES(?,?,?,?) ON CONFLICT(agent) DO UPDATE SET "
                       "presence_until=MAX(mesh_presence.presence_until,excluded.presence_until), "
                       "updated_at=MAX(mesh_presence.updated_at,excluded.updated_at), "
                       "last_seq=MAX(mesh_presence.last_seq,excluded.last_seq)", (agent, until, updated, seq))
        _set_meta(db, "projected_seq", _meta(scratch, "projected_seq", 0))
    scratch.close()
    return {"diffs": diffs, "resource_diffs": resource_diffs,
            "kept_expired_nodes": kept, "applied": bool(apply_changes and fresh)}

if __name__ == "__main__":
    _integrity_require_config()
