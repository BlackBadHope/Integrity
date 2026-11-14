#!/usr/bin/python3 -I
# SPDX-License-Identifier: BUSL-1.1
"""bus_core_daemon - the LLM bus hub. Intended to run as a dedicated nologin user in a systemd sandbox
without network access (PrivateNetwork); see examples/systemd.

INVARIANT: through the service connection LLM clients can send and read messages, never execute code on the hub.
Mechanism:
  * the only entry is a unix socket with a fixed protocol (see OPS);
  * strict JSON: objects only, no duplicate keys, a whitelist of fields and types, size limits;
  * NO subprocess/os.system/eval/exec/templates/file paths taken from data - the server calls only
    bus library functions (bus.MessageStore, owner_verify, room_acl) with checked values;
  * a message body is an opaque string, stored and returned as is (JSON is parsed only to look for
    owner-signature fields in the owner gate and room_acl; that is reading data, not executing it);
  * identity: a vendor connecting over SSH is named by the gateway (bus-gateway; the socket checks
    SO_PEERCRED: the uid of the configured gateway user), a local client is identified by its key
    (sha256 in principals.json). The sender address always comes from the key.
A GO is only the owner's signature (owner gate inside MessageStore.post); no key replaces it.

Configuration: the integrity-llm-bus configuration (INTEGRITY_LLM_BUS_CONFIG) is required, because the bus
library modules read their state directory from it. Its `core_config` value (or BUS_CORE_CONF, which takes
precedence) names core.json (see examples/core.example.json). There are no built-in paths, users or groups.
"""
import hashlib, hmac, json, os, queue, re, socket, socketserver, struct, sys, threading, time
from pathlib import Path

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

HERE = os.path.dirname(os.path.abspath(__file__))
CONF = json.load(open(os.environ.get("BUS_CORE_CONF") or _integrity_value('core_config'), encoding="utf-8"))
sys.path.insert(0, CONF.get("bus_dir") or os.path.dirname(HERE)); sys.path.insert(0, HERE)
import bus, agent_registry, room_acl, bus_journal as J  # noqa: E402  (bus library code, room_acl included)

STATE = Path(CONF["state_dir"]); STORE = bus.MessageStore(STATE / "bus.sqlite3", CONF.get("ttl_hours", 168) * 3600)
try:  # without a configured gateway user the "vendor via SSH gateway" path is simply closed
    import pwd
    GW_UID = pwd.getpwnam(CONF["gateway_user"]).pw_uid if CONF.get("gateway_user") else None
except (ImportError, KeyError):
    GW_UID = None
ADDR = re.compile(r"[a-z0-9-]{2,32}\Z"); MID = bus.ID_RE
MAX_REQ = 300 * 1024; MAX_BODY = bus.MAX_BODY_BYTES
OPS = {  # op: ({field: (type, required)}, writes?)
    "send":       ({"to": (str, True), "id": (str, True), "body": (str, True), "reply_to": ((str, type(None)), False),
                    "delivery": (str, False), "as": (str, False),
                    "route_used": (str, False), "since": (int, False)}, True),
    "poll":       ({"as": (str, False), "limit": (int, False), "after_seq": (int, False)}, False),
    "get":        ({"as": (str, False), "id": (str, True)}, False),
    "ack":        ({"as": (str, False), "id": (str, True), "since": (int, False)}, True),
    "status":     ({"id": (str, True)}, False),
    "list-rooms": ({}, False),
    # reactivity: event stream without bodies, agent status, wake-attempt accounting
    "watch":         ({"addresses": (list, False)}, False),
    "agents-status": ({}, False),
    # route catalog exported from the action log (safe fields only) and hints for tasks
    "routes":        ({"query": (str, False), "limit": (int, False)}, False),
    "wake-log":      ({"to": (str, True), "id": (str, True), "adapter": (str, True), "result": (str, True),
                       "code": (int, False), "latency_ms": (int, False), "pending": (int, False)}, True),
    # a client's read-only replica catches up through the change log; the registry is written here
    "changes":       ({"since": (int, True), "limit": (int, False)}, False),
    "registry":      ({"fn": (str, True), "harness": (str, False), "identity": (str, False), "source": (str, False),
                       "vendor": ((str, type(None)), False), "model": ((str, type(None)), False), "topic": (str, False),
                       "address": (str, False), "thread": (str, False), "expected": ((str, type(None)), False),
                       "since": (int, False)}, True),
}
REGISTRY_FNS = {"ensure", "register", "alias"}
# human-operator room: choosing the room Arbiter among connected vendors, vendor cards, vendor heartbeats.
OPS.update({
    "room-arbiter":     ({}, False),
    "room-arbiter-set": ({"vendor": (str, True)}, True),
    "vendor-cards":     ({"days": (int, False)}, False),
    "status-batch":     ({"ids": (list, True)}, False),
    "vendor-heartbeat": ({"vendor": (str, True), "state": (str, True), "detail": (str, False),
                          "reset_at": ((int, float), False)}, True),
})
FAMILY_OF_VENDOR = {"anthropic": "claude", "openai": "codex", "google": "gemini", "xai": "grok"}
FAMILY_OF_HARNESS = {"claude": "claude", "codex": "codex", "antigravity": "gemini", "gemini": "gemini", "chatgpt": "chatgpt"}
FAMILY_OF_BUILTIN = {"claude": "claude", "codex": "codex", "codexfc": "codex", "grok": "grok"}
# tables a client replica receives through the change log (messages_archive and _repl_log stay on the hub)
REPL_TABLES = ("messages", "agents", "registry_meta", "owner_nonces", "mesh_edges", "mesh_meta", "mesh_msgs",
               "mesh_presence", "mesh_rejects", "mesh_resources", "mesh_work", "vendor_runtime_health")
HUB_DENY = re.compile(r"(owner|human-.*|room-.*|bus-relay)\Z")
WAKE_ADAPTERS = {"webhook", "flag", "steer", "pull"}
ROUTE_ID = re.compile(r"(none|[a-z0-9][a-z0-9._-]{1,63})\Z")
_routes = {"m": 0, "doc": None, "mod": None}
HINTS = {}           # msg_id -> [route_id, ...] (hints for a message; ids only)


def route_catalog():
    path = CONF.get("routes_catalog")
    if not path or not os.path.exists(path):
        return None, None
    m = os.stat(path).st_mtime
    if m != _routes["m"]:
        _routes["doc"] = json.load(open(path, encoding="utf-8")); _routes["m"] = m
        if _routes["mod"] is None and os.path.exists(CONF.get("routes_module", "")):
            import importlib.util
            spec = importlib.util.spec_from_file_location("uroboros_routes", CONF["routes_module"])
            mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); _routes["mod"] = mod
    return _routes["doc"], _routes["mod"]


def route_hints_for(text, limit=3):
    doc, mod = route_catalog()
    if not doc or not mod or not text:
        return []
    terms = re.findall(r"[\w.:@/-]{3,}", text.lower())[:mod.MAX_TERMS * 4]
    try:
        res = mod.build_known_routes(terms, doc["routes"], limit=limit)
    except Exception:
        return []
    out = []
    for r in res.get("routes", []) if isinstance(res, dict) else []:
        if r.get("source") == "explicit" and r.get("route_id"):
            out.append({"route_id": r["route_id"], "version": r.get("version"), "safety": r.get("safety") or "read",
                        "hint": mod.route_hint(r)})
    return out
WAKE_RESULTS = {"sent", "coalesced", "deduped", "rate-limited", "failed", "skipped"}
SUBS = []            # [(key, set(addresses) | None = all, Queue)]
LAST_ACT = {}        # address -> ts of the key's last activity
WAKES = {}           # address -> last wake attempt (metadata)
_lock = threading.Lock(); _rate = {}; _arate = {}; _pc = {"m": 0, "d": {}, "a": {}}
# Vendor account / subscription label: not a secret, only an identifier for accounting and quota.
VENDORS = {"claude", "codex", "antigravity", "grok", "bus", "human"}   # per-vendor route metric
ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{1,63}\Z")
SECRET_LIKE = re.compile(r"(?i)^(sk-|sk_|xox[abp]-|ghp_|gho_|github_pat_|AKIA|AIza|ya29\.|eyJ)|[A-Za-z0-9+/=_-]{40,}")


class Deny(Exception):
    pass


def principals():
    m = os.stat(CONF["principals"]).st_mtime
    if m != _pc["m"]:
        doc = json.load(open(CONF["principals"], encoding="utf-8"))
        _pc["d"] = doc["principals"]; _pc["a"] = doc.get("accounts", {}); _pc["m"] = m
    return _pc["d"]


def accounts():
    principals()
    return _pc["a"]


def strict_json(raw: bytes):
    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise Deny("duplicate JSON key")
            d[k] = v
        return d
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=hook, parse_constant=lambda c: (_ for _ in ()).throw(Deny("bad constant")))
    except (UnicodeDecodeError, ValueError) as e:
        raise Deny("invalid JSON") from e


def principal_for(req, peer_uid):
    if GW_UID is not None and peer_uid == GW_UID:
        name = req.get("vendor")
        if not isinstance(name, str) or not ADDR.match(name):
            raise Deny("gateway sent no valid vendor id")
        p = principals().get(name)
    else:
        tok = req.get("token")
        if not isinstance(tok, str):
            raise Deny("no key")
        h = hashlib.sha256(tok.encode()).hexdigest()
        name, p = next(((n, q) for n, q in principals().items() if hmac.compare_digest(q.get("key_sha256", "-"), h)), (None, None))
    if not p:
        raise Deny("unknown vendor key")
    if p.get("revoked"):
        raise Deny("key revoked")
    if p.get("expires") and time.time() > p["expires"]:
        raise Deny("key expired")
    if p.get("vendor") not in VENDORS:
        raise Deny("key has no valid vendor (claude|codex|antigravity|grok|bus|human)")
    acc = p.get("account")
    if not isinstance(acc, str) or not ACCOUNT.match(acc) or SECRET_LIKE.search(acc):
        raise Deny("key has no valid account label (account_id / subscription label, never a secret)")
    seats = (accounts().get(acc) or {}).get("seats")
    if seats is not None:
        active = sorted(n for n, q in principals().items() if q.get("account") == acc and not q.get("revoked"))
        if name not in active[:int(seats)]:
            raise Deny(f"account {acc}: seats limit {seats} exceeded")
    return name, p


def check_args(op, args):
    if op not in OPS:
        raise Deny("unknown op")
    spec, writes = OPS[op]
    if not isinstance(args, dict):
        raise Deny("args must be an object")
    extra = set(args) - set(spec)
    if extra:
        raise Deny(f"field not allowed: {sorted(extra)[0]}")
    for k, (typ, req) in spec.items():
        if req and k not in args:
            raise Deny(f"missing field: {k}")
        if k in args and (not isinstance(args[k], typ) or isinstance(args[k], bool)):
            raise Deny(f"bad type: {k}")
    for k in ("to", "as"):
        if k in args and not ADDR.match(args[k]):
            raise Deny(f"bad address: {k}")
    for k in ("id", "reply_to"):
        if isinstance(args.get(k), str) and not MID.fullmatch(args[k]):
            raise Deny(f"bad id: {k}")
    if "body" in args and len(args["body"].encode("utf-8")) > MAX_BODY:
        raise Deny("body too large")
    if "delivery" in args and args["delivery"] not in bus.DELIVERY_MODES:
        raise Deny("bad delivery")
    if "limit" in args and op != "changes" and not 1 <= args["limit"] <= 50:
        raise Deny("limit 1..50")
    if "after_seq" in args and args["after_seq"] < 0:
        raise Deny("after_seq >= 0")
    if "addresses" in args and (len(args["addresses"]) > 64 or not all(isinstance(a, str) and ADDR.match(a) for a in args["addresses"])):
        raise Deny("bad addresses")
    if "route_used" in args and not ROUTE_ID.match(args["route_used"]):
        raise Deny("bad route_used")
    if "query" in args and len(args["query"]) > 400:
        raise Deny("query too long")
    if op == "changes" and "limit" in args and not 1 <= args["limit"] <= 2000:
        raise Deny("limit 1..2000")
    if "since" in args and args["since"] < 0:
        raise Deny("since >= 0")
    if op == "registry":
        if args["fn"] not in REGISTRY_FNS:
            raise Deny("registry fn: ensure|register|alias")
        for k in ("harness", "identity", "source", "vendor", "model", "topic", "address", "thread", "expected"):
            if isinstance(args.get(k), str) and len(args[k]) > 200:
                raise Deny(f"too long: {k}")
        for k in ("address", "expected"):
            if isinstance(args.get(k), str) and not ADDR.match(args[k]):
                raise Deny(f"bad address: {k}")
    if op == "routes" and "limit" in args and not 1 <= args["limit"] <= 20:
        raise Deny("limit 1..20")
    if op == "wake-log" and (args["adapter"] not in WAKE_ADAPTERS or args["result"] not in WAKE_RESULTS):
        raise Deny("bad wake adapter/result")
    return writes


def publish(ev):
    """An event carries metadata only (id, from, to, time), never the body."""
    with _lock:
        subs = list(SUBS)
    for _name, addrs, q in subs:
        if addrs is None or ev.get("to") in addrs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass


def agents_status():
    now = int(time.time())
    with STORE._connection() as db:
        pend = dict(db.execute("SELECT recipient, count(*) FROM messages WHERE status='pending' GROUP BY recipient").fetchall())
        open_ = dict(db.execute("SELECT recipient, count(*) FROM messages WHERE status='acked' GROUP BY recipient").fetchall())
        sent = dict(db.execute("SELECT sender, max(created_at) FROM messages GROUP BY sender").fetchall())
        got = dict(db.execute("SELECT recipient, max(created_at) FROM messages GROUP BY recipient").fetchall())
    pr = principals()
    keyed = {a for q in pr.values() for a in q.get("addresses", [])}
    agents = []
    for a in sorted(set(pend) | set(sent) | set(LAST_ACT) | keyed | set(WAKES)):
        last = max(LAST_ACT.get(a, 0), sent.get(a) or 0)
        idle = now - last if last else None
        if idle is not None and idle < 120:
            state = "busy" if open_.get(a) else "online"
        elif pend.get(a):
            state = "waiting"
        else:
            state = "silent"
        agents.append({"address": a, "state": state, "idle_s": idle, "unread": pend.get(a, 0), "in_work": open_.get(a, 0),
                       "last_sent": sent.get(a), "last_received": got.get(a), "last_wake": WAKES.get(a)})
    with _lock:
        keys = [{"key": n, "account": q.get("account"), "role": q.get("role"), "addresses": q.get("addresses", []),
                 "revoked": bool(q.get("revoked")), "expires": q.get("expires"),
                 "expires_in_s": (int(q["expires"] - now) if q.get("expires") else None),
                 "rate_per_min": q.get("rate_per_min", 30),
                 "used_last_min": len([t for t in _rate.get(n, []) if now - t < 60])} for n, q in pr.items()]
        accs = {}
        for k in keys:
            a = accs.setdefault(k["account"] or "(none)", {"keys": 0, **(accounts().get(k["account"]) or {})})
            a["keys"] += 1
        for acc, a in accs.items():
            a["used_last_min"] = len([t for t in _arate.get(acc, []) if now - t < 60])
    return {"ts": now, "agents": agents, "keys": keys, "accounts": accs}


def room_cfg():
    """The room installed by the operator: <state>/room.json (shared with room_acl)."""
    return room_acl.room_config(STATE)


def room_human():
    """The human-operator address of the room, or None when no room is installed."""
    h = room_cfg().get("human")
    return h if isinstance(h, str) and h.startswith(room_acl.HUMAN_PREFIX) and ADDR.match(h) else None


def is_room_vendor(addr):
    return isinstance(addr, str) and addr.startswith(room_acl.WORKER_PREFIX)


def room_arbiter():
    try:
        return json.load(open(STATE / "room-arbiter.json", encoding="utf-8"))
    except (OSError, ValueError):
        return None


def arbiter_set(p, vendor, who):
    arb = room_cfg().get("arbiters", {})
    c = arb.get(vendor)
    if not c:
        raise Deny("unknown room Arbiter candidate")
    if not c.get("ro_verified"):
        # the read-only mechanism of this vendor was not verified on a stand: it cannot be the room Arbiter
        raise Deny(f"{vendor}: read-only mechanism not verified, cannot be room Arbiter")
    prev = room_arbiter()
    doc = {"arbiter": vendor, "address": c["address"], "ro": c.get("ro"), "set_by": who, "ts": int(time.time()),
           "previous": prev.get("arbiter") if prev else None}
    tmp = STATE / "room-arbiter.json.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    os.replace(tmp, STATE / "room-arbiter.json")
    publish({"event": "arbiter", "arbiter": vendor, "to": c["address"], "previous": doc["previous"], "ts": doc["ts"]})
    return doc


def address_families():
    fam = dict(FAMILY_OF_BUILTIN)
    with STORE._connection() as db:
        for a, v, h in db.execute("SELECT address, vendor, harness FROM agents"):
            f = FAMILY_OF_VENDOR.get(v or "") or FAMILY_OF_HARNESS.get(h or "")
            if f:
                fam[a] = f
    for v, c in room_cfg().get("arbiters", {}).items():
        fam[c["address"]] = v
    return fam


def vendor_health_record(vendor, state, detail="", reset_at=0.0):
    now = time.time()
    with STORE._connection() as db:
        db.execute("INSERT INTO vendor_runtime_health(vendor, state, detail, reset_at, updated_at) "
                   "VALUES(?, ?, ?, ?, ?) "
                   "ON CONFLICT(vendor) DO UPDATE SET state=excluded.state, detail=excluded.detail, "
                   "reset_at=excluded.reset_at, updated_at=excluded.updated_at",
                   (vendor, state, str(detail)[:240], float(reset_at or 0.0), now))


def vendor_health_get(vendor):
    now = time.time()
    with STORE._connection() as db:
        row = db.execute("SELECT state, detail, reset_at, updated_at FROM vendor_runtime_health WHERE vendor=?",
                         (vendor,)).fetchone()
    if not row:
        return "waker_offline", "no heartbeat received", 0.0
    st, det, rst, upd = row
    if now - upd > 180:
        return "waker_offline", f"heartbeat expired ({int(now - upd)}s ago)", rst
    if st == "quota_exhausted" and rst and rst < now:
        return "ready", "quota reset time passed", 0.0
    return st, det or "", rst or 0.0


def account_quota(accs, keys, now):
    """(exhausted, note) from the manual account flag. A flag without a future reset_at has no effect:
    otherwise a card would stay "exhausted" forever over a fresh waker heartbeat."""
    for n, q in keys:
        a = accs.get(q.get("account")) or {}
        if not a.get("quota_exhausted"):
            continue
        try:
            rst = float(a.get("reset_at") or 0.0)
        except (TypeError, ValueError):
            rst = 0.0
        if rst > now:
            return True, a.get("tokens_note", "")
    return False, ""


_cards = {"ts": 0, "days": None, "doc": None}


def vendor_cards(days=7):
    """Room Arbiter candidate cards from the bus archive (messages_archive, no TTL) and principals.
    Metrics count only the room's tasks (from the human-operator address to its room-* vendor).
    Button availability (gate/selectable) considers the key, the read-only verification and the waker's runtime health."""
    now = int(time.time())
    if _cards["doc"] and _cards["days"] == days and now - _cards["ts"] < 15:
        return _cards["doc"]
    since = now - days * 86400
    cfg = room_cfg().get("arbiters", {})
    cur = room_arbiter()
    human = room_human()
    pr, accs = principals(), accounts()

    stats = {}
    with STORE._connection() as db:
        for v, c in cfg.items():
            addr = c["address"]
            t_rows = db.execute(
                "SELECT id, created_at FROM messages_archive WHERE sender = ? AND recipient = ? "
                "AND reply_to IS NULL AND created_at >= ?", (human, addr, since)
            ).fetchall() if human else []
            first = dict(db.execute(
                "SELECT reply_to, MIN(created_at) FROM messages_archive WHERE sender = ? AND reply_to IS NOT NULL "
                "AND created_at >= ? GROUP BY reply_to", (addr, since)
            ).fetchall())
            tasks_count = len(t_rows)
            done_count = 0
            lat = []
            for mid, ts in t_rows:
                r_ts = first.get(mid)
                if r_ts is not None and r_ts - ts <= 86400:
                    done_count += 1
                    lat.append(r_ts - ts)
            lat.sort()
            stats[v] = {"tasks": tasks_count, "done": done_count, "lat": lat}

        sent = db.execute("SELECT sender, count(*), sum(length(body)) FROM messages_archive WHERE created_at >= ? GROUP BY sender",
                          (since,)).fetchall()
        usage = {}
        for snd, n, b in sent:
            for v, c in cfg.items():
                if snd == c["address"]:
                    u = usage.setdefault(v, {"messages": 0, "bytes": 0})
                    u["messages"] += n
                    u["bytes"] += b or 0

    try:
        evals = json.load(open(STATE / "vendor-eval.json", encoding="utf-8"))
    except (OSError, ValueError):
        evals = {}

    cards = []
    for v in sorted(cfg.keys()):
        c_info = cfg[v]
        addr = c_info["address"]
        s = stats.get(v, {"tasks": 0, "done": 0, "lat": []})
        lat = s["lat"]

        keys = [(n, q) for n, q in pr.items() if q.get("vendor") == v or addr in q.get("addresses", [])]
        health = []
        for n, q in keys:
            exp = q.get("expires")
            used = len([t for t in _rate.get(n, []) if now - t < 60])
            st = "revoked" if q.get("revoked") else ("expired" if exp and exp < now else
                 ("expiring" if exp and exp - now < 7 * 86400 else q.get("state", "ok")))
            health.append({"key": n, "revoked": bool(q.get("revoked")), "expires_in_s": int(exp - now) if exp else None,
                           "rate_used_min": used, "rate_limit_min": int(q.get("rate_per_min", 30)),
                           "state": st})

        has_room_key = any(h["state"] == "ok" for h in health)
        runtime_state, runtime_detail, reset_at = vendor_health_get(v)
        ro_ok = bool(c_info.get("ro_verified"))

        # account-level quota check (manual flag in principals.json; effective only until its reset_at)
        acc_exhausted, acc_note = account_quota(accs, keys, now)

        if acc_exhausted and runtime_state != "quota_exhausted":
            runtime_state = "quota_exhausted"
            runtime_detail = acc_note or runtime_detail

        if runtime_state == "quota_exhausted":
            gate = "amber"
            selectable = False
            gate_reason = f"Лимит провайдера исчерпан: {runtime_detail}"
        elif not has_room_key:
            gate = "red"
            selectable = False
            gate_reason = "Нет активного ключа комнаты на ядре (no-key)"
        elif not ro_ok:
            gate = "red"
            selectable = False
            gate_reason = c_info.get("ro_gap") or "Механизм «только чтение» не подтверждён"
        elif runtime_state == "waker_offline":
            gate = "amber"
            selectable = False
            gate_reason = f"Будильник офлайн: {runtime_detail}"
        elif runtime_state == "ready":
            gate = "green"
            selectable = True
            gate_reason = c_info.get("ro_evidence") or "Режим «только чтение» подтверждён"
        else:
            gate = "red"
            selectable = False
            gate_reason = f"Статус: {runtime_state} ({runtime_detail})"

        quota = None
        for n, q in keys:
            a = accs.get(q.get("account")) or {}
            if a.get("weekly_messages") or a.get("tier"):
                used_msgs = usage.get(v, {}).get("messages", 0)
                limit_msgs = a.get("weekly_messages")
                pct_val = round((used_msgs / limit_msgs) * 100, 1) if limit_msgs else 0.0
                quota = {
                    "account": q.get("account"),
                    "provider": a.get("provider", ""),
                    "tier": a.get("tier", ""),
                    "tokens_note": a.get("tokens_note", ""),
                    "token_limits": a.get("token_limits", {}),
                    "limit": limit_msgs,
                    "used": used_msgs,
                    "pct": pct_val
                }

        cards.append({
            "vendor": v,
            "address": addr,
            "selected": bool(cur and cur.get("arbiter") == v),
            "ro": c_info.get("ro"),
            "ro_verified": ro_ok,
            "selectable": selectable,
            "gate": gate,
            "gate_reason": gate_reason,
            "runtime_state": runtime_state,
            "runtime_detail": runtime_detail,
            "reset_at": reset_at,
            "token_health": health or [{"state": "no-key"}],
            "tasks": s["tasks"],
            "success_rate": round(s["done"] / s["tasks"], 3) if s["tasks"] else None,
            "median_reply_s": lat[len(lat) // 2] if lat else None,
            "p90_reply_s": lat[int(len(lat) * 0.9)] if lat else None,
            "bus_usage_week": usage.get(v, {"messages": 0, "bytes": 0}),
            "weekly_quota": quota or {"limit": None, "note": "quota of the provider is not visible to the bus"},
            "eval": evals.get(v)
        })

    doc = {
        "ts": now,
        "days": days,
        "arbiter": cur,
        "cards": cards,
        "method": "tasks = messages from the room's human-* address to its room-* vendor; success = reply within 24h"
    }
    _cards.update(ts=now, days=days, doc=doc)
    return doc


def acting_address(p, args):
    addrs = p.get("addresses", [])
    a = args.get("as") or (addrs[0] if addrs else None)
    if p.get("role") == "hub" and p.get("any_address") and isinstance(a, str) and ADDR.match(a):
        # a client hub key keeps the rights local processes had before the move (any registry address),
        # except owner (only the owner-console key + owner signature), the room and the system bus-relay
        if HUB_DENY.match(a):
            raise Deny("hub key may not act as owner / human-* / room-* / bus-relay")
        return a
    if a not in addrs:
        raise Deny("address is not granted to this key")
    if a == "owner" and p.get("role") != "owner-console":
        raise Deny("owner address only for the owner-console key")
    return a


def execute(name, p, op, args):
    writes = check_args(op, args)
    if op not in p.get("ops", []):
        raise Deny(f"op {op} not granted to this key")
    if writes and not p.get("write"):
        raise Deny("read-only key")
    if "since" in args and p.get("role") not in ("hub", "owner-console"):
        # since returns changes of the WHOLE database (other agents' bodies): only for client replicas
        raise Deny("since (replica changes) only for the hub / owner-console key")
    now = time.time(); acc = p["account"]; alim = (accounts().get(acc) or {}).get("rate_per_min")
    with _lock:
        w = [t for t in _rate.get(name, []) if now - t < 60]
        if len(w) >= int(p.get("rate_per_min", 30)):
            raise Deny("rate limit")
        aw = [t for t in _arate.get(acc, []) if now - t < 60]
        if alim is not None and len(aw) >= int(alim):
            raise Deny(f"account {acc}: rate limit")
        w.append(now); _rate[name] = w; aw.append(now); _arate[acc] = aw
    for a in p.get("addresses", []):
        LAST_ACT[a] = int(now)
    if op == "agents-status":
        if p.get("role") != "observer":
            raise Deny("agents-status only for the observer key")
        return agents_status()
    if op == "wake-log":
        if p.get("role") != "waker":
            raise Deny("wake-log only for the waker key")
        rec = {k: args[k] for k in ("adapter", "result", "code", "latency_ms", "pending", "id") if k in args}
        rec["ts"] = int(now)
        WAKES[args["to"]] = rec
        publish({"event": "wake", "to": args["to"], **rec})
        return {"logged": True}
    if op == "routes":
        doc, mod = route_catalog()
        if not doc:
            raise Deny("route catalog not available")
        if args.get("query"):
            return {"source": doc["source"], "seed_max_event_id": doc["seed_max_event_id"],
                    "routes": route_hints_for(args["query"], args.get("limit", 5))}
        return {"source": doc["source"], "seed_max_event_id": doc["seed_max_event_id"], "exported_at": doc["exported_at"],
                "routes": [e["details"]["uroboros_route"] | {"event_id": e["id"]} for e in doc["routes"]][: args.get("limit", 20)]}
    if op == "list-rooms":
        return {"addresses": p.get("addresses", []), "agents": list(agent_registry.all_agents(STATE))}
    if op == "changes":
        if p.get("role") != "hub":
            raise Deny("changes only for the hub (replica) key")
        return repl_changes(args["since"], args.get("limit", 500))
    if op == "registry":
        if p.get("role") != "hub":
            raise Deny("registry only for the hub key")
        import autoreg
        fn = args["fn"]
        if fn == "ensure":
            res = autoreg.ensure(args.get("harness", ""), args.get("identity", ""), source=args.get("source", "bus-core"),
                                 vendor=args.get("vendor"), model=args.get("model"), topic=args.get("topic", ""),
                                 state_dir=STATE)
        elif fn == "register":
            entry, existing = agent_registry.register(args.get("address", ""), args.get("thread", ""),
                                                      args.get("harness", "codex"), args.get("topic", ""), STATE)
            res = {"entry": entry, "existing": existing}
        else:
            res = agent_registry.set_claude_alias(args.get("address", ""), args.get("expected"), STATE)
        publish({"event": "registry", "fn": fn, "ts": int(time.time())})
        out = {"registry": res}
        if "since" in args:
            out["changes"] = repl_changes(args["since"])
        return out
    if op in ("room-arbiter", "room-arbiter-set", "vendor-cards"):
        addrs = set(p.get("addresses", []))
        human_addr = room_human()
        human = bool(human_addr and human_addr in addrs)
        if op == "room-arbiter-set":
            if not (human or p.get("role") == "owner-console"):
                raise Deny("room Arbiter is chosen only by the room's human-* address or the owner console")
            return arbiter_set(p, args["vendor"], human_addr if human else "owner")
        room_vendor = any(is_room_vendor(a) for a in addrs)
        if not (human or room_vendor or p.get("role") in ("owner-console", "observer")):
            raise Deny(f"{op} only for the room, the owner console or the observer")
        if op == "room-arbiter":
            return {"arbiter": room_arbiter(), "candidates": {v: {k: c.get(k) for k in ("address", "ro", "ro_verified")}
                                                              for v, c in room_cfg().get("arbiters", {}).items()}}
        d = args.get("days", 7)
        if not 1 <= d <= 30:
            raise Deny("days 1..30")
        return vendor_cards(d)
    if op == "status":
        st = msg_status(args["id"])   # own copy of local_cli.status: local_cli pulls in reachability (subprocess)
        m = st.get("message")
        if m and m["from"] not in p.get("addresses", []) and m["to"] not in p.get("addresses", []):
            raise Deny("status only for own messages")
        return st
    if op == "status-batch":
        ids = [str(x) for x in (args.get("ids") or [])[:100] if isinstance(x, str)]
        res = {}
        if ids:
            placeholders = ",".join("?" for _ in ids)
            with STORE._connection() as db:
                rows = db.execute(f"SELECT id, status FROM messages WHERE id IN ({placeholders})", ids).fetchall()
                res = {r[0]: r[1] for r in rows}
        return {"ok": True, "statuses": res}
    if op == "vendor-heartbeat":
        role = p.get("role")
        addrs = set(p.get("addresses", []))
        if role not in ("admin", "operator", "waker", "room-vendor", "owner-console") and not any(is_room_vendor(a) for a in addrs):
            raise Deny("vendor-heartbeat not allowed for this key")
        v = args["vendor"]
        if p.get("role") == "room-vendor" and p.get("vendor"):
            raw_v = p.get("vendor")
            v = FAMILY_OF_HARNESS.get(raw_v) or FAMILY_OF_VENDOR.get(raw_v) or raw_v
        vendor_health_record(v, args["state"], args.get("detail", ""), args.get("reset_at", 0.0))
        publish({"event": "vendor-heartbeat", "vendor": v, "state": args["state"], "ts": int(time.time())})
        return {"ok": True, "vendor": v, "state": args["state"]}
    me = acting_address(p, args)
    human_addr = room_human()
    if op == "send":
        if human_addr and me == human_addr and args["to"] != "owner":
            cur = room_arbiter()
            if not cur:
                raise Deny("no room Arbiter selected: the human-* address writes only to the owner")
            if args["to"] != cur["address"]:
                raise Deny("the human-* address writes only to the selected room Arbiter")
        msg = {"id": args["id"], "from": me, "to": args["to"], "body": args["body"], "reply_to": args.get("reply_to")}
        if "delivery" in args:
            msg["delivery"] = args["delivery"]
        bus._validate_message(msg, me, STATE)
        row, dup = STORE.post(msg)  # owner gate (owner signature) and room_acl run inside post
        hints = []
        if not dup:
            if args["to"] != "owner":
                hints = route_hints_for(args["body"])   # the body is read as data to pick a hint
                if hints:
                    HINTS[row["id"]] = [h["route_id"] for h in hints]
            publish({"event": "message", "id": row["id"], "from": row["from"], "to": row["to"],
                     "room_arbiter": bool(human_addr and me == human_addr and row["to"] != "owner"),
                     "reply_to": row.get("reply_to"), "delivery": row.get("delivery"), "ts": int(time.time()),
                     "route_hints": HINTS.get(row["id"], [])})
        out = {"message": {k: v for k, v in row.items() if k != "body"}, "duplicate": dup,
               "route_used": args.get("route_used"), "route_hints": [h["route_id"] for h in hints]}
        if not dup:
            out["mesh_projection"] = mesh_project()
        if "since" in args:
            out["changes"] = repl_changes(args["since"])
        return out
    if op == "poll":
        page = bus.queue_page(STORE, me, args.get("limit", 20), args.get("after_seq", 0))
        for item in page.get("queue", []) if isinstance(page, dict) else []:
            if HINTS.get(item.get("id")):
                item["route_hints"] = HINTS[item["id"]]
        return page
    if op == "get":
        with STORE._connection() as db:
            row = db.execute("SELECT * FROM messages WHERE id=? AND recipient=?", (args["id"], me)).fetchone()
        if row is None:
            raise Deny("message not found for this recipient")
        m = bus._row(row)
        hints = route_hints_for(m["body"])
        return {"message": m, "route_hints": hints}
    if op == "ack":
        r = STORE.ack(args["id"], me)
        if r is None:
            raise Deny("message not found for this recipient")
        publish({"event": "ack", "id": args["id"], "to": r["from"], "by": me, "ts": int(time.time())})
        out = {"message": {k: v for k, v in r.items() if k != "body"}}
        if "since" in args:
            out["changes"] = repl_changes(args["since"])
        return out


def repl_setup():
    """Change log for client replicas: triggers on every replicated table (rowid + kind of change)."""
    with STORE._connection() as db:
        db.execute("CREATE TABLE IF NOT EXISTS vendor_runtime_health ("
                   "vendor TEXT PRIMARY KEY, state TEXT NOT NULL, detail TEXT, "
                   "reset_at REAL, updated_at REAL NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS _repl_log(v INTEGER PRIMARY KEY AUTOINCREMENT, t TEXT NOT NULL, "
                   "rid INTEGER NOT NULL, op TEXT NOT NULL)")
        have = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "messages" in have and "messages_archive" not in have:
            # A new hub has no history moved in by migrate.py; vendor-cards still reads the archive.
            import migrate
            db.executescript(migrate.ARCHIVE)
        for t in REPL_TABLES:
            if t not in have:
                continue
            db.execute(f"CREATE TRIGGER IF NOT EXISTS _repl_{t}_ai AFTER INSERT ON {t} BEGIN "
                       f"INSERT INTO _repl_log(t,rid,op) VALUES('{t}', NEW.rowid, 'u'); END")
            db.execute(f"CREATE TRIGGER IF NOT EXISTS _repl_{t}_au AFTER UPDATE ON {t} BEGIN "
                       f"INSERT INTO _repl_log(t,rid,op) SELECT '{t}', OLD.rowid, 'd' WHERE OLD.rowid <> NEW.rowid; "
                       f"INSERT INTO _repl_log(t,rid,op) VALUES('{t}', NEW.rowid, 'u'); END")
            db.execute(f"CREATE TRIGGER IF NOT EXISTS _repl_{t}_ad AFTER DELETE ON {t} BEGIN "
                       f"INSERT INTO _repl_log(t,rid,op) VALUES('{t}', OLD.rowid, 'd'); END")
        db.execute("DELETE FROM _repl_log WHERE v < (SELECT COALESCE(MAX(v),0) FROM _repl_log) - 200000")


def repl_changes(since, limit=500, max_bytes=8 * 1024 * 1024):
    """Changes after cursor `since`: the whole row for 'u', only the rowid for 'd'.
    Read in one read transaction (consistent WAL snapshot)."""
    out, size, more = [], 0, False
    with STORE._connection() as db:
        db.execute("BEGIN")
        head = db.execute("SELECT COALESCE(MAX(v),0) FROM _repl_log").fetchone()[0]
        rows = db.execute("SELECT v, t, rid, op FROM _repl_log WHERE v > ? ORDER BY v LIMIT ?", (since, limit + 1)).fetchall()
        if len(rows) > limit:
            rows, more = rows[:limit], True
        cursor = since
        for v, t, rid, op in rows:
            if t not in REPL_TABLES:
                cursor = v
                continue
            ch = {"v": v, "t": t, "rid": rid, "op": op}
            if op == "u":
                r = db.execute(f'SELECT rowid AS "__rowid__", * FROM {t} WHERE rowid = ?', (rid,)).fetchone()
                if r is None:
                    ch["op"] = "d"
                else:
                    ch["row"] = dict(r)
            size += len(json.dumps(ch, ensure_ascii=False, default=str))
            if out and size > max_bytes:
                more = True
                break
            out.append(ch)
            cursor = v
    return {"cursor": cursor, "head": head, "more": more, "changes": out}


def msg_status(mid):
    def summary(m):
        r = {k: v for k, v in m.items() if k != "body"}
        r["body_sha256"] = hashlib.sha256(m["body"].encode("utf-8")).hexdigest()
        return r
    with STORE._connection() as db:
        row = db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        replies = db.execute("SELECT * FROM messages WHERE reply_to=? ORDER BY seq", (mid,)).fetchall()
    return {"message": summary(bus._row(row)) if row else None, "replies": [summary(bus._row(x)) for x in replies]}


def mesh_project():
    """The agent-mesh/1 projection is rebuilt on the hub after every write (clients no longer write it)."""
    try:
        import mesh_store as MS
        with STORE._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            MS.project(db, MS.load_limits(STATE))
        return "ok"
    except Exception as e:  # the projection is derived data; an error does not undo the stored message
        return f"error: {type(e).__name__}: {str(e)[:120]}"


class H(socketserver.StreamRequestHandler):
    def handle(self):
        cred = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", cred)
        raw = self.rfile.readline(MAX_REQ + 1)
        meta = {"peer_uid": uid}
        try:
            if len(raw) > MAX_REQ:
                raise Deny("request too large")
            req = strict_json(raw)
            if not isinstance(req, dict) or set(req) - {"v", "op", "vendor", "token", "args"} or req.get("v") != 1:
                raise Deny("bad envelope")
            if uid != GW_UID and "vendor" in req:
                raise Deny("only the SSH gateway may name a vendor")
            name, p = principal_for(req, uid)
            meta.update(principal=name, vendor=p.get("vendor"), account=p.get("account"), op=req.get("op"))
            args = req.get("args", {})
            if isinstance(args, dict):
                meta.update({k: args.get(k) for k in ("to", "as", "id", "reply_to") if k in args})
                if isinstance(args.get("route_used"), str):
                    meta["route_used"] = args["route_used"]
                if isinstance(args.get("body"), str):
                    meta.update(body_sha256=hashlib.sha256(args["body"].encode()).hexdigest(), body_bytes=len(args["body"].encode()))
            if req.get("op") == "watch":
                return self.watch(name, p, args, meta)
            out = execute(name, p, req.get("op"), args)
            J.append(CONF["journal_dir"], dict(meta, verdict="ok")); resp = {"ok": True, "result": out}
        except Deny as e:
            J.append(CONF["journal_dir"], dict(meta, verdict="denied", reason=str(e))); resp = {"ok": False, "error": str(e)}
        except Exception as e:  # bus library errors (owner gate, room_acl, validation) are refusals too
            J.append(CONF["journal_dir"], dict(meta, verdict="rejected", reason=f"{type(e).__name__}: {str(e)[:160]}"))
            resp = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:300]}"}
        self.wfile.write((json.dumps(resp, ensure_ascii=False, default=str) + "\n").encode())


    def watch(self, name, p, args, meta):
        check_args("watch", args)
        if "watch" not in p.get("ops", []):
            raise Deny("op watch not granted to this key")
        if p.get("watch_any") and p.get("role") in ("observer", "waker", "hub"):
            addrs = set(args["addresses"]) if args.get("addresses") else None
        else:
            own = set(p.get("addresses", []))
            addrs = set(args.get("addresses") or own)
            if not addrs <= own:
                raise Deny("watch only own addresses")
        with _lock:
            if sum(1 for n, _a, _q in SUBS if n == name) >= 4:
                raise Deny("too many watch streams for this key")
            q = queue.Queue(maxsize=1000)
            SUBS.append((name, addrs, q))
        label = sorted(addrs) if addrs else "*"
        J.append(CONF["journal_dir"], dict(meta, verdict="watch-start", addresses=label))
        try:
            self.wfile.write((json.dumps({"ok": True, "event": "hello", "addresses": label}) + "\n").encode())
            self.wfile.flush()
            while True:
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    ev = {"event": "hb", "ts": int(time.time())}
                self.wfile.write((json.dumps(ev, ensure_ascii=False) + "\n").encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _lock:
                SUBS[:] = [x for x in SUBS if x[2] is not q]
            J.append(CONF["journal_dir"], dict(meta, verdict="watch-end"))


class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


if __name__ == "__main__":
    _integrity_require_config()
    import grp
    sock = CONF["socket"]
    try: os.unlink(sock)
    except FileNotFoundError: pass
    old = os.umask(0o117); srv = S(sock, H); os.umask(old)
    gid = grp.getgrnam(CONF["socket_group"]).gr_gid
    os.chown(sock, -1, gid); os.chmod(sock, 0o660)
    # socket directory (systemd RuntimeDirectory): the gateway group must be able to enter it
    d = os.path.dirname(sock); os.chown(d, -1, gid); os.chmod(d, 0o750)
    repl_setup()
    J.append(CONF["journal_dir"], {"verdict": "service-start"})
    srv.serve_forever()
