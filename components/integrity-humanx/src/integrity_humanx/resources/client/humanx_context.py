"""humanx_context - read-only history for room arbiters (ON DEMAND, never pushed in the wake payload).

Reads the local replica of the bus (sqlite, mode=ro). Used only by room_tool.py `history`.
Model: the arbiter keeps work/topics.json (compact: id, topic, status, state, last ids) and pulls the messages of ONE topic
(or the last N, or the topic index) when it needs them. Every answer is bounded by HIST_LIMIT bytes (oldest messages dropped first).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import datetime
import os
import re
import sqlite3

OPERATOR = _hx_operator()
HIST_LIMIT = 16 * 1024
DEFAULT_N = 10
MAX_N = 40
CYR = re.compile("[А-Яа-яЁё]")
TEMA_RE = re.compile(r"^\s*Тема:\s*(.*)$")
# lines that must not be fed back to the arbiter as examples of a "good" answer (process narration / meta / escalation)
META_RE = re.compile(
    r"GROK\.md|GEMINI\.md|AGENTS\.md|CLAUDE\.md|room_tool|по инструкции|инструкци[яи] комнаты|"
    r"только чтени[ея]|я только чита|только читаю|heartbeat|копи[яюи] шины|"
    r"Повтор:|Поправка:|исправленная копия|эскалац", re.I)
MOJI_RE = re.compile(r"\?{3,}|\ufffd")
_MR_FLAG = re.compile(r"(?m)^[ \t]*\[HUMANX-MAXR v=1\][ \t]*(?:\r?\n|$)")
CORRUPT_NOTE = "[ответ повреждён кодировкой, не опирайся на него]"
NO_ANSWER = "(без ответа)"
EMPTY_NOTE = "(служебный ответ, текст убран)"
OPEN_WINDOW_S = 6 * 3600


def fmt_ts(ts):
    return datetime.datetime.fromtimestamp(int(ts)).strftime("%d.%m %H:%M")


def trim(s, n):
    s = (s or "").strip()
    return s if len(s) <= n else s[: max(0, n - 1)].rstrip() + "…"


def norm_title(t):
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def title_of(body):
    for line in (body or "").lstrip("\ufeff \t\r\n").split("\n", 3)[:2]:
        m = TEMA_RE.match(line)
        if m:
            return m.group(1).strip()[:120]
    return ""


def clean_arbiter(body):
    """Arbiter text for the dialogue: no 'Тема:' line (it goes to the header), no meta lines; mojibake -> None."""
    b = body or ""
    if MOJI_RE.search(b) and (not CYR.search(b) or b.count("?") >= 10):
        return None
    out = []
    for line in b.split("\n"):
        if TEMA_RE.match(line) or META_RE.search(line):
            continue
        out.append(line.rstrip())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def _connect(path):
    return sqlite3.connect("file:%s?mode=ro" % path.replace("\\", "/"), uri=True, timeout=5)


ROOM_PREFIX = _hx_room_prefix()


def _rows_to_msgs(rows, as_of=None):
    out = []
    for seq, mid, snd, rcp, body, rto, st, ts in rows:
        if as_of is not None and ts >= as_of:
            continue
        room = rcp if snd == OPERATOR else snd
        out.append({"seq": seq, "id": mid, "from": "operator" if snd == OPERATOR else "arbiter", "reply_to": rto,
                    "status": st, "ts": ts, "body": (_MR_FLAG.sub("", body).strip() if body and "[HUMANX-MAXR" in body else (body or "")), "room": room, "vendor": room.replace(ROOM_PREFIX, "")})
    return out


def load_room(path, addr, as_of=None):
    """All messages of ONE room (the operator <-> arbiter), ordered by seq. as_of: only created_at < as_of (replay)."""
    con = _connect(path)
    try:
        rows = con.execute(
            "SELECT seq,id,sender,recipient,body,reply_to,status,created_at FROM messages "
            "WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) ORDER BY seq",
            (OPERATOR, addr, addr, OPERATOR)).fetchall()
    finally:
        con.close()
    return _rows_to_msgs(rows, as_of)


def load_all(path, as_of=None):
    """Messages of ALL the operator rooms (gemini, grok, codex, claude), ordered by the global seq: a topic started with one
    vendor is readable by the others."""
    con = _connect(path)
    try:
        rows = con.execute(
            "SELECT seq,id,sender,recipient,body,reply_to,status,created_at FROM messages "
            "WHERE (sender=? AND recipient LIKE ?) OR (recipient=? AND sender LIKE ?) ORDER BY seq",
            (OPERATOR, ROOM_PREFIX + "%", OPERATOR, ROOM_PREFIX + "%")).fetchall()
    finally:
        con.close()
    return _rows_to_msgs(rows, as_of)


def topic_map(msgs):
    """message id -> topic title (from the arbiter's 'Тема:' lines; a the operator message takes the title of its last titled reply)."""
    by_id = {m["id"]: m for m in msgs}
    titles = {}
    for m in msgs:
        if m["from"] == "arbiter":
            t = title_of(m["body"])
            if t:
                titles[m["id"]] = t
                if m["reply_to"] in by_id:
                    titles[m["reply_to"]] = t
    for m in msgs:
        if m["from"] == "arbiter" and m["id"] not in titles and titles.get(m["reply_to"]):
            titles[m["id"]] = titles[m["reply_to"]]
    return titles


def render_msg(m, titles):
    i = m["id"][:8]
    t = titles.get(m["id"], "")
    if m["from"] == "operator":
        head = "#%s %s ОПЕРАТОР→%s" % (i, fmt_ts(m["ts"]), m.get("vendor", "?"))
        if m["reply_to"]:
            head += " (на #%s)" % m["reply_to"][:8]
        if t:
            head += " | тема: %s" % t
        body = (m["body"] or "").strip()
    else:
        head = "#%s %s АРБИТР[%s]" % (i, fmt_ts(m["ts"]), m.get("vendor", "?"))
        if m["reply_to"]:
            head += " ответ на #%s" % m["reply_to"][:8]
        if t:
            head += " | Тема: %s" % t
        c = clean_arbiter(m["body"])
        body = CORRUPT_NOTE if c is None else (c or EMPTY_NOTE)
    return head + "\n" + body


def build_topics(msgs, now):
    """Topics = messages grouped by 'Тема:' title; unanswered the operator messages are their own 'waiting' topic."""
    titles = topic_map(msgs)
    topics, order = {}, []
    for m in msgs:
        t = titles.get(m["id"])
        if t:
            key, title = norm_title(t), t
        elif m["from"] == "operator":
            key, title = "wait:" + m["id"], trim(m["body"], 60) or NO_ANSWER
        else:
            continue
        e = topics.get(key)
        if e is None:
            e = topics[key] = {"root": m["id"], "title": title, "n": 0, "first_ts": m["ts"], "last_ts": m["ts"],
                               "ids": [], "waiting": key.startswith("wait:")}
            order.append(key)
        e["n"] += 1
        e["ids"].append(m["id"])
        e["last_ts"] = max(e["last_ts"], m["ts"])
        e["title"] = title if not e["waiting"] else e["title"]
    res = [topics[k] for k in order]
    for e in res:
        e["status"] = "open" if (e["waiting"] or now - e["last_ts"] <= OPEN_WINDOW_S) else "done"
    return res


def headers_text(msgs, now):
    out = []
    for e in sorted(build_topics(msgs, now), key=lambda e: e["first_ts"]):
        out.append("- [%s] %s | корень #%s | сообщений: %d | последнее: %s" % (
            e["status"], e["title"], e["root"][:8], e["n"], fmt_ts(e["last_ts"])))
    return "\n".join(out)


def _bytes(s):
    return len(s.encode("utf-8"))


def resolve_topic(msgs, titles, key, topics=None):
    """key = topic id (root message id prefix, as in work/topics.json) or a part of the topic title.
    Members: messages carrying the topic title (arbiter 'Тема:' lines and the the operator messages they answer), the root message and
    the 'last' ids of the topics.json entry. Returns (title, members)."""
    key = str(key).strip()
    entry = None
    for e in topics or []:
        if isinstance(e, dict) and (str(e.get("id", "")).startswith(key) and len(key) >= 4 or norm_title(e.get("topic")) == norm_title(key)):
            entry = e
            break
    title = (entry or {}).get("topic") or ""
    pref = [str((entry or {}).get("id", ""))] + [str(x) for x in (entry or {}).get("last", []) or []]
    if not entry:
        root = [m for m in msgs if len(key) >= 4 and m["id"].startswith(key)]
        if root:
            title = titles.get(root[0]["id"], "")
            pref = [root[0]["id"]]
        else:
            title = key
    pref = [x for x in pref if len(x) >= 4]
    nt = norm_title(title)
    members = [m for m in msgs if (nt and norm_title(titles.get(m["id"], "")) == nt) or any(m["id"].startswith(x) for x in pref)]
    if not members and nt:
        members = [m for m in msgs if nt in norm_title(titles.get(m["id"], ""))]
    return title, members


def index_text(msgs, now, limit=6 * 1024):
    """One-time bootstrap for an empty topics.json: topics derived from the arbiter's 'Тема:' titles (the arbiter then merges them)."""
    out, size = [], 0
    for e in sorted(build_topics(msgs, now), key=lambda e: e["first_ts"]):
        line = "- id %s | %s | %s | сообщений %d | %s" % (e["root"][:8], e["status"], e["title"], e["n"], fmt_ts(e["last_ts"]))
        size += _bytes(line) + 1
        if size > limit:
            out.append("(список обрезан по лимиту)")
            break
        out.append(line)
    return "\n".join(out)


def build_context(msgs, before_seq=None, now=None, limit=HIST_LIMIT, topic=None, last_n=None, topics=None, index=False):
    """Bounded history. topic -> messages of that topic; index -> topic list; else the last last_n (default DEFAULT_N) messages.
    Returns {"mode", "title", "text", "bytes", "n_total", "n_shown", "truncated"}."""
    now = now if now is not None else (max([m["ts"] for m in msgs]) if msgs else 0)
    hist = [m for m in msgs if before_seq is None or m["seq"] < before_seq]
    titles = topic_map(hist)
    res = {"title": "", "n_total": len(hist), "truncated": False}
    if index:
        text = index_text(hist, now)
        res.update(mode="index", text=text, bytes=_bytes(text), n_shown=0)
        return res
    if topic:
        res["title"], shown = resolve_topic(hist, titles, topic, topics)
        res["mode"] = "topic"
        if last_n:
            shown = shown[-min(int(last_n), MAX_N):]
    else:
        shown = hist[-min(int(last_n or DEFAULT_N), MAX_N):]
        res["mode"] = "last"
    blocks = [render_msg(m, titles) for m in shown]
    while blocks and _bytes("\n\n".join(blocks)) > limit:
        blocks.pop(0)
        res["truncated"] = True
    text = "\n\n".join(blocks)
    res.update(text=text, bytes=_bytes(text), n_shown=len(blocks))
    return res
