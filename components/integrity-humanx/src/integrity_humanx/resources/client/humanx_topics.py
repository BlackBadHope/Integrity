"""humanx_topics - ONE vendor-neutral topics state for the operator's room, shared by every arbiter (gemini, grok, codex, claude).

Single source of truth: <pilot>/shared/operator-topics.json  {"rev": N, "topics": [record, ...]}
Record: id (first 8 chars of the topic's first message id), topic (== text after 'Тема:' in the replies), status (open|done),
state (<=160 chars: what is established / what the operator waits for), last (<=3 ids of the latest messages), arbiter (vendor that last
answered; set by the tool, not by the model), updated (ISO, minutes).
Writes: lock file + temp file + os.replace (atomic), merge-by-id upserts (no lost updates between vendors), limits 25 topics / 8 KB:
over the limit the oldest `done` topics move to <pilot>/shared/operator-topics-archive.jsonl; if only open topics remain the write is refused.
Used by room_tool.py ops topics_get / topics_put and by the wakers (count/size only).
"""
import datetime
import json
import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SHARED = os.environ.get("HUMANX_SHARED_DIR", os.path.join(HERE, "shared"))
FILE = os.path.join(SHARED, "operator-topics.json")
ARCHIVE = os.path.join(SHARED, "operator-topics-archive.jsonl")
LOCK = os.path.join(SHARED, ".operator-topics.lock")
MAX_TOPICS = 25
MAX_BYTES = 8192
TOPIC_MAX = 120
STATE_MAX = 160
LAST_MAX = 3
ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z_-]{3,35}")
BAD_TEXT = re.compile(r"\?{3,}|\ufffd")


class TopicsError(ValueError):
    pass


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M")


def _dump(obj):
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def norm(t):
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def load():
    """-> {"rev": int, "topics": [...]}; missing/corrupt file -> empty rev 0 (corrupt raises TopicsError)."""
    try:
        with open(FILE, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return {"rev": 0, "topics": []}
    try:
        d = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(d, dict) or not isinstance(d.get("topics"), list):
            raise ValueError("bad shape")
        return {"rev": int(d.get("rev", 0)), "topics": d["topics"]}
    except (ValueError, UnicodeDecodeError) as e:
        raise TopicsError("operator-topics.json повреждён: %s" % str(e)[:80])


def info():
    """For the wakers: (status, count, bytes). Never raises."""
    try:
        raw = os.path.getsize(FILE) if os.path.exists(FILE) else 0
        d = load()
        return ("ok" if d["topics"] else "empty"), len(d["topics"]), raw
    except Exception:
        return "invalid", 0, 0


def validate(rec, vendor, warnings, keep_updated=False):
    if not isinstance(rec, dict):
        raise TopicsError("запись темы должна быть объектом")
    rid = str(rec.get("id", "")).strip()
    if not ID_RE.fullmatch(rid):
        raise TopicsError("id темы: 4-36 символов [0-9A-Za-z_-] (первые 8 символов id первого письма темы), получено %r" % rid[:40])
    topic = re.sub(r"\s+", " ", str(rec.get("topic", "")).strip())
    if not topic:
        raise TopicsError("topic пустой (id %s)" % rid)
    if BAD_TEXT.search(topic) or BAD_TEXT.search(str(rec.get("state", ""))):
        raise TopicsError("в тексте темы '???' или U+FFFD: кодировка потеряна при записи файла (пиши UTF-8). Ничего не записано.")
    if len(topic) > TOPIC_MAX:
        topic = topic[:TOPIC_MAX].rstrip()
        warnings.append("topic %s обрезан до %d символов" % (rid[:8], TOPIC_MAX))
    status = str(rec.get("status", "open")).strip().lower()
    if status not in ("open", "done"):
        raise TopicsError("status: open или done, получено %r" % status[:20])
    state = re.sub(r"\s+", " ", str(rec.get("state", "")).strip())
    if len(state) > STATE_MAX:
        state = state[:STATE_MAX - 1].rstrip() + "…"
        warnings.append("state %s обрезан до %d символов" % (rid[:8], STATE_MAX))
    last = rec.get("last", [])
    if not isinstance(last, list):
        raise TopicsError("last: список id (до %d)" % LAST_MAX)
    last = [str(x).strip()[:8] for x in last if ID_RE.fullmatch(str(x).strip())][-LAST_MAX:]
    upd = str(rec.get("updated", ""))[:16]
    if not (keep_updated and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d", upd)):
        upd = _now()
    return {"id": rid[:8], "topic": topic, "status": status, "state": state, "last": last,
            "arbiter": vendor, "updated": upd}


def _acquire(timeout=10.0):
    os.makedirs(SHARED, exist_ok=True)
    t0 = time.time()
    while True:
        try:
            os.close(os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(LOCK) > 15:
                    os.remove(LOCK)
                    continue
            except OSError:
                pass
        except PermissionError:
            # Windows: after another writer os.remove, the lock file can stay
            # DELETE_PENDING; O_CREAT|O_EXCL then raises PermissionError
            # (ERROR_ACCESS_DENIED) instead of FileExistsError. Retry until timeout
            # so concurrent topics_put from several wakers does not crash.
            pass
        if time.time() - t0 > timeout:
            raise TopicsError("общий список тем занят другой записью, повтори через несколько секунд")
        time.sleep(0.05)


def _release():
    try:
        os.remove(LOCK)
    except OSError:
        pass


def _archive(recs, who, why):
    if not recs:
        return
    with open(ARCHIVE, "ab") as f:
        for r in recs:
            f.write(json.dumps({"archived": _now(), "by": who, "why": why, **r}, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")


def put(upsert=None, remove=None, vendor="unknown", expect_rev=None, seed=False):
    """Merge upserts by id (and by normalized topic title), archive `remove` ids, enforce limits, atomic write.
    -> {"ok", "rev", "count", "bytes", "archived": [ids], "warnings": [...]}; raises TopicsError (nothing written)."""
    upsert = upsert or []
    remove = [str(x)[:8] for x in (remove or [])]
    if not isinstance(upsert, list) or len(upsert) > (200 if seed else 40):
        raise TopicsError("upsert: список записей тем (до 40 за вызов)")
    warnings = []
    recs = [validate(r, vendor, warnings, keep_updated=seed) for r in upsert]
    _acquire()
    try:
        cur = load()
        if expect_rev is not None and int(expect_rev) != cur["rev"]:
            raise TopicsError("список тем изменён другим арбитром (rev %d, ты ждал %s): сделай topics_get и повтори" % (cur["rev"], expect_rev))
        topics = [t for t in cur["topics"] if isinstance(t, dict)]
        by_id = {t.get("id"): i for i, t in enumerate(topics)}
        by_title = {norm(t.get("topic")): i for i, t in enumerate(topics)}
        for r in recs:
            i = by_id.get(r["id"])
            if i is None:
                i = by_title.get(norm(r["topic"]))
                if i is not None:
                    warnings.append("тема %r уже есть под id %s: запись объединена" % (r["topic"][:40], topics[i].get("id")))
                    r["id"] = topics[i].get("id", r["id"])
            if i is None:
                topics.append(r)
                by_id[r["id"]] = len(topics) - 1
                by_title[norm(r["topic"])] = len(topics) - 1
            else:
                topics[i] = r
        gone = [t for t in topics if t.get("id") in remove]
        topics = [t for t in topics if t.get("id") not in remove]
        archived = list(gone)
        _archive(gone, vendor, "remove")

        def size():
            return len(_dump({"rev": cur["rev"] + 1, "topics": topics}))

        evicted = []
        while len(topics) > MAX_TOPICS or size() > MAX_BYTES:
            done = [t for t in topics if t.get("status") == "done"]
            if not done:
                raise TopicsError("лимит %d тем / %d КБ: открытых тем слишком много (%d, %d байт). Закрой или объедини темы (status done) и повтори. Ничего не записано."
                                  % (MAX_TOPICS, MAX_BYTES // 1024, len(topics), size()))
            old = min(done, key=lambda t: str(t.get("updated", "")))
            topics.remove(old)
            evicted.append(old)
        if evicted:
            _archive(evicted, vendor, "limit")
            warnings.append("в архив ушли закрытые темы по лимиту: " + ", ".join(str(t.get("id")) for t in evicted))
        rev = cur["rev"] + 1
        data = _dump({"rev": rev, "topics": topics})
        os.makedirs(SHARED, exist_ok=True)
        tmp = FILE + ".tmp-%d" % os.getpid()
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, FILE)
        return {"ok": True, "rev": rev, "count": len(topics), "bytes": len(data),
                "archived": [t.get("id") for t in archived + evicted], "warnings": warnings}
    finally:
        _release()


def get():
    d = load()
    raw = len(_dump(d))
    return {"ok": True, "rev": d["rev"], "count": len(d["topics"]), "bytes": raw, "topics": d["topics"],
            "limits": {"topics": MAX_TOPICS, "bytes": MAX_BYTES}}