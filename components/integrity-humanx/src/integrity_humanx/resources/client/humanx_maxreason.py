# -*- coding: utf-8 -*-
"""humanx_maxreason - режим «Max Reasoning» комнаты HumanX (пакет maxreason).

Галочка в веб-комнате добавляет в тело письма оператора служебную строку `[HUMANX-MAXR v=1]` (как `[HUMANX-FILE ...]`).
Будильник выбранного Арбитра, увидев её, не будит одного вендора, а ведёт задание через общую рабочую область
<pilot>/shared/maxreason/jobs/<id письма>/ (черновики туда, оператору НЕ уходят):

  p1  независимые черновики всех доступных вендоров (gemini, claude, codex, grok), параллельно, у каждого в своей комнате;
  p2  одна сверка: каждый видит чужие черновики и перечисляет ТОЛЬКО фактические расхождения/ошибки с доказательством по живым данным;
  p3  один синтезирующий Арбитр (выбранный, иначе первый доступный) пишет итог и явно показывает неснятые расхождения.
      Выбранный Арбитр отвечает обычным путём своего будильника (один reply с reply_to = id письма оператора, один topics_put).
      Если выбранный Арбитр недоступен, итог пишет другой вендор в файл, а reply один раз отправляет будильник выбранного Арбитра.

Дедлайны фаз и запасные пути: недоступный/опоздавший вендор пропускается и это записывается; не удался синтез -> выбранный Арбитр отвечает
обычным (не-MR) путём. Режим выключен (нет строки) -> этот модуль ничего не читает и не пишет: поведение будильников прежнее.
Исполнитель фаз p1/p2 у каждого вендора свой (runner в будильнике); модуль ведёт состояние в файлах и не знает движков.

Файлы задания: job.json (пишет только координатор = будильник Арбитра), task-<v>-<фаза>.json, claim-<v>-<фаза>, res-<v>-<фаза>.json
(пишет исполнитель), report.json (тайминги и стоимость по фазам). Общий журнал: shared/maxreason/log.jsonl. active.json: одно активное задание.
Стоп-кран: файл shared/maxreason/DISABLED или env HUMANX_MR_DISABLE=1 -> флаг игнорируется (письмо идёт обычным путём).
Диагностика (только чтение): python humanx_maxreason.py avail <каталог pilot>.
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import humanx_delivery as DL  # noqa: E402
try:
    import humanx_kparts as KP  # noqa: E402  (пакет K, часть mr_late)
except ImportError:              # без K — прежнее поведение
    KP = None

FLAG_LINE = "[HUMANX-MAXR v=1]"
FLAG_RE = re.compile(r"(?m)^[ \t]*\[HUMANX-MAXR v=1\][ \t]*(?:\r?\n|$)")
VENDORS = ("gemini", "claude", "codex", "grok")
TERMINAL = ("done", "fallback_done", "failed")
DEFAULTS = {"enabled": True, "grok_enabled": False, "p1_s": 540, "p2_s": 150, "p3_s": 480, "job_hard_s": 1500,   # p1 540 с: черновики Gemini 354-469 с; фаза кончается раньше, как только ответили все
            "hb_max_age_s": 150, "beacon_max_age_s": 400, "draft_max": 12000, "review_max": 4000,
            "fo_s": 420, "fo_wait_s": 900}
_INT_KEYS = ("p1_s", "p2_s", "p3_s", "job_hard_s", "hb_max_age_s", "beacon_max_age_s", "draft_max", "review_max", "fo_s", "fo_wait_s")
FO_PREFIX = "fo-"                       # задание переадресации (failover): jobs/fo-<id письма>; не зависит от флага Max Reasoning
FO_ORDER = ("grok", "claude", "gemini", "codex")      # по живым замерам: grok 30-50 с, gemini пишет ответ через 6-8 мин
FO_MIN_S = {"gemini": 600}
VENDOR_TITLE = {"gemini": "Gemini", "claude": "Claude", "codex": "Codex", "grok": "Grok"}


# ----------------------------------------------------------------------------------------------------------- helpers
def safe_id(mid):
    return "".join(c for c in str(mid) if c.isalnum() or c in "-_.")[:80]


def parse(body):
    """(тело без служебной строки, есть_флаг). Тело без флага возвращается БЕЗ изменений."""
    b = body or ""
    if FLAG_LINE not in b:
        return b, False
    if not FLAG_RE.search(b):
        return b, False
    return FLAG_RE.sub("", b).strip(), True


def strip(body):
    return parse(body)[0]


def mr_root(room):
    return os.environ.get("HUMANX_MR_DIR") or os.path.join(os.path.dirname(os.path.abspath(room)), "shared", "maxreason")


def jobdir(root, mid):
    return os.path.join(root, "jobs", safe_id(mid))


def _rj(path, default=None):
    for i in range(6):
        try:
            with open(path, "r", encoding="utf-8-sig") as h:
                return json.load(h)
        except FileNotFoundError:
            return default
        except (OSError, ValueError):                       # Windows: файл в этот миг заменяют (PermissionError) или он дописывается
            if i < 5:
                time.sleep(0.05)
    return default


def _wj(path, obj):
    """Атомарная запись JSON. На Windows os.replace падает с PermissionError, пока другой процесс (исполнитель другого вендора) держит файл открытым
    на чтение: повторяем ~0.5 с, затем пишем на месте (читатели через _rj повторяют чтение при пустом/битом JSON), исключение - только если и это не вышло."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.%d.%d.tmp" % (path, os.getpid(), int(time.time() * 1000) % 100000)
    data = json.dumps(obj, ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8", newline="\n") as h:
        h.write(data)
    last = None
    for i in range(10):
        try:
            os.replace(tmp, path)
            return
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as h:        # запасной путь: запись на месте
            h.write(data)
        return
    except OSError as exc:
        last = exc
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    raise last


def log(room, rec):
    try:
        root = mr_root(room)
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(root, "log.jsonl"), "a", encoding="utf-8", newline="\n") as h:
            h.write(json.dumps({"ts": round(time.time(), 2), **rec}, ensure_ascii=False) + "\n")
    except OSError:
        pass


def cfg(room):
    c = dict(DEFAULTS)
    root = mr_root(room)
    over = _rj(os.path.join(root, "config.json"), {}) or {}
    if isinstance(over, dict):
        for k, v in over.items():
            if k in DEFAULTS:
                c[k] = v
    for k in _INT_KEYS:
        ev = os.environ.get("HUMANX_MR_" + k.upper())
        if ev:
            try:
                c[k] = int(ev)
            except ValueError:
                pass
    if os.environ.get("HUMANX_MR_GROK"):
        c["grok_enabled"] = os.environ["HUMANX_MR_GROK"] == "1"
    if os.path.exists(os.path.join(root, "DISABLED")) or os.environ.get("HUMANX_MR_DISABLE") == "1":
        c["enabled"] = False
    c["fo_enabled"] = not (os.path.exists(os.path.join(root, "FAILOVER_DISABLED")) or os.environ.get("HUMANX_FO_DISABLE") == "1")
    return c


NO_REPLY_TTL_S = 6 * 3600      # пакет G: отметка «не ответил» действует 6 ч, потом исполнитель снова в MR на одну пробу (не липкая)


def vendor_room(room, v):
    return os.path.join(os.path.dirname(os.path.abspath(room)), "room-" + v)


def availability(room, v, c=None, now=None):
    """(доступен, причина). Источник: waker вендора пишет work/<v>-hb.json каждые 45 с и маяк journal/health.json."""
    c = c or cfg(room)
    now = time.time() if now is None else now
    if v == "grok" and not c.get("grok_enabled"):
        return False, "grok_routine_not_enabled"
    base = vendor_room(room, v)
    if os.path.exists(os.path.join(base, "WAKE_STOP")):
        return False, "stop_flag"
    hbp = os.path.join(base, "work", v + "-hb.json")
    try:
        age = now - os.path.getmtime(hbp)
    except OSError:
        return False, "no_heartbeat"
    if age > c["hb_max_age_s"]:
        return False, "heartbeat_stale_%ds" % int(age)
    hb = _rj(hbp, {}) or {}
    st = str(hb.get("state", "ready"))
    if st != "ready":
        return False, "state_" + st
    qs = _rj(os.path.join(base, "work", "quota_status.json"), {}) or {}
    if isinstance(qs, dict) and qs.get("state") == "no_reply":      # пакет G: исполнитель молчит после принятого запроса — заведомо недоступен
        try:
            t0 = float(qs.get("since") or 0)
        except (TypeError, ValueError):
            t0 = 0.0
        if now - t0 < NO_REPLY_TTL_S:                                    # старше 6 ч — снова участник (проба); новый пропуск обновит отметку
            return False, "no_reply_since_" + time.strftime("%H:%M", time.localtime(t0))
    b = DL.read_beacon(base)
    if b is not None:
        try:
            if now - float(b.get("ts", 0)) > c["beacon_max_age_s"] and float(b.get("busy_until", 0) or 0) < now:
                return False, "waker_loop_stale"
        except (TypeError, ValueError):
            pass
    return True, "ok"


# ----------------------------------------------------------------------------------------------------------- jobs
def load_job(room, mid):
    return _rj(os.path.join(jobdir(mr_root(room), mid), "job.json"))


def save_job(room, job):
    _wj(os.path.join(jobdir(mr_root(room), job["id"]), "job.json"), job)


def create_job(room, vendor, mid, msg_obj, now=None):
    now = time.time() if now is None else now
    job = {"id": mid, "created": now, "arbiter": vendor, "arbiter_room": os.path.abspath(room), "state": "queued", "msg": msg_obj}
    save_job(room, job)
    log(room, {"job": mid, "event": "job_queued", "arbiter": vendor})
    return job


def intercept(room, vendor, msgs, acc, ctx=None):
    """Убирает из обычного потока письма с флагом Max Reasoning. acc = (id_of, body_of, with_body, to_json).
    Возвращает (письма для обычного пути, id удержанных). Письма без флага проходят без изменений и без обращения к диску."""
    idf, bodyf, setf, tojson = acc
    rest, held = [], []
    for m in msgs:
        clean, flag = parse(bodyf(m))
        if not flag:
            rest.append(m)
            continue
        m2 = setf(m, clean)
        mid = idf(m)
        c = cfg(room)
        if not c["enabled"]:
            rest.append(m2)
            continue
        job = load_job(room, mid)
        if job is None:
            create_job(room, vendor, mid, tojson(m2))
            if ctx and ctx.get("ack"):
                try:
                    ctx["ack"](mid)                      # «Арбитр взял в работу» сразу: письмо не должно висеть pending (supervisor stuck_message)
                except Exception:
                    pass
            held.append(mid)
        elif job.get("state") in TERMINAL:
            rest.append(m2)
        else:
            if ctx and ctx.get("ack"):                  # письмо снова видно как pending = прошлый ack не дошёл до ядра: повторяем (идемпотентно)
                try:
                    ctx["ack"](mid)
                except Exception:
                    pass
            held.append(mid)
    return rest, held


def _release_active(room, mid):
    ap = os.path.join(mr_root(room), "active.json")
    a = _rj(ap)
    if a and a.get("job") == mid:
        try:
            os.remove(ap)
        except OSError:
            pass


def _claim_active(room, mid, phase, deadline, vendor, now, hard_s):
    root = mr_root(room)
    ap = os.path.join(root, "active.json")
    os.makedirs(root, exist_ok=True)
    a = _rj(ap)
    if a:
        other = load_job(room, a.get("job", ""))
        stale = (not other) or other.get("state") in TERMINAL or now - float(a.get("ts", 0)) > hard_s + 120
        if not stale:
            return a.get("job") == mid
        try:
            os.remove(ap)
        except OSError:
            pass
    try:
        fd = os.open(ap, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as h:
        json.dump({"job": mid, "phase": phase, "arbiter": vendor, "deadline": deadline, "ts": now}, h, ensure_ascii=False)
    return True


def _set_active(room, mid, phase, deadline, vendor, now):
    try:                                                     # информационный файл (какая фаза/дедлайн): сбой записи не должен ломать переход состояния
        _wj(os.path.join(mr_root(room), "active.json"), {"job": mid, "phase": phase, "arbiter": vendor, "deadline": deadline, "ts": now})
    except OSError as exc:
        log(room, {"job": mid, "event": "active_write_failed", "error": str(exc)[:120]})


def _write_tasks(room, job, phase, vendors, deadline, now):
    jd = jobdir(mr_root(room), job["id"])
    for v in vendors:
        _wj(os.path.join(jd, "task-%s-%s.json" % (v, phase)),
            {"job": job["id"], "vendor": v, "phase": phase, "created": now, "deadline": deadline})
    log(room, {"job": job["id"], "event": "phase_start", "phase": phase, "vendors": list(vendors), "deadline_in_s": int(deadline - now)})


def read_results(room, job, phase, vendors=VENDORS):
    jd = jobdir(mr_root(room), job["id"])
    out = {}
    for v in vendors:
        r = _rj(os.path.join(jd, "res-%s-%s.json" % (v, phase)))
        if isinstance(r, dict):
            out[v] = r
    return out


def _tasks_of(room, job, phase):
    jd = jobdir(mr_root(room), job["id"])
    return [v for v in VENDORS if os.path.exists(os.path.join(jd, "task-%s-%s.json" % (v, phase)))]


def _phase_summary(room, job, phase, start, now):
    tasks = _tasks_of(room, job, phase)
    res = read_results(room, job, phase)
    ok = [v for v in tasks if res.get(v, {}).get("ok")]
    failed = {v: res[v].get("error") or "failed" for v in tasks if v in res and not res[v].get("ok")}
    missing = [v for v in tasks if v not in res]
    detail = {v: {"secs": res[v].get("secs"), "ok": bool(res[v].get("ok")), "chars": len(res[v].get("text") or ""),
                  "cost_usd": (res[v].get("meta") or {}).get("cost_usd"), "error": res[v].get("error")} for v in tasks if v in res}
    s = {"start": round(start, 1), "end": round(now, 1), "secs": round(now - start, 1), "ok": ok, "failed": failed, "missing": missing, "tasks": detail}
    job.setdefault("timings", {})[phase] = s
    log(room, {"job": job["id"], "event": "phase_end", "phase": phase, "secs": s["secs"], "ok": ok, "failed": failed, "missing": missing})
    return s


def _write_report(room, job, now):
    t = job.get("timings", {})
    cost = 0.0
    known = False
    for ph in t.values():
        for d in (ph.get("tasks") or {}).values():
            if isinstance(d.get("cost_usd"), (int, float)):
                cost += d["cost_usd"]
                known = True
    rep = {"job": job["id"], "arbiter": job.get("arbiter"), "state": job.get("state"), "mode": job.get("mode"), "synth": job.get("synth"),
           "bridge": bool(job.get("bridge")), "fallback_reason": job.get("fallback_reason"), "skipped": job.get("skipped"),
           "participants": job.get("participants"), "total_secs": round(now - float(job.get("created", now)), 1), "phases": t,
           "cost_usd_known": round(cost, 4) if known else None, "cost_note": "cost_usd есть только у вендоров, чей CLI его отдаёт (Claude); остальные - по символам черновиков",
           "replies": job.get("replies"), "topics_puts": job.get("topics_puts")}
    if job.get("mode") == "failover":
        rep.update({"mid": job.get("mid"), "tried": job.get("tried"), "attempts": job.get("attempts"), "fo_result": job.get("fo_result"),
                    "reason": job.get("reason")})
    try:
        _wj(os.path.join(jobdir(mr_root(room), job["id"]), "report.json"), rep)
    except OSError:
        pass
    log(room, {"job": job["id"], "event": "job_end", "state": job.get("state"), "mode": job.get("mode"), "secs": rep["total_secs"],
               "cost_usd_known": rep["cost_usd_known"], "fallback_reason": job.get("fallback_reason")})


def _journal_ops(room, op, since, mid=None, tail=800):
    n = 0
    lines = []
    for fn in ("room.jsonl.1", "room.jsonl"):
        try:
            with open(os.path.join(room, "journal", fn), "rb") as h:
                lines += h.read().splitlines()[-tail:]
        except OSError:
            pass
    for ln in lines[-tail:]:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("op") == op and r.get("result") == "ok" and int(r.get("ts") or 0) >= int(since) - 1 and (mid is None or r.get("reply_to") == mid):
            n += 1
    return n


def _to_fallback(room, job, reason):
    """Запасной путь: выбранный Арбитр отвечает обычным (не-MR) путём. Возвращает письмо для обычного пути (один раз)."""
    mid = job["id"]
    sf = os.path.join(job.get("arbiter_room", room), "work", "mr-synth-%s.json" % safe_id(mid))
    try:
        os.remove(sf)
    except OSError:
        pass
    job["state"] = "fallback"
    job["mode"] = "fallback"
    job["fallback_reason"] = reason
    job["fallback_used"] = True
    job["fallback_at"] = time.time()
    save_job(room, job)
    log(room, {"job": mid, "event": "fallback", "reason": reason})
    return [job["msg"]]


def _finish(room, job, state, now):
    job["state"] = state
    job["finished"] = now
    save_job(room, job)
    _write_report(room, job, now)
    _release_active(room, mid=job["id"])


def pick_synth(room, job):
    arb = job["arbiter"]
    av = job.get("avail", {})
    p1 = read_results(room, job, "p1")
    arb_dead = av.get(arb, {}).get("ok") is not True or (arb in p1 and not p1[arb].get("ok") and str(p1[arb].get("error", "")).startswith("quota"))
    if not arb_dead:
        return arb, False
    for v in VENDORS:
        if v != arb and av.get(v, {}).get("ok") and not (v in p1 and not p1[v].get("ok") and str(p1[v].get("error", "")).startswith("quota")):
            return v, True
    return None, False


def _texts(room, job, phase, cap):
    out = {}
    for v, r in read_results(room, job, phase).items():
        if r.get("ok") and (r.get("text") or "").strip():
            out[v] = (r["text"].strip())[:cap]
    return out


def late_p1(room, job, now=None):
    """K mr_late: вендоры p1 без черновика к сроку -> {vendor: текст}; часть выключена или K нет -> None."""
    if KP is None or not KP.on(room, "mr_late"):
        return None
    p1 = (job.get("timings", {}) or {}).get("p1") or {}
    mins = max(1, int(round(float(p1.get("secs") or cfg(room)["p1_s"]) / 60)))
    now = time.time() if now is None else now
    out = {}
    for v in p1.get("missing") or []:
        h = _rj(os.path.join(vendor_room(room, v), "journal", "health.json"), {}) or {}
        busy = float(h.get("busy_until") or 0) > now
        out[v] = ("не успел за %d мин, черновик ещё готовился" if busy else "не ответил за %d мин") % mins
    return out


def synth_payload(room, job):
    c = cfg(room)
    late = late_p1(room, job)
    extra = {} if late is None else {"p1_late": late}
    return {**extra, "job": job["id"], "message": job["msg"],
            "drafts": _texts(room, job, "p1", c["draft_max"]), "cross_checks": _texts(room, job, "p2", c["review_max"]),
            "participants": job.get("participants"), "skipped": job.get("skipped"),
            "p1_missing": (job.get("timings", {}).get("p1") or {}).get("missing"),
            "p1_failed": (job.get("timings", {}).get("p1") or {}).get("failed"),
            "p2_missing": (job.get("timings", {}).get("p2") or {}).get("missing")}


def tick(room, vendor, ctx=None, now=None):
    """Один шаг координатора для будильника Арбитра `vendor`. Возвращает письма (сырые объекты), которые будильник должен
    теперь обработать обычным путём: синтез (рядом лежит work/mr-synth-<id>.json) или запасной путь. Не бросает исключений."""
    try:
        return _tick(room, vendor, ctx or {}, time.time() if now is None else now)
    except Exception as exc:  # noqa: BLE001 - координатор не должен ронять будильник (crash_loop)
        log(room, {"event": "tick_error", "vendor": vendor, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])})
        return []


def _my_jobs(room, vendor, c, now):
    jd = os.path.join(mr_root(room), "jobs")
    try:
        names = os.listdir(jd)
    except OSError:
        return []
    out = []
    for n in names:
        p = os.path.join(jd, n)
        try:
            if now - os.path.getmtime(p) > c["job_hard_s"] * 3:
                continue
        except OSError:
            continue
        j = _rj(os.path.join(p, "job.json"))
        if isinstance(j, dict) and j.get("arbiter") == vendor and j.get("state") not in TERMINAL:
            out.append(j)
    out.sort(key=lambda j: (j.get("created", 0), j.get("id", "")))
    return out


def _tick(room, vendor, ctx, now):
    c = cfg(room)
    jobs = _my_jobs(room, vendor, c, now)
    wake = []
    for job in jobs:
        if now - float(job.get("created", now)) > c["job_hard_s"] and job["state"] in ("queued", "p1", "p2", "p3x", "p3"):
            if job["state"] == "p3":
                wake += _p3_hard(room, job, now)
            else:
                wake += _to_fallback(room, job, "job_hard_deadline")
                _release_active(room, job["id"])
            continue
        wake += _advance(room, vendor, job, c, ctx, now)
    return wake


def _p3_hard(room, job, now):
    out = _to_fallback(room, job, "job_hard_deadline")
    _release_active(room, job["id"])
    return out


def _advance(room, vendor, job, c, ctx, now):
    st = job["state"]
    mid = job["id"]
    if job.get("mode") == "failover":
        return _fo_advance(room, vendor, job, c, ctx, now)
    if st == "queued":
        if not c["enabled"]:
            return _to_fallback(room, job, "disabled")
        if not _claim_active(room, mid, "p1", now + c["p1_s"], vendor, now, c["job_hard_s"]):
            return []                                                   # ждём очереди: одно активное задание
        avail = {}
        skipped = {}
        for v in VENDORS:
            ok, why = availability(room, v, c, now)
            avail[v] = {"ok": ok, "reason": why}
            if not ok:
                skipped[v] = why
        parts = [v for v in VENDORS if avail[v]["ok"]]
        job["avail"], job["skipped"], job["participants"] = avail, skipped, parts
        job["phase_started"] = now
        log(room, {"job": mid, "event": "job_start", "arbiter": vendor, "participants": parts, "skipped": skipped})
        if not parts:
            _release_active(room, mid)
            return _to_fallback(room, job, "no_available_vendors")
        job["deadline"] = now + c["p1_s"]
        _write_tasks(room, job, "p1", parts, job["deadline"], now)     # сначала задания, потом состояние: сбой записи оставит queued и шаг повторится
        job["state"] = "p1"
        save_job(room, job)
        _set_active(room, mid, "p1", job["deadline"], vendor, now)
        return []
    if st in ("p1", "p2"):
        tasks = _tasks_of(room, job, st)
        res = read_results(room, job, st)
        if len(res) < len(tasks) and now < job["deadline"]:
            return []
        _phase_summary(room, job, st, job["phase_started"], now)
        ok = [v for v in tasks if res.get(v, {}).get("ok")]
        if st == "p1":
            if not ok:
                save_job(room, job)
                _release_active(room, mid)
                return _to_fallback(room, job, "no_drafts")
            if len(ok) >= 2:
                job["phase_started"], job["deadline"] = now, now + c["p2_s"]
                _write_tasks(room, job, "p2", ok, job["deadline"], now)
                job["state"] = "p2"
                save_job(room, job)
                _set_active(room, mid, "p2", job["deadline"], vendor, now)
                return []
            job.setdefault("timings", {})["p2"] = {"skipped": "fewer_than_two_drafts"}
            log(room, {"job": mid, "event": "phase_skipped", "phase": "p2", "reason": "fewer_than_two_drafts"})
        return _enter_p3(room, vendor, job, c, ctx, now)
    if st == "p3x":
        tasks = _tasks_of(room, job, "p3x")
        res = read_results(room, job, "p3x")
        if not res and now < job["deadline"]:
            return []
        _phase_summary(room, job, "p3x", job["phase_started"], now)
        r = res.get(job.get("synth"), {})
        if not (r.get("ok") and (r.get("text") or "").strip()):
            save_job(room, job)
            _release_active(room, mid)
            return _to_fallback(room, job, "bridge_synthesis_failed:" + str(r.get("error") or "no_result"))
        body = (r["text"] or "").strip()
        if not body.lstrip("\ufeff \t\r\n").startswith("Тема:"):
            body = "Тема: Ответ Арбитра\n" + body
        if not post_reply(room, ctx, mid, body):
            save_job(room, job)
            _release_active(room, mid)
            return _to_fallback(room, job, "bridge_post_failed")
        job["replies"] = 1
        job["topics_puts"] = _journal_ops(vendor_room(room, job["synth"]), "topics_put", job["phase_started"])
        job["mode"] = "synth_bridge"
        _finish(room, job, "done", now)
        return []
    if st == "fallback":
        rp = DL.replied_ids(job.get("arbiter_room", room), [mid])
        if mid in rp:
            job["replies"] = _journal_ops(job["arbiter_room"], "reply", job.get("fallback_at", now) - 2, mid)
            _finish(room, job, "fallback_done", now)
            return []
        if job.get("fb_returned") or now - float(job.get("fallback_at", now)) > 1800:
            job["fallback_noreply"] = True
            if fo_active(room, mid):                                    # вопрос уже передан другому Арбитру: уведомление «недоступен» не шлём
                log(room, {"job": mid, "event": "fallback_handed_to_failover"})
                _finish(room, job, "fallback_done", now)
                return []
            notice = ctx.get("notice")
            if notice:
                try:
                    notice()
                except Exception:
                    pass
            log(room, {"job": mid, "event": "fallback_no_reply", "notice": bool(notice)})
            _finish(room, job, "fallback_done", now)
        return []
    if st == "p3":
        rp = DL.replied_ids(job.get("arbiter_room", room), [mid])
        if mid in rp:
            _phase_summary_p3(room, job, now)
            job["replies"] = _journal_ops(job["arbiter_room"], "reply", job["phase_started"], mid)
            job["topics_puts"] = _journal_ops(job["arbiter_room"], "topics_put", job["phase_started"])
            job["mode"] = "synth"
            _finish(room, job, "done", now)
            return []
        if job.get("p3_returned") or now >= job["deadline"]:
            reason = "synthesis_no_reply_after_attempt" if job.get("p3_returned") else "synthesis_deadline"
            _phase_summary_p3(room, job, now)
            out = _to_fallback(room, job, reason)
            _release_active(room, mid)
            return out
        return []
    return []


# ------------------------------------------------------------------------------------------------ failover (fo)
# Сбой Арбитра (таймаут, ошибка, лимит) не считается ответом: вопрос оператора уходит следующему доступному Арбитру.
# Исполнитель пишет готовый ответ в файл (как p3x), отправляет его оператору будильник ВЫБРАННОГО Арбитра через свой room_tool
# (reply_to = id письма, проверки room_tool те же). Не удалось ни у кого -> честное сообщение оператору и уведомление.
def fo_job_id(mid):
    return FO_PREFIX + safe_id(mid)


def fo_active(room, mid):
    j = load_job(room, fo_job_id(mid))
    return bool(j) and j.get("state") not in TERMINAL


def fo_candidates(room, exclude=(), c=None, now=None):
    c = c or cfg(room)
    out = []
    for v in FO_ORDER:
        if v in exclude:
            continue
        ok, _why = availability(room, v, c, now)
        if ok:
            out.append(v)
    return out


def failover_start(room, vendor, msg_obj, reason, now=None):
    """Будильник `vendor` не смог ответить на письмо msg_obj. Создаёт задание fo-<id>. Возвращает True, если вопрос передан
    (есть хотя бы один доступный Арбитр и переадресация не выключена); False -> будильник отвечает прежним путём (ошибка/квота)."""
    now = time.time() if now is None else now
    try:
        c = cfg(room)
        if not c.get("fo_enabled"):
            return False
        mid = msg_obj["id"]
        cands = fo_candidates(room, exclude=(vendor,), c=c, now=now)
        if not cands:
            log(room, {"job": fo_job_id(mid), "event": "fo_no_candidates", "arbiter": vendor, "reason": str(reason)[:120]})
            return False
        old = load_job(room, fo_job_id(mid))
        if old and old.get("state") not in TERMINAL:
            return True                                         # уже передан (повторный сбой того же письма)
        msg = dict(msg_obj)
        msg["body"] = strip(msg.get("body", ""))
        job = {"id": fo_job_id(mid), "mid": mid, "mode": "failover", "created": now, "arbiter": vendor, "arbiter_room": os.path.abspath(room),
               "state": "fo_queued", "msg": msg, "tried": [vendor], "reason": str(reason)[:200], "attempts": []}
        save_job(room, job)
        log(room, {"job": job["id"], "event": "fo_queued", "arbiter": vendor, "reason": job["reason"], "candidates": cands})
        return True
    except Exception as exc:  # noqa: BLE001 - сбой переадресации не должен ронять будильник; тогда прежний путь
        log(room, {"event": "fo_start_error", "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])})
        return False


FO_FAIL_BODY = ("Тема: Ответ задерживается\n\n"
                "Оператор, сейчас ни один Арбитр не смог подготовить ответ на ваш вопрос: выбранный не ответил вовремя, остальные недоступны или тоже не успели. "
                "Повторите вопрос через несколько минут или выберите другого Арбитра.")


def _fo_fail(room, job, ctx, now, why):
    """Все кандидаты не смогли: одно честное письмо оператору (без второго уведомления «недоступен»), запись в журнале maxreason."""
    mid = job["mid"]
    job["fo_result"] = "failed:" + why
    sent = post_reply(room, ctx, mid, FO_FAIL_BODY)
    log(room, {"job": job["id"], "event": "fo_failed", "why": why, "error_reply": sent, "tried": job.get("tried")})
    _finish(room, job, "failed", now)
    return []


def _fo_advance(room, vendor, job, c, ctx, now):
    mid, st = job["mid"], job["state"]
    if mid in DL.replied_ids(job.get("arbiter_room", room), [mid]):          # ответ уже ушёл (например, выбранный Арбитр всё же ответил)
        log(room, {"job": job["id"], "event": "fo_already_replied"})
        _finish(room, job, "done", now)
        return []
    if st == "fo_queued":
        if now - float(job.get("created", now)) > c["fo_wait_s"]:
            return _fo_fail(room, job, ctx, now, "wait_deadline")
        cands = fo_candidates(room, exclude=job.get("tried", []), c=c, now=now)
        if not cands:
            return _fo_fail(room, job, ctx, now, "no_candidates")
        v = cands[0]
        deadline = now + max(int(c["fo_s"]), FO_MIN_S.get(v, 0))
        if not _claim_active(room, job["id"], "fo", deadline, vendor, now, c["job_hard_s"]):
            return []                                                       # идёт задание Max Reasoning: ждём очереди (не дольше fo_wait_s)
        job["fo_vendor"], job["deadline"], job["phase_started"] = v, deadline, now
        _write_tasks(room, job, "fo", [v], deadline, now)
        job["state"] = "fo"
        save_job(room, job)
        _set_active(room, job["id"], "fo", deadline, vendor, now)
        return []
    if st == "fo":
        v = job.get("fo_vendor")
        res = read_results(room, job, "fo", [v]).get(v)
        if res is None and now < float(job.get("deadline", now)):
            return []
        att = {"vendor": v, "ok": bool(res and res.get("ok")), "secs": (res or {}).get("secs"), "error": (res or {}).get("error") if res else "deadline"}
        job.setdefault("attempts", []).append(att)
        job.setdefault("tried", []).append(v)
        _release_active(room, job["id"])
        body = ((res or {}).get("text") or "").strip() if res and res.get("ok") else ""
        if body:
            if not body.lstrip("﻿ \t\r\n").startswith("Тема:"):
                body = "Тема: Ответ Арбитра\n" + body
            body += "\n\n(Ответ подготовил Арбитр %s: Арбитр %s не ответил вовремя.)" % (VENDOR_TITLE.get(v, v), VENDOR_TITLE.get(job["arbiter"], job["arbiter"]))
            if post_reply(room, ctx, mid, body):
                job["fo_result"] = "answered_by_" + v
                log(room, {"job": job["id"], "event": "fo_done", "vendor": v, "secs": att["secs"]})
                _finish(room, job, "done", now)
                return []
            att["error"] = "post_failed"
        log(room, {"job": job["id"], "event": "fo_attempt_failed", "vendor": v, "error": att["error"]})
        job["state"] = "fo_queued"
        save_job(room, job)
        return []
    return []


def _phase_summary_p3(room, job, now):
    s = {"start": round(job.get("phase_started", now), 1), "end": round(now, 1), "secs": round(now - job.get("phase_started", now), 1),
         "synth": job.get("synth"), "bridge": False}
    job.setdefault("timings", {})["p3"] = s
    log(room, {"job": job["id"], "event": "phase_end", "phase": "p3", "secs": s["secs"], "synth": job.get("synth")})


def _enter_p3(room, vendor, job, c, ctx, now):
    mid = job["id"]
    synth, bridge = pick_synth(room, job)
    if not synth:
        save_job(room, job)
        _release_active(room, mid)
        return _to_fallback(room, job, "no_synthesizer")
    job["synth"], job["bridge"] = synth, bridge
    job["phase_started"] = now
    job["deadline"] = now + c["p3_s"]
    payload = synth_payload(room, job)
    log(room, {"job": mid, "event": "synth_chosen", "synth": synth, "bridge": bridge})
    if bridge:
        _write_tasks(room, job, "p3x", [synth], job["deadline"], now)
        job["state"] = "p3x"
        save_job(room, job)
        _set_active(room, mid, "p3x", job["deadline"], vendor, now)
        return []
    _wj(os.path.join(job["arbiter_room"], "work", "mr-synth-%s.json" % safe_id(mid)), payload)
    job["state"] = "p3"
    save_job(room, job)
    _set_active(room, mid, "p3", job["deadline"], vendor, now)
    log(room, {"job": mid, "event": "phase_start", "phase": "p3", "vendors": [synth], "deadline_in_s": int(job["deadline"] - now)})
    return [job["msg"]]


def post_reply(room, ctx, mid, body, attempts=2):
    """Единственная отправка оператору для моста (синтез сделал другой вендор): reply через room_tool выбранного Арбитра."""
    py, rt = ctx.get("py"), ctx.get("rt")
    if not py or not rt:
        return False
    for i in range(attempts):
        ok, info = DL.room_call(room, py, rt, "reply", "reply-mr-%s" % safe_id(mid), {"reply_to": mid, "body": body})
        log(room, {"job": mid, "event": "bridge_reply", "ok": ok, "attempt": i + 1, "info": "" if ok else str(info)[:160]})
        if ok:
            return True
        time.sleep(2)
    return False


def note_returned(room, ids):
    """Будильник сообщает: обычный wake письма вернулся (для фазы p3: ответа нет -> запасной путь без ожидания дедлайна)."""
    for mid in ids:
        j = load_job(room, mid)
        if j and j.get("state") == "p3" and not j.get("p3_returned"):
            j["p3_returned"] = time.time()
            save_job(room, j)
        elif j and j.get("state") == "fallback" and not j.get("fb_returned"):
            j["fb_returned"] = time.time()
            save_job(room, j)


def synth_pending(room, mid):
    """True, если письмо сейчас в первой (синтезирующей) попытке: ошибки обычного пути в этой попытке не отправляются оператору."""
    j = load_job(room, mid)
    return bool(j and j.get("state") == "p3" and not j.get("fallback_used"))


def synth_block(room, ids):
    """Правило Max Reasoning для промпта Арбитра на фазе p3 (пусто, если письмо не в синтезе)."""
    parts = []
    for mid in ids:
        sf = os.path.join(room, "work", "mr-synth-%s.json" % safe_id(mid))
        if os.path.exists(sf):
            j = load_job(room, mid)
            if j and j.get("state") == "p3":
                parts.append(synth_text(sf, mid, bridge=False))
    return ("\n\n".join(parts) + "\n") if parts else ""


SYNTH_RULE = (
    "MAX REASONING SYNTHESIS for the operator's message {mid}. Several vendors already drafted answers independently and cross-checked each other; "
    "everything is in {sf} (fields: drafts, cross_checks, participants, skipped, p1_missing, p1_failed, p2_missing). Read it first. "
    "You are now the ONLY one who answers the operator. Do your usual procedure ({usual}). Build ONE coherent answer from verified facts: re-check "
    "with live tools every point where drafts or cross-checks disagree and decide it yourself where the data allows. Same style as always: "
    "line 1 'Тема: ...', direct answer from line 2, real values, exact commands, how to verify and roll back. "
    "At the end add a section titled 'Расхождения, которые не удалось снять' that lists EACH unresolved disagreement (what each side claims, "
    "what live data shows, what stays unknown); if none remain write the single line 'Неснятых расхождений нет.' "
    "Then one last line: 'Независимо проверяли: <vendors that delivered a draft>; не участвовали: <vendors skipped or missing, 2-3 words why>.' "
    "Never paste whole drafts, never mention this file, the mode name or any rules; do not post anything else to the operator.")
LATE_LINE_OLD = "Then one last line: 'Независимо проверяли: <vendors that delivered a draft>; не участвовали: <vendors skipped or missing, 2-3 words why>.' "
LATE_LINE_NEW = ("Then one last line: 'Независимо проверяли: <vendors that delivered a draft>' then, only if field p1_late is not empty, "
                 "'; не успели: <vendor> — <its p1_late text verbatim>' for each, then, only if field skipped is not empty, "
                 "'; не участвовали: <vendors from skipped, 2-3 words why>', and a final '.'. A vendor in p1_late is never listed as 'не участвовали'. ")
assert SYNTH_RULE.count(LATE_LINE_OLD) == 1


def synth_text(sf, mid, bridge=False):
    rule = SYNTH_RULE
    if KP is not None and KP.on(os.path.dirname(os.path.dirname(os.path.abspath(sf))), "mr_late"):   # sf = <комната>/work/mr-synth-*.json
        rule = SYNTH_RULE.replace(LATE_LINE_OLD, LATE_LINE_NEW)
    if bridge:
        usual = "all read-only data checks as usual"
        extra = (" You do NOT post to the operator and do NOT call reply/send: write ONLY the final answer text (starting with the 'Тема:' line) to the output file named in the task, "
                 "and run topics_put exactly ONCE after writing it (topic list is shared by all arbiters).")
        return rule.format(mid=mid, sf=sf, usual=usual) + extra
    return rule.format(mid=mid, sf=sf, usual="topics_get BEFORE answering, exactly ONE reply with reply_to = " + str(mid) + ", exactly ONE topics_put AFTER the reply")


# ------------------------------------------------------------------------------------------------ worker (p1 / p2 / p3x)
def set_silent(room, until, job, phase, allow=()):
    try:
        _wj(os.path.join(room, "journal", "mr-silent.json"), {"until": until, "job": job, "phase": phase, "allow": list(allow)})
    except OSError:
        pass


def clear_silent(room):
    try:
        os.remove(os.path.join(room, "journal", "mr-silent.json"))
    except OSError:
        pass


def prepare_input(room, job, task):
    """Входной файл задания в комнате исполнителя: work/mr-in-<id>-<фаза>.json. Возвращает пути."""
    vendor, phase = task["vendor"], task["phase"]
    c = cfg(room)
    sid = safe_id(job["id"])
    msg = job["msg"] if isinstance(job["msg"], dict) else {}
    body = msg.get("body", "") or ""
    atts = []
    try:
        import humanx_attach as HA
        body, atts = HA.fetch(room, job["id"], body, extract_text=(vendor == "grok"))
    except Exception as exc:  # noqa: BLE001
        atts = [{"error": "%s: %s" % (type(exc).__name__, str(exc)[:80])}]
    inp = {"phase": phase, "job": job["id"], "message": {"id": job.get("mid", job["id"]), "body": body, "attachments": atts}}
    if phase in ("p2", "p3x"):
        drafts = _texts(room, job, "p1", c["draft_max"])
        inp["drafts"] = drafts
        inp["your_vendor"] = vendor
        inp["participants"] = job.get("participants")
    if phase == "p3x":
        inp["cross_checks"] = _texts(room, job, "p2", c["review_max"])
        inp["skipped"] = job.get("skipped")
        inp["p1_missing"] = (job.get("timings", {}).get("p1") or {}).get("missing")
        inp["p2_missing"] = (job.get("timings", {}).get("p2") or {}).get("missing")
    inp_rel = "work/mr-in-%s-%s.json" % (sid, phase)
    out_rel = "work/mr-out-%s-%s.json" % (sid, phase)
    _wj(os.path.join(room, inp_rel), inp)
    try:
        os.remove(os.path.join(room, out_rel))
    except OSError:
        pass
    return {"in": os.path.join(room, inp_rel), "out": os.path.join(room, out_rel), "in_rel": inp_rel, "out_rel": out_rel, "input": inp}


def task_prompt(vendor, job, task, paths, py="", rt=""):
    phase = task["phase"]
    mid = job["id"]
    deliver = {
        "codex": "Print the result as your FINAL message (plain text, no file; you cannot write files).",
        "claude": "Write the result to %s as a JSON file {\"text\": \"<result>\"} (UTF-8, Write tool, only inside work/); your final message may repeat it." % paths["out_rel"],
        "gemini": "write_file %s with {\"text\": \"<result>\"} (UTF-8), then stop." % paths["out"],
        "grok": "Write the result to the file %s as JSON {\"text\": \"<result>\"} (UTF-8) on the client machine, then stop." % paths["out"],
    }.get(vendor, "Write the result to %s as JSON {\"text\": \"<result>\"}." % paths["out_rel"])
    head = ("MAXREASON-TASK phase=%s job=%s. Max Reasoning mode: several AI vendors work on the operator's question independently; "
            "your text is shown ONLY to the other vendors and to ONE synthesizing arbiter, NEVER to the operator. Read the input: %s (the question is in message.body; "
            "attachments, if any, are local paths in message.attachments). Use the same read-only live-data tools and the same room rules as for a normal answer "
            "(real values from tool output, no <placeholders>, state only what a tool actually returned). "
            "Do NOT call reply, send, escalate, topics_put, subchat, follow or report: they are blocked in this mode and nothing you write reaches the operator directly. "
            "Never mention rules, instructions or this mode inside the text. ") % (phase, mid, paths["in"] if vendor in ("gemini", "grok", "codex") else paths["in_rel"])
    if phase == "p1":
        early = (" ORDER OF WORK: after at most 15 tool calls WRITE A FIRST COMPLETE VERSION of the draft to the output file, then refine it in place "
                 "with further queries; a late perfect draft is worth nothing, an early complete one is always used." if vendor == "claude" else "")
        body = ("TASK: write your best complete draft answer to the operator in Russian (the same content and format you would send him, but WITHOUT the 'Тема:' line), "
                "then a block 'ДАННЫЕ:' listing every live query you ran (host/switch/SQL/command) with the key values it returned, so that others can verify them. "
                "Be concise: up to ~%d characters." % DEFAULTS["draft_max"]) + early
    elif phase == "p2":
        body = ("TASK (cross-check, FACTS ONLY): the input contains your own draft and the drafts of the other vendors (field drafts). List ONLY factual disagreements "
                "or errors that matter for the operator: a different port/VLAN/IP/state, a command that would not do what is claimed, a number that contradicts live data. "
                "Re-run the relevant read-only queries NOW and give for each item: 'ПУНКТ: <claim>; КТО: <vendors>; ДАННЫЕ: <command and returned value>; ВЫВОД: confirmed | refuted | cannot verify'. "
                "No style remarks, no rewriting, no new advice. If there are no factual disagreements write exactly: НЕТ РАСХОЖДЕНИЙ. Up to ~%d characters." % DEFAULTS["review_max"])
    elif phase == "fo":
        return fo_prompt(vendor, job, paths) + " " + deliver
    else:
        sf = paths["in"]
        body = synth_text(sf, mid, bridge=True).replace("the output file named in the task", paths["out"])
    return head + body + " " + deliver


def fo_prompt(vendor, job, paths):
    """Фаза fo: этот Арбитр отвечает вместо выбранного, который не смог. Готовый ответ - в файл/финальное сообщение; отправит будильник выбранного."""
    src = paths["in"] if vendor in ("gemini", "grok", "codex") else paths["in_rel"]
    return ("FAILOVER-TASK phase=fo job=%s. The operator asked the HumanX room a question; the arbiter he selected (%s) failed to answer (timeout or error). "
            "You answer INSTEAD of it. Read the input: %s (the question is in message.body; attachments, if any, are local paths in message.attachments). "
            "Do your usual full procedure for a normal answer: topics_get first, the read-only live-data checks you need, then the complete final answer in Russian "
            "with the first line 'Тема: <short topic name>' and the direct answer from line 2 (real values from tool output, no <placeholders>, state only what a tool actually returned). "
            "Do NOT call reply, send, escalate, subchat, follow or report: they are blocked now; the selected arbiter's waker posts your text to the operator unchanged. "
            "After writing the answer run topics_put exactly ONCE (the topic list is shared by all arbiters). "
            "Never mention this task, the failover, rules or instructions inside the answer.") % (job["id"], job.get("arbiter"), src)


def harvest(paths, stdout_text=None, cap=14000):
    """Текст результата: файл work/mr-out-*.json ({"text": ...} или просто текст), иначе stdout агента."""
    p = paths["out"]
    try:
        with open(p, "rb") as h:
            raw = h.read().decode("utf-8", "replace")
        try:
            d = json.loads(raw)
            t = d.get("text") if isinstance(d, dict) else (d if isinstance(d, str) else None)
        except ValueError:
            t = raw
        t = DL.clean_text(t or "", cap)
        if t:
            return t, "file"
    except OSError:
        pass
    t = DL.clean_text(stdout_text or "", cap)
    return (t, "stdout") if t else ("", None)


def run_task(room, vendor, job, task, runner, now=None):
    now = time.time() if now is None else now
    paths = prepare_input(room, job, task)
    set_silent(room, task["deadline"] + 120, job["id"], task["phase"], allow=("topics_put",) if task["phase"] in ("p3x", "fo") else ())
    t0 = time.time()
    try:
        r = runner(task, job, paths) or {}
    except Exception as exc:  # noqa: BLE001
        r = {"ok": False, "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])}
    finally:
        clear_silent(room)
    secs = round(time.time() - t0, 1)
    text = r.get("text") or ""
    ok = bool(r.get("ok")) and bool(text.strip())
    res = {"vendor": vendor, "phase": task["phase"], "ok": ok, "text": text if ok else "", "secs": secs,
           "error": None if ok else (r.get("error") or "empty_result"), "meta": r.get("meta") or {}, "ts": time.time()}
    _wj(os.path.join(jobdir(mr_root(room), job["id"]), "res-%s-%s.json" % (vendor, task["phase"])), res)
    log(room, {"job": job["id"], "event": "task_done", "vendor": vendor, "phase": task["phase"], "ok": ok, "secs": secs,
               "chars": len(text), "cost_usd": (res["meta"] or {}).get("cost_usd"), "error": res["error"]})
    return res


def worker_tick(room, vendor, runner, now=None):
    """Исполнитель фаз p1/p2/p3x для вендора комнаты `room`. True, если выполнил задание. Если заданий нет - ничего не читает кроме active.json."""
    now = time.time() if now is None else now
    root = mr_root(room)
    ap = os.path.join(root, "active.json")
    if not os.path.exists(ap):
        return False
    a = _rj(ap)
    if not a:
        return False
    jd = jobdir(root, a.get("job", ""))
    job = _rj(os.path.join(jd, "job.json"))
    if not job or job.get("state") not in ("p1", "p2", "p3x", "fo"):
        return False
    phase = job["state"]
    tf = os.path.join(jd, "task-%s-%s.json" % (vendor, phase))
    if not os.path.exists(tf):
        return False
    rf = os.path.join(jd, "res-%s-%s.json" % (vendor, phase))
    cf = os.path.join(jd, "claim-%s-%s" % (vendor, phase))
    if os.path.exists(rf) or os.path.exists(cf):
        return False
    try:
        os.close(os.open(cf, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
    except OSError:
        return False
    task = _rj(tf)
    if not task:
        return False
    if now >= float(task["deadline"]):
        _wj(rf, {"vendor": vendor, "phase": phase, "ok": False, "text": "", "secs": 0, "error": "deadline_before_start", "meta": {}, "ts": time.time()})
        log(room, {"job": job["id"], "event": "task_done", "vendor": vendor, "phase": phase, "ok": False, "error": "deadline_before_start"})
        return False
    run_task(room, vendor, job, task, runner, now)
    return True


# ------------------------------------------------------------------------------------------------------------- CLI
def _cli(argv):
    if len(argv) >= 3 and argv[1] == "avail":
        pilot = os.path.abspath(argv[2])
        fake_room = os.path.join(pilot, "room-gemini")
        c = cfg(fake_room)
        out = {v: dict(zip(("ok", "reason"), availability(fake_room, v, c))) for v in VENDORS}
        print(json.dumps({"config": c, "availability": out, "root": mr_root(fake_room), "root_exists": os.path.isdir(mr_root(fake_room))}, ensure_ascii=False, indent=1))
        return 0
    print("usage: humanx_maxreason.py avail <pilot dir>")
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv))
