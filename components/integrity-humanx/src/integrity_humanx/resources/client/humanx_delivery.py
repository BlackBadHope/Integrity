"""humanx_delivery — общие помощники будильников комнаты HumanX.

* Retry: повторы доставки с backoff 10→20→40→80→160→300 с (потолок 300 с); состояние хранится в wake-state.json.
* send_notice: один раз на письмо через 5 минут неудачной доставки пишет оператору «арбитр временно недоступен».
  Уведомление уходит как send БЕЗ reply_to: reply пометил бы письмо оператора replied, и оно перестало бы повторяться.
* room_call: вызов room_tool с записью аргументов в work/*.json (UTF-8) и проверкой результата.
* replied_ids: какие письма пачки уже получили reply (по journal/room.jsonl комнаты).
* start_thread: heartbeat в отдельном потоке (иначе во время долгого запуска агента heartbeat пропадает, а ядро считает waker_offline через 180 с).
* hardening (pkg hard): room_op/ack_message/send_heartbeat (одна точка запуска room_tool, байты + decode replace, None-safe),
  agent_argv (скрипты .py как агент в стенде), beacon/read_beacon (маяк живости цикла waker), tail_events/crash_loop/oldest_pending/evaluate
  (здоровье waker по journal/wake.jsonl, реплике и маяку), Healer (рестарт с backoff -> алерт -> notice), alert (logs/alerts.jsonl),
  send_notice с защитой от дубля (journal/notice-sent.json).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

NOTICE_AFTER_S = 300
NOTICE_BODY = ("Тема: Арбитр временно недоступен\n"
               "Арбитр временно недоступен, ответ задержится. Ваше сообщение сохранено и будет обработано, "
               "как только Арбитр вернётся.")
_NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def backoff_s(n):
    return min(300, 10 * 2 ** max(0, int(n) - 1))


class Retry:
    """store — словарь, который вызывающий хранит в state['retry'] (сохраняется save_state)."""

    def __init__(self, store):
        self.d = store

    def due(self, mid, now=None):
        e = self.d.get(mid)
        return (not e) or (now if now is not None else time.time()) >= e.get("next", 0)

    def fail(self, mid, reason="", now=None):
        now = now if now is not None else time.time()
        e = self.d.setdefault(mid, {"first": now, "n": 0, "notified": False})
        e["n"] += 1
        e["next"] = now + backoff_s(e["n"])
        e["reason"] = str(reason)[:160]
        return e

    def ok(self, mid):
        self.d.pop(mid, None)

    def purge(self, alive):
        for mid in [k for k in self.d if k not in alive]:
            self.d.pop(mid, None)

    def overdue(self, now=None, after=NOTICE_AFTER_S):
        now = now if now is not None else time.time()
        return [k for k, e in self.d.items() if not e.get("notified") and now - e.get("first", now) >= after]

    def mark_notified(self, ids):
        for k in ids:
            if k in self.d:
                self.d[k]["notified"] = True


def decode_bytes(b):
    """bytes/str/None -> str; никогда не бросает (UTF-8, ошибки заменяются)."""
    if isinstance(b, str):
        return b
    if isinstance(b, (bytes, bytearray)):
        return bytes(b).decode("utf-8", "replace")
    return ""


def room_op(room, py, rt, op, rel, timeout=60):
    """room_tool <op> <rel> в каталоге комнаты. Возвращает (ok, вывод[:400]). Байтовый вывод, decode UTF-8/replace, None-safe."""
    try:
        p = subprocess.run([py, "-I", rt, op, rel], cwd=room, capture_output=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, creationflags=_NOWIN)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"{type(e).__name__}: {e}"[:200]
    out = decode_bytes(p.stdout) + decode_bytes(p.stderr)
    return (p.returncode == 0 and '"ok": false' not in out), out[:400]


def write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as h:
        json.dump(obj, h, ensure_ascii=False)
    os.replace(tmp, path)


def safe_id(mid):
    return "".join(c for c in str(mid) if c.isalnum() or c in "-_.")[:80]


def ack_message(room, py, rt, mid, timeout=60):
    """ack письма на ядре через room_tool. Возвращает ok."""
    name = "ack-%s.json" % safe_id(mid)
    try:
        write_json_atomic(os.path.join(room, "work", name), {"id": mid})
    except OSError:
        return False
    return room_op(room, py, rt, "ack", "work/" + name, timeout)[0]


def send_heartbeat(room, py, rt, vendor, state, detail="", reset_at=0.0, timeout=30):
    """vendor-heartbeat на ядро. Возвращает ok; ошибки не бросает."""
    name = "%s-hb.json" % vendor
    try:
        write_json_atomic(os.path.join(room, "work", name),
                          {"vendor": vendor, "state": state, "detail": str(detail)[:240], "reset_at": float(reset_at or 0.0)})
    except (OSError, TypeError, ValueError):
        return False
    return room_op(room, py, rt, "heartbeat", "work/" + name, timeout)[0]


def agent_argv(binary, args, py=None):
    """argv агента. Если binary - скрипт .py (стенд/тесты), он запускается интерпретатором py; реальные .exe не затрагиваются."""
    if str(binary).lower().endswith(".py"):
        return [py or sys.executable, "-B", str(binary), *args]
    return [binary, *args]


def clean_text(s, limit=6000):
    """Очистка вывода агента перед ответом оператору: U+FFFD и управляющие символы убираются; без единой буквы/цифры -> ''."""
    s = decode_bytes(s)
    s = "".join(ch for ch in s if ch in "\n\t" or (ord(ch) >= 32 and ch != "\ufffd" and ord(ch) != 127)).strip()
    return s[:limit] if any(ch.isalnum() for ch in s) else ""


# Пакет K: служебные абзацы агента о доставке, подтверждениях и памяти — не для оператора. Ответы Codex
# могут кончаться ими (абзацы об отклонённой отправке ответа в комнату или о недоступном сервисе памяти).
_SERVICE_NOTE = re.compile(
    r"(ответ\w*\s+в\s+комнату\s+(не\s+доставлен|был[аио]?\s+отклонен|отклонен)|"
    r"отправк\w*\s+(этого\s+)?ответа\s+в\s+комнату|"
    r"автоматическ\w*\s+проверк\w*\s+(отклонил|потребовал)|"
    r"политик\w*\s+сессии\s+не\s+допуска|"
    r"подтверждени\w*,?\s+(которое\s+)?(политика\s+сессии\s+не\s+допускает|недоступн)|"
    r"каноническ\w*\s+(сервис|инструмент\w*)\s+(\w+\s+)?памят|"
    r"инструмент\w*\s+(чтения\s+и\s+)?закрытия\s+хода|"
    r"\broom_reply\b|\bapproval\b)", re.I)


def strip_service_notes(text, removed=None):
    """Убрать абзацы-служебные заметки агента. Возвращает (текст, сколько абзацев убрано). Если служебным оказался весь
    текст — возвращает '' (ответа нет). Абзац = блок между пустыми строками; внутри кода (```) ничего не трогаем.
    removed (список) — сюда кладутся убранные абзацы целиком, чтобы журнал показал, что именно не ушло оператору."""
    if not text:
        return text, 0
    paras = re.split(r"\n[ \t]*\n", text)
    keep, dropped, in_code = [], 0, False
    for p in paras:
        fences = p.count("```")
        if not in_code and fences == 0 and _SERVICE_NOTE.search(p):
            dropped += 1
            if removed is not None:
                removed.append(p)
        else:
            keep.append(p)
        if fences % 2:
            in_code = not in_code
    out = "\n\n".join(keep).strip()
    return out, dropped


def room_call(room, py, rt, op, name, obj, timeout=60):
    """Записать аргумент в work/<name>.json (UTF-8) и вызвать room_tool. Возвращает (ok, вывод)."""
    rel = "work/" + name + ".json"
    with open(os.path.join(room, "work", name + ".json"), "w", encoding="utf-8") as h:
        json.dump(obj, h, ensure_ascii=False)
    return room_op(room, py, rt, op, rel, timeout)


NOTICE_MIN_GAP_S = 600


def send_notice(room, py, rt, body=NOTICE_BODY, force=False):
    """Одно «арбитр временно недоступен» оператору. Защита от дубля между waker и supervisor: не чаще раза в NOTICE_MIN_GAP_S.
    Подавленный дубль возвращает (True, 'suppressed ...'): вызывающий считает письмо уведомлённым."""
    mk = os.path.join(room, "journal", "notice-sent.json")
    if not force:
        try:
            with open(mk, "r", encoding="utf-8") as h:
                last = float(json.load(h).get("ts", 0))
        except (OSError, ValueError, AttributeError, TypeError):
            last = 0.0
        if time.time() - last < NOTICE_MIN_GAP_S:
            return True, "suppressed: notice sent %ds ago" % int(time.time() - last)
    ok, info = room_call(room, py, rt, "send", "notice-unavailable-%d" % int(time.time()), {"to": _hx_operator(), "body": body})
    if ok:
        try:
            os.makedirs(os.path.dirname(mk), exist_ok=True)
            write_json_atomic(mk, {"ts": time.time(), "pid": os.getpid()})
        except OSError:
            pass
    return ok, info


def replied_ids(room, ids, tail=400):
    ids = set(ids)
    out = set()
    lines = []
    for fn in ("room.jsonl.1", "room.jsonl"):             # fix13: после ротации журнала недавние ответы могут лежать в room.jsonl.1
        try:
            with open(os.path.join(room, "journal", fn), "rb") as h:
                lines += h.read().splitlines()[-tail:]
        except OSError:
            pass
    lines = lines[-tail:]
    if not lines:
        return out
    for ln in lines:
        try:
            row = json.loads(ln)
        except ValueError:
            continue
        if row.get("op") == "reply" and row.get("reply_to") in ids and row.get("result") == "ok":
            out.add(row["reply_to"])
    return out


def start_thread(fn, interval=45.0, name="hb"):
    def run():
        while True:
            try:
                fn()
            except Exception:
                pass
            time.sleep(interval)
    t = threading.Thread(target=run, daemon=True, name=name)
    t.start()
    return t


NO_REPLY_FRESH_S = 6 * 3600   # = humanx_maxreason.NO_REPLY_TTL_S (пакет G); тест QJ сверяет значения


def quota_view(qfile, qs, default_detail):
    """(исчерпана_сейчас, detail, reset_at). Пометка «данные устарели»: файл квоты старше 1 часа или reset_at уже прошёл
    (раньше показывался замороженный текст вроде «сброс через 18 часов»; исчерпанная квота после reset_at не снималась)."""
    now = time.time()
    qs = qs or {}
    detail = qs.get("detail") or default_detail
    exhausted = bool(qs.get("quota_exhausted"))
    try:
        reset_at = float(qs.get("reset_at") or 0.0)
    except (TypeError, ValueError):
        reset_at = 0.0
    stale = False
    mtime = None
    if qs:
        try:
            mtime = os.path.getmtime(qfile)
        except OSError:
            mtime = None
        if mtime is not None and now - mtime > 3600:
            stale = True
        if qs.get("state") == "no_reply":                 # пакет J: отметка «не ответил с …» свежа столько же, сколько её держит MR
            try:                                          # (NO_REPLY_TTL_S = 6 ч), а не час от записи файла
                stale = now - float(qs.get("since") or 0) > NO_REPLY_FRESH_S
            except (TypeError, ValueError):
                pass
    if exhausted and reset_at and now > reset_at:
        exhausted, stale = False, True
        detail = f"{detail} (срок сброса прошёл, считаем доступным)"
    if not exhausted and "исчерп" in detail.lower() and detail != default_detail and qs.get("state") != "no_reply":
        detail = default_detail                           # старый текст «исчерпано», а флага нет: не вводим в заблуждение
        # пакет J: отметка no_reply Grok («лимит неизвестен (возможно, исчерпан)») - честный текст, его не заменяем
    if stale:
        when = time.strftime("%d.%m %H:%M", time.localtime(mtime)) if mtime else "давно"
        if exhausted:
            detail = f"{detail} [данные устарели, обновлено {when}]"
        else:                                             # устаревшее «1% использовано / доступно» нельзя выдавать за текущее: честное «нет данных»
            plan = str(qs.get("plan") or "").strip()
            detail = f"{plan + ': ' if plan else ''}нет свежих данных о лимите (последнее значение от {when} устарело)"
    return exhausted, detail, reset_at


_LOCKS = {}


def single_instance(path):
    """Один waker на комнату: эксклюзивный замок файла (msvcrt, снимается ОС при смерти процесса). Второй экземпляр выходит с кодом 3."""
    if path in _LOCKS:
        return True
    try:
        import msvcrt
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fh = open(path, "a+")
        fh.seek(1024)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    except ImportError:
        return True                                   # не Windows: замок не поддержан
    except OSError:
        print(f"[single_instance] {path} is held by another process, exiting", flush=True)
        sys.exit(3)
    fh.seek(0)
    fh.truncate()
    fh.write(f"{os.getpid()} {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    fh.flush()
    _LOCKS[path] = fh
    return True


# ---------------------------------------------------------------------------------------------------------------------
# Здоровье waker: маяк цикла, анализ journal/wake.jsonl, возраст недоставленных писем, рестарт с backoff -> алерт -> notice
# ---------------------------------------------------------------------------------------------------------------------
ERROR_EVENTS = frozenset({"error", "poll_error"})          # внутренние сбои цикла (не «агент недоступен» - его ловит правило недоставки)
SENDERS = (_hx_operator(), "owner")
HEALTH_CFG = {"crash_n": 5, "crash_recent_s": 180, "stuck_s": 120, "hung_s": 300, "grace_s": 45, "notice_after_s": NOTICE_AFTER_S, "recover_s": 300}


def beacon(room, busy_s=0.0):
    """Маяк живости главного цикла: journal/health.json {pid, ts, busy_until}. busy_s>0: waker законно занят блокирующей операцией."""
    now = time.time()
    try:
        write_json_atomic(os.path.join(room, "journal", "health.json"),
                          {"pid": os.getpid(), "ts": now, "busy_until": (now + float(busy_s)) if busy_s and busy_s > 0 else 0.0})
        return True
    except (OSError, TypeError, ValueError):
        return False


def read_beacon(room):
    try:
        with open(os.path.join(room, "journal", "health.json"), "r", encoding="utf-8") as h:
            b = json.load(h)
        return b if isinstance(b, dict) else None
    except (OSError, ValueError):
        return None


def tail_events(room, max_bytes=65536):
    """Последние записи journal/wake.jsonl (битые/обрезанные строки пропускаются)."""
    f = os.path.join(room, "journal", "wake.jsonl")
    try:
        with open(f, "rb") as h:
            h.seek(0, os.SEEK_END)
            size = h.tell()
            h.seek(max(0, size - max_bytes))
            data = h.read()
    except OSError:
        return []
    out = []
    for ln in data.splitlines():
        try:
            r = json.loads(ln.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(r, dict):
            out.append(r)
    return out


def crash_loop(events, since_ts, now, n=5, recent_s=180):
    """N одинаковых подряд идущих error-событий (после since_ts), последнее не старше recent_s.
    Любое другое событие (успех, taken, deliver ...) обрывает серию. Возвращает (событие, ошибка, длина) или None."""
    ev = [e for e in events if float(e.get("ts", 0) or 0) >= since_ts]
    sig = None
    run = 0
    last_ts = 0.0
    for e in reversed(ev):
        name = e.get("event")
        if name not in ERROR_EVENTS:
            break
        s = (name, str(e.get("error", ""))[:160])
        if sig is not None and s != sig:
            break
        sig = s
        run += 1
        if run == 1:
            last_ts = float(e.get("ts", 0) or 0)
    if sig is not None and run >= n and now - last_ts <= recent_s:
        return sig[0], sig[1], run
    return None


def oldest_pending(replica, addr, now=None, senders=SENDERS):
    """[(id, возраст_с)] писем адресату в статусе pending (старые первыми); None, если реплика не читается."""
    now = time.time() if now is None else now
    try:
        con = sqlite3.connect(Path(replica).resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
        try:
            ph = ",".join("?" * len(senders))
            rows = con.execute("SELECT id, created_at FROM messages WHERE recipient=? AND status='pending' AND expires_at>? "
                               "AND sender IN (%s) ORDER BY seq" % ph, (addr, int(now), *senders)).fetchall()
        finally:
            con.close()
    except (sqlite3.Error, OSError, ValueError):
        return None
    return [(r[0], max(0, int(now - float(r[1] or now)))) for r in rows]


def evaluate(room, addr, replica, pid, started_at, now=None, cfg=None):
    """Здоров ли живой waker. None - здоров; иначе {kind, detail, ids, oldest_age_s}.
    kind: crash_loop (серия одинаковых error), hung_loop (нет маяка цикла дольше hung_s вне busy), stuck_message (письмо pending дольше stuck_s вне busy)."""
    c = dict(HEALTH_CFG, **(cfg or {}))
    now = time.time() if now is None else now
    b = read_beacon(room)
    if b is not None and b.get("pid") != pid:
        b = None                                            # маяк от прошлого процесса не считается
    busy = bool(b) and float(b.get("busy_until", 0) or 0) > now
    events = tail_events(room)
    pend = oldest_pending(replica, addr, now)
    acked = {e.get("id") for e in events if (e.get("event") == "ack" and e.get("ok") is True) or (e.get("event") == "woken" and e.get("ack") is True)}
    if pend:                                                # ack на ядре уже прошёл (по журналу waker), реплика просто отстаёт: не «застряло»
        pend = [x for x in pend if x[0] not in acked]
    ids = [p[0] for p in (pend or [])]
    age = max([p[1] for p in (pend or [])] or [0])
    base = {"ids": ids, "oldest_age_s": age}
    cl = crash_loop(events, started_at, now, c["crash_n"], c["crash_recent_s"])
    if cl:
        return dict(base, kind="crash_loop", detail="%d x %s: %s" % (cl[2], cl[0], cl[1][:100]))
    last = float(b.get("ts", 0) or 0) if b else started_at
    if not busy and now - max(last, started_at) > c["hung_s"]:
        return dict(base, kind="hung_loop", detail="нет маяка цикла %ds" % int(now - max(last, started_at)))
    if not busy and pend and age > c["stuck_s"]:
        return dict(base, kind="stuck_message", detail="письмо pending %ds (%d шт.)" % (age, len(ids)))
    return None


def alert(logdir, rec):
    """Запись для администратора в logs/alerts.jsonl. Наружу ничего не отправляется."""
    try:
        os.makedirs(logdir, exist_ok=True)
        with open(os.path.join(logdir, "alerts.jsonl"), "a", encoding="utf-8") as h:
            h.write(json.dumps({"ts": int(time.time()), "iso": time.strftime("%Y-%m-%d %H:%M:%S"), **rec}, ensure_ascii=False) + "\n")
        return True
    except OSError:
        return False


class Healer:
    """Политика самолечения одного waker: нездоров -> рестарт (backoff 60/120/240/480/600 с, не более max_restarts за инцидент);
    если после рестарта всё ещё нездоров -> алерт администратору и notice оператору (если письмо висит >= notice_after_s); выздоровел -> запись recovered.
    recover_s: инцидент закрывается только после непрерывного «здоров» не короче этого окна (по умолчанию 300 с = hung_s).
    Один тик evaluate()=None сразу после рестарта (ещё нет crash_n ошибок, маяк свежий) НЕ сбрасывает счётчик рестартов.
    restart(reason), alert(rec), notice(issue)->bool - колбэки; время передаётся явно (тестируемо без sleep)."""
    BACKOFF = (60, 120, 240, 480, 600)

    def __init__(self, name, restart, alert_fn, notice=None, max_restarts=3, notice_after_s=NOTICE_AFTER_S, recover_s=None):
        self.name, self.restart, self.alert, self.notice = name, restart, alert_fn, notice
        self.max_restarts, self.notice_after_s = max_restarts, notice_after_s
        self.recover_s = HEALTH_CFG["recover_s"] if recover_s is None else recover_s
        self.inc = None

    def observe(self, issue, now):
        if issue is None:
            if self.inc:
                if self.inc.get("healthy_since") is None:
                    self.inc["healthy_since"] = now
                if now - self.inc["healthy_since"] >= self.recover_s:
                    self.alert({"vendor": self.name, "severity": "info", "kind": "recovered", "incident": self.inc["kind"],
                                "restarts": self.inc["restarts"], "duration_s": int(now - self.inc["since"])})
                    self.inc = None
                    return "recovered"
                return "wait"
            return "ok"
        inc = self.inc
        if inc is None:
            inc = self.inc = {"since": now, "kind": issue["kind"], "restarts": 0, "next": 0.0, "alerted": False, "noticed": False, "healthy_since": None}
        else:
            inc["healthy_since"] = None
        inc["kind"] = issue["kind"]
        if inc["restarts"] == 0:
            self.restart("%s: %s" % (issue["kind"], issue.get("detail", "")))
            inc.update(restarts=1, next=now + self.BACKOFF[0])
            self.alert({"vendor": self.name, "severity": "warn", "kind": issue["kind"], "detail": issue.get("detail"),
                        "action": "restart", "restarts": 1, "pending_ids": issue.get("ids", [])})
            return "restart"
        action = "wait"
        if not inc["alerted"]:
            inc["alerted"] = True
            action = "alert"
            self.alert({"vendor": self.name, "severity": "crit", "kind": issue["kind"], "detail": issue.get("detail"),
                        "action": "persistent_after_restart", "restarts": inc["restarts"], "pending_ids": issue.get("ids", []),
                        "oldest_age_s": issue.get("oldest_age_s", 0)})
        if not inc["noticed"] and self.notice and issue.get("ids") and issue.get("oldest_age_s", 0) >= self.notice_after_s:
            ok = False
            try:
                ok = bool(self.notice(issue))
            except Exception as exc:                          # noqa: BLE001 - сбой notice не должен ронять supervisor
                self.alert({"vendor": self.name, "severity": "warn", "kind": "notice_failed", "error": "%s: %s" % (type(exc).__name__, exc)})
            inc["noticed"] = ok
            self.alert({"vendor": self.name, "severity": "info", "kind": "notice", "sent": ok, "pending_ids": issue.get("ids", [])})
            action = "notice"
        if inc["restarts"] < self.max_restarts and now >= inc["next"]:
            self.restart("%s: %s (повтор %d)" % (issue["kind"], issue.get("detail", ""), inc["restarts"] + 1))
            inc["restarts"] += 1
            inc["next"] = now + self.BACKOFF[min(inc["restarts"] - 1, len(self.BACKOFF) - 1)]
            return "restart"
        return action
