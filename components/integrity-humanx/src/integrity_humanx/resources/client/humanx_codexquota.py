# -*- coding: utf-8 -*-
"""humanx_codexquota - свежее состояние лимитов Codex (ChatGPT Plus: окно 5 ч и недельное) для карточки CODEX в HumanX.

Источники (только чтение, без обращений к сети и без запуска codex):
  1) журналы сессий Codex ~/.codex/sessions/**/rollout-*.jsonl: события token_count содержат rate_limits
     {limit_id:"codex", primary:{used_percent, window_minutes:300, resets_at}, secondary:{... 10080 ...}, credits:{has_credits,..}};
     пишет и приложение Codex, и `codex exec` будильника - это самые свежие данные;
  2) текст ошибки "You've hit your usage limit ... try again at 11:24 PM." (запуск codex упал на лимите): помечаем исчерпание
     немедленно и берём время сброса из текста.
Результат: <room>/work/quota_status.json (его читает humanx_delivery.quota_view) и словарь для heartbeat (state/detail/reset_at).
После reset_at состояние само возвращается в «доступно» (окно сброшено); если лимит исчерпан, а время сброса неизвестно - 1 час.
Диагностика (только чтение): python humanx_codexquota.py <каталог room-codex> [<каталог .codex>]"""
import json
import os
import re
import sys
import threading
import time
from datetime import datetime

PLAN = "ChatGPT Plus"
FULL = 99.5                   # used_percent >= FULL: окно исчерпано
MAX_AGE_S = 8 * 86400         # события старше недели не используем (окна уже сброшены)
TAIL_BYTES = 3 * 1024 * 1024
FALLBACK_RESET_S = 3600.0
REWRITE_S = 300.0             # перезапись файла статуса не реже раза в 5 минут (свежая метка времени)
_LOCK = threading.Lock()
_CACHE = {}

_MONTHS = {m: i + 1 for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"))}


def codex_home():
    return os.environ.get("HUMANX_CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")


def _hm(h, mi, ap):
    h, mi = int(h), int(mi)
    if ap:
        ap = ap.upper()
        h = h % 12 + (12 if ap == "PM" else 0)
    return h, mi


def parse_reset(text, now=None):
    """Время сброса (epoch) из текста ошибки Codex: 'try again at 11:24 PM', 'try again at Nov 14th, 2026 3:12 PM', 'try again in 2 hours 5 minutes'. Иначе None."""
    now = time.time() if now is None else now
    t = str(text or "")
    m = re.search(r"try again in\s+((?:\d+\s*(?:d|day|days|h|hr|hrs|hour|hours|m|min|mins|minute|minutes)\b[\s,and]*)+)", t, re.I)
    if m:
        sec = 0
        for n, u in re.findall(r"(\d+)\s*([a-z]+)", m.group(1), re.I):
            u = u.lower()
            sec += int(n) * (86400 if u.startswith("d") else 3600 if u.startswith("h") else 60)
        if sec > 0:
            return now + sec
    m = re.search(r"try again at\s+([^\n]*)", t, re.I)
    if not m:
        return None
    s = m.group(1).strip().rstrip(".").strip()
    d = re.search(r"([A-Za-z]{3})[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s*(\d{4})?,?\s*(?:at\s+)?(\d{1,2}):(\d{2})\s*(AM|PM)?", s, re.I)
    try:
        if d and d.group(1).lower() in _MONTHS:
            h, mi = _hm(d.group(4), d.group(5), d.group(6))
            lt = time.localtime(now)
            year = int(d.group(3)) if d.group(3) else lt.tm_year
            ts = time.mktime((year, _MONTHS[d.group(1).lower()], int(d.group(2)), h, mi, 0, 0, 0, -1))
            if not d.group(3) and ts < now - 86400:
                ts = time.mktime((year + 1, _MONTHS[d.group(1).lower()], int(d.group(2)), h, mi, 0, 0, 0, -1))
            return ts
        tm = re.search(r"(\d{1,2}):(\d{2})\s*(AM|PM)?", s, re.I)
        if tm:
            h, mi = _hm(tm.group(1), tm.group(2), tm.group(3))
            lt = time.localtime(now)
            ts = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, h, mi, 0, 0, 0, -1))
            if ts < now - 60:
                ts += 86400
            return ts
    except (ValueError, OverflowError):
        return None
    return None


def _iso_ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _recent_files(sessions, days_n=3, limit=60):
    """Файлы rollout за последние дни (по именам каталогов). mtime у журналов Codex ненадёжен (бывает старше последних событий) -
    поэтому не отсекаем по нему, а выбираем событие с максимальной меткой времени."""
    days = []
    try:
        for y in sorted(os.listdir(sessions), reverse=True):
            for mo in sorted(os.listdir(os.path.join(sessions, y)), reverse=True):
                for d in sorted(os.listdir(os.path.join(sessions, y, mo)), reverse=True):
                    days.append(os.path.join(sessions, y, mo, d))
                    if len(days) >= days_n:
                        raise StopIteration
    except StopIteration:
        pass
    except OSError:
        pass
    files = []
    for dd in days:
        try:
            for f in os.listdir(dd):
                if f.startswith("rollout-") and f.endswith(".jsonl"):
                    p = os.path.join(dd, f)
                    try:
                        st = os.stat(p)
                        files.append((f, st.st_mtime, st.st_size, p))
                    except OSError:
                        pass
        except OSError:
            pass
    files.sort(reverse=True)                                   # по имени (оно начинается с времени старта сессии)
    return files[:limit]


def _tail_event(path, size):
    """Последнее событие rate_limits с limit_id=codex и непустым primary из хвоста файла -> dict или None."""
    try:
        with open(path, "rb") as h:
            if size > TAIL_BYTES:
                h.seek(size - TAIL_BYTES)
            data = h.read()
    except OSError:
        return None
    pos = len(data)
    while True:
        i = data.rfind(b'"rate_limits"', 0, pos)
        if i < 0:
            return None
        pos = i
        ls = data.rfind(b"\n", 0, i) + 1
        le = data.find(b"\n", i)
        line = data[ls:(le if le >= 0 else len(data))]
        try:
            obj = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            continue
        pl = obj.get("payload") if isinstance(obj, dict) else None
        rl = pl.get("rate_limits") if isinstance(pl, dict) else None
        if not isinstance(rl, dict) or rl.get("limit_id") != "codex" or not isinstance(rl.get("primary"), dict):
            continue
        sec = rl.get("secondary") if isinstance(rl.get("secondary"), dict) else {}
        pr = rl["primary"]
        cr = rl.get("credits") if isinstance(rl.get("credits"), dict) else {}
        try:
            return {"ts": _iso_ts(obj.get("timestamp")), "p_used": float(pr.get("used_percent")), "p_reset": float(pr.get("resets_at") or 0),
                    "p_win": pr.get("window_minutes"),
                    "w_used": (float(sec["used_percent"]) if sec.get("used_percent") is not None else None),
                    "w_reset": float(sec.get("resets_at") or 0), "w_win": sec.get("window_minutes"),
                    "credits": bool(cr.get("has_credits") or cr.get("unlimited")), "file": os.path.basename(path)}
        except (TypeError, ValueError):
            continue


def scan_rate_limits(home=None, now=None):
    """Самое свежее (по метке события) известное состояние окон Codex или None. Кэш на файл по (mtime, размер): дорого читаются только изменившиеся."""
    now = time.time() if now is None else now
    home = home or codex_home()
    files = _recent_files(os.path.join(home, "sessions"))
    cache = _CACHE.setdefault(home, {})
    ev = None
    live = set()
    for name, m, s, p in files:
        live.add(p)
        c = cache.get(p)
        if c and c[0] == (m, s):
            e = c[1]
        else:
            e = _tail_event(p, s)
            cache[p] = ((m, s), e)
        if e and (ev is None or e["ts"] > ev["ts"]):
            ev = e
    for p in [k for k in cache if k not in live]:
        del cache[p]
    if ev and now - ev["ts"] > MAX_AGE_S:
        return None
    return ev


def _fmt_t(ts, now):
    a, b = time.localtime(ts), time.localtime(now)
    return time.strftime("%H:%M" if (a.tm_year, a.tm_yday) == (b.tm_year, b.tm_yday) else "%d.%m %H:%M", a)


def _left(used, reset, now):
    """(осталось %, окно уже сброшено). После resets_at окно новое: остаток 100% (пока Codex не сообщит иное)."""
    if used is None:
        return None, False
    if reset and reset <= now:
        return 100, True
    return max(0, int(round(100.0 - used))), False


def evaluate(scan, forced_at, forced_reset, now):
    p_left, p_rst = _left(scan["p_used"], scan["p_reset"], now) if scan else (None, False)
    w_left, w_rst = _left(scan["w_used"], scan["w_reset"], now) if scan else (None, False)
    p_ex = bool(scan) and not p_rst and scan["p_used"] >= FULL and scan["p_reset"] > now
    w_ex = bool(scan) and not w_rst and scan["w_used"] is not None and scan["w_used"] >= FULL and scan["w_reset"] > now
    if scan and scan.get("credits") and not (forced_reset and forced_reset > now):
        p_ex = w_ex = False                                   # есть кредиты: Codex продолжает работать за кредиты
    forced = bool(forced_reset and forced_reset > now)
    exhausted = p_ex or w_ex or forced
    resets = [r for ok_, r in ((p_ex, scan["p_reset"] if scan else 0), (w_ex, scan["w_reset"] if scan else 0), (forced, forced_reset)) if ok_ and r]
    reset_at = max(resets) if resets else 0.0
    window = None
    if exhausted:
        weekly = w_ex or (forced and not p_ex and forced_at and (forced_reset - forced_at) > 5.5 * 3600)
        window = "weekly" if weekly else "5h"
        if window == "weekly":
            reset_at = max([r for ok_, r in ((w_ex, scan["w_reset"] if scan else 0), (forced, forced_reset)) if ok_ and r] or [reset_at])
    hm = time.strftime("%H:%M", time.localtime(now))
    if exhausted:
        rt = _fmt_t(reset_at, now)
        if window == "weekly":
            tail = "; остаток 5 ч %d%%" % p_left if p_left is not None else ""
            detail = "%s: недельный лимит исчерпан, сброс %s%s; проверено %s" % (PLAN, rt, tail, hm)
        else:
            tail = "; недельный остаток %d%%" % w_left if w_left is not None else ""
            detail = "%s: лимит 5 ч исчерпан, сброс %s%s; проверено %s" % (PLAN, rt, tail, hm)
    elif scan:
        a = "5 ч: окно сброшено" if p_rst else "5 ч: осталось %d%% (сброс %s)" % (p_left, _fmt_t(scan["p_reset"], now))
        b = "" if w_left is None else ("; неделя: окно сброшено" if w_rst else "; неделя: %d%% (сброс %s)" % (w_left, _fmt_t(scan["w_reset"], now)))
        cr = "; кредиты есть" if scan.get("credits") else ""
        detail = "%s: доступно; %s%s%s; проверено %s" % (PLAN, a, b, cr, hm)
    else:
        detail = "%s: доступно (данных о лимитах нет); проверено %s" % (PLAN, hm)
    return {"quota_exhausted": exhausted, "window": window, "reset_at": float(reset_at), "resets": _fmt_t(reset_at, now) if reset_at else "",
            "limit_5h_pct": p_left, "limit_weekly_pct": w_left, "detail": detail[:240]}


def _rj(path):
    for _ in range(4):
        try:
            with open(path, "r", encoding="utf-8-sig") as h:
                o = json.load(h)
            return o if isinstance(o, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            time.sleep(0.05)
    return {}


def _wj(path, obj):
    tmp = "%s.tmp%d" % (path, os.getpid())
    data = json.dumps(obj, ensure_ascii=False)
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as h:
            h.write(data)
        for _ in range(8):
            try:
                os.replace(tmp, path)
                return True
            except OSError:
                time.sleep(0.05)
        with open(path, "w", encoding="utf-8", newline="\n") as h:
            h.write(data)
        return True
    except OSError:
        return False
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def refresh(room, err_text=None, now=None, home=None):
    """Пересчитать состояние, при необходимости обновить <room>/work/quota_status.json. err_text - текст ошибки лимита (запуск упал на нём).
    Возвращает dict(state, quota_exhausted, detail, reset_at, ...). Не бросает исключений из-за диска; вызывать из потока heartbeat и из мест отказа."""
    now = time.time() if now is None else now
    path = os.path.join(room, "work", "quota_status.json")
    with _LOCK:
        prev = _rj(path)
        scan = scan_rate_limits(home, now)
        f_at, f_reset = prev.get("forced_at"), prev.get("forced_reset_at")
        try:
            f_at, f_reset = (float(f_at) if f_at else 0.0), (float(f_reset) if f_reset else 0.0)
        except (TypeError, ValueError):
            f_at, f_reset = 0.0, 0.0
        if err_text:
            f_at = now
            f_reset = parse_reset(err_text, now)
            if not f_reset or f_reset <= now:
                sx = None
                if scan:
                    sx = [r for r, u in ((scan["p_reset"], scan["p_used"]), (scan["w_reset"], scan["w_used"])) if u is not None and u >= FULL and r > now]
                f_reset = max(sx) if sx else now + FALLBACK_RESET_S
        elif f_reset and f_reset > now and scan and scan["ts"] > f_at + 5 and scan["p_used"] < FULL and not (scan["w_used"] or 0) >= FULL \
                and scan["p_reset"] > now:
            f_at = f_reset = 0.0                                  # после ошибки Codex сам сообщил свободное окно: лимит снят (кредиты/апгрейд)
        elif f_reset and f_reset <= now:
            f_at = f_reset = 0.0
        ev = evaluate(scan, f_at, f_reset, now)
        st = {"vendor": "codex", "state": "quota_exhausted" if ev["quota_exhausted"] else "ready", "plan": PLAN, **ev,
              "reset_5h_at": scan["p_reset"] if scan else 0.0, "reset_weekly_at": scan["w_reset"] if scan else 0.0,
              "source": ("error+rollout" if err_text and scan else "error" if err_text else "rollout" if scan else "none"),
              "source_ts": scan["ts"] if scan else 0.0, "forced_at": f_at, "forced_reset_at": f_reset,
              "checked_at": now, "checked_at_text": time.strftime("%d.%m %H:%M:%S", time.localtime(now))}
        skip = ("checked_at", "checked_at_text", "detail", "source")
        same = all(prev.get(k) == v for k, v in st.items() if k not in skip) and now - float(prev.get("checked_at") or 0) < REWRITE_S
        if err_text or not same:
            _wj(path, st)
        return st


def main(argv):
    if len(argv) < 2:
        print("usage: humanx_codexquota.py <room-codex dir> [codex home]")
        return 2
    scan = scan_rate_limits(argv[2] if len(argv) > 2 else None)
    now = time.time()
    out = {"scan": scan, "evaluate": evaluate(scan, 0.0, 0.0, now)}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
