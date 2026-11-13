#!/usr/bin/python3 -I
"""humanx_web — чат комнаты HumanX (оператор ↔ Арбитр) поверх шины ядра. v3: вложения, темы Арбитра.

Слушает только адрес из конфига (bind, port), принимает только IP из allow;
то же держат nft и systemd IPAddressAllow. Отправитель всегда human-<operator_id> (по ключу веба на ядре, токен 0400).
Чат: лента писем оператора и ответов Арбитра, статус каждого письма (отправлено → Арбитр взял в работу → ответ),
индикатор «Арбитр думает… N мин», выбор Арбитра карточками в отдельной панели. Кода, путей и shell из данных нет.
v3: вложения (кнопка, вставка из буфера, перетаскивание) — файлы в <state>/files, тип только по расширению
из белого списка, отдаются с nosniff и CSP sandbox; в письмо шины идут строки [HUMANX-FILE id=… name=…], будильник
на клиентской машине забирает файлы в комнату Арбитра. Первая строка ответа «Тема: …» показывается плашкой темы.
Запуск: humanx_web.py   (конфиг веба — файл web_config; история отправленного: StateDirectory или web_state_dir)
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import http.server, json, os, re, socket, socketserver, sys, threading, time, urllib.parse, uuid

CONF = json.load(open(_integrity_value("web_config"), encoding="utf-8"))
TOKEN = open(CONF["token_file"], encoding="utf-8").read().strip()
ALLOW = set(CONF["allow"])
SENT_F = os.path.join(os.environ.get("STATE_DIRECTORY") or _integrity_value("web_state_dir"), "sent.jsonl")
_lock = threading.Lock(); _pull = threading.Lock()
_cache = {"cards": None, "cards_ts": 0}
FILES_D = os.path.join(os.path.dirname(SENT_F), "files")
FILE_MAX, FILES_TOTAL_MAX = 15 * 1024 * 1024, 2 * 1024 ** 3
TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
         ".bmp": "image/bmp", ".pdf": "application/pdf", ".txt": "text/plain; charset=utf-8",
         ".log": "text/plain; charset=utf-8", ".csv": "text/csv; charset=utf-8", ".json": "application/json",
         ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".doc": "application/msword",
         ".xls": "application/vnd.ms-excel", ".zip": "application/zip"}
MAXR_LINE = "[HUMANX-MAXR v=1]"          # Max Reasoning: служебная строка в теле письма (как [HUMANX-FILE ...]); будильник Арбитра её убирает
PAGE_BUILD = "r20261111b"                 # версия страницы: вкладка, открытая до обновления веба, не шлёт её -> просим обновить (иначе галочка молча теряется)
FID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def file_meta(fid):
    if not FID.match(fid or ""):
        return None
    try:
        return json.load(open(os.path.join(FILES_D, fid + ".json"), encoding="utf-8"))
    except (OSError, ValueError):
        return None


def file_save(name, data):
    name = os.path.basename(str(name).replace("\\", "/"))[:200] or "file"
    ext = os.path.splitext(name)[1].lower()
    if ext not in TYPES:
        return None, "Такой тип файла не принимается: " + (ext or "без расширения")
    os.makedirs(FILES_D, mode=0o700, exist_ok=True)
    used = sum(e.stat().st_size for e in os.scandir(FILES_D))
    if used + len(data) > FILES_TOTAL_MAX:
        return None, "Хранилище вложений заполнено, напишите администратору"
    fid = str(uuid.uuid4())
    tmp = os.path.join(FILES_D, fid + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, os.path.join(FILES_D, fid + ext))
    meta = {"id": fid, "name": name, "ext": ext, "size": len(data), "ts": int(time.time())}
    json.dump(meta, open(os.path.join(FILES_D, fid + ".json"), "w", encoding="utf-8"), ensure_ascii=False)
    return meta, None


def bus(op, args=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(20)
    s.connect(CONF["socket"])
    s.sendall(json.dumps({"v": 1, "op": op, "token": TOKEN, "args": args or {}}, ensure_ascii=False).encode() + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    return json.loads(buf)


def sent_list():
    try:
        return [json.loads(l) for l in open(SENT_F, encoding="utf-8") if l.strip()][-100:]
    except OSError:
        return []


def sent_add(rec):
    with _lock, open(SENT_F, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


REPL_F = os.path.join(os.path.dirname(SENT_F), "replies.jsonl")
ARB_LOG_F = os.path.join(os.path.dirname(SENT_F), "arbiter-switch.jsonl")   # K: журнал переключений Арбитра
NOTE_OFF_F = os.path.join(os.path.dirname(SENT_F), "note.off")             # K: стоп-кран «Записки» (галочка скрыта)
NOTE_LINE = "[HUMANX-NOTE v=1]"                                            # K: записка — будильник не запускает агента
HIST_OFF_F = os.path.join(os.path.dirname(SENT_F), "history.off")          # K: стоп-кран подгрузки истории
RINGS_OFF_F = os.path.join(os.path.dirname(SENT_F), "rings.off")            # пакет M: стоп-кран экрана колец (404)
try:                                                                         # пакет M: экран колец без модели (rings_screen.py рядом)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import rings_screen as RS
except Exception:                                                            # нет модуля — веб работает как до M, /rings = 404
    RS = None
STORM_OFF_F = os.path.join(os.path.dirname(SENT_F), "storm.off")            # пакет N: стоп-кран экрана шторма (404)
try:                                                                         # пакет N: экран шторма без модели (storm_screen.py рядом)
    import storm_screen as SS
except Exception:                                                            # нет модуля — /storm = 404, остальное как до N
    SS = None
HIST_N = 80                                                                # K: порция истории (как окно опроса)
ARB_NOTE_S = 7200                                                          # K: пометка, если Арбитр не claude дольше 2 ч


def arb_log_add(rec):
    with _lock, open(ARB_LOG_F, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def arb_log_tail(n=10):
    try:
        with _lock, open(ARB_LOG_F, encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out


def arb_note(arb, now):
    """«Арбитр — X с HH:MM (переключил …)», если Арбитр не claude дольше ARB_NOTE_S. Иначе пусто."""
    if not isinstance(arb, dict) or not arb.get("arbiter") or arb.get("arbiter") == "claude":
        return ""
    ts = int(arb.get("ts") or 0)
    if not ts or now - ts < ARB_NOTE_S:
        return ""
    return "Арбитр — %s с %s (переключил %s)" % (arb["arbiter"], time.strftime("%d.%m %H:%M", time.localtime(ts)),
                                                 arb.get("set_by") or "неизвестно")


def replies_list():
    try:
        return [json.loads(l) for l in open(REPL_F, encoding="utf-8") if l.strip()][-200:]
    except OSError:
        return []


def pull_replies():
    """Новые письма оператору: тело сохраняется в replies.jsonl (лента не теряет ответ после TTL), затем ack — очередь не растёт."""
    with _pull:                                            # две вкладки не запишут один ответ дважды
        q = bus("poll", {"limit": 50})
        have = {m["id"] for m in replies_list()}
        for it in (q.get("result", {}).get("queue") or []) if q.get("ok") else []:
            if it["id"] not in have:
                g = bus("get", {"id": it["id"]})
                if not g.get("ok"):
                    continue
                m = g["result"]["message"]
                with _lock, open(REPL_F, "a", encoding="utf-8") as f:
                    f.write(json.dumps({k: m.get(k) for k in ("id", "from", "body", "reply_to", "created_at")},
                                       ensure_ascii=False) + "\n")
            bus("ack", {"id": it["id"]})


def state():
    now = int(time.time())
    arb = bus("room-arbiter").get("result", {}).get("arbiter")
    cur_v = (arb.get("arbiter") if isinstance(arb, dict) else "") or ""
    cur_addr = _hx_room(cur_v) if cur_v else ""

    if not _cache["cards"] or now - _cache["cards_ts"] > 15:
        c = bus("vendor-cards", {"days": 7})
        if c.get("ok"):
            _cache["cards"], _cache["cards_ts"] = c["result"]["cards"], now

    pull_replies()
    replies = replies_list()
    sent = sent_list()
    chat, working = build_chat(sent, replies, now, cur_addr, True)
    return {"arbiter": arb, "cards": _cache["cards"] or [], "chat": chat[-80:], "working": working, "now": now,
            "arb_note": arb_note(arb, now), "arb_log": arb_log_tail(), "note_ui": not os.path.exists(NOTE_OFF_F),
            "hist_ui": not os.path.exists(HIST_OFF_F)}


def jsonl_all(path):
    """K: весь файл — только для /api/history (по запросу при прокрутке вверх)."""
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    except OSError:
        return []


def history(before, n=HIST_N):
    """K: n записей ленты до записи before (id) в порядке всей истории; start — дошли до начала. Шина не вызывается."""
    chat, _ = build_chat(jsonl_all(SENT_F), jsonl_all(REPL_F), int(time.time()), "", False)
    ids = [x["id"] for x in chat]
    if before not in ids:
        return {"chat": [], "start": False, "found": False, "total": len(chat)}
    i = ids.index(before)
    lo = max(0, i - n)
    return {"chat": chat[lo:i], "start": lo == 0, "found": True, "total": len(chat)}


def build_chat(sent, replies, now, cur_addr, live):
    """Лента по нитям (как раньше в state()); live=False — история: статусы у шины не спрашиваются."""
    by_parent = {}
    for m in replies:
        parent = m.get("reply_to")
        if not parent:
            before = [s for s in sent if s["ts"] <= (m.get("created_at") or now)]
            parent = before[-1]["id"] if before else None
        if parent:
            by_parent.setdefault(parent, []).append(m)

    # Batch status lookup for recent unanswered messages (< 15 min / 900 s)
    pending_ids = [s["id"] for s in sent if not by_parent.get(s["id"]) and now - s["ts"] < 900]
    status_map = {}
    if pending_ids and live:
        r = bus("status-batch", {"ids": pending_ids})
        if r.get("ok"):
            status_map = r.get("result", {}).get("statuses") or {}

    def as_arb(m):
        body, topic = m["body"] or "", None
        if body.startswith("Тема:"):                       # Арбитр сам называет тему первой строкой ответа
            first, _, rest = body.partition("\n")
            topic, body = first[5:].strip()[:120], rest.strip()
        return {"id": m["id"], "side": "arb", "who": m["from"], "body": body, "topic": topic, "ts": m.get("created_at") or now,
                "reply_to": m.get("reply_to")}

    groups, placed, working = [], set(), None              # лента по нитям: письмо оператора, сразу под ним — ответы на него
    for s in sent:
        if by_parent.get(s["id"]):
            st = "answered"
        elif now - s["ts"] < 900:
            raw_st = status_map.get(s["id"], "pending")
            st = {"pending": "sent", "acked": "working", "replied": "answered"}.get(raw_st, "sent")
        else:
            st = "timeout"
        if s.get("note") and st != "answered":             # K: записка — Арбитр не запускается и не отвечает
            st = "note"

        kids = sorted(by_parent.get(s["id"], []), key=lambda m: m.get("created_at") or now)
        placed.update(m["id"] for m in kids)
        groups.append((s["ts"], [{"id": s["id"], "side": "me", "body": s["body"], "ts": s["ts"], "to": s["to"], "status": st,
                                  "files": s.get("files") or [], "maxr": bool(s.get("maxr")), "note": bool(s.get("note"))}]
                       + [as_arb(m) for m in kids]))

        # P1.2 fix: working only for messages to current Arbiter within 15 min
        if st in ("sent", "working") and s.get("to") == cur_addr and now - s["ts"] < 900:
            working = {"since": s["ts"], "status": st, "to": s["to"], "maxr": bool(s.get("maxr"))}

    for m in replies:                                      # письма Арбитра без известного письма оператора — по времени
        if m["id"] not in placed:
            groups.append((m.get("created_at") or now, [as_arb(m)]))
    groups.sort(key=lambda g: g[0])
    chat = [x for _, g in groups for x in g]
    return chat, working


PAGE = r"""<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Комната оператора</title>
<style>
:root{
  --bg:#f4f2ee;--fg:#141414;--mut:#5c5c5c;--me:#d7e7ff;--arb:#ffffff;--line:#d9d5cc;
  --acc:#1f5fd1;--ok:#1d7a3a;--bad:#a12a2a;--bar:#ffffff;--warn:#d97706;
  --q-bad-bg:rgba(239,68,68,0.08);--q-bad-br:#ef4444;--q-bad-fg:#991b1b;
  --q-ok-bg:rgba(34,197,94,0.08);--q-ok-br:#22c55e;--q-ok-fg:#166534;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#121212;--fg:#f1f1f1;--mut:#a8a8a8;--me:#1f3a63;--arb:#1f1f1f;--line:#333;
    --acc:#7aa7ff;--ok:#4cc477;--bad:#ff7a7a;--bar:#1a1a1a;--warn:#f59e0b;
    --q-bad-bg:rgba(239,68,68,0.18);--q-bad-br:#ef4444;--q-bad-fg:#fca5a5;
    --q-ok-bg:rgba(34,197,94,0.18);--q-ok-br:#22c55e;--q-ok-fg:#86efac;
  }
}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);font:19px/1.45 system-ui,Segoe UI,Arial;display:flex;flex-direction:column}
header{background:var(--bar);border-bottom:1px solid var(--line);padding:10px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px}
.h-left{display:flex;align-items:center;gap:12px;min-width:0;flex:1 1 auto}
.h-left h1{font-size:22px;margin:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.h-right{display:flex;align-items:center;gap:8px;flex:0 0 auto}
.chip{border:1.5px solid var(--line);border-radius:999px;padding:4px 12px;font-weight:600;font-size:15px;white-space:nowrap}
button{font:inherit;font-size:18px;padding:8px 16px;border-radius:12px;border:0;background:var(--acc);color:#fff;cursor:pointer}
button.ghost{background:transparent;color:var(--acc);border:2px solid var(--acc)}
button[disabled]{opacity:.45;cursor:not-allowed}
button#pick{font-size:15px;padding:6px 14px;border-radius:10px;white-space:nowrap}
#mrl{cursor:pointer;user-select:none;display:inline-flex;align-items:center;gap:6px}#mrl input{transform:scale(1.25);cursor:pointer}
.mrb{font-size:13px;font-weight:700;color:var(--acc);margin-bottom:4px}
main{flex:1 1 auto;overflow-y:auto;padding:14px}
.wrap{max-width:900px;margin:0 auto}
.row{display:flex;margin:10px 0}.row.me{justify-content:flex-end}
.b{max-width:80%;padding:12px 16px;border-radius:18px;white-space:pre-wrap;word-wrap:break-word;border:1px solid var(--line);font-size:18px}
.me .b{background:var(--me);border-bottom-right-radius:6px}
.arb .b{background:var(--arb);border-bottom-left-radius:6px}
.meta{font-size:14px;color:var(--mut);margin-top:5px}
.empty{color:var(--mut);text-align:center;margin-top:16vh;font-size:22px}
.work{display:flex;align-items:center;gap:10px;color:var(--mut);margin:14px 0;font-size:18px}
.dots span{display:inline-block;width:9px;height:9px;margin:0 2px;border-radius:50%;background:var(--acc);animation:p 1.2s infinite}
.dots span:nth-child(2){animation-delay:.2s}.dots span:nth-child(3){animation-delay:.4s}
@keyframes p{0%,80%,100%{opacity:.25}40%{opacity:1}}
footer{background:var(--bar);border-top:1px solid var(--line);padding:10px 16px}
footer .wrap{display:flex;gap:10px;align-items:flex-end}
textarea{flex:1 1 auto;font:inherit;font-size:17px;min-height:54px;max-height:200px;padding:10px 12px;border-radius:12px;border:2px solid var(--line);background:var(--bg);color:var(--fg);resize:vertical}
button.clip{background:transparent;color:var(--fg);border:2px solid var(--line);font-size:22px;padding:6px 12px;min-width:44px;border-radius:10px}
#send{font-size:17px;padding:9px 18px;border-radius:10px;font-weight:600;white-space:nowrap}
#panel{display:none;background:var(--bar);border-bottom:1px solid var(--line);padding:14px 16px}
#panel.open{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;max-width:1100px;margin:0 auto}
.card{border:2px solid var(--line);border-radius:14px;padding:12px;background:var(--bg);display:flex;flex-direction:column;gap:6px}
.card.sel{border-color:var(--acc);border-width:3px}
.card.amber{border-color:var(--warn)}.card.red{border-color:var(--bad)}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
.card-title{font-weight:700;font-size:18px}
.badge{display:inline-block;font-size:13px;padding:2px 8px;border-radius:6px;font-weight:600;white-space:nowrap}
.badge.green{background:#166534;color:#bbf7d0}
.badge.bad{background:#7f1d1d;color:#fecaca}
.badge.warn{background:#78350f;color:#fde68a}
.badge.sel{background:var(--acc);color:#fff}
.qbox{border-radius:8px;padding:8px 10px;margin:4px 0;font-size:14px;border:1px solid var(--line)}
.qbox.exhausted{background:var(--q-bad-bg);border-color:var(--q-bad-br);color:var(--q-bad-fg)}
.qbox.ready{background:var(--q-ok-bg);border-color:var(--q-ok-br);color:var(--q-ok-fg)}
.qbox.unknown{background:transparent;border-color:#a3a3a3;color:inherit}
.qbox-h{font-weight:700;margin-bottom:2px}
.qbox-d{font-size:13px;line-height:1.35}
.qbox-tier{font-size:12px;opacity:0.85;margin-top:3px}
.k{font-size:15px;color:var(--mut)}
.k.warn{color:var(--warn);font-size:14px}
.msg-actions{display:flex;gap:6px;margin-top:6px}
button.act-btn{font-size:13px;padding:3px 8px;border-radius:6px;background:transparent;border:1px solid var(--line);color:var(--mut)}
button.act-btn:hover{color:var(--fg);border-color:var(--acc)}
#err{color:var(--bad);font-weight:700;text-align:center;padding:4px 0}
.topic{display:inline-block;font-size:15px;font-weight:700;color:var(--acc);border:2px solid var(--acc);border-radius:999px;padding:2px 10px;margin-bottom:6px}
.files{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.files img{max-width:320px;max-height:240px;border-radius:10px;border:1px solid var(--line);cursor:zoom-in;display:block}
a.file{color:inherit;border:1px solid var(--line);border-radius:10px;padding:5px 8px;text-decoration:none;font-size:16px}
#tray{display:flex;flex-wrap:wrap;gap:8px;max-width:900px;margin:0 auto 8px}#tray:empty{display:none}
.att{display:flex;align-items:center;gap:6px;border:2px solid var(--line);border-radius:10px;padding:4px 8px;font-size:15px;background:var(--bg)}
.att img{width:48px;height:48px;object-fit:cover;border-radius:6px}
.att.err{border-color:var(--bad)}
.att .x{background:transparent;color:var(--fg);padding:2px 6px;font-size:18px}
body.drag main{outline:4px dashed var(--acc);outline-offset:-12px}

/* Mobile responsive overhaul (<650px) */
@media (max-width:650px){
  body{font-size:16px}
  header{padding:8px 10px;gap:8px}
  .h-left h1{font-size:17px}
  .chip{font-size:12px;padding:3px 8px}
  button#pick{font-size:12px;padding:4px 9px;border-radius:8px}
  main{padding:8px}
  .row{margin:6px 0}
  .b{max-width:92%;padding:9px 12px;font-size:15px;border-radius:14px}
  .meta{font-size:12px;margin-top:3px}
  .topic{font-size:13px;padding:1px 8px}
  .msg-actions{gap:4px;margin-top:5px}
  button.act-btn{font-size:12px;padding:2px 6px;border-radius:5px}
  footer{padding:8px 10px}
  footer .wrap{gap:6px}
  button.clip{font-size:20px;padding:6px 8px;min-width:38px;border-radius:8px}
  textarea{font-size:16px;min-height:40px;max-height:110px;padding:8px 10px;border-radius:10px}
  #send{font-size:15px;padding:8px 12px;border-radius:8px}
  #panel{padding:10px}
  .cards{grid-template-columns:1fr;gap:10px}
  .card{padding:10px}
  .files img{max-width:100%;max-height:200px}
}
</style>
<header>
  <div class="h-left"><h1>Комната оператора</h1></div>
  <div class="h-right"><a class="chip" id="rings" href="/rings" target="_blank" rel="noopener noreferrer" style="margin:0;color:inherit;text-decoration:none" title="Кольца на ядрах: шлюз чтения, без модели">Кольца</a><a class="chip" id="storml" href="/storm" target="_blank" rel="noopener noreferrer" style="margin:0;color:inherit;text-decoration:none" title="Шторм: датчик транка, журнал свичей и изменения перед началом. Шлюз чтения, без модели">Шторм</a><label class="chip" id="mrl" title="Все доступные модели отвечают независимо, сверяют факты, один Арбитр пишет итог. Дольше (обычно 3–8 мин, максимум около 14) и дороже обычного ответа."><input type="checkbox" id="mr">Max Reasoning</label><span class="chip" id="arb">Арбитр: …</span><button class="ghost" id="pick">Сменить</button></div>
</header>
<div id="panel"><div class="cards" id="cards"></div></div>
<main><div class="wrap"><div id="err"></div><div id="chat"></div><div id="work"></div></div></main>
<footer><div id="tray"></div><div class="wrap"><button class="clip" id="clip" title="Прикрепить файл или скриншот">📎</button><input type="file" id="fin" multiple hidden accept=".png,.jpg,.jpeg,.gif,.webp,.bmp,.pdf,.txt,.log,.csv,.json,.docx,.xlsx,.doc,.xls,.zip"><textarea id="text" placeholder="Напишите вопрос Арбитру…"></textarea><label class="chip" id="notel" title="Записка: письмо остаётся в переписке, Арбитр не запускается и не отвечает (без затрат). Галочка снимается после отправки."><input type="checkbox" id="note">Записка</label><button id="send">Отправить</button></div></footer>
<script>
const BUILD='r20261111b';
const $=id=>document.getElementById(id);
function el(t,c,txt){const e=document.createElement(t);if(c)e.className=c;if(txt!==undefined)e.textContent=txt;return e}
function hm(ts){const d=new Date(ts*1000);return d.toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})}
function ago(s){s=Math.max(0,s);if(s<60)return s+' с';const m=Math.floor(s/60);return m+' мин'+(s%60?' '+(s%60)+' с':'')}
function pct(x){return x==null?'нет данных':Math.round(x*100)+'%'}
function dur(s){if(s==null)return'нет данных';if(s<120)return s+' с';if(s<7200)return Math.round(s/60)+' мин';return Math.round(s/3600)+' ч'}
const ST={sent:'Отправлено, ждёт Арбитра',working:'Арбитр взял в работу',answered:'Ответ получен',timeout:'Ожидает ответа (превышен лимит 15 мин)',note:'Записка: Арбитр не читает и не отвечает'};
async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json','X-HumanX':'1'},body:JSON.stringify(body)}:{});return r.json()}
let last='',busy=false;
async function load(){
 let s;try{s=await api('/api/state')}catch(e){$('err').textContent='Нет связи с комнатой, пробую снова…';return}
 $('err').textContent='';
 const a=s.arbiter;$('arb').textContent='Арбитр: '+(a?a.arbiter:'не выбран');
 {const n=s.arb_note||'';$('arb').title=n;$('arb').style.outline=n?'2px solid #d97706':'';let e=$('arbnote');
  if(!e){e=document.createElement('div');e.id='arbnote';e.style.cssText='padding:4px 12px;font-size:13px;color:#92400e;background:#fef3c7';document.querySelector('header').after(e)}
  const lg=(s.arb_log||[]).slice().reverse().map(r=>new Date(r.ts*1000).toLocaleString('ru-RU')+': '+(r.from||'—')+' → '+r.to+(r.ok?'':' (отказ)')+', адрес '+r.ip+(r.set_by?', '+r.set_by:'')).join('\n');
  e.textContent=n;e.title=lg?'Переключения Арбитра:\n'+lg:'';e.style.display=n?'':'none';$('arb').title=(n?n+'\n\n':'')+(lg?'Переключения Арбитра:\n'+lg:'')}
 renderCards(s.cards,a);
 const key=JSON.stringify([s.chat,s.working&&s.working.status]);
 const mn=document.querySelector('main'),atEnd=mn.scrollHeight-mn.scrollTop-mn.clientHeight<100,changed=key!==last;
 const hasSel=window.getSelection()&&window.getSelection().toString().length>0;
 HX.on=s.hist_ui===true;
 if(changed&&!hasSel){last=key;if(HX.on){kept=hxMerge(kept,s.chat);keepView(()=>renderChat(kept),!atEnd)}else{kept=[];renderChat(s.chat)}}
 const w=$('work');w.replaceChildren();
 if(s.working){const d=el('div','work');const dots=el('span','dots');dots.append(el('span'),el('span'),el('span'));
  d.append(dots,el('span',null,(s.working.status==='working'?'Арбитр работает над ответом':'Письмо доставлено, Арбитр вот-вот возьмёт')+(s.working.maxr?' · Max Reasoning: отвечают несколько моделей, это дольше обычного':'')+' · '+ago(s.now-s.working.since)));w.append(d)}
 {const nl=$('notel');if(nl)nl.style.display=s.note_ui===false?'none':'';if(s.note_ui===false)$('note').checked=false}
 if(!a&&!s.chat.length){$('panel').classList.add('open')}
 if(atEnd)mn.scrollTop=mn.scrollHeight
 if(HX.on&&mn.scrollHeight<=mn.clientHeight+150)older()
}
function renderChat(chat){const c=$('chat');c.replaceChildren();
 if(HX.on&&chat.length){const h=el('div',null,HX.start?'начало истории':HX.loading?'загружаю более ранние…':'');h.id='hist';
  h.style.cssText='height:22px;line-height:22px;text-align:center;font-size:12px;color:var(--mut)';c.append(h)}
 if(!chat.length){c.append(el('div','empty','Здесь будет ваша переписка с Арбитром. Напишите вопрос внизу.'));return}
 for(const m of chat){const r=el('div','row '+(m.side==='me'?'me':'arb'));r.dataset.id=m.id;const b=el('div','b');b.append(el('div',null,m.body));
  if(m.topic)b.prepend(el('div','topic','Тема: '+m.topic));
  if(m.maxr)b.prepend(el('div','mrb','Max Reasoning'));
  if(m.note)b.prepend(el('div','mrb','Записка'));
  if(m.files&&m.files.length){const f=el('div','files');for(const x of m.files){const u='/api/file/'+x.id;
   if(/^\.(png|jpe?g|gif|webp|bmp)$/.test(x.ext)){const i=el('img');i.src=u;i.alt=x.name;i.onclick=()=>window.open(u,'_blank');f.append(i)}
   else{const a=el('a','file','📄 '+x.name);a.href=u;a.target='_blank';f.append(a)}}b.append(f)}
  if(m.side==='arb'){
   const acts=el('div','msg-actions');
   const copyBtn=el('button','act-btn','📋 Скопировать');
   copyBtn.onclick=()=>{navigator.clipboard.writeText(m.body);copyBtn.textContent='✓ Скопировано';setTimeout(()=>copyBtn.textContent='📋 Скопировать',2000)};
   acts.append(copyBtn);
   if('speechSynthesis' in window){
    const spBtn=el('button','act-btn','🔊 Озвучить');
    spBtn.onclick=()=>{
     if(window.speechSynthesis.speaking){window.speechSynthesis.cancel();spBtn.textContent='🔊 Озвучить';return}
     const u=new SpeechSynthesisUtterance(m.body);u.lang='ru-RU';u.rate=0.95;
     u.onend=()=>spBtn.textContent='🔊 Озвучить';u.onerror=()=>spBtn.textContent='🔊 Озвучить';
     window.speechSynthesis.speak(u);spBtn.textContent='⏹ Остановить';
    };
    acts.append(spBtn);
   }
   b.append(acts);
  }
  b.append(el('div','meta',m.side==='me'?'Вы · '+hm(m.ts)+' · '+(ST[m.status]||m.status||''):(m.who||'').replace('__HX_ROOM_PREFIX__','Арбитр ')+' · '+hm(m.ts)));
  r.append(b);c.append(r)}}
// лимит неизвестен: нет цифр квоты или они устарели — «Доступен» как факт не показываем
function quotaUnknown(d){d=d||'';if(/нет свежих данных|данные устарели|устарел/.test(d))return true;return !/\d+\s*%/.test(d)}
function renderCards(cards,a){const c=$('cards');c.replaceChildren();
 for(const x of cards){
  const d=el('div','card'+(x.selected?' sel':'')+(x.gate==='red'?' red':'')+(x.gate==='amber'?' amber':''));
  const hd=el('div','card-head');
  hd.append(el('span','card-title', x.vendor.toUpperCase() + (x.selected?' — ВЫБРАН':'')));
  const isExhausted = (x.runtime_state === 'quota_exhausted');
  const isUnknown = !isExhausted && x.runtime_state === 'ready' && quotaUnknown(x.runtime_detail);
  let bText = 'Доступен';
  let bClass = 'green';
  if(x.selected){bText='Выбран';bClass='sel'}
  else if(isExhausted){bText='Лимит исчерпан';bClass='bad'}
  else if(isUnknown && x.gate==='green'){bText='Лимит неизвестен';bClass='warn'}
  else if(x.gate==='amber'){bText='Недоступен';bClass='warn'}
  else if(x.gate==='red'){bText='Пока нельзя';bClass='bad'}
  hd.append(el('span','badge '+bClass, bText));
  d.append(hd);

  const q = x.weekly_quota || {};
  const qb = el('div', 'qbox ' + (isExhausted ? 'exhausted' : (isUnknown ? 'unknown' : 'ready')));
  qb.append(el('div', 'qbox-h', isExhausted ? '🔴 Квота токенов исчерпана' : (isUnknown ? '⚪ Лимит неизвестен' : '🟢 Токены / квота провайдера')));
  const qText = isUnknown && !/нет свежих данных|устарел/.test(x.runtime_detail||'')
    ? 'Нет свежих данных о лимите провайдера' + (x.runtime_detail ? ' (будильник: ' + x.runtime_detail + ')' : '')
    : (x.runtime_detail && !x.runtime_detail.includes('agentapi ready'))
    ? x.runtime_detail
    : (q.tokens_note || (isExhausted ? 'Лимит тарифного плана исчерпан' : 'Квота в порядке'));
  qb.append(el('div', 'qbox-d', qText));
  if(q.tier) qb.append(el('div', 'qbox-tier', 'Тариф: ' + q.tier));
  d.append(qb);

  if(x.gate!=='green' && !isExhausted && x.gate_reason){
    d.append(el('div','k warn', x.gate_reason));
  }

  const th=(x.token_health||[]).map(t=>t.state==='ok'?'подключён':t.state==='no-key'?'нет ключа':t.state).join(', ');
  d.append(el('div','k','Шина ядра: '+(th||'нет')));
  d.append(el('div','k','Задач за неделю: '+x.tasks+', с ответом: '+pct(x.success_rate)));
  d.append(el('div','k','Скорость ответа: '+dur(x.median_reply_s)));

  const btn=el('button', x.selected ? 'ghost' : null, x.selected ? '✓ Выбран' : (isExhausted ? 'Недоступен (лимит)' : 'Выбрать Арбитром'));
  btn.disabled = !x.selectable || x.selected;
  btn.onclick=async()=>{
    btn.disabled=true;
    const r=await api('/api/arbiter',{vendor:x.vendor});
    if(!r.ok)$('err').textContent=r.error||'не удалось';
    else $('panel').classList.remove('open');
    load();
  };
  const row=el('div');row.style.marginTop='6px';row.append(btn);d.append(row);c.append(d);
 }}
const OKEXT=/\.(png|jpe?g|gif|webp|bmp|pdf|txt|log|csv|json|docx|xlsx|doc|xls|zip)$/i;let att=[];
function tray(){const t=$('tray');t.replaceChildren();for(const a of att){const d=el('div','att'+(a.err?' err':''));
  if(a.thumb){const i=el('img');i.src=a.thumb;d.append(i)}
  d.append(el('span',null,a.name+(a.err?' — '+a.err:a.id?'':' — загружаю…')));
  const x=el('button','x','×');x.title='Убрать';x.onclick=()=>{att=att.filter(z=>z!==a);tray()};d.append(x);t.append(d)}}
function addFiles(list){for(let f of list){let name=f.name||'';
  if(!name||name==='image.png'){const d=new Date();name='Скриншот '+d.toLocaleTimeString('ru-RU').replace(/:/g,'-')+'.png'}
  const a={name,thumb:/^image\//.test(f.type)?URL.createObjectURL(f):null};att.push(a);
  if(!OKEXT.test(name)){a.err='такой тип не принимается';continue}
  if(f.size>15*1024*1024){a.err='больше 15 МБ';continue}
  a.p=fetch('/api/upload',{method:'POST',headers:{'X-HumanX':'1','X-File-Name':encodeURIComponent(name),'Content-Type':'application/octet-stream'},body:f})
   .then(r=>r.json()).then(r=>{if(r.ok)a.id=r.file.id;else a.err=r.error||'не загрузилось';tray()}).catch(()=>{a.err='нет связи';tray()})}
 tray()}
async function send(){if(busy)return;const t=$('text').value.trim();if(!t&&!att.length)return;busy=true;$('send').disabled=true;
 await Promise.all(att.map(a=>a.p).filter(Boolean));
 if(att.some(a=>a.err)){busy=false;$('send').disabled=false;$('err').textContent='Есть вложение с ошибкой — уберите его (×)';return}
 const r=await api('/api/send',{body:t,files:att.map(a=>a.id),note:$('note').checked,maxr:$('mr').checked,page:BUILD});busy=false;$('send').disabled=false;
 if(r.ok){$('text').value='';att=[];$('note').checked=false;tray();load()}else $('err').textContent=r.error||'не отправлено'}
$('clip').onclick=()=>$('fin').click();$('fin').onchange=e=>{addFiles(e.target.files);e.target.value=''};
document.addEventListener('paste',e=>{const fs=[...(e.clipboardData&&e.clipboardData.files||[])];if(!fs.length)return;
 if(!e.clipboardData.getData('text/plain'))e.preventDefault();addFiles(fs)});
document.addEventListener('dragover',e=>{e.preventDefault();document.body.classList.add('drag')});
document.addEventListener('dragleave',e=>{if(!e.relatedTarget)document.body.classList.remove('drag')});
document.addEventListener('drop',e=>{e.preventDefault();document.body.classList.remove('drag');if(e.dataTransfer&&e.dataTransfer.files.length)addFiles(e.dataTransfer.files)});
$('send').onclick=send;$('text').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send()}});
$('pick').onclick=()=>$('panel').classList.toggle('open');
try{$('mr').checked=localStorage.getItem('humanx_maxr')==='1'}catch(e){}
$('mr').onchange=()=>{try{localStorage.setItem('humanx_maxr',$('mr').checked?'1':'0')}catch(e){}};
// K history: подгрузка более ранних записей при прокрутке к верху
let kept=[];const HX={on:false,loading:false,start:false,cool:0};
function hxMerge(k,live){if(!k.length)return live.slice();const L=new Set(live.map(x=>x.id));
 const i=live.length?k.findIndex(x=>x.id===live[0].id):-1;return (i>=0?k.slice(0,i):k).filter(x=>!L.has(x.id)).concat(live)}
function hxAnchor(k){if(!k.length)return null;if(k[0].h)return k[0];return k.find(x=>x.side==='me')||k[0]}
function hxPrepend(k,add){const have=new Set(k.map(x=>x.id));return add.filter(x=>!have.has(x.id)).map(x=>Object.assign({},x,{h:1})).concat(k)}
function keepView(fn,keep){const mn=document.querySelector('main');if(!keep){fn();return}
 const top=mn.getBoundingClientRect().top;let id=null,off=0;
 for(const r of $('chat').children){if(!r.dataset.id)continue;const b=r.getBoundingClientRect();if(b.bottom>top){id=r.dataset.id;off=b.top;break}}
 fn();if(id===null)return;for(const r of $('chat').children){if(r.dataset.id===id){mn.scrollTop+=r.getBoundingClientRect().top-off;break}}}
async function older(){if(!HX.on||HX.loading||HX.start||!kept.length||Date.now()<HX.cool)return;
 const a=hxAnchor(kept);HX.loading=true;{const h=$('hist');if(h)h.textContent='загружаю более ранние…'}
 let r=null;try{r=await api('/api/history?before='+encodeURIComponent(a.id))}catch(e){r=null}
 HX.loading=false;
 if(!r||!Array.isArray(r.chat)||!r.found){HX.cool=Date.now()+5000;const h=$('hist');if(h)h.textContent='';return}
 HX.start=!!r.start;kept=hxPrepend(kept,r.chat);keepView(()=>renderChat(kept),true)}
document.querySelector('main').addEventListener('scroll',function(){if(this.scrollTop<150)older()},{passive:true});
load();setInterval(load,4000);
</script></html>"""


class H(http.server.BaseHTTPRequestHandler):
    server_version = "humanx"

    def log_message(self, *a):
        pass

    def _ok_ip(self):
        if self.client_address[0] not in ALLOW:
            self.send_error(403); return False
        return True

    def _json(self, code, doc):
        b = json.dumps(doc, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(b))); self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not self._ok_ip():
            return
        if self.path == "/":
            b = PAGE.replace("__HX_ROOM_PREFIX__", _hx_room_prefix()).encode()   # префикс комнаты из конфига
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' blob:; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
            self.send_header("X-Frame-Options", "DENY"); self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
        elif self.path.startswith("/api/file/"):
            meta = file_meta(self.path[len("/api/file/"):])
            if not meta:
                self.send_error(404); return
            try:
                data = open(os.path.join(FILES_D, meta["id"] + meta["ext"]), "rb").read()
            except OSError:
                self.send_error(404); return
            ctype = TYPES[meta["ext"]]
            inline = ctype.startswith(("image/", "text/", "application/pdf"))
            self.send_response(200); self.send_header("Content-Type", ctype)
            self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Security-Policy", "sandbox")
            self.send_header("Content-Disposition", ("inline" if inline else "attachment") + "; filename*=UTF-8''" +
                             urllib.parse.quote(meta["name"]))
            self.send_header("Cache-Control", "private, max-age=86400"); self.send_header("Content-Length", str(len(data)))
            self.end_headers(); self.wfile.write(data)
        elif self.path == "/api/state":
            try:
                self._json(200, state())
            except Exception as e:
                self.send_response(503); self.end_headers()
        elif self.path.startswith("/api/history?") and not os.path.exists(HIST_OFF_F):   # K: история по запросу
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                self._json(200, history((q.get("before") or [""])[0][:80]))
            except Exception:
                self.send_response(503); self.end_headers()
        elif self.path == "/storm" and SS is not None and not os.path.exists(STORM_OFF_F):   # пакет N (FDB, П3, выключен)
            try:
                doc, m = SS.screen(os.path.dirname(SENT_F), gw_call=SS.gw_storm)
            except Exception:
                self.send_response(503); self.end_headers(); return
            b = doc.encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                                                        "form-action 'none'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY"); self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer"); self.send_header("Cache-Control", "no-store")
            self.send_header("Server-Timing", "gw;dur=%d, render;dur=%d" % (m["gw_ms"], m["render_ms"]))
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
        elif self.path in ("/rings", "/rings?fresh=1") and RS is not None and not os.path.exists(RINGS_OFF_F):   # пакет M
            try:
                doc, m = RS.screen(os.path.dirname(SENT_F), fresh=self.path.endswith("fresh=1"))
            except Exception:
                self.send_response(503); self.end_headers(); return
            b = doc.encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                                                        "form-action 'none'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY"); self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer"); self.send_header("Cache-Control", "no-store")
            self.send_header("Server-Timing", "gw;dur=%d, render;dur=%d" % (m["gw_ms"], m["render_ms"]))
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            self.wfile.write(b)
        else:
            self.send_error(404)

    def do_POST(self):
        if not self._ok_ip():
            return
        if self.headers.get("X-HumanX") != "1":          # CSRF: чужой сайт не может поставить этот заголовок
            self.send_error(403); return
        n = int(self.headers.get("Content-Length") or 0)
        if self.path == "/api/upload":
            if n <= 0 or n > FILE_MAX:
                self._json(200, {"ok": False, "error": "Файл пустой или больше 15 МБ"}); return
            data = self.rfile.read(n)
            meta, err = file_save(urllib.parse.unquote(self.headers.get("X-File-Name") or ""), data)
            self._json(200, {"ok": bool(meta), "error": err, "file": meta}); return
        if n > 40000:
            self.send_error(413); return
        try:
            a = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            self.send_error(400); return
        if self.path == "/api/arbiter":
            prev = bus("room-arbiter").get("result", {}).get("arbiter")
            want = str(a.get("vendor", ""))[:32]
            r = bus("room-arbiter-set", {"vendor": want})
            try:                                             # журнал не должен ломать переключение
                arb_log_add({"ts": int(time.time()), "from": prev.get("arbiter") if isinstance(prev, dict) else None,
                             "to": want, "ok": bool(r.get("ok")), "error": r.get("error"), "ip": self.client_address[0],
                             "set_by": (r.get("result") or {}).get("set_by") if isinstance(r.get("result"), dict) else None})
            except OSError:
                pass
            self._json(200, {"ok": r.get("ok"), "error": r.get("error")})
        elif self.path == "/api/send":
            if a.get("page") != PAGE_BUILD:                     # вкладка со старой версией страницы (без галочки/версии): письмо не уходит, просим обновить
                self._json(200, {"ok": False, "error": "Страница устарела: обновите её (F5) и отправьте снова"}); return
            body = str(a.get("body", "")).strip()[:8000]
            files = [file_meta(str(x)) for x in (a.get("files") or [])[:10]]
            if any(f is None for f in files):
                self._json(200, {"ok": False, "error": "Вложение не найдено, прикрепите заново"}); return
            if not body and not files:
                self._json(200, {"ok": False, "error": "Пустое сообщение"}); return
            cur = bus("room-arbiter").get("result", {}).get("arbiter")
            if not cur:
                self._json(200, {"ok": False, "error": "Сначала выберите Арбитра (кнопка «Сменить Арбитра»)"}); return
            mid = str(uuid.uuid4())
            bus_body = (body or "(вложение)") + "".join(f"\n[HUMANX-FILE id={f['id']} name={urllib.parse.quote(f['name'])}]"
                                                        for f in files)
            mv = a.get("maxr", None)
            maxr_req = "absent" if "maxr" not in a else ("true" if mv is True else ("false" if mv is False else "other"))
            maxr = a.get("maxr") is True                        # только JSON true; без галочки тело письма ровно прежнее
            note = a.get("note") is True and not os.path.exists(NOTE_OFF_F)   # K: только JSON true и часть включена
            if note:
                maxr = False                                    # записка не запускает и Max Reasoning
                bus_body += "\n" + NOTE_LINE
            if maxr:
                bus_body += "\n" + MAXR_LINE
            r = bus("send", {"to": cur["address"], "id": mid, "body": bus_body, "reply_to": None})
            if r.get("ok"):
                sent_add(dict(dict({"maxr": True} if maxr else {}, **({"note": True} if note else {})), **{"id": mid, "to": cur["address"], "body": body, "ts": int(time.time()),
                          "ip": self.client_address[0], "maxr_req": maxr_req, "page": PAGE_BUILD,
                          "files": [{k: f[k] for k in ("id", "name", "ext", "size")} for f in files]}))
            self._json(200, {"ok": r.get("ok"), "error": r.get("error")})
        else:
            self.send_error(404)


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    S((CONF["bind"], int(CONF["port"])), H).serve_forever()
