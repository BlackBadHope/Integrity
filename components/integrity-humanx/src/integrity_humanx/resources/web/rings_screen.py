"""Пакет M: экран колец для оператора в вебе комнаты HumanX. Модель не участвует ни в первом показе, ни в повторе.

Слои концепта «Живой экран»:
  0 данные     — шлюз чтения комнаты, op switch: ядра из карты колец (cores), ровно 4 команды show (см. CMDS);
  1 экран      — фиксированный шаблон этого файла; значения подставляет и экранирует сервер (html.escape), чисел от модели нет;
  3 линтер     — lint(): нет скриптов, обработчиков, внешних адресов, форм, фреймов; все кольца и ядра из данных на экране;
                 сумма плиток = числу колец; размер ≤ 64 КБ;
  4 изоляция   — веб отдаёт экран с CSP «sandbox; default-src 'none'; style-src 'unsafe-inline'»: скриптов нет вовсе, сети нет;
  5 макрос     — sha шаблона и sha схемы данных в <meta name="hx-macro">; повтор = данные + подстановка, 0 вызовов модели.
Кэш ответов шлюза — <state>/rings-cache.json: повтор в течение TTL не опрашивает свичи; «Обновить» не чаще FRESH_MIN.
Стоп-кран: файл <state>/rings.off (веб отдаёт 404, ссылка в шапке остаётся). Стенд: HUMANX_RINGS_FIXTURES=<каталог с core-<ip>.json>.
Разбор вывода D-Link — из стенда ring_data.py (v2: общий порт — плечо кольца с меньшим числом портов).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import hashlib
import html
import json
import os
import re
import socket
import threading
import time

CMDS = ["show ports description", "show stp ports", "show stp", "show erps"]
GW_SOCK = _integrity_value("ro_gateway_socket")
GW_VENDOR = "web-rings"
GW_TIMEOUT = 180
TTL = 300
FRESH_MIN = 60
MAX_BYTES = 64 * 1024
HERE = os.path.dirname(os.path.abspath(__file__))
MAP_F = _integrity_value("ring_map_file")
with open(MAP_F, encoding="utf-8") as _fh:              # cores and not_polled come from the ring map file
    _RMAP = json.load(_fh)
CORES = [str(x) for x in _RMAP["cores"]]
_lock = threading.Lock()

# ------------------------------------------------------------------ слой 0: разбор вывода свича
PORT_RE = re.compile(r"^\s*(\d{1,2})(?:\s+\((C|F)\))?\s+(Enabled|Disabled)\s+\S+\s+(Link Down|\d+M/\S+)", re.M)


def parse_ports(txt):
    ports, cur = {}, None
    for line in (txt or "").splitlines():
        m = PORT_RE.match(line)
        if m:
            p, admin, conn = int(m.group(1)), m.group(3), m.group(4)
            link = "нет" if conn == "Link Down" else conn.split("/")[0]
            old = ports.get(p)
            if not old or (old["link"] == "нет" and link != "нет"):      # combo-порт: берём среду с линком
                ports[p] = {"admin": "вкл" if admin == "Enabled" else "выкл", "link": link, "descr": ""}
            cur = p
            continue
        d = re.match(r"^\s+Description:\s*(.*)$", line)
        if d and cur in ports and d.group(1).strip() and not ports[cur]["descr"]:
            ports[cur]["descr"] = d.group(1).strip()[:60]
    return ports


def parse_stp_ports(txt):
    res = {}
    for blk in re.split(r"(?=Port Index\s*:)", txt or ""):
        m = re.match(r"Port Index\s*:\s*(\d+)", blk)
        if not m:
            continue
        on = re.search(r"Port STP\s*:\s*(\w+)", blk)
        rows = re.findall(r"^\s*(\d+)\s+\S+\s+\d+\s+\d+\s+(\w+)\s+(\w+)\s*$", blk, re.M)
        cist = next(((s, r) for i, s, r in rows if i == "0"), ("-", "-"))
        blocked = any(s in ("Discarding", "Blocking") for _, s, _ in rows)
        res[int(m.group(1))] = {"stp": "вкл" if on and on.group(1) == "Enabled" else "выкл",
                                "cist": "%s/%s" % cist, "blocked": "да" if blocked else "нет"}
    return res


def parse_global(stp_txt, erps_txt):
    on = {"Enabled": "вкл", "Disabled": "выкл"}
    v = re.search(r"STP Version\s*:\s*(\S+)", stp_txt or "")
    s = re.search(r"STP Status\s*:\s*(\S+)", stp_txt or "")
    e = re.search(r"Global Status\s*:\s*(\S+)", erps_txt or "")
    return {"stp": on.get(s.group(1), s.group(1)) if s else "?", "stp_ver": v.group(1) if v else "?",
            "erps": on.get(e.group(1), e.group(1)) if e else "?"}


# ------------------------------------------------------------------ слой 0: шлюз и кэш
def gw_call(ip):
    """Один запрос к шлюзу чтения через его сокет (uid процесса веба; шлюз пускает его только на этот экран)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(GW_TIMEOUT)
    try:
        s.connect(GW_SOCK)
        s.sendall((json.dumps({"vendor": GW_VENDOR, "op": "switch", "args": {"ip": ip, "cmds": CMDS}}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8"))
    except (OSError, ValueError) as e:
        return {"ok": False, "error": "шлюз чтения недоступен: " + type(e).__name__}
    finally:
        s.close()


def fetch(state_dir, fresh=False, now=None, call=None):
    """Ответы шлюза по ядрам. Кэш моложе TTL — без опроса; fresh — опрос, если кэш старше FRESH_MIN.
    Ошибка опроса — остаётся прежний ответ (помечен stale) и текст ошибки."""
    now = time.time() if now is None else now
    fx = os.environ.get("HUMANX_RINGS_FIXTURES")
    if fx:
        docs = {}
        for ip in CORES:
            try:
                d = json.load(open(os.path.join(fx, "core-%s.json" % ip), encoding="utf-8"))
            except (OSError, ValueError):
                d = {"ok": False, "error": "нет сохранённого ответа"}
            d["fixture"] = True
            docs[ip] = d
        return docs, 0
    call = call or gw_call
    cache_f = os.path.join(state_dir, "rings-cache.json")
    with _lock:
        try:
            cache = json.load(open(cache_f, encoding="utf-8"))
        except (OSError, ValueError):
            cache = {}
        polled = 0
        for ip in CORES:
            old = cache.get(ip) or {}
            age = now - float(old.get("fetched_at") or 0)
            if old.get("ok") and (age < (FRESH_MIN if fresh else TTL)):
                continue
            d = call(ip)
            polled += 1
            if d.get("ok"):
                d.pop("banner", None)
                d["fetched_at"] = now - float(d.get("age_s") or 0)     # общий ответ шлюза (MR-очередь): время самого чтения свича
                cache[ip] = d
            else:
                cache[ip] = dict(old, error=str(d.get("error") or "нет ответа")[:160], error_at=now)
        tmp = cache_f + ".tmp"
        with open(tmp, "w", encoding="utf-8") as h:
            json.dump(cache, h, ensure_ascii=False)
        os.replace(tmp, cache_f)
        return cache, polled


# ------------------------------------------------------------------ данные экрана
STATES = ["разомкнуто", "без линка на ядре", "одно плечо на ядре", "неполное", "замкнуто"]
# ядра вне опроса показываются явной строкой и в «всего в опросе» не входят
NOT_POLLED = [{"ring": str(x["ring"]), "core": str(x["core"])} for x in _RMAP.get("not_polled", [])]


def build(docs, rmap, now=None):
    now = time.time() if now is None else now
    cores = []
    parsed = {}
    for ip in CORES:
        d = docs.get(ip) or {}
        c = {"ip": ip, "short": ip.split(".", 2)[-1], "ok": bool(d.get("outputs")), "error": d.get("error") if not d.get("ok") or d.get("error_at") else None,
             "at": d.get("fetched_at"), "fixture": bool(d.get("fixture"))}
        if c["ok"]:
            o = d["outputs"]
            parsed[ip] = {"ports": parse_ports(o.get("show ports description")), "stp": parse_stp_ports(o.get("show stp ports"))}
            c.update(parse_global(o.get("show stp"), o.get("show erps")))
            c["age_s"] = int(now - float(c["at"] or now))
        cores.append(c)
    owner = {}
    for r in sorted(rmap["rings"], key=lambda x: (len(x["ports"]), int(x["ring"]))):
        for p in r["ports"]:
            owner.setdefault((r["core"], p), r["ring"])
    rings = []
    for r in rmap["rings"]:
        pc = parsed.get(r["core"])
        ring = {"ring": r["ring"], "core": r["core"].split(".", 2)[-1], "cls": r.get("class", ""), "arms": [], "transit": []}
        for p in r["ports"]:
            if owner[(r["core"], p)] != r["ring"]:
                ring["transit"].append({"port": p, "of": owner[(r["core"], p)]})
                continue
            if pc is None:
                ring["arms"].append({"port": p, "admin": "?", "link": "?", "stp": "?", "cist": "?", "blocked": "?", "descr": "", "up": False})
                continue
            pt, st = pc["ports"].get(p, {}), pc["stp"].get(p, {})
            ring["arms"].append({"port": p, "admin": pt.get("admin", "?"), "link": pt.get("link", "?"), "stp": st.get("stp", "?"),
                                 "cist": st.get("cist", "?"), "blocked": st.get("blocked", "?"), "descr": pt.get("descr", ""),
                                 "up": pt.get("admin") == "вкл" and pt.get("link", "нет") not in ("нет", "?")})
        n = sum(a["up"] for a in ring["arms"])
        if pc is None:
            ring["state"] = "нет данных"
        elif len(ring["arms"]) == 1:
            ring["state"] = "одно плечо на ядре" if n else "без линка на ядре"
        else:
            # замкнуто — линк на ВСЕХ плечах; 2 из 3 и т. п. — «неполное: N из M плеч»
            ring["state"] = ("замкнуто" if n == len(ring["arms"]) else "неполное") if n >= 2 else ("разомкнуто" if n == 1 else "без линка на ядре")
        ring["up"], ring["n_arms"] = n, len(ring["arms"])
        rings.append(ring)
    order = {s: i for i, s in enumerate(STATES + ["нет данных"])}
    rings.sort(key=lambda x: (order.get(x["state"], 9), int(x["ring"]) if x["ring"].isdigit() else 9999))
    counts = {s: sum(1 for x in rings if x["state"] == s) for s in STATES + ["нет данных"]}
    oks = [c for c in cores if c["ok"]]
    attention = sum(1 for x in rings if STATE_CLS.get(x["state"]) != "ok")
    return {"cores": cores, "rings": rings, "counts": counts, "total": len(rings), "attention": attention, "not_polled": NOT_POLLED,
            "live": any(not c["fixture"] for c in oks), "map_source": rmap.get("source", ""), "built_at": now}


def schema_sha(data):
    """sha схемы данных (ключи и типы, без значений): изменилась — макрос экрана не применяется."""
    def shape(v):
        if isinstance(v, dict):
            return {k: shape(v[k]) for k in sorted(v)}
        if isinstance(v, list):
            return [shape(v[0])] if v else []
        return type(v).__name__ if v is not None else "null"
    sh = shape({"cores": data["cores"][:1], "rings": data["rings"][:1], "counts": data["counts"], "total": 0, "attention": 0,
                "not_polled": data["not_polled"][:1]})
    return hashlib.sha256(json.dumps(sh, sort_keys=True).encode()).hexdigest()[:16]


# ------------------------------------------------------------------ слой 1: шаблон (фиксированный, без скриптов)
CSS = """
:root{color-scheme:dark light;--bg:#14161a;--card:#1d2026;--line:#2c313a;--tx:#e8eaed;--mut:#9aa0a6;--ok:#2e7d4f;--okt:#7ee2a8;
--bad:#7a2630;--badt:#ff9aa5;--warn:#6b5414;--warnt:#ffd77a;--info:#23395d;--infot:#9cc3ff}
@media (prefers-color-scheme:light){:root{--bg:#f6f7f9;--card:#fff;--line:#dde1e6;--tx:#1b1d21;--mut:#5f6368;--ok:#e3f4ea;--okt:#17663b;
--bad:#fde7ea;--badt:#a3202f;--warn:#fff4d6;--warnt:#7a5a00;--info:#e6efff;--infot:#1f4f99}}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:680px;margin:0 auto;padding:12px 12px 24px;display:flex;flex-direction:column;gap:10px}
h1{font-size:17px;margin:0;font-weight:600}.top{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
a{color:var(--infot)}.btn{display:inline-block;padding:6px 12px;border:1px solid var(--line);border-radius:8px;text-decoration:none;color:var(--tx);background:var(--card)}
.prov{padding:8px 10px;border-radius:8px;background:var(--info);color:var(--infot);font-size:13px}
.prov.fx{background:var(--warn);color:var(--warnt);font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px}
.tile{padding:8px;border-radius:8px;background:var(--card);border:1px solid var(--line);min-width:0}
.tile b{display:block;font-size:22px;font-weight:600}.tile span{font-size:12px;color:var(--mut)}
.tile.bad{background:var(--bad);color:var(--badt)}.tile.ok{background:var(--ok);color:var(--okt)}.tile.warn{background:var(--warn);color:var(--warnt)}
.tile.bad span,.tile.ok span,.tile.warn span{color:inherit}
.core{padding:8px 10px;border-radius:8px;background:var(--card);border:1px solid var(--line);font-size:13px}
.core.err{border-color:var(--badt)}.core .e{color:var(--badt)}
.ring{border-radius:10px;background:var(--card);border:1px solid var(--line);padding:8px 10px;display:flex;flex-direction:column;gap:6px;min-width:0}
.ring.st-bad{border-left:4px solid var(--badt)}.ring.st-warn{border-left:4px solid var(--warnt)}.ring.st-ok{border-left:4px solid var(--okt)}
.rh{display:flex;justify-content:space-between;gap:8px;align-items:baseline;flex-wrap:wrap}.rh b{font-size:15px}
summary.rh{cursor:pointer;list-style:none}summary.rh::-webkit-details-marker{display:none}summary.rh b::before{content:"▸ ";color:var(--mut)}
details[open]>summary.rh b::before{content:"▾ "}details.ring:not([open]){gap:0}
.pill{padding:1px 8px;border-radius:10px;font-size:12px;white-space:nowrap}
.pill.bad{background:var(--bad);color:var(--badt)}.pill.warn{background:var(--warn);color:var(--warnt)}.pill.ok{background:var(--ok);color:var(--okt)}
.arm{display:grid;grid-template-columns:auto minmax(0,1fr);gap:2px 10px;font-size:13px;padding-top:4px;border-top:1px dashed var(--line)}
.arm .p{font-weight:600;white-space:nowrap}.arm .d{color:var(--mut);overflow-wrap:anywhere}.arm .k{overflow-wrap:anywhere}
.down{color:var(--badt);font-weight:600}.mut{color:var(--mut);font-size:12px;overflow-wrap:anywhere}
h2{font-size:14px;margin:6px 0 0;color:var(--mut);font-weight:600}
"""

STATE_CLS = {"разомкнуто": "bad", "без линка на ядре": "bad", "одно плечо на ядре": "warn", "неполное": "warn", "замкнуто": "ok", "нет данных": "warn"}
TEMPLATE_SHA = hashlib.sha256((CSS + "|".join("%s=%s" % kv for kv in sorted(STATE_CLS.items())) + "|tpl-v2").encode()).hexdigest()[:16]
E = html.escape


def _hm(ts):
    return time.strftime("%d.%m %H:%M:%S", time.localtime(ts)) if ts else "?"


def render(data):
    out = []
    w = out.append
    sha = schema_sha(data)
    w('<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    w('<meta name="hx-macro" content="intent=rings;template=%s;schema=%s;model_calls=0">' % (TEMPLATE_SHA, sha))
    w("<title>Кольца на ядрах</title><style>%s</style></head><body><main>" % CSS)
    w('<div class="top"><h1>Кольца на ядрах %s</h1>' % E(" и ".join(c["short"] for c in data["cores"])) + '<span><a class="btn" href="/rings?fresh=1">Обновить</a> '
      '<a class="btn" href="/">Комната</a></span></div>')
    fx = any(c.get("fixture") for c in data["cores"])
    reads = "; ".join("%s — %s" % (E(c["short"]), _hm(c["at"])) for c in data["cores"] if c["ok"])
    w('<div class="prov%s" data-k="provenance">%s Опрос ядер через шлюз чтения комнаты (только show): %s. '
      'Плечи колец — по карте колец; общий порт отнесён к кольцу с меньшим числом портов. Экран без модели: шаблон и подстановка.</div>'
      % (" fx" if fx else "", "НЕ ЖИВЫЕ ДАННЫЕ — сохранённый ответ шлюза." if fx else "Данные шлюза.", reads or "нет ответов"))
    cnt = data["counts"]
    tiles = [("bad", cnt["разомкнуто"] + cnt["без линка на ядре"], "разомкнуто или без линка"),
             ("warn", cnt["одно плечо на ядре"] + cnt["неполное"] + cnt["нет данных"], "неполное, одно плечо или нет данных"),
             ("ok", cnt["замкнуто"], "замкнуто"), ("", data["total"], "всего в опросе")]
    w('<div class="tiles">')
    for cls, n, label in tiles:
        w('<div class="tile %s" data-k="tile"><b>%d</b><span>%s</span></div>' % (cls if n else "", n, E(label)))
    w("</div>")
    for x in data["not_polled"]:
        w('<div class="core err" data-k="not-polled">Кольцо %s (ядро %s) в опрос не входит: его состояния здесь нет, в «всего в опросе» оно не считается.</div>'
          % (E(x["ring"]), E(x["core"].split(".", 2)[-1])))
    for c in data["cores"]:
        if c["ok"]:
            stale = (' · <span class="e">не обновилось: %s</span>' % E(str(c["error"]))) if c.get("error") else ""
            w('<div class="core" data-core="%s">Ядро %s: STP %s (%s), ERPS %s · прочитано %s, %s назад%s</div>'
              % (E(c["ip"]), E(c["short"]), E(c["stp"]), E(c["stp_ver"]), E(c["erps"]), _hm(c["at"]), _ago(c.get("age_s", 0)), stale))
        else:
            w('<div class="core err" data-core="%s">Ядро %s: <span class="e">нет данных — %s</span></div>' % (E(c["ip"]), E(c["short"]), E(str(c["error"] or "нет ответа"))))
    head = None
    for r in data["rings"]:
        grp = "Требуют внимания" if STATE_CLS.get(r["state"]) != "ok" else "Замкнуты"
        if grp != head:
            w('<h2 data-k="group">%s</h2>' % (("%s: %d" % (grp, data["attention"])) if grp == "Требуют внимания" else grp))
            head = grp
        cls = STATE_CLS.get(r["state"], "warn")
        pill = ("неполное: %d из %d плеч" % (r["up"], r["n_arms"])) if r["state"] == "неполное" else "%s · плеч с линком %d/%d" % (r["state"], r["up"], r["n_arms"])
        tag = "details" if cls == "ok" else "section"          # замкнутые свёрнуты (без JS), требующие внимания раскрыты
        hd = "summary" if cls == "ok" else "div"
        w('<%s class="ring st-%s" data-ring="%s"><%s class="rh"><b>Кольцо %s</b><span class="pill %s">%s</span></%s>'
          % (tag, cls, E(r["ring"]), hd, E(r["ring"]), cls, E(pill), hd))
        w('<div class="mut">ядро %s · класс %s</div>' % (E(r["core"]), E(r["cls"])))
        for a in r["arms"]:
            link = '<span class="down">нет линка</span>' if a["link"] == "нет" else E(a["link"])
            adm = "" if a["admin"] == "вкл" else ' · <span class="down">порт %s</span>' % E(a["admin"])
            w('<div class="arm"><span class="p">порт %s</span><span class="k">линк %s%s · STP %s · CIST %s · блок %s</span>'
              % (E(str(a["port"])), link, adm, E(a["stp"]), E(a["cist"]), E(a["blocked"])))
            if a["descr"]:
                w('<span></span><span class="d">%s</span>' % E(a["descr"]))
            w("</div>")
        if r["transit"]:
            w('<div class="mut">VLAN также на портах %s</div>' % E(", ".join("%s (плечо кольца %s)" % (t["port"], t["of"]) for t in r["transit"])))
        w("</%s>" % tag)
    w('<div class="mut">Источник: %s; карта колец: %s. Только чтение: экран ничего не меняет на свичах.</div>' % (E(", ".join(CMDS)), E(data["map_source"])))
    w("</main></body></html>")
    return "".join(out)


def _ago(s):
    s = max(0, int(s))
    return "%d с" % s if s < 90 else ("%d мин" % (s // 60) if s < 5400 else "%d ч" % (s // 3600))


# ------------------------------------------------------------------ слой 3: линтер
# Разметка проверяется без текста между тегами (описание порта «uplink //A» — текст, не адрес), стиль — отдельно.
FORBID_MARKUP = [(re.compile(r"<\s*script", re.I), "script"), (re.compile(r"\son[a-z]+\s*=", re.I), "обработчик on*"),
                 (re.compile(r"javascript:", re.I), "javascript:"),
                 (re.compile(r"\s(src|srcset|action|formaction|poster|data|style)\s*=", re.I), "атрибут с адресом или стилем"),
                 (re.compile(r"<\s*(form|iframe|frame|object|embed|img|link|base|svg|video|audio|meta\s+http-equiv)\b", re.I), "запрещённый тег")]
FORBID_STYLE = [(re.compile(r"@import|url\s*\(|expression\s*\(", re.I), "внешний ресурс в стиле")]
HREF_OK = {"/rings?fresh=1", "/"}


def lint(doc, data):
    styles = "".join(re.findall(r"<style>(.*?)</style>", doc, re.S))
    markup = re.sub(r">[^<]*<", "><", re.sub(r"<style>.*?</style>", "<style></style>", doc, flags=re.S))
    bad = [name for rx, name in FORBID_MARKUP if rx.search(markup)] + [name for rx, name in FORBID_STYLE if rx.search(styles)]
    if doc.count("<style>") != 1:
        bad.append("стилей не один блок")
    bad += ["ссылка %s" % h for h in re.findall(r'href="([^"]*)"', doc) if h not in HREF_OK]
    if len(doc.encode()) > MAX_BYTES:
        bad.append("размер %d > %d" % (len(doc.encode()), MAX_BYTES))
    for r in data["rings"]:
        if doc.count('data-ring="%s"' % E(r["ring"])) != 1:
            bad.append("кольцо %s не на экране" % r["ring"])
    for c in data["cores"]:
        if 'data-core="%s"' % c["ip"] not in doc:
            bad.append("ядро %s не на экране" % c["ip"])
    if sum(data["counts"].values()) != data["total"]:
        bad.append("плитки не сходятся с числом колец")
    tl = [int(x) for x in re.findall(r'data-k="tile"><b>(\d+)</b>', doc)]
    if len(tl) != 4 or sum(tl[:3]) != tl[3] or tl[3] != data["total"]:
        bad.append("видимые плитки не сходятся с «всего в опросе» %r" % tl)
    g = re.findall(r'data-k="group">Требуют внимания: (\d+)<', doc)
    want_g = [str(data["attention"])] if data["attention"] else []
    if g != want_g or (len(tl) == 4 and data["attention"] != tl[0] + tl[1]):
        bad.append("«Требуют внимания» не сходится с плитками")
    for x in data["not_polled"]:
        if doc.count('data-k="not-polled">Кольцо %s ' % E(x["ring"])) != 1:
            bad.append("нет строки «кольцо %s вне опроса»" % x["ring"])
    if 'data-k="provenance"' not in doc:
        bad.append("нет строки происхождения данных")
    return bad


# ------------------------------------------------------------------ вход для веба
def screen(state_dir, fresh=False):
    """HTML экрана и метрики. Линтер не прошёл — безопасная страница с перечнем причин (без данных)."""
    t0 = time.time()
    docs, polled = fetch(state_dir, fresh)
    t1 = time.time()
    rmap = json.load(open(MAP_F, encoding="utf-8"))
    data = build(docs, rmap)
    doc = render(data)
    bad = lint(doc, data)
    if bad:
        doc = ('<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Кольца</title></head><body>'
               "<p>Экран колец не прошёл проверку: %s. Спросите Арбитра в комнате.</p></body></html>" % E("; ".join(bad)[:400]))
    return doc, {"polled": polled, "gw_ms": int((t1 - t0) * 1000), "render_ms": int((time.time() - t1) * 1000), "lint": bad,
                 "bytes": len(doc.encode()), "template": TEMPLATE_SHA, "schema": schema_sha(data) if not bad else None}
