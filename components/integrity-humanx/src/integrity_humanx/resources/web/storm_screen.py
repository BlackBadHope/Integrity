"""storm_screen — экран шторма для оператора в вебе комнаты (пакет N, стенд). Без модели: разбор, фиксированный шаблон, линтер.

Слои (как в M):
  0 данные   — (а) датчик транка гипервизора: строки «TRUNKBCAST alarm|clear …» из журнала службы датчика транка
                   и state.json; (б) журнал свичей на сервере журналов с 15 мин до начала серии и до сейчас;
                   (в) карта колец пакета M (VLAN кольца = номер кольца, ядро и порты-плечи).
               Живой путь к (а) и (б) из веба идёт только через операцию шлюза storm-read (отдельное право).
               Стенд — сохранённые данные сегодняшнего шторма (HUMANX_STORM_FIXTURES).
  1 экран    — фиксированный шаблон; значения через html.escape; стили — общий CSS экрана колец.
  2 FDB      — вторым слоем и только по кнопке «/storm?fdb=1»: MAC по портам ядра в VLAN шторма через шлюз чтения
               (команда из реестра команд по модели ядра; права у веба на неё пока нет).
  3 линтер   — те же запреты разметки, что в M; ссылки только /, /rings, /storm, /storm?fdb=1; вывод сверху обязателен;
               каждая серия и каждое ядро шторма на экране.
  4 изоляция — веб отдаёт с теми же заголовками, что /rings (CSP sandbox, без скриптов).
Вывод сверху ставится по событиям, а не по догадке: «за K с до начала на свиче X выключен STP (вход с адреса Y)» — только если
в журнале есть «spanning tree protocol is disabled» в 15 мин до начала серии; иначе «изменений конфигурации перед началом не видно».
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import datetime as dt, hashlib, html, json, os, re, socket, time

HERE = os.path.dirname(os.path.abspath(__file__))
MAP_F = _integrity_value("ring_map_file")
with open(MAP_F, encoding="utf-8") as _fh:   # первые два октета адресов свичей доступа (<prefix>.<кольцо>.x) — из карты колец
    ACCESS_PREFIX = str(json.load(_fh)["access_prefix"])
PRE_S = 900            # окно журнала до начала серии
CHAIN_S = 900          # эпизоды датчика ближе этого — одна серия
MAX_BYTES = 64 * 1024   # рост страницы ограничен по существу, предел остаётся с запасом над худшим замером
EV_MAX = 150           # строк в разделе «Изменения и входы» (после свёртки повторов); остальное — строкой «показано N из M»
EV_PIN_MAX = 60        # из них STP и сохранения конфигурации показываются всегда, но не больше этого
FOLD_MIN, FOLD_GAP = 3, 300   # линк/топология/порт STP одного свича-порта: от 3 смен с паузами <= 5 мин — одна строка
COLS_EXTRA = 6         # столбцов таблицы ядра сверх плеч кольца
TOP_N = 5              # шум, повторы, шторм на других свичах — первые 5 и счётчик остального
try:
    import rings_screen as RS                      # общий CSS и запреты разметки экрана колец (пакет M)
    CSS_BASE, FORBID_MARKUP, FORBID_STYLE = RS.CSS, RS.FORBID_MARKUP, RS.FORBID_STYLE
except Exception:                                  # стенд без M рядом
    CSS_BASE, FORBID_MARKUP, FORBID_STYLE = "", [(re.compile(r"<\s*script", re.I), "script")], []
CSS = CSS_BASE + """
.head{padding:10px 12px;border-radius:10px;font-size:15px;font-weight:600;background:var(--bad);color:var(--badt)}
.head.clear{background:var(--card);color:var(--tx);border:1px solid var(--line)}
table.m{border-collapse:collapse;width:100%;font-size:12px}table.m td,table.m th{border-bottom:1px solid var(--line);padding:2px 4px;text-align:right}
table.m th:first-child,table.m td:first-child{text-align:left}.ev{display:grid;grid-template-columns:auto minmax(0,1fr);gap:2px 10px;font-size:13px}
.ev .t{white-space:nowrap;color:var(--mut)}.ev .x{overflow-wrap:anywhere}.ev .hot{color:var(--badt);font-weight:600}
.scroll{overflow-x:auto}
"""
TEMPLATE_SHA = hashlib.sha256((CSS + "|storm-v2").encode()).hexdigest()[:16]
E = html.escape

SENS_RE = re.compile(r"^(\S+)\s.*TRUNKBCAST (alarm|clear) id=(\d+) rx_pps=(\d+) mc_pps=(\d+) peak=(\d+) since=(\S+) vlans=(\S+)")
LOG_RE = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:.]+[+-]\d\d:\d\d)\s+(\d+\.\d+\.\d+\.\d+)\s+(.*)$")
R_STORM = re.compile(r"port (\d+) (broadcast|multicast)\s+storm (is occurring|has cleared)", re.I)
R_STP = re.compile(r"spanning tree protocol is (disabled|enabled)", re.I)
R_SAVE = re.compile(r"configuration saved", re.I)
R_LOGIN = re.compile(r"successful login through (web|telnet)\s*\(\s*(?:username:\s*([^,\s]+),\s*)?ip:\s*([\d.]+)", re.I)
R_LINK = re.compile(r"port (\d+) link (up|down)", re.I)
R_STPP = re.compile(r"spanning tree port (status|role)\s+change \(instance:(\d+), port:(\d+)\) (\S+)", re.I)
R_TOPO = re.compile(r"topology changed", re.I)


def _ts(s):
    return dt.datetime.fromisoformat(s).timestamp()


def parse_sensor(lines):
    eps = {}
    for l in lines:
        m = SENS_RE.match(l.strip())
        if not m:
            continue
        since = _ts(m.group(7))
        e = eps.setdefault(since, {"since": since, "alarm": None, "clear": None, "peak": 0, "vlans": []})
        e["peak"] = max(e["peak"], int(m.group(6)))
        if m.group(2) == "alarm":
            e["alarm"] = _ts(m.group(1))
            for v in m.group(8).split(","):
                mm = re.match(r"([^:]+):(\d+)/(\d+)$", v)
                if mm:
                    e["vlans"].append({"vlan": mm.group(1), "n": int(mm.group(2)), "of": int(mm.group(3))})
        else:
            e["clear"] = _ts(m.group(1))
    return sorted(eps.values(), key=lambda e: e["since"])


def parse_log(lines, dups=None):
    """dups (dict) — сюда пишется, какие свичи шлют точные повторы строки подряд (тот же свич и текст в пределах 1 с)."""
    out, prev = [], None
    for l in lines:
        m = LOG_RE.match(l.rstrip("\n"))
        if not m:
            continue
        ts, sw, msg = _ts(m.group(1)), m.group(2), m.group(3).strip()
        if prev and prev[0] == sw and prev[1] == msg and ts - prev[2] < 1.0:   # точный повтор подряд — одна запись
            if dups is not None:
                dups[sw] = dups.get(sw, 0) + 1
            continue
        prev = (sw, msg, ts)
        r = {"ts": ts, "sw": sw}
        if (x := R_STORM.search(msg)):
            r.update(k="storm", port=int(x.group(1)), kind=x.group(2).lower(), on=x.group(3).lower() == "is occurring")
        elif (x := R_STP.search(msg)):
            r.update(k="stp", on=x.group(1).lower() == "enabled")
        elif R_SAVE.search(msg):
            r.update(k="save")
        elif (x := R_LOGIN.search(msg)):
            r.update(k="login", how=x.group(1).lower(), user=x.group(2) or "", ip=x.group(3))
        elif (x := R_STPP.search(msg)):
            r.update(k="stpport", port=int(x.group(3)), change=x.group(4))
        elif (x := R_LINK.search(msg)):
            r.update(k="link", port=int(x.group(1)), up=x.group(2).lower() == "up")
        elif R_TOPO.search(msg):
            r.update(k="topo")
        else:
            continue
        out.append(r)
    return out


def series(eps):
    """Последняя серия эпизодов датчика (между отбоем и новым началом меньше CHAIN_S)."""
    if not eps:
        return []
    cur = [eps[0]]
    for e in eps[1:]:
        prev_end = cur[-1]["clear"] or cur[-1]["alarm"] or cur[-1]["since"]
        cur = cur + [e] if e["since"] - prev_end < CHAIN_S else [e]
    return cur


def ring_of_sw(sw):
    p = sw.split(".")
    return p[2] if len(p) == 4 and ".".join(p[:2]) == ACCESS_PREFIX else None   # свичи доступа <access_prefix>.<кольцо>.x


KIND_RU = {"stp": "STP", "save": "сохранения", "login": "входы", "link": "линки", "topo": "смены топологии",
           "stpport": "порты STP", "fold": "свёрнутые серии"}


def fold_events(keep):
    """Серии смен одного вида на одном свиче-порту (линк, топология, порт STP), паузы <= FOLD_GAP, от FOLD_MIN смен — одна строка."""
    rows, runs = [], {}
    for e in keep:
        if e["k"] in ("link", "topo", "stpport"):
            key = (e["k"], e["sw"], e.get("port"))
            r = runs.get(key)
            if r is not None and e["ts"] - r[-1]["ts"] <= FOLD_GAP:
                r.append(e)
                continue
            runs[key] = [e]
            rows.append(runs[key])
        else:
            rows.append(e)
    out = []
    for x in rows:
        if isinstance(x, dict):
            out.append(x)
        elif len(x) >= FOLD_MIN:
            out.append({"k": "fold", "of": x[0]["k"], "sw": x[0]["sw"], "port": x[0].get("port"), "n": len(x),
                        "ts": x[0]["ts"], "ts2": x[-1]["ts"]})
        else:
            out.extend(x)
    out.sort(key=lambda e: e["ts"])
    return out


def cap_events(rows, pin_also=()):
    """Не больше EV_MAX строк: STP, сохранения и строки вывода сверху — всегда (до EV_PIN_MAX), остальное — по времени с начала окна.
    -> (показанные строки, {вид: скрыто})."""
    if len(rows) <= EV_MAX:
        return rows, {}
    pin = [i for i, e in enumerate(rows) if e["k"] in ("stp", "save") or any(e is p for p in pin_also)][:EV_PIN_MAX]
    ps = set(pin)
    rest = [i for i in range(len(rows)) if i not in ps][:EV_MAX - len(pin)]
    show = sorted(ps | set(rest))
    shown = set(show)
    hid = {}
    for i, e in enumerate(rows):
        if i not in shown:
            hid[e["k"]] = hid.get(e["k"], 0) + (e["n"] if e["k"] == "fold" else 1)
    return [rows[i] for i in show], hid


def build(sensor_lines, log_lines, rmap, now=None, state=None):
    eps = parse_sensor(sensor_lines)
    ser = series(eps)
    dups = {}
    ev = parse_log(log_lines, dups)
    now = now or max([e["ts"] for e in ev] + [x for e in eps for x in (e["alarm"], e["clear"]) if x] + [0]) or time.time()
    d = {"built_at": now, "dups": sorted(dups.items(), key=lambda x: -x[1]), "episodes": ser, "all_episodes": len(eps), "state": state or {}, "map_source": rmap.get("source", "")}
    if not ser:
        d["headline"] = "Датчик транка шторма не отмечал."
        d.update(vlan=None, ring=None, minutes=[], events=[], noise=[], others=[], active=False, start=None)
        return d
    start = ser[0]["since"]
    votes = {}
    for e in ser:
        if e["vlans"] and e["vlans"][0]["vlan"] != "untagged":
            votes[e["vlans"][0]["vlan"]] = votes.get(e["vlans"][0]["vlan"], 0) + 1
    vlan = max(votes, key=votes.get) if votes else None
    ring = next((r for r in rmap["rings"] if r["ring"] == vlan), None)
    w0 = start - PRE_S
    win = [e for e in ev if e["ts"] >= w0]
    core = ring["core"] if ring else None
    ports = ring["ports"] if ring else []
    # поминутно: «storm is occurring» на портах ядра кольца
    mins = {}
    for e in win:
        if e["k"] == "storm" and e["on"] and e["sw"] == core:
            m = int(e["ts"] // 60 * 60)
            mins.setdefault(m, {}).setdefault(e["port"], 0)
            mins[m][e["port"]] += 1
    extra = {}
    for v in mins.values():
        for p, n in v.items():
            if p not in ports:
                extra[p] = extra.get(p, 0) + n
    cols = list(ports) + sorted(sorted(extra, key=lambda p: -extra[p])[:COLS_EXTRA])
    cols_hidden = {p: n for p, n in extra.items() if p not in cols}
    minutes = [{"t": m, "by": [mins[m].get(p, 0) for p in cols]} for m in sorted(mins)]
    # события конфигурации и колец
    keep = []
    for e in win:
        if e["k"] in ("stp", "save", "login"):
            keep.append(e)
        elif e["k"] in ("link", "stpport") and e["sw"] == core and e["port"] in ports:
            keep.append(e)
        elif e["k"] in ("link", "topo") and ring and ring_of_sw(e["sw"]) == ring["ring"]:
            keep.append(e)
    # шум линков вне кольца шторма (хлопающие порты)
    flap = {}
    for e in win:
        if e["k"] == "link" and not (e["sw"] == core and e["port"] in ports) and not (ring and ring_of_sw(e["sw"]) == ring["ring"]):
            flap[(e["sw"], e["port"])] = flap.get((e["sw"], e["port"]), 0) + 1
    noisy = [{"sw": k[0], "port": k[1], "n": n} for k, n in sorted(flap.items(), key=lambda x: -x[1]) if n >= 6]
    noise, noise_tot = noisy[:TOP_N], {"ports": len(noisy), "n": sum(x["n"] for x in noisy)}
    others = {}
    for e in win:
        if e["k"] == "storm" and e["on"] and e["sw"] != core:
            others[e["sw"]] = others.get(e["sw"], 0) + 1
    first_core = next((e for e in win if e["k"] == "storm" and e["on"] and e["sw"] == core and e["ts"] >= start - 60), None)
    # вывод сверху — только по событиям
    pre = [e for e in win if e["k"] == "stp" and not e["on"] and w0 <= e["ts"] <= start]
    same = [e for e in pre if ring and ring_of_sw(e["sw"]) == ring["ring"]]
    cause = (same or pre or [None])[-1]
    last = ser[-1]
    active = not last["clear"]
    head = "Шторм в VLAN %s" % vlan if vlan else "Шторм на транке (VLAN не определён)"
    if ring:
        head += ", кольцо %s, порты ядра %s: %s" % (ring["ring"], core.split(".", 2)[-1], ", ".join(map(str, ports)))
    lg = []
    if cause:
        lg = [e for e in win if e["k"] == "login" and e["sw"] == cause["sw"] and cause["ts"] - PRE_S <= e["ts"] <= cause["ts"]]
        who = (" (вход по %s с адреса %s)" % (lg[-1]["how"], lg[-1]["ip"])) if lg else " (входа в журнале перед этим нет)"
        head += "; за %d с до начала по датчику транка" % round(start - cause["ts"])
        if first_core and first_core["ts"] >= cause["ts"]:
            head += " (за %d с до первой защиты на ядре, порт %d)" % (round(first_core["ts"] - cause["ts"]), first_core["port"])
        head += " на свиче %s выключен STP%s" % (cause["sw"], who)
        if len(pre) > 1:
            head += "; всего за 15 мин до начала STP выключен на %d свичах" % len({e["sw"] for e in pre})
    else:
        head += "; изменений конфигурации перед началом не видно"
    rows = fold_events(keep)
    shown, hid = cap_events(rows, pin_also=[x for x in (cause, lg[-1] if cause and lg else None) if x])
    oth = sorted(({"sw": k, "n": v} for k, v in others.items()), key=lambda x: -x["n"])
    d.update(vlan=vlan, ring=ring, core=core, cols=cols, cols_hidden=cols_hidden, minutes=minutes, events=shown,
             events_rows=len(rows), events_raw=len(keep), events_hidden=hid, noise=noise, noise_tot=noise_tot, active=active, start=start,
             others=oth[:TOP_N], others_tot={"sw": len(oth), "n": sum(x["n"] for x in oth)}, headline=head + ".",
             first_core=first_core, cause=cause, stp_off=[e for e in win if e["k"] == "stp" and not e["on"]])
    return d


def parse_fdb(txt, vlan):
    """Сводка FDB: число MAC в VLAN по портам (строки D-Link «VID  VLAN Name  MAC Address  Port  Type …»)."""
    by = {}
    for l in txt.splitlines():
        m = re.match(r"\s*(\d+)\s+\S+\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(\d+(?::\d+)?)\s+\S+", l)
        if m and m.group(1) == str(vlan):
            by[m.group(3)] = by.get(m.group(3), 0) + 1
    return by


# ------------------------------------------------------------------ слой 1: экран
def _hm(ts, tz):
    return dt.datetime.fromtimestamp(ts, tz).strftime("%H:%M:%S") if ts else "?"


def render(d, tz, fx=False, fdb=None):
    out = []
    w = out.append
    sha = hashlib.sha256(json.dumps(sorted(d.keys())).encode()).hexdigest()[:16]
    w('<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    w('<meta name="hx-macro" content="intent=storm;template=%s;schema=%s;model_calls=0">' % (TEMPLATE_SHA, sha))
    w("<title>Шторм</title><style>%s</style></head><body><main>" % CSS)
    w('<div class="top"><h1>Шторм на транке</h1><span><a class="btn" href="/storm">Обновить</a> <a class="btn" href="/rings">Кольца</a> '
      '<a class="btn" href="/">Комната</a></span></div>')
    w('<div class="head%s" data-k="headline">%s</div>' % ("" if d["episodes"] and d["active"] else " clear", E(d["headline"])))
    w('<div class="prov%s" data-k="provenance">%s Датчик транка гипервизора и журнал свичей сервера журналов (с %s), карта колец: %s. '
      'Экран без модели: разбор журнала и шаблон. Только чтение.%s</div>'
      % (" fx" if fx else "", "НЕ ЖИВЫЕ ДАННЫЕ — сохранённые журналы." if fx else "Данные журналов.",
         _hm(d["start"] - PRE_S, tz) if d.get("start") else "—", E(d["map_source"]),
         (' <b data-k="cut">Журнал обрезан пределом %d строк: показано с %s, более раннее в окно %d мин не попало — начало серии могло быть раньше.</b>'
          % (STORM_LINES, E(d["cut_from"]), STORM_MIN)) if d.get("cut_from") else ""))
    st = d.get("state") or {}
    if st:
        w('<div class="core%s" data-k="sensor">Датчик сейчас (%s): %s · %s пак/с, мультикаст %s · порог шторма %s, отбоя %s · состояние с %s</div>'
          % (" err" if st.get("state") == "alarm" else "", _hm(st.get("ts"), tz), "ШТОРМ" if st.get("state") == "alarm" else "спокойно",
             E(str(st.get("rx_pps", "?"))), E(str(st.get("mc_pps", "?"))), E(str(st.get("storm_pps", "?"))), E(str(st.get("clear_pps", "?"))),
             _hm(st.get("since"), tz)))
    else:
        w('<div class="core" data-k="sensor">Датчик сейчас: нет данных state.json</div>')
    for i, e in enumerate(d["episodes"]):
        v = ", ".join("%s — %d из %d" % (x["vlan"], x["n"], x["of"]) for x in e["vlans"]) or "нет выборки"
        w('<div class="core%s" data-k="episode">Эпизод %d: начало %s · %s · пик %d пак/с · VLAN в выборке: %s</div>'
          % ("" if e["clear"] else " err", i + 1, _hm(e["since"], tz), ("отбой %s" % _hm(e["clear"], tz)) if e["clear"] else "идёт",
             e["peak"], E(v)))
    if d.get("ring") and d["minutes"]:
        w('<h2 data-k="minutes">Защита от шторма на ядре %s, срабатываний в минуту</h2><div class="scroll"><table class="m"><tr><th>мин</th>' % E(d["core"]))
        w("".join("<th>п.%d%s</th>" % (p, "" if p in d["ring"]["ports"] else "*") for p in d["cols"]) + "</tr>")
        for m in d["minutes"]:
            w("<tr><td>%s</td>%s</tr>" % (_hm(m["t"], tz)[:5], "".join("<td>%s</td>" % (n or "") for n in m["by"])))
        w("</table></div>")
        if d.get("first_core"):
            w('<div class="mut">Первым на ядре — порт %d в %s. * — порт не из плеч кольца.</div>' % (d["first_core"]["port"], _hm(d["first_core"]["ts"], tz)))
        if d.get("cols_hidden"):
            w('<div class="mut" data-k="cols-cut">Ещё %d портов ядра вне таблицы, у них %d срабатываний.</div>'
              % (len(d["cols_hidden"]), sum(d["cols_hidden"].values())))
    w('<h2 data-k="events">Изменения и входы на свичи</h2><div class="ev">')
    for e in d["events"]:
        hot = e["k"] == "stp" and not e["on"]
        txt = {"stp": lambda: "STP %s" % ("включён" if e["on"] else "выключен"), "save": lambda: "конфигурация сохранена",
               "login": lambda: "вход по %s%s с %s" % (e["how"], (" (" + e["user"] + ")") if e["user"] else "", e["ip"]),
               "link": lambda: "порт %d: линк %s" % (e["port"], "есть" if e["up"] else "пропал"),
               "stpport": lambda: "порт %d: STP %s" % (e["port"], e["change"]), "topo": lambda: "смена топологии STP",
               "fold": lambda: {"link": "порт %s: линк пропадал и появлялся" % e["port"], "topo": "смена топологии STP",
                                "stpport": "порт %s: STP менялся" % e["port"]}[e["of"]] + " — %d раз, до %s" % (e["n"], _hm(e["ts2"], tz))}[e["k"]]()
        w('<span class="t">%s</span><span class="x%s">%s · %s</span>' % (_hm(e["ts"], tz), " hot" if hot else "", E(e["sw"]), E(txt)))
    if not d["events"]:
        w('<span class="t">—</span><span class="x">событий нет</span>')
    w("</div>")
    if d.get("events_hidden"):
        w('<div class="mut" data-k="ev-cut">Показано %d из %d записей (повторы свёрнуты; строк журнала в разделе %d). Не показаны более поздние: %s.</div>'
          % (len(d["events"]), d["events_rows"], d["events_raw"],
             E(", ".join("%s — %d" % (KIND_RU.get(k, k), n) for k, n in sorted(d["events_hidden"].items(), key=lambda x: -x[1])))))
    if d.get("others"):
        ot = d.get("others_tot") or {"sw": len(d["others"]), "n": sum(x["n"] for x in d["others"])}
        w('<div class="mut">Шторм на других свичах: %d свичей, %d срабатываний; больше всех: %s</div>'
          % (ot["sw"], ot["n"], E(", ".join("%s — %d" % (x["sw"], x["n"]) for x in d["others"]))))
    if d.get("noise"):
        nt = d.get("noise_tot") or {"ports": len(d["noise"]), "n": sum(x["n"] for x in d["noise"])}
        w('<div class="mut" data-k="noise">Шум вне кольца шторма: хлопают линком %d портов, всего %d смен; больше всех: %s</div>'
          % (nt["ports"], nt["n"], E(", ".join("%s порт %d — %d" % (x["sw"], x["port"], x["n"]) for x in d["noise"]))))
    if d.get("ring"):
        if fdb is None and not d.get("fdb_on"):
            w('<div class="mut" data-k="fdb-off">Слой MAC по портам ядра выключен (право шлюза на show fdb выдаётся отдельно).</div>')
        elif fdb is None:
            w('<div><a class="btn" href="/storm?fdb=1">MAC по портам ядра в VLAN %s</a> <span class="mut">опрос ядра через шлюз только по кнопке</span></div>' % E(d["vlan"]))
        elif fdb.get("error"):
            w('<div class="core err" data-k="fdb"><span class="e">FDB: нет данных — %s</span></div>' % E(fdb["error"]))
        else:
            w('<div class="core" data-k="fdb">MAC в VLAN %s на ядре %s (прочитано %s): %s</div>'
              % (E(d["vlan"]), E(d["core"]), _hm(fdb["at"], tz), E(", ".join("порт %s — %d" % kv for kv in sorted(fdb["by"].items())) or "нет записей")))
    if d.get("dups"):
        dp = d["dups"]
        w('<div class="mut" data-k="dups">Точные повторы строк журнала свёрнуты в одну запись: %d свичей, %d повторов; больше всех: %s</div>'
          % (len(dp), sum(n for _, n in dp), E(", ".join("%s — %d" % kv for kv in dp[:TOP_N]))))
    w('<div class="mut">Источник: строки TRUNKBCAST службы датчика транка; журнал свичей (storm, STP, сохранение, входы, линки). '
      'Вывод сверху ставится только по записям журнала. Экран ничего не меняет на свичах.</div>')
    w("</main></body></html>")
    return "".join(out)


HREF_OK = {"/", "/rings", "/storm", "/storm?fdb=1"}


def lint(doc, d):
    styles = "".join(re.findall(r"<style>(.*?)</style>", doc, re.S))
    markup = re.sub(r">[^<]*<", "><", re.sub(r"<style>.*?</style>", "<style></style>", doc, flags=re.S))
    bad = [name for rx, name in FORBID_MARKUP if rx.search(markup)] + [name for rx, name in FORBID_STYLE if rx.search(styles)]
    if doc.count("<style>") != 1:
        bad.append("стилей не один блок")
    bad += ["ссылка %s" % h for h in re.findall(r'href="([^"]*)"', doc) if h not in HREF_OK]
    if len(doc.encode()) > MAX_BYTES:
        bad.append("размер %d > %d" % (len(doc.encode()), MAX_BYTES))
    rows = doc.count('<span class="t">')
    if rows > max(len(d.get("events") or []), 1) or len(d.get("events") or []) > EV_MAX:
        bad.append("строк событий %d больше предела %d" % (rows, EV_MAX))
    if bool(d.get("events_hidden")) != ('data-k="ev-cut"' in doc):
        bad.append("скрытые строки событий не показаны счётчиком")
    if doc.count("<tr>") > 200 or doc.count("<th>п.") > len((d.get("ring") or {}).get("ports") or []) + COLS_EXTRA:
        bad.append("таблица ядра больше предела")
    if doc.count('data-k="headline"') != 1:
        bad.append("нет вывода сверху")
    if doc.count('data-k="episode"') != len(d["episodes"]):
        bad.append("эпизоды датчика не все на экране")
    if 'data-k="provenance"' not in doc:
        bad.append("нет строки происхождения данных")
    if bool(d.get("cut_from")) != ('data-k="cut"' in doc):
        bad.append("срезка журнала пределом строк не показана")
    if d.get("cause") and "выключен STP" not in d["headline"]:
        bad.append("событие STP есть, а в выводе его нет")
    if not d.get("cause") and "выключен STP" in d["headline"]:
        bad.append("вывод про STP без события в журнале")
    return bad


C_ALARM = re.compile(r"Шторм на транке[^:]*:\s*([\d  ]+)\s*пак/с.*?начало:\s*(\d\d:\d\d:\d\d).*?VLAN по выборке[^:]*:\s*(\S+)", re.S)
C_CLEAR = re.compile(r"закончился:\s*сейчас\s*([\d  ]+)\s*пак/с.*?пик\s*([\d  ]+)\s*пак/с,\s*начало было\s*(\d\d:\d\d:\d\d)", re.S)


def cards_to_sensor(cards, tz):
    """Карточки датчика из outbox telegram-шлюза сервера журналов ([created_at, text]) -> строки в формате TRUNKBCAST для parse_sensor.
    Время начала в карточке — HH:MM:SS по местному времени; дата берётся из created_at (если начало «позже» карточки — это предыдущие сутки)."""
    out = []
    num = lambda s: int(re.sub(r"\D", "", s))
    for ca, text in cards:
        m, kind = C_ALARM.search(text), "alarm"
        if not m:
            m, kind = C_CLEAR.search(text), "clear"
        if not m:
            continue
        t = dt.datetime.fromtimestamp(ca, tz)
        hh = (m.group(2) if kind == "alarm" else m.group(3)).split(":")
        s = t.replace(hour=int(hh[0]), minute=int(hh[1]), second=int(hh[2]), microsecond=0)
        if s.timestamp() > ca + 60:
            s -= dt.timedelta(days=1)
        if kind == "alarm":
            rx = num(m.group(1)); line = "%s x TRUNKBCAST alarm id=%d rx_pps=%d mc_pps=0 peak=%d since=%s vlans=%s" % (
                t.isoformat(), ca, rx, rx, s.isoformat(), m.group(3))
        else:
            line = "%s x TRUNKBCAST clear id=%d rx_pps=%d mc_pps=0 peak=%d since=%s vlans=-" % (
                t.isoformat(), ca, num(m.group(1)), num(m.group(2)), s.isoformat())
        out.append(line)
    return out


def state_from_cards(sens):
    """Состояние датчика по последней карточке (живого пак/с у сервера журналов нет: датчик шлёт только смены состояния)."""
    eps = parse_sensor(sens)
    if not eps:
        return {}
    e = eps[-1]
    return {"state": "clear" if e["clear"] else "alarm", "ts": e["clear"] or e["alarm"], "since": e["since"],
            "rx_pps": "—", "mc_pps": "—", "storm_pps": 5000, "clear_pps": 1000, "from_cards": True}


# ------------------------------------------------------------------ вход для веба
STORM_MIN, STORM_LINES = 120, 3000   # в шторм в окне 120 мин бывает 2000–2200 строк (предел 2000 срезал начало)
GW_SOCK = _integrity_value("ro_gateway_socket")
GW_TIMEOUT = 40        # шлюз: ssh 25 с + ожидание чужой сессии; дольше страница не ждёт


def gw_storm(op, args):
    """Один запрос к шлюзу чтения (uid веба; шлюз пускает его только на storm-read, vendor web-storm)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(GW_TIMEOUT)
    try:
        s.connect(GW_SOCK)
        s.sendall((json.dumps({"vendor": "web-storm", "op": op, "args": args}) + "\n").encode())
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


def fetch_sources(gw_call=None):
    """Живой путь: одна операция шлюза (gw_call("storm-read", {...}) -> {"ok","log","cards"}), источник — сервер журналов.
    Стенд: HUMANX_STORM_FIXTURES. Без права и без стенда — «нет права»."""
    fx = os.environ.get("HUMANX_STORM_FIXTURES")
    if not fx and gw_call:
        r = gw_call("storm-read", {"minutes": STORM_MIN, "lines": STORM_LINES})
        if not r.get("ok"):
            return None, None, None, "чтение журнала сервера журналов через шлюз не удалось: %s" % str(r.get("error", "?"))[:200]
        log = r.get("log") or []
        tz = dt.datetime.fromisoformat(LOG_RE.match(log[0]).group(1)).tzinfo if log and LOG_RE.match(log[0]) else \
            dt.timezone(dt.timedelta(hours=2))
        sens = cards_to_sensor(r.get("cards") or [], tz)
        return sens, log, state_from_cards(sens), None
    if not fx:
        return None, None, None, "нет права чтения журнала свичей и датчика транка для веба"
    sens = open(os.path.join(fx, "trunk-sensor-journal.txt"), encoding="utf-8").read().splitlines()
    log = open(os.path.join(fx, "syslog-sw.txt"), encoding="utf-8").read().splitlines()
    st = {}
    try:
        st = json.load(open(os.path.join(fx, "trunk-sensor-state.json"), encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return sens, log, st, None


def screen(state_dir=None, fdb=False, fdb_call=None, gw_call=None, fdb_on=None):
    t0 = time.time()
    live = bool(gw_call) and not os.environ.get("HUMANX_STORM_FIXTURES")
    sens, log, st, err = fetch_sources(gw_call)
    rmap = json.load(open(MAP_F, encoding="utf-8"))
    if err:
        doc = ('<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Шторм</title><style>%s</style></head><body><main>'
               '<div class="head clear" data-k="headline">Экран шторма: нет данных — %s</div><a class="btn" href="/">Комната</a></main></body></html>' % (CSS, E(err)))
        return doc, {"render_ms": int((time.time() - t0) * 1000), "gw_ms": 0, "lint": []}
    d = build(sens, log, rmap, state=st)
    m0 = LOG_RE.match(log[0]) if live and len(log) >= STORM_LINES else None   # пакет N: шлюз отдал ровно предел — окно срезано
    d["cut_from"] = dt.datetime.fromisoformat(m0.group(1)).strftime("%H:%M:%S") if m0 else None
    d["fdb_on"] = (fdb_call is not None) if fdb_on is None else bool(fdb_on)
    fdb = fdb and d["fdb_on"]
    tz = dt.datetime.fromisoformat(LOG_RE.match(log[0]).group(1)).tzinfo if log and LOG_RE.match(log[0]) else None
    f = None
    if fdb and d.get("ring"):
        f = (fdb_call or (lambda core, vlan: {"error": "право шлюза на show fdb для веба не выдано"}))(d["core"], d["vlan"])
    doc = render(d, tz, fx=not live, fdb=f)
    bad = lint(doc, d)
    if bad:
        doc = ('<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Шторм</title></head><body>'
               '<p>Экран шторма не прошёл проверку: %s</p><p><a href="/">Комната</a></p></body></html>' % E("; ".join(bad)))
    return doc, {"render_ms": int((time.time() - t0) * 1000), "gw_ms": 0, "lint": bad}
