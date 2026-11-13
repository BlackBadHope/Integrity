#!/usr/bin/python3 -I
"""humanx_ro_gw — шлюзы ЧТЕНИЯ прода для Арбитров комнаты HumanX (HumanX шаг 3). Пользователь шлюза — отдельная учётка.

Кто может спросить: только процесс uid gateway_user (bus-gateway — forced command SSH-ключа вендора; id вендора он берёт
из authorized_keys, не от клиента) и только вендоры комнаты из конфига шлюза ("vendors"). Сокет — "socket" конфига шлюза.
Пакет M: ещё процесс веба комнаты (uid web_user, vendor web-rings) — только switch на ядра web_rings_ips и ровно
4 команды экрана колец (WEB_RINGS); лимиты свичей общие с комнатой; стоп-кран — файл web_rings_off.
Пакет N: тот же uid веба, vendor web-storm — только storm-read {"minutes" 5..180, "lines" 100..3000}: одна ssh-сессия
на сервер журналов storm_host ключом storm_key (forced command на сервере журналов, строгая проверка ключа хоста
по storm_known_hosts), таймаут 25 с, общий ответ 30 с; стоп-кран — файл web_storm_off.
Операции (один JSON-объект в строке → один ответ):
  sql        {"db", "query"}            один SELECT/SHOW/DESCRIBE/EXPLAIN/WITH; сессия READ ONLY; учётка чтения на сервере
                                        имеет только SELECT (секретные колонки — пароли, токены, карты — не выданы вовсе);
                                        30 с, 2 одновременных, ответ до 2 МБ (TSV)
  integrity  {"q": "recent"|"search"|"show"|"stats", "text", "id", "n"}  копия Action Log (снимок раз в 10 мин), только чтение
  switch     {"ip", "cmds": ["show ports 5", ...]}  живое чтение ОДНОГО свича D-Link по telnet, до 4 команд за сессию.
             Только белый список show из webswitch/dlinkcli (config/account/snmp/password/... запрещены всегда).
             Пароль — файл switch_cred (0400, администратор — учётка шлюза), наружу не выходит. Одна сессия на свич,
             не чаще раза в 20 с на свич и 8 сессий в минуту на комнату; отказ входа — без повтора 30 мин.
Ничего не исполняет из данных: SQL проверяется и уходит одной строкой в stdin клиента mariadb; shell нет.
Журнал шлюза — файл log конфига шлюза: время, вендор, операция, sha256 запроса, rc (тексты запросов с ПДн не пишутся).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import grp, hashlib, ipaddress, json, os, pwd, re, socket, socketserver, sqlite3, struct, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dlinkcli  # noqa: E402

CONF = json.load(open(_integrity_value("ro_gateway_config"), encoding="utf-8"))   # every path and account below comes from this file
SOCK = CONF["socket"]
CNF = CONF["mysql_defaults_file"]
SEED = CONF["integrity_snapshot"]
LOG = CONF["log"]
GW_UID = pwd.getpwnam(CONF["gateway_user"]).pw_uid
VENDORS = set(CONF.get("vendors", []))
FIRST = {"select", "show", "describe", "desc", "explain", "with"}
BAD = re.compile(r"(;|/\*|\*/|--|#|\\|\binto\s+(outfile|dumpfile|@)|\bfor\s+update\b|\block\s+in\s+share\s+mode\b|"
                 r"\bget_lock\s*\(|\bsleep\s*\(|\bbenchmark\s*\(|\bload_file\s*\(|\bsys_exec\b|\bsys_eval\b)", re.I)
SEM = threading.BoundedSemaphore(2)
MAXOUT = 2 * 1024 * 1024
_log = threading.Lock()
try:
    WEB_UID = pwd.getpwnam(CONF["web_user"]).pw_uid               # пакет M: процесс веба комнаты (humanx-web)
except KeyError:
    WEB_UID = None
WEB_RINGS = {"vendor": "web-rings", "ips": tuple(str(x) for x in CONF["web_rings_ips"]),
             "cmds": ["show ports description", "show stp ports", "show stp", "show erps"]}
WEB_OFF = CONF["web_rings_off"]


def web_rings_allowed(uid, vendor, op, args):
    """Пакет M: веб читает только экран колец — два ядра, ровно 4 команды в этом порядке, других ключей нет."""
    return (WEB_UID is not None and uid == WEB_UID and vendor == WEB_RINGS["vendor"] and op == "switch"
            and isinstance(args, dict) and set(args) == {"ip", "cmds"} and str(args["ip"]) in WEB_RINGS["ips"]
            and isinstance(args["cmds"], list) and [" ".join(str(c).split()) for c in args["cmds"]] == WEB_RINGS["cmds"]
            and not os.path.exists(WEB_OFF))


def log(rec):
    with _log, open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": int(time.time()), **rec}, ensure_ascii=False) + "\n")


# fix13: '#', '--', ';' inside simple quoted literals / `identifiers` are data, not syntax. A literal with a backslash is
# NOT stripped, so the backslash stays visible to BAD and the query is still rejected (no escape-based bypass).
_Q = re.compile(r"'[^'\\]*'|\"[^\"\\]*\"|`[^`]*`")


def _strip_lits(s):
    return _Q.sub(lambda m: "x" if m.group(0)[0] == "`" else "''", s)


def check_sql(sql):
    s = " ".join(str(sql).split()).rstrip(";").strip()
    if not s or len(s) > 8000:
        return None, "пустой или слишком длинный запрос"
    if s.split(" ", 1)[0].lower() not in FIRST:
        return None, "разрешены только SELECT, SHOW, DESCRIBE, EXPLAIN, WITH"
    if BAD.search(_strip_lits(s)):
        return None, "запрос содержит запрещённую конструкцию (;, комментарий, INTO OUTFILE, SLEEP, FOR UPDATE …)"
    return s, None


def op_sql(a):
    sql, err = check_sql(a.get("query", ""))
    db = str(a.get("db", "") or "")
    if db and not re.fullmatch(r"[A-Za-z0-9_]{1,64}", db):
        err = "неверное имя базы"
    if err:
        return {"ok": False, "error": "Отказ шлюза: " + err}
    if not SEM.acquire(timeout=10):
        return {"ok": False, "error": "Шлюз занят, повторите через минуту"}
    try:
        cmd = [CONF.get("mysql", "/usr/bin/mariadb"), f"--defaults-extra-file={CNF}", "--batch", "--connect-timeout=10",
               "--init-command=SET SESSION TRANSACTION READ ONLY"] + ([db] if db else [])
        p = subprocess.run(cmd, input=sql + "\n", capture_output=True, text=True, timeout=30, env={"LANG": "C.UTF-8"})
        out = p.stdout[:MAXOUT]
        return {"ok": p.returncode == 0, "rows_tsv": out, "truncated": len(p.stdout) > MAXOUT,
                "error": (p.stderr.strip()[-1500:] or None) if p.returncode else None}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Запрос шёл дольше 30 с и остановлен"}
    finally:
        SEM.release()


def op_integrity(a):
    q = str(a.get("q", "recent"))
    n = max(1, min(int(a.get("n", 15) or 15), 50))
    try:
        d = sqlite3.connect(f"file:{SEED}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error:
        return {"ok": False, "error": "копия Integrity ещё не готова"}
    cols = "id, ts_utc, actor, action, summary"
    if q == "recent":
        rows = d.execute(f"SELECT {cols} FROM events ORDER BY id DESC LIMIT ?", (n,)).fetchall()
    elif q == "search":
        t = str(a.get("text", "")).strip()[:200]
        if not t:
            return {"ok": False, "error": "нужен text"}
        rows = d.execute(f"SELECT {cols} FROM events WHERE summary LIKE ? OR tags LIKE ? ORDER BY id DESC LIMIT ?",
                         (f"%{t}%", f"%{t}%", n)).fetchall()
    elif q == "show":
        r = d.execute("SELECT id, ts_utc, actor, action, summary, details, tags FROM events WHERE id=?",
                      (int(a.get("id", 0) or 0),)).fetchone()
        return {"ok": bool(r), "event": dict(zip(("id", "ts_utc", "actor", "action", "summary", "details", "tags"), r)) if r else None}
    elif q == "stats":
        c, m = d.execute("SELECT COUNT(*), MAX(ts_utc) FROM events").fetchone()
        return {"ok": True, "events": c, "last_ts": m, "snapshot_mtime": int(os.path.getmtime(SEED))}
    else:
        return {"ok": False, "error": "q: recent | search | show | stats"}
    return {"ok": True, "events": [dict(zip(("id", "ts_utc", "actor", "action", "summary"), r)) for r in rows]}


SW_CRED = CONF["switch_cred"]
SW_NETS = [ipaddress.ip_network(n) for n in CONF["switch_nets"]]
_sw = threading.Lock(); _sw_last = {}; _sw_room = []; _sw_busy = set(); _sw_reject = {}
# MR-очередь: общий свежий ответ свича (25 с) и ожидание до 22 с вместо отказа; 22 + самая долгая сессия
# (около 32 с) + ssh укладываются в 60 с таймаута вызывающего. Стоп-кран: файл SW_SHARE_OFF — прежнее поведение.
SW_SHARE_S, SW_WAIT_S, SW_SHARE_OFF = 25, 22, CONF["sw_share_off"]
_sw_cv = threading.Condition(_sw); _sw_cache = {}    # ip -> (время конца сессии, {команда: вывод}, banner)
SW_WAITERS_MAX = 16; _sw_wait_n = [0]                # не больше 16 ждущих потоков сразу; сверх — прежний мгновенный отказ


def _sw_shared(ip, cmds, now):
    c = _sw_cache.get(ip)
    if c and now - c[0] <= SW_SHARE_S and all(x in c[1] for x in cmds):
        return {"ok": True, "ip": ip, "banner": c[2], "outputs": {x: c[1][x] for x in cmds},
                "shared": True, "age_s": round(now - c[0], 1)}
    return None


def op_switch(a):
    ip = str(a.get("ip", "")).strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "нужен ip одного свича (массовые опросы — по базе switches и истории)"}
    if not any(addr in n for n in SW_NETS):
        return {"ok": False, "error": "этот адрес не из сети управления свичами"}
    cmds = a.get("cmds") or ([a["cmd"]] if a.get("cmd") else [])
    if not isinstance(cmds, list) or not 1 <= len(cmds) <= 4:
        return {"ok": False, "error": "cmds: от 1 до 4 команд show"}
    cmds = [" ".join(str(c).split()) for c in cmds]
    bad = [c for c in cmds if not dlinkcli.allowed(c)]
    if bad:
        return {"ok": False, "error": "только команды чтения из белого списка (show switch/ports/stp/vlan/fdb/log/loopdetect/"
                                      "traffic control/error ports/lldp …): отказ для " + "; ".join(bad)[:200]}
    share = not os.path.exists(SW_SHARE_OFF)
    fresh = a.get("fresh") is True                          # свежее чтение: общий ответ не берётся, правила свича те же
    deadline = time.time() + (SW_WAIT_S if share and not a.get("_nowait") else 0)   # веб не ждёт: у него кэш и строка «не обновилось»
    with _sw_cv:
        while True:
            now = time.time()
            if now - _sw_reject.get(ip, 0) < 1800:
                return {"ok": False, "error": "этот свич недавно отказал во входе; повтор не раньше чем через 30 мин (нужен администратор)"}
            hit = _sw_shared(ip, cmds, now) if share and not fresh else None
            if hit:
                return hit
            _sw_room[:] = [x for x in _sw_room if now - x < 60]
            if len(_sw_room) >= 8:
                why, wake = "лимит комнаты: не больше 8 живых опросов свичей в минуту", 60 - (now - _sw_room[0])
            elif ip in _sw_busy:
                why, wake = "со свичем уже идёт сессия", None          # разбудит notify_all по концу сессии
            elif now - _sw_last.get(ip, 0) < 20:
                why, wake = "этот свич опрашивали меньше 20 с назад; объедините команды в одну просьбу (до 4)", 20 - (now - _sw_last.get(ip, 0))
            else:
                break
            left = deadline - now
            if left <= 0 or _sw_wait_n[0] >= SW_WAITERS_MAX:
                return {"ok": False, "error": why}
            _sw_wait_n[0] += 1
            try:
                _sw_cv.wait(max(0.05, min(left, wake if wake is not None else left)))
            finally:
                _sw_wait_n[0] -= 1
        _sw_busy.add(ip); _sw_last[ip] = now; _sw_room.append(now)
    done = None
    try:
        st = os.stat(SW_CRED)
        if st.st_mode & 0o077:
            return {"ok": False, "error": "пароль свичей хранится с нестрогими правами: шлюз закрыт (access gap)"}
        user, pw = (open(SW_CRED, encoding="utf-8").read().splitlines() + ["", ""])[:2]
        sess = dlinkcli.CliSession(ip, login_timeout=20, cmd_timeout=60)
        try:
            sess.login(user.strip() or "admin", pw)
            pw = None
            out = {c: sess.run(c)[:200000] for c in cmds}
        finally:
            sess.logout()
        done = (time.time(), out, sess.banner.strip()[:300])
        return {"ok": True, "ip": ip, "banner": done[2], "outputs": out}
    except dlinkcli.CliRejected:
        _sw_reject[ip] = time.time()
        return {"ok": False, "error": "свич отказал во входе (одна попытка, без повтора); возможно, нужна другая учётка — скажи оператору честно"}
    except (dlinkcli.CliError, OSError, TimeoutError) as e:
        return {"ok": False, "error": "свич не ответил: " + str(e)[:120]}
    finally:
        with _sw_cv:
            _sw_busy.discard(ip)
            if done and share:
                _sw_cache[ip] = done
                for k in [k for k, v in _sw_cache.items() if done[0] - v[0] > SW_SHARE_S]:   # старше 25 с — не нужны
                    del _sw_cache[k]
            _sw_cv.notify_all()


WEB_STORM_OFF = CONF["web_storm_off"]                               # пакет N
STORM = {"key": CONF["storm_key"], "kh": CONF["storm_known_hosts"], "host": CONF["storm_host"],
         "ttl": 30, "timeout": 25}
_storm = {"t": 0.0, "k": None, "res": None, "busy": False}
_storm_cv = threading.Condition()


def web_storm_allowed(uid, vendor, op, args):
    """Пакет N: веб комнаты читает журнал свичей и карточки датчика с сервера журналов; два целых в пределах, других ключей нет."""
    return (WEB_UID is not None and uid == WEB_UID and vendor == "web-storm" and op == "storm-read"
            and isinstance(args, dict) and set(args) == {"minutes", "lines"}
            and type(args["minutes"]) is int and type(args["lines"]) is int
            and 5 <= args["minutes"] <= 180 and 100 <= args["lines"] <= 3000 and not os.path.exists(WEB_STORM_OFF))


def _storm_ssh(k):
    cmd = ["ssh", "-F", "/dev/null", "-i", STORM["key"], "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + STORM["kh"], "-o", "GlobalKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "-T", STORM["host"],
           "storm %d %d" % k]
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=STORM["timeout"],
                           env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"})
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "сервер журналов: нет ответа за %d с" % STORM["timeout"]}
    except OSError as e:
        return {"ok": False, "error": "сервер журналов: ssh не запустился (%s)" % type(e).__name__}
    if p.returncode != 0:
        return {"ok": False, "error": "сервер журналов: ssh rc=%d" % p.returncode}
    if len(p.stdout) > MAXOUT:
        return {"ok": False, "error": "сервер журналов: ответ больше %d байт" % MAXOUT}
    try:
        d = json.loads(p.stdout.decode("utf-8"))
        log_ = [str(x)[:300] for x in d["log"]][-k[1]:]
        cards = [[int(c[0]), str(c[1])[:600]] for c in d.get("cards") or []][-50:]
    except (ValueError, KeyError, TypeError, IndexError):
        return {"ok": False, "error": "сервер журналов: ответ не JSON экрана шторма"}
    return {"ok": True, "now": int(d.get("now") or 0), "log": log_, "cards": cards, "cards_error": str(d.get("cards_error") or "")[:80]}


def op_storm_read(a):
    """Пакет N: одна сессия на сервер журналов за раз. Свежий общий ответ (<30 с) — сразу, без сессии; пока идёт сессия, остальные
    ждут её итога (не дольше таймаута), а не открывают вторую. Ошибка не кэшируется."""
    k = (a["minutes"], a["lines"])
    with _storm_cv:
        while True:
            now = time.time()
            if _storm["res"] is not None and _storm["k"] == k and now - _storm["t"] < STORM["ttl"]:
                return dict(_storm["res"], shared=True, age_s=round(now - _storm["t"], 1))
            if not _storm["busy"]:
                _storm["busy"] = True
                break
            if not _storm_cv.wait(STORM["timeout"] + 5):
                return {"ok": False, "error": "сервер журналов: сессия уже идёт"}
    res = {"ok": False, "error": "сервер журналов: чтение прервано"}   # отказ по умолчанию: finally ниже всегда снимает занятость
    try:
        res = _storm_ssh(k)
    finally:
        with _storm_cv:
            _storm["busy"] = False
            if res.get("ok"):
                _storm.update(t=time.time(), k=k, res=res)
            _storm_cv.notify_all()
    return res


OPS = {"sql": op_sql, "integrity": op_integrity, "switch": op_switch}


class H(socketserver.StreamRequestHandler):
    def handle(self):
        cred = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        uid = struct.unpack("3i", cred)[1]
        t0 = time.time(); vendor = op = None; req = {}; res = {"ok": False, "error": "bad request"}
        try:
            req = json.loads(self.rfile.readline(64 * 1024).decode("utf-8"))
            vendor, op, args = str(req.get("vendor", "")), str(req.get("op", "")), req.get("args") or {}
            if web_rings_allowed(uid, vendor, op, args):     # пакет M: веб комнаты, только экран колец
                res = op_switch(dict(args, _nowait=True))    # MR-очередь: общий ответ берёт, но в очереди не ждёт
            elif web_storm_allowed(uid, vendor, op, args):   # пакет N: веб комнаты, только журнал шторма с сервера журналов
                res = op_storm_read(args)
            elif uid != GW_UID:
                res = {"ok": False, "error": "only the bus gateway may call"}
            elif vendor not in VENDORS:
                res = {"ok": False, "error": f"{vendor}: read gateways are only for the HumanX room Arbiters"}
            elif op not in OPS or not isinstance(args, dict):
                res = {"ok": False, "error": "ops: sql | integrity | switch"}
            else:
                res = OPS[op](args)
        except Exception as e:                       # без деталей окружения
            res = {"ok": False, "error": "gateway error: " + type(e).__name__}
        err = None
        if not res.get("ok"):                        # fix13: error text for diagnostics; sql: only the server error code (no query fragments)
            e0 = str(res.get("error") or "")
            m0 = re.match(r"ERROR \d+ \(\w+\)", e0) if op == "sql" else None
            err = (m0.group(0) if m0 else (e0[:120] if e0.startswith("\u041e\u0442\u043a\u0430\u0437") or op != "sql" else "sql error")) if e0 else None
        log({"uid": uid, "vendor": vendor, "op": op, "ok": bool(res.get("ok")), "err": err, "ms": int((time.time() - t0) * 1000), **({"shared": True} if res.get("shared") else {}),
             **({"by": "executor"} if isinstance(req, dict) and isinstance(req.get("args"), dict)
                and req["args"].get("by") == "executor" else {}),
             "req_sha256": hashlib.sha256(json.dumps((op, req.get("args") if isinstance(req, dict) else None),
                                                     ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()})
        self.wfile.write((json.dumps(res, ensure_ascii=False) + "\n").encode("utf-8"))


class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


if __name__ == "__main__":
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    old = os.umask(0o117)
    srv = S(SOCK, H)
    os.umask(old)
    os.chown(SOCK, -1, grp.getgrnam(CONF["socket_group"]).gr_gid)
    os.chmod(SOCK, 0o660)
    srv.serve_forever()
