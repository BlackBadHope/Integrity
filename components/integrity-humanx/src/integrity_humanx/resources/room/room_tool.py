"""room_tool — единственный выход Арбитра комнаты HumanX наружу. Запуск: python -I room_tool.py <op> [work/<файл>.json]

Аргументы — только JSON-файл в work/ (никаких строк shell). Каждая операция пишется в journal/room.jsonl (хеш-цепочка).
  poll                      — письма комнате (адрес room-<operator_id>-claude) из шины
  get   {"id"}              — одно письмо целиком
  ack   {"id"}              — отметить прочитанным
  reply {"reply_to","body"} — ответ оператору (human-<operator_id>); отчёты по субагентам — тоже сюда
  send  {"to","body"}       — письмо human-<operator_id> или owner (room_acl на ядре другого не пропустит)
  escalate {"body"}         — нужно изменение: просьба администратору (owner) через шину. Сам Арбитр ничего не меняет
  cards / arbiter           — карточки вендоров / кто выбран Арбитром
  sql {"db","query"} / switch {"ip","cmds":[show …]} / integrity {"q",…} — шлюзы ЧТЕНИЯ прода на ядре (humanx-ro-gw)
  host {"host","op","args":[…]} — чтение VM: forced-command ключ humanx-host-ro, «только чтение» держит сама VM
        host: имя из таблицы хостов комнаты (hosts_file)
        op: summary | services | failed | status <unit> | journal <unit|-> [N] [prio] | net | listen | nft | ps
  history {"topic"?,"n"?,"index"?} — ТОЛЬКО ЧТЕНИЕ, по запросу, до 16 КБ, по ВСЕМ комнатам оператора (gemini/grok/codex/claude): сообщения одной темы (topic = id из общего списка тем или часть названия), последние n, или index=true — список тем
  ring_commands {"model"?}  — ТОЛЬКО ЧТЕНИЕ: справочник команд защиты колец для оператора (shared/ring-commands.md), раздел модели или весь
  topics_get                — общий для всех арбитров список тем оператора (shared/operator-topics.json): id, topic, status, state, last, arbiter, updated
  topics_put {"upsert":[{id,topic,status,state,last}],"remove":[id]} — атомарно обновить общий список (до 25 тем / 8 КБ; лишние закрытые уходят в архив)
  subchat {"topic","task"}   — (Gemini) Арбитр открывает сабчат темы: новая беседа Antigravity под тем же сторожем
  follow  {"subchat","body"} — (Gemini) Арбитр дописывает в сабчат темы
  report  {"subchat","body"} — (Gemini) сабчат отчитывается Арбитру (в его постоянную беседу); оператору пишет только Арбитр
Режимы транспорта (room.json): core — шина ядра по SSH-ключу комнаты.
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import hashlib, json, os, re, sqlite3, subprocess, sys, time, uuid
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

ROOM = os.path.dirname(os.path.abspath(__file__))
CONF = json.load(open(os.path.join(ROOM, "room.json"), encoding="utf-8"))
ME = CONF.get("address") or _hx_room("claude")
OPS = {"poll", "get", "ack", "reply", "send", "escalate", "cards", "arbiter", "sql", "switch", "integrity",
       "subchat", "follow", "report", "host", "heartbeat", "history", "topics_get", "topics_put", "ring_commands"}
SILENT_BLOCK = {"reply", "send", "escalate", "subchat", "follow", "report", "topics_put"}   # Max Reasoning: черновой этап молчит


def silent_state():
    """journal/mr-silent.json {until, job, phase, allow}: пока действует (until в будущем), запись оператору и в общие темы запрещена. Сам истекает по времени."""
    try:
        with open(os.path.join(ROOM, "journal", "mr-silent.json"), encoding="utf-8-sig") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) and time.time() < float(d.get("until", 0)) else None
    except (OSError, ValueError, TypeError):
        return None


PY = _integrity_value("python")
REPLICA = os.environ.get("BUS_REPLICA") or _integrity_value("bus_replica")
MAX_BODY_BYTES = 32768          # лимит ядра (bus_core: body <= 32 KiB)
CYR = re.compile("[А-Яа-яЁё]")
UTF8_HINT = ("сохраняй файл аргументов в UTF-8: [IO.File]::WriteAllText($path,$text,(New-Object Text.UTF8Encoding($false))) "
             "или python open(...,'w',encoding='utf-8'); не используй Set-Content/Out-File/'>' по умолчанию и не передавай текст через stdin в python")


JOURNAL_MAX_BYTES = int(os.environ.get("ROOM_JOURNAL_MAX", 2 * 1024 * 1024))   # fix13
JOURNAL_KEEP = 50                                                                 # room.jsonl.1 .. .50 (по ~2 МБ; вытеснение только после 50 ротаций)


def _journal_lock(d):
    """Файл-замок на журнал: heartbeat waker'а и ответ агента не должны одновременно читать prev и ветвить хеш-цепочку."""
    lk = os.path.join(d, ".room.lock"); t0 = time.time()
    while True:
        try:
            os.close(os.open(lk, os.O_CREAT | os.O_EXCL | os.O_WRONLY)); return lk
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lk) > 10:
                    os.remove(lk)
            except OSError:
                pass
            if time.time() - t0 > 8:
                return None
            time.sleep(0.05)


def journal(rec):
    d = os.path.join(ROOM, "journal"); os.makedirs(d, exist_ok=True)
    lk = _journal_lock(d)
    try:
        f = os.path.join(d, "room.jsonl"); prev = "0" * 64
        try:
            with open(f, "rb") as h:
                prev = json.loads(h.read().splitlines()[-1])["hash"]
        except (OSError, IndexError, ValueError, KeyError):
            pass
        try:                                              # fix13: ротация — старый файл остаётся как room.jsonl.1, цепочка (prev) продолжается
            if os.path.getsize(f) > JOURNAL_MAX_BYTES and prev != "0" * 64:
                for k in range(JOURNAL_KEEP - 1, 0, -1):
                    if os.path.exists("%s.%d" % (f, k)):
                        os.replace("%s.%d" % (f, k), "%s.%d" % (f, k + 1))
                os.replace(f, f + ".1")
        except OSError:
            pass
        rec = {"ts": int(time.time()), "prev": prev, "by": ME, **rec}
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        with open(f, "a", encoding="utf-8") as h:
            h.write(json.dumps(rec, ensure_ascii=False) + "\n")
    finally:
        if lk:
            try:
                os.remove(lk)
            except OSError:
                pass


def bus(op, args):
    ssh = CONF.get("ssh", "ssh")
    argv = [ssh, *CONF.get("ssh_args", []), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", CONF["key"], CONF["dest"], op]
    env = os.environ.copy()
    if os.path.dirname(ssh):
        env["PATH"] = os.path.dirname(ssh) + os.pathsep + env.get("PATH", "")
    try:
        p = subprocess.run(argv, input=json.dumps(args, ensure_ascii=False).encode("utf-8"), capture_output=True, timeout=60, env=env)
    except subprocess.TimeoutExpired:
        raise SystemExit(json.dumps({"ok": False, "error": "bus timeout: ядро не ответило за 60 с, сообщение НЕ отправлено, повтори позже"}, ensure_ascii=False))
    except OSError as e:
        raise SystemExit(json.dumps({"ok": False, "error": f"bus unreachable: ssh не запустился ({type(e).__name__})"}, ensure_ascii=False))
    try:
        doc = json.loads(p.stdout.decode("utf-8").strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise SystemExit(json.dumps({"ok": False, "error": "bus unreachable"}))
    if not doc.get("ok"):
        raise SystemExit(json.dumps(doc, ensure_ascii=False))
    return doc["result"] if "result" in doc else doc    # шлюзы чтения отвечают без обёртки result


def agentapi(*args):
    """Сабчаты Арбитра Gemini: штатный agentapi Antigravity (адрес и токен живого language server берёт antigravity_wake)."""
    import tempfile
    sys.path.insert(0, _integrity_value("antigravity_wake_dir"))
    import antigravity_wake as AW
    t = tempfile.mkdtemp()
    w = AW.Waker({"state_dir": t, "targets": {}, "state_file": os.path.join(t, "s.json"), "log": os.path.join(t, "l.log")})
    return w.agentapi(*args)


def subchats():
    try:
        return json.load(open(os.path.join(ROOM, "journal", "subchats.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def clean_single_line(s):
    return s.replace("\r", " ").replace("\n", " ").strip()


def subchat_op(op, a, argfile):
    if ME != _hx_room("gemini"):
        return {"ok": False, "error": "sub-chats via room_tool are for the Gemini Arbiter; Claude uses its own subagents"}
    reg = subchats()
    rt = os.path.join(ROOM, "room_tool.py")
    if op == "subchat":
        sid = uuid.uuid4().hex[:8]
        origin = str(a.get("reply_to") or a.get("origin_msg_id") or "")
        json.dump({"subchat": sid, "topic": str(a.get("topic", ""))[:200], "task": str(a.get("task", ""))[:20000],
                   "origin_msg_id": origin, "created": int(time.time())},
                  open(os.path.join(ROOM, "work", f"sub-{sid}-task.json"), "w", encoding="utf-8"),
                  ensure_ascii=False)
        nonce = uuid.uuid4().hex
        os.makedirs(os.path.join(ROOM, "nonces"), exist_ok=True); open(os.path.join(ROOM, "nonces", nonce), "w").close()
        task_f = os.path.join(ROOM, "work", f"sub-{sid}-task.json")
        rep_f = os.path.join(ROOM, "work", f"rep-{sid}-1.json")
        prompt = (f"HUMANX-ROOM-v1:{nonce} You are a read-only SUB-CHAT of the HumanX room Arbiter, topic id {sid}. "
                  f"Read your task: read_file {task_f} and the rules: read_file {os.path.join(ROOM, 'GEMINI.md')} . "
                  f"Tools: read_file inside the room, write_file in {os.path.join(ROOM, 'work')}, run_command exactly "
                  f"{PY} -I {rt} <op> work\\<file>.json . You never write to the operator and never use reply or send. "
                  f"Report to the Arbiter: write_file {rep_f} with {{\"subchat\": \"{sid}\", \"body\": \"<report in Russian>\"}} "
                  f"then run_command exactly {PY} -I {rt} report work\\rep-{sid}-1.json (next reports: rep-{sid}-2.json and so on).")
        r = agentapi("new-conversation", "--model=gemini-3.8-flash-high", f"--title=HumanX sub {sid}", clean_single_line(prompt))
        conv = (r.get("response", {}).get("newConversation", {}) or {}).get("conversationId")
        if not conv:
            return {"ok": False, "error": "sub-chat not created: " + str(r.get("error"))[:100]}
        with open(os.path.join(ROOM, "conversations.txt"), "a", encoding="utf-8") as h:
            h.write(conv + "\n")
        reg[sid] = {"conv": conv, "topic": str(a.get("topic", ""))[:200], "origin_msg_id": origin, "created": int(time.time())}
        tmp = os.path.join(ROOM, "journal", "subchats.json.tmp")
        json.dump(reg, open(tmp, "w", encoding="utf-8"), ensure_ascii=False); os.replace(tmp, tmp[:-4])
        return {"ok": True, "subchat": sid, "topic": reg[sid]["topic"]}
    sid = str(a.get("subchat", ""))
    if sid not in reg:
        return {"ok": False, "error": "unknown subchat id; see journal/subchats.json"}
    path = os.path.join(ROOM, argfile.replace("/", os.sep))
    if op == "follow":
        target, text = reg[sid]["conv"], f"HUMANX-ROOM-v1 Follow-up from the Arbiter for sub-chat {sid}: read_file {path}"
    else:
        try:
            target = json.load(open(os.path.join(ROOM, "journal", "wake-state.json"), encoding="utf-8"))["arbiter_conv"]
        except (OSError, ValueError, KeyError):
            target = None
        if not target:
            return {"ok": False, "error": "Arbiter conversation unknown"}
        text = (f"HUMANX-ROOM-v1 Report from sub-chat {sid} (topic in journal\\subchats.json): read_file {path} . "
                f"Decide what to tell the operator (op reply) or what to ask the sub-chat next (op follow).")
    r = agentapi("send-message", target, clean_single_line(text))
    return {"ok": bool(r.get("response", {}).get("sendMessage")), "subchat": sid}


def bus_ro(op, args):
    """Шлюз чтения: ошибка шлюза — это ответ Арбитру (с текстом причины), а не падение room_tool."""
    try:
        return bus(op, args)
    except SystemExit as e:
        try:
            return json.loads(str(e.code))
        except (TypeError, ValueError):
            return {"ok": False, "error": "read gateway unreachable"}


def _load_hosts():
    """Host table from the configured hosts_file: {"jump": "<ssh alias>", "hosts": {"<name>": {"dest": "<ssh dest>", "jump": bool}}}."""
    with open(_integrity_value("hosts_file"), encoding="utf-8") as fh:
        d = json.load(fh)
    return {str(k): (str(v["dest"]), bool(v.get("jump"))) for k, v in d["hosts"].items()}, str(d.get("jump") or "")


HOSTS, JUMP = _load_hosts()
HOST_KEY = _integrity_value("host_ssh_key")
SSH_CFG = _integrity_value("ssh_config")


HOST_SOFT_ERR = re.compile(r"^(sudo:|usage:|humanx-host-ro:|unit \S+ could not be found|failed to |permission denied|command not found)|"
                           r"interactive authentication is required|a password is required", re.I | re.M)


def host_read(a):
    """Чтение VM: строка операции уходит как SSH_ORIGINAL_COMMAND; цель сама пускает только список чтения."""
    h = str(a.get("host", ""))
    if h not in HOSTS:
        return {"ok": False, "error": "host: " + " | ".join(HOSTS)}
    if len(a.get("args") or []) > 3:
        return {"ok": False, "error": "host: максимум 3 аргумента (лишние раньше молча отбрасывались)"}
    words = [str(a.get("op", ""))] + [str(x) for x in (a.get("args") or [])]
    if not all(re.fullmatch(r"[A-Za-z0-9@._:-]{1,96}", w) for w in words):
        return {"ok": False, "error": "op/args: только буквы, цифры и @._:-"}
    dest, jump = HOSTS[h]
    ssh = CONF.get("ssh", "ssh")
    argv = [ssh, "-F", SSH_CFG, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "IdentitiesOnly=yes", "-i", HOST_KEY]
    if jump:
        argv += ["-o", f"ProxyCommand=ssh -F {SSH_CFG} {JUMP} -W %h:%p"]   # путь Git ssh с пробелом ломает ProxyCommand; ssh — из PATH ниже
    env = os.environ.copy()
    if os.path.dirname(ssh):
        env["PATH"] = os.path.dirname(ssh) + os.pathsep + env.get("PATH", "")
    try:
        p = subprocess.run(argv + [dest, " ".join(words)], capture_output=True, timeout=60, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "хост не ответил за 60 с"}
    out = p.stdout.decode("utf-8", "replace")
    if p.returncode == 255:
        return {"ok": False, "error": "нет связи с хостом или ключ не принят (access gap)"}
    ok = p.returncode == 0
    soft = HOST_SOFT_ERR.search(out[:300]) if ok and len(out) < 1200 else None   # цель отвечает текстом ошибки с кодом 0
    if soft:
        ok = False
    return {"ok": ok, "host": h, "output": out[:400000],
            "error": None if ok else (out[:300] or ("rc=%s: %s" % (p.returncode, p.stderr.decode("utf-8", "replace")[:200])))}


def load_args(path):
    if not path:
        return {}
    path = path.replace("\\", "/")                      # Windows: work\x.json = work/x.json
    if not re.fullmatch(r"work/[A-Za-z0-9_.-]{1,80}\.json", path):
        raise SystemExit(json.dumps({"ok": False, "error": "argument must be work/<name>.json"}))
    try:
        with open(os.path.join(ROOM, path), encoding="utf-8-sig") as fh:
            a = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(json.dumps({"ok": False, "error": f"файл {path} не найден в комнате"}, ensure_ascii=False))
    except UnicodeDecodeError as e:
        raise SystemExit(json.dumps({"ok": False, "error": f"файл {path} не в UTF-8 ({type(e).__name__}: байт 0x{e.object[e.start]:02x} на позиции {e.start}; "
                                     f"похоже на cp1251 или UTF-16). Ничего не отправлено. " + UTF8_HINT}, ensure_ascii=False))
    except ValueError as e:
        raise SystemExit(json.dumps({"ok": False, "error": f"файл {path}: невалидный JSON ({str(e)[:100]}). Ничего не отправлено."}, ensure_ascii=False))
    if not isinstance(a, dict):
        raise SystemExit(json.dumps({"ok": False, "error": "argument must be a JSON object"}))
    return a


def _fail(msg):
    raise SystemExit(json.dumps({"ok": False, "error": msg}, ensure_ascii=False))


def check_text(body, what="body"):
    """Клиентская проверка текста: пусто, размер, потерянная кодировка («?» вместо кириллицы), U+FFFD."""
    if not body.strip():
        _fail(f"{what} пустой. Ничего не отправлено.")
    n = len(body.encode("utf-8"))
    if n > MAX_BODY_BYTES:
        _fail(f"{what} {n} байт > лимита ядра {MAX_BODY_BYTES} байт (около {MAX_BODY_BYTES // 2} кириллических символов). Сократи или раздели. Ничего не отправлено.")
    q = body.count("?")
    nonspace = len(re.sub(r"\s", "", body)) or 1
    if "\ufffd" in body:
        _fail("в тексте символ замены U+FFFD: кодировка потеряна при записи файла. Ничего не отправлено. " + UTF8_HINT)
    if q >= 10 and (not CYR.search(body) or q / nonspace >= 0.4):
        _fail(f"в тексте {q} знаков '?' из {nonspace} символов"
              + (" и нет ни одной кириллической буквы" if not CYR.search(body) else "")
              + ": похоже, кириллица потеряна при записи файла (мойибаке). Ничего не отправлено. " + UTF8_HINT)


def replica_msg(mid):
    """Строка письма из локальной реплики шины (только чтение) или None; при недоступной реплике - 'n/a'."""
    try:
        con = sqlite3.connect(f"file:{REPLICA}?mode=ro", uri=True, timeout=3)
        try:
            return con.execute("SELECT seq, sender, recipient, status FROM messages WHERE id=?", (mid,)).fetchone()
        finally:
            con.close()
    except Exception:
        return "n/a"


def newer_open(seq):
    try:
        con = sqlite3.connect(f"file:{REPLICA}?mode=ro", uri=True, timeout=3)
        try:
            return [r[0] for r in con.execute(
                "SELECT id FROM messages WHERE recipient=? AND sender=? AND seq>? AND status IN ('pending','acked') ORDER BY seq",
                (ME, _hx_operator(), seq)).fetchall()]
        finally:
            con.close()
    except Exception:
        return []


def check_reply_to(rt, warnings, required):
    if rt in (None, ""):
        if required:
            _fail("reply обязан иметь reply_to: id письма оператора, на которое отвечаешь (из poll/inbox). Ничего не отправлено.")
        return None
    rt = str(rt)
    if not re.fullmatch(r"[0-9a-fA-F-]{8,40}", rt):
        _fail("reply_to должен быть id письма (uuid), получено: " + rt[:40] + ". Ничего не отправлено.")
    row = replica_msg(rt)
    if row == "n/a":
        warnings.append("реплика шины недоступна: reply_to не проверен локально (проверит ядро)")
    elif row is None:
        _fail(f"reply_to {rt[:8]} не найден в шине (письмо старше 7 суток, удалено или неверный id). Ничего не отправлено.")
    else:
        seq, snd, rcp, st = row
        if snd != _hx_operator() or rcp != ME:
            _fail(f"reply_to {rt[:8]}: это письмо не от {_hx_operator()} к {ME} (отправитель {snd}, получатель {rcp}). "
                  f"reply_to = id письма оператора, на которое отвечаешь. Ничего не отправлено.")
        newer = newer_open(seq)
        if newer:
            warnings.append("есть более новые письма оператора без ответа: " + ", ".join(i[:8] for i in newer[:8])
                            + f" (всего {len(newer)}). Проверь, что reply_to {rt[:8]} - именно то письмо, на которое отвечаешь; "
                            "на остальные нужен отдельный ответ с их reply_to")
    return rt


META_WARN = re.compile(
    r"GROK\.md|GEMINI\.md|AGENTS\.md|CLAUDE\.md|room_tool|по инструкции|инструкци[яи] комнаты|только чтени[ея]|я только чита|"
    r"heartbeat|копи[яюи] шины|эскалац|передать администратору|передам администратору|"
    r"правил[оауе]\s*\d+|не могу внести", re.I)

RAW_MAX = 8192
RAW_KEEP = 40
_REDACT = re.compile(
    r"(?is)(?:(?:password|passwd|pwd|community|secret|token|api[_-]?key|auth(?:key|orization)?)\s*[=:]\s*)\S+"
    r"|(?:snmp\s+(?:community|priv|auth)\s+)\S+"
    r"|(?:(?:community|password|passwd|pwd|secret)\s+)\S+"
    r"|-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----"
)


def redact_raw(s):
    """Та же идея, что у шлюзов: не сохранять пароли, community, секреты, токены."""
    s = "" if s is None else str(s)
    return _REDACT.sub("[REDACTED]", s)


def _raw_text(out):
    if not isinstance(out, dict):
        return str(out)
    parts = []
    for k in ("output", "rows_tsv", "text", "result", "error", "stdout"):
        v = out.get(k) if isinstance(out, dict) else None
        if v not in (None, ""):
            parts.append("%s:\n%s" % (k, v))
    return "\n".join(parts) if parts else json.dumps(out, ensure_ascii=False)


def is_executor(a):
    """Тег исполнителя: {"by": "executor"} в файле запроса. Это подпись, а не право: лимиты те же,
    вендор в шлюзе тот же (из authorized_keys); отдельный вендор = отдельный ключ — только с разрешения администратора."""
    return isinstance(a, dict) and a.get("by") == "executor"


def persist_raw(op, args, out):
    """Сохранить ограниченный, редact-нутый сырой вывод sql/switch/host в work/raw/ (ротация)."""
    if op not in ("sql", "switch", "host"):
        return None
    text = redact_raw(_raw_text(out))
    rawb = text.encode("utf-8")
    if len(rawb) > RAW_MAX:
        text = rawb[:RAW_MAX].decode("utf-8", "ignore") + "\n…[truncated]"
    raw_dir = os.path.join(ROOM, "work", "raw-exec" if is_executor(args) else "raw")   # тег исполнителя: не чтения комнаты
    try:
        os.makedirs(raw_dir, exist_ok=True)
        files = sorted((os.path.join(raw_dir, n) for n in os.listdir(raw_dir) if n.endswith(".txt")),
                       key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
        for old in files[: max(0, len(files) - RAW_KEEP + 1)]:
            try:
                os.remove(old)
            except OSError:
                pass
    except OSError:
        return None
    name = "%s-%s-%s.txt" % (op, time.strftime("%Y%m%d-%H%M%S"), os.getpid())
    path = os.path.join(raw_dir, name)
    header = "op=%s\nargs=%s\n---\n" % (op, redact_raw(json.dumps(args, ensure_ascii=False)))
    body = header + text + "\n"
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
    except OSError:
        return None
    return {"raw": "work/raw/" + name, "raw_bytes": len(body.encode("utf-8"))}



def meta_warning(body):
    """Предупреждение (не отказ): служебные/мета-фразы в ответе оператору."""
    hits = sorted({m.group(0).lower() for m in META_WARN.finditer(body)})
    if not hits:
        return None
    return ("в ответе служебные фразы (" + ", ".join(hits[:5]) + "): оператору нужен прямой ответ по существу, без пересказа процесса, "
            "инструкций и предложений эскалации. Если ответ уже ушёл, в следующем письме не повторяй это.")


def _pilot():
    p = os.path.dirname(ROOM)                           # humanx_context / humanx_topics лежат рядом с каталогами комнат
    if p not in sys.path:
        sys.path.insert(0, p)


def _mirror(HT, d):
    """Локальный work/topics.json комнаты = копия общего списка, только как запасной вариант для чтения."""
    try:
        with open(os.path.join(ROOM, "work", "topics.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(d["topics"], fh, ensure_ascii=False, separators=(",", ":"))
    except OSError:
        pass


RING_REF = os.path.join(os.path.dirname(ROOM), "shared", "ring-commands.md")
RING_MAX = 16000


def ring_commands_op(a):
    """K: справочник колец (только текст для ответа оператору). {"model": "DGS-3420"} — только разделы «## ...», где есть модель."""
    try:
        txt = open(RING_REF, encoding="utf-8").read()
    except OSError:
        return {"ok": False, "error": "справочника колец нет: синтаксис для любой модели не подтверждён"}
    model = " ".join(str(a.get("model", "")).split())[:40]
    if model:
        head, *secs = txt.split("\n## ")
        hit = [s for s in secs if model.lower() in s.split("\n", 1)[0].lower()]
        if not hit:
            return {"ok": True, "model": model, "found": False,
                    "text": "Модели %s в справочнике нет: синтаксис для этой модели не подтверждён." % model}
        txt = head.split("\n", 1)[0] + "\n\n## " + "\n## ".join(hit)
    return {"ok": True, "model": model or None, "found": True, "text": txt[:RING_MAX], "truncated": len(txt) > RING_MAX}


def topics_op(op, a):
    _pilot()
    try:
        import humanx_topics as HT
        vendor = ME.replace(_hx_room_prefix(), "")
        if op == "topics_get":
            out = HT.get()
            _mirror(HT, out)
            return out
        up = a.get("upsert", a.get("topics", []))
        out = HT.put(upsert=up, remove=a.get("remove"), vendor=vendor, expect_rev=a.get("rev"))
        _mirror(HT, HT.get())
        return out
    except Exception as e:
        return {"ok": False, "error": (str(e) if type(e).__name__ == "TopicsError" else type(e).__name__ + ": " + str(e))[:400]}


def history_op(a):
    """ТОЛЬКО ЧТЕНИЕ, по запросу, до 16 КБ, по всем комнатам оператора: {"topic": "<id из общего списка тем или часть названия>"} | {"n": N} | {"index": true}."""
    _pilot()
    try:
        import humanx_context as HC
        import humanx_topics as HT
        msgs = HC.load_all(REPLICA)
        try:
            topics = HT.load()["topics"]
        except Exception:
            topics = []
        n = a.get("n")
        c = HC.build_context(msgs, topic=(str(a.get("topic")) if a.get("topic") else None), last_n=(int(n) if n else None),
                             topics=topics, index=bool(a.get("index")))
        return {"ok": True, "room": ME, **c}
    except Exception as e:
        return {"ok": False, "error": "history: " + type(e).__name__ + ": " + str(e)[:160]}


# Пакет K: кольца и STP — зона оператора: настройку STP и защиты колец оператор ведёт сам.
# Команды ERPS/STP/MSTP/loopdetect оператору даются текстом, но только полным ответом: модель свитча, откат,
# проверка после и предупреждение о петле. Механизм, а не только текст инструкций. Сама комната на свитчи не пишет (шлюз).
RING_CHANGE = re.compile(r"(?i)\b(?:config|create|delete|enable|disable)\s+(?:erps|stp|mstp|loopdetect|lbd)\b")


RING_MODEL = re.compile(r"(?i)\b(?:DES|DGS|DXS|DES-1210|DGS-3420|DGS-1510)-?\d{3,4}|модел[ьи]\s*:")
RING_ROLLBACK = re.compile(r"(?i)откат")
RING_CHECK = re.compile(r"(?i)проверк|проверить|проверьте")
RING_LOOP = re.compile(r"(?i)петл")


def ring_change_check(body):
    m = RING_CHANGE.search(body or "")
    if not m:
        return
    miss = [name for name, rx in (("модель свитча", RING_MODEL), ("откат", RING_ROLLBACK), ("проверка после", RING_CHECK),
                                  ("предупреждение о петле", RING_LOOP)) if not rx.search(body)]
    if miss:
        _fail("в ответе оператору команда изменения колец/STP («" + m.group(0)[:40] + "»), но нет: " + ", ".join(miss) + ". "
              "Такой ответ должен содержать: текущее состояние с временем опроса, модель свитча, команды из справочника для этой модели, "
              "порядок применения, откат, проверку после и предупреждение о петле. Допиши и отправь снова. Ничего не отправлено.")


FALLBACK_WHY = {"no_drafts": "ни один независимый черновик не пришёл вовремя", "no_available_vendors": "других Арбитров не было в доступе",
                "synthesis_deadline": "синтез черновиков не успел", "synthesis_no_reply_after_attempt": "синтез черновиков не удался",
                "job_hard_deadline": "задание Max Reasoning не уложилось в срок", "disabled": "режим Max Reasoning выключен"}


def mr_fallback_note(reply_to, body):
    """Пакет G: ответ на письмо Max Reasoning, ушедшее в запасной путь, сам помечается до отправки — сразу после строки «Тема:»
    (она обязана быть первой): «Независимой проверки не было: <причина>, это ответ одного Арбитра.» Механизм, а не правило в промпте."""
    if not reply_to:
        return body
    root = os.environ.get("HUMANX_MR_DIR") or os.path.join(os.path.dirname(ROOM), "shared", "maxreason")
    sid = "".join(c for c in str(reply_to) if c.isalnum() or c in "-_.")[:80]
    try:
        job = json.load(open(os.path.join(root, "jobs", sid, "job.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return body
    if not isinstance(job, dict) or job.get("mode") != "fallback" or "Независимой проверки не было" in body[:600]:
        return body
    head, _, rest = body.lstrip("\ufeff").partition("\n")
    if not head.startswith("Тема:"):
        return body                                            # validate_outgoing отклонит такой ответ сам
    why = FALLBACK_WHY.get(str(job.get("fallback_reason", "")).split(":")[0], "режим Max Reasoning не завершился")
    return head.rstrip() + " (без независимой проверки)\nНезависимой проверки не было: %s, это ответ одного Арбитра.\n" % why + rest


def validate_outgoing(op, a, to, body):
    """Возвращает (reply_to, warnings); при нарушении - SystemExit с понятной ошибкой, ничего не уходит."""
    warnings = []
    if to == _hx_operator():
        ring_change_check(body)
    if op == "send" and to not in (_hx_operator(), "owner"):
        _fail("send: to только " + _hx_operator() + " или owner. Ничего не отправлено.")
    check_text(body)
    if to == _hx_operator():
        first = body.lstrip("\ufeff \t\r\n").split("\n", 1)[0]
        if not first.startswith("Тема:"):
            _fail("первая строка ответа оператору должна начинаться с 'Тема:' (например 'Тема: Кольцо ERPS 100'). Ничего не отправлено.")
        mw = meta_warning("\n".join(body.split("\n")[1:]))
        if mw and op != "escalate":
            warnings.append(mw)
    if op == "escalate":
        if a.get("reply_to"):
            warnings.append("escalate: reply_to отброшен (ядро отклоняет reply_to в письме администратору)")
        return None, warnings
    rt = check_reply_to(a.get("reply_to"), warnings, required=(op == "reply"))
    if rt and to == "owner":
        warnings.append("send к owner: reply_to не из переписки с owner будет отклонён ядром")
    return rt, warnings


def main(argv):
    if len(argv) not in (2, 3) or argv[1] not in OPS:
        print(json.dumps({"ok": False, "error": "usage: room_tool.py <op> [work/<file>.json]", "ops": sorted(OPS)})); return 2
    op, a = argv[1], load_args(argv[2] if len(argv) == 3 else None)
    if op in SILENT_BLOCK:
        sil = silent_state()
        if sil and op not in (sil.get("allow") or []):
            journal({"op": op, "result": "blocked_mr_silent", "job": sil.get("job"), "phase": sil.get("phase")})
            _fail("Max Reasoning: это промежуточный этап, оператору и в общие темы сейчас писать нельзя (операция %s заблокирована). "
                  "Результат этапа положи в файл work/mr-out-<id>-<фаза>.json или выдай финальным сообщением. Ничего не отправлено." % op)
    if op == "poll":
        out = bus("poll", {"as": ME, "limit": 20})
    elif op in ("get", "ack"):
        out = bus(op, {"as": ME, "id": str(a.get("id", ""))})
    elif op in ("reply", "send", "escalate"):
        to = _hx_operator() if op == "reply" else ("owner" if op == "escalate" else str(a.get("to", "")))
        body = str(a.get("body", ""))
        if op == "escalate":
            check_text(body)
            body = "ЭСКАЛАЦИЯ из комнаты HumanX (Арбитр комнаты сам ничего не меняет): " + body
        if op == "reply":
            body = mr_fallback_note(a.get("reply_to"), body)
        reply_to, warns = validate_outgoing(op, a, to, body)
        msg = {"as": ME, "to": to, "id": str(uuid.uuid4()), "body": body, "reply_to": reply_to}
        out = bus("send", msg)
        if warns:
            for w in warns:
                print("WARNING: " + w, file=sys.stderr)
            if isinstance(out, dict):
                out["warnings"] = warns
    elif op == "cards":
        out = bus("vendor-cards", {"days": int(a.get("days", 7))})
    elif op == "heartbeat":
        v = str(a.get("vendor", "") or ME.replace(_hx_room_prefix(), ""))
        out = bus("vendor-heartbeat", {"vendor": v, "state": str(a.get("state", "ready")),
                                       "detail": str(a.get("detail", "")), "reset_at": float(a.get("reset_at", 0.0))})
    elif op == "history":
        out = history_op(a)
    elif op in ("topics_get", "topics_put"):
        out = topics_op(op, a)
    elif op == "ring_commands":
        out = ring_commands_op(a)
    elif op == "arbiter":
        out = bus("room-arbiter", {})
    elif op in ("subchat", "follow", "report"):
        if len(argv) != 3:
            raise SystemExit(json.dumps({"ok": False, "error": f"{op} needs work/<file>.json"}))
        out = subchat_op(op, a, argv[2].replace("\\", "/"))
    elif op == "host":                        # чтение VM (forced-command humanx-host-ro на цели)
        out = host_read(a)
    elif op == "sql":                         # HumanX шаг 3: прод-БД биллинга только на чтение (humanx-ro-gw на ядре)
        out = bus_ro("ro-sql", {"db": str(a.get("db", "")), "query": str(a.get("query", ""))})
    elif op == "integrity":                   # копия Integrity Action Log, только чтение
        out = bus_ro("ro-integrity", {k: a[k] for k in ("q", "text", "id", "n") if k in a})
    else:                                     # switch: живое чтение одного свича (только show из белого списка)
        cmds = a.get("cmds") or ([a["cmd"]] if a.get("cmd") else [])
        if len(cmds) > 4:
            _fail(f"switch: {len(cmds)} команд, максимум 4 за вызов (лишние раньше молча отбрасывались). Раздели на несколько вызовов. Ничего не выполнено.")
        out = bus_ro("ro-switch", {"ip": str(a.get("ip", "")), "cmds": [str(c) for c in cmds],
                                   **({"by": "executor"} if is_executor(a) else {}),
                                   **({"fresh": True} if a.get("fresh") is True else {})})   # MR-очередь: свежее чтение без общего ответа
    rec = {"op": op, "args_sha256": hashlib.sha256(json.dumps(a, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
           "to": a.get("to") if op == "send" else None, "reply_to": a.get("reply_to") if op == "reply" else None,
           "subchat": a.get("subchat") if op in ("follow", "report") else None,
           "result": "ok" if not (isinstance(out, dict) and out.get("ok") is False) else "error"}
    if is_executor(a):
        rec["by"] = "executor@" + ME
    raw_meta = persist_raw(op, a, out) if op in ("sql", "switch", "host") else None
    if raw_meta:
        rec.update(raw_meta)
    journal(rec)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
