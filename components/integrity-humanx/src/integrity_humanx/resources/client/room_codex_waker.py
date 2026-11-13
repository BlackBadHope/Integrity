#!/usr/bin/env python3
"""room_codex_waker — on-demand будильник Арбитра Codex в комнате оператора.

Соблюдает строгое правило: без постоянного процесса Codex:
  * В простое в памяти клиентской машины НЕТ постоянного процесса Codex (0 МБ RAM).
  * При получении сообщения оператора запускается одноразовый `codex exec -s read-only`.
  * Все глобальные MCP-серверы и web_search принудительно отключаются флагами -c.
  * Единственный доступный инструмент — изолированный stdio MCP humanx_room_ro_mcp.py
    с шестью Read-Only операциями комнаты.
  * Раз в 45 секунд отправляет vendor-heartbeat на ядро (state: ready).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import codecs
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time

ROOM = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "room-codex"))
ADDR = _hx_room("codex")
REPLICA = os.environ.get("BUS_REPLICA") or _integrity_value("bus_replica")
CODEX_BIN = os.environ.get("CODEX_BIN", "codex")
STATE = os.path.join(ROOM, "journal", "wake-state.json")
PY = _integrity_value("python")
RT = os.path.join(ROOM, "room_tool.py")
MCP_SCRIPT = os.path.join(ROOM, "humanx_room_ro_mcp.py")
CODEX_CONFIG = os.path.expanduser(r"~\.codex\config.toml")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import humanx_attach as HA  # noqa: E402
import humanx_delivery as DL  # noqa: E402
import humanx_maxreason as MR  # noqa: E402
import humanx_kparts as KP  # noqa: E402
try:
    import humanx_codexquota as CQ  # noqa: E402  свежее состояние лимитов Codex (5 ч / неделя); нет модуля - прежнее поведение
except ImportError:
    CQ = None


def load_state():
    try:
        return json.load(open(STATE, encoding="utf-8"))
    except (OSError, ValueError):
        return {"seen": [], "last_hb": 0}


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)
    os.replace(tmp, STATE)


def log(rec):
    os.makedirs(os.path.join(ROOM, "journal"), exist_ok=True)
    with open(os.path.join(ROOM, "journal", "wake.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": int(time.time()), **rec}, ensure_ascii=False) + "\n")


# узкие признаки исчерпанной квоты ("rate limit"/"quota"/"try again at" давали ложные срабатывания)
QUOTA_PATTERNS = ("hit your usage limit", "usage limit", "upgrade to pro", "purchase more credits")


def detect_quota_error(rc, stdout, stderr):
    combined = f"{stdout}\n{stderr}".lower()
    if rc != 0 and any(p in combined for p in QUOTA_PATTERNS):
        for line in (stderr or stdout).splitlines():
            if any(p in line.lower() for p in QUOTA_PATTERNS):
                return line.strip()[:240]
        return (stderr or stdout).strip()[:240]
    return None


def get_quota_status():
    qf = os.path.join(ROOM, "work", "quota_status.json")
    try:
        if os.path.exists(qf):
            return json.load(open(qf, encoding="utf-8"))
    except Exception:
        pass
    return None


def send_heartbeat(state_name="ready", detail="on-demand codex ready", reset_at=0.0):
    try:
        DL.send_heartbeat(ROOM, PY, RT, "codex", state_name, detail, reset_at)
    except Exception:
        pass


def mark_quota(err_text):
    """Запуск Codex упал на лимите: сразу помечаем исчерпание (с временем сброса из текста ошибки) и шлём heartbeat quota_exhausted.
    Возвращает статус (dict) или None, если модуль лимитов недоступен."""
    if CQ is None or not err_text:
        return None
    try:
        st = CQ.refresh(ROOM, err_text=err_text)
    except Exception as exc:  # noqa: BLE001
        log({"event": "quota_refresh_error", "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])})
        return None
    send_heartbeat("quota_exhausted", st["detail"], reset_at=st["reset_at"])
    log({"event": "quota_marked", "window": st.get("window"), "reset_at": st.get("reset_at"), "source": st.get("source")})
    return st


def get_all_configured_mcp_servers():
    servers = set()
    if os.path.exists(CODEX_CONFIG):
        try:
            with open(CODEX_CONFIG, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = re.match(r"^\s*\[mcp_servers\.([A-Za-z0-9_-]+)\]", line)
                    if m:
                        servers.add(m.group(1))
        except Exception:
            pass
    servers.discard("humanx_room_ro")
    return sorted(servers)


def new_messages(seen):
    if not os.path.exists(REPLICA):
        return []
    db = sqlite3.connect(f"file:{REPLICA}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute("SELECT id, sender, recipient, body, reply_to, created_at FROM messages "
                          "WHERE recipient=? AND status='pending' ORDER BY seq", (ADDR,)).fetchall()
        return [dict(id=r["id"], from_addr=r["sender"], to_addr=r["recipient"], body=r["body"],
                     reply_to=r["reply_to"], created_at=r["created_at"])
                for r in rows if r["id"] not in seen and r["sender"] in (_hx_operator(), "owner")]
    finally:
        db.close()


def ack(mid):
    ok = DL.ack_message(ROOM, PY, RT, mid)
    log({"event": "ack", "id": mid, "ok": ok})
    return ok


def get_recent_room_context(limit=8):
    if not os.path.exists(REPLICA):
        return ""
    try:
        db = sqlite3.connect(f"file:{REPLICA}?mode=ro", uri=True)
        rows = db.execute(
            "SELECT sender, recipient, body FROM messages "
            "WHERE (sender LIKE ? OR recipient LIKE ?) "
            "ORDER BY seq DESC LIMIT ?", ("%" + _hx_operator_id() + "%", "%" + _hx_operator_id() + "%", limit)
        ).fetchall()
        db.close()
        if not rows:
            return ""
        lines = []
        for s, r, b in reversed(rows):
            sender_label = "Operator" if _hx_operator_id() in s and "room" not in s else f"Arbiter ({s.replace(_hx_room_prefix(), '')})"
            clean_b = MR.strip(b or "").strip()
            lines.append(f"[{sender_label}]: {clean_b}")
        return "\n\n".join(lines)
    except Exception:
        return ""


def _safe(mid):
    return "".join(c for c in mid if c.isalnum() or c in "-_.")[:80]


def _reply(kind, mid, body):
    """reply через room_tool с проверкой результата; 2 попытки. Возвращает ok."""
    for attempt in (1, 2):
        ok, info = DL.room_call(ROOM, PY, RT, "reply", f"reply-{kind}-{_safe(mid)}", {"reply_to": mid, "body": body})
        log({"event": "reply_" + kind, "id": mid, "ok": ok, "attempt": attempt, "info": "" if ok else info[:200]})
        if ok:
            return True
        time.sleep(3)
    return False



EXEC_HARD_S = int(os.environ.get("HUMANX_CODEX_EXEC_HARD_S", "420"))   # пакет H: 420 < p3 480; env - только для стенда
EXEC_GRACE_S = 45

# --- Max Reasoning (пакет maxreason): письма с флагом уходят в координатор MR; без флага поведение прежнее ---
MR_ACC = (lambda m: m["id"], lambda m: m.get("body", ""), lambda m, b: dict(m, body=b), lambda m: dict(m))
MR_CTX = {"ack": lambda mid: ack(mid), "py": PY, "rt": RT, "notice": lambda: DL.send_notice(ROOM, PY, RT)}


# Возможности Codex, которые в комнате только чтения не нужны и обходят sandbox: коннекторы ChatGPT (apps: bus_send, *_send_prompt,
# Gmail, Slack, управление разрешениями), плагины, браузер, computer use, память, субагенты. Хуки (Integrity, vendor_room_guard) остаются.
ROOM_DISABLED_FEATURES = ("apps", "plugins", "remote_plugin", "browser_use", "browser_use_external", "computer_use", "in_app_browser",
                          "memories", "multi_agent", "image_generation", "tool_suggest", "skill_mcp_dependency_install")


ROOM_MCP_CFG = os.path.join(ROOM, "codex-room-mcp.json")
_APPROVAL_MODES = ("approve", "prompt", "auto", "writes")
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")


def room_mcp_flags():
    """Конфиг MCP комнаты в каталоге комнаты (а не глобально в ~/.codex/config.toml): codex-room-mcp.json =
    {"required": true, "default_tools_approval_mode": "approve", "tools": {"room_reply": "prompt"}, "disabled_tools": ["room_escalate"]}.
    Нет файла - флагов нет (прежнее поведение). Неверные имена/значения пропускаются и пишутся в журнал."""
    try:
        with open(ROOM_MCP_CFG, encoding="utf-8-sig") as h:
            c = json.load(h)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        log({"event": "room_mcp_cfg_error", "error": "%s: %s" % (type(exc).__name__, str(exc)[:120])})
        return []
    out, bad = [], []
    if c.get("required") is True:
        out += ["-c", "mcp_servers.humanx_room_ro.required=true"]
    d = c.get("default_tools_approval_mode")
    if d in _APPROVAL_MODES:
        out += ["-c", f'mcp_servers.humanx_room_ro.default_tools_approval_mode="{d}"']
    elif d is not None:
        bad.append("default=%s" % d)
    for name, mode in sorted((c.get("tools") or {}).items()):
        if _TOOL_NAME.match(str(name)) and mode in _APPROVAL_MODES:
            out += ["-c", f'mcp_servers.humanx_room_ro.tools.{name}.approval_mode="{mode}"']
        else:
            bad.append("%s=%s" % (str(name)[:40], str(mode)[:20]))
    dis = [str(x) for x in (c.get("disabled_tools") or []) if _TOOL_NAME.match(str(x))]
    if dis:
        out += ["-c", "mcp_servers.humanx_room_ro.disabled_tools=[%s]" % ",".join('"%s"' % x for x in dis)]
    if bad:
        log({"event": "room_mcp_cfg_skipped", "entries": bad[:10]})
    return out


def _codex_cmd(prompt):
    all_servers = get_all_configured_mcp_servers()
    escaped_mcp_script = MCP_SCRIPT.replace("\\", "\\\\")
    cmd = [CODEX_BIN, "exec", "--skip-git-repo-check", "-s", "read-only", "-C", ROOM, "-c", 'web_search="disabled"',
           "-c", f'mcp_servers.humanx_room_ro.command="{PY}"', "-c", f'mcp_servers.humanx_room_ro.args=["{escaped_mcp_script}"]']
    cmd += room_mcp_flags()
    for feat in ROOM_DISABLED_FEATURES:
        cmd.extend(["-c", f"features.{feat}=false"])
    for srv in all_servers:
        cmd.extend(["-c", f"mcp_servers.{srv}.enabled=false"])
    cmd.append(prompt)
    return DL.agent_argv(cmd[0], cmd[1:], PY)


def mr_runner(task, job, paths):
    """MR p1/p2/p3x: одноразовый `codex exec -s read-only` (тот же набор флагов и MCP, что у обычного запуска); результат - финальное сообщение."""
    prompt = MR.task_prompt("codex", job, task, paths)
    left = max(20.0, min(float(task["deadline"]) - time.time(), 900.0))
    DL.beacon(ROOM, left + 90)
    try:
        proc = subprocess.Popen(_codex_cmd(prompt), cwd=ROOM, env=_room_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        return {"ok": False, "error": "launch: %s: %s" % (type(exc).__name__, str(exc)[:120])}
    timed = False
    try:
        out, err = proc.communicate(timeout=left)
    except subprocess.TimeoutExpired:
        timed = True
        proc.kill()
        out, err = proc.communicate()
    rc = -9 if timed else proc.returncode
    q = detect_quota_error(rc, DL.clean_text((out or "").strip()), (err or "").strip())
    if q:
        mark_quota(q)                                         # полный текст (со временем сброса) - до обрезки в error
        return {"ok": False, "error": "quota: " + q[:120], "meta": {"rc": rc}}
    text, src = MR.harvest(paths, out)
    return {"ok": bool(text), "text": text, "error": None if text else ("timeout" if timed else "no_output rc=%s" % rc), "meta": {"src": src, "rc": rc}}


def _journal_ops_since(room, op, since_ts, tail=400):
    """Сколько успешных записей op в journal/room.jsonl(.1) с ts >= since_ts."""
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
            row = json.loads(ln)
        except ValueError:
            continue
        if row.get("op") == op and row.get("result") == "ok" and int(row.get("ts") or 0) >= int(since_ts):
            n += 1
    return n


def _batch_complete(room, ids, since_ts):
    try:
        replied = DL.replied_ids(room, ids)
    except Exception:
        replied = set()
    return set(ids) <= set(replied) and _journal_ops_since(room, "topics_put", since_ts) >= 1


def _pid_alive(pid):
    if not pid:
        return False
    try:
        if os.name == "nt":
            import ctypes
            k = ctypes.windll.kernel32
            h = k.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                return False
            k.CloseHandle(h)
            return True
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, OverflowError, AttributeError):
        return False


def _room_env():
    """Пакет K: признак сессии комнаты для слоя Integrity у Codex; сам по себе ничего не меняет,
    пока слой его не читает. Остальное окружение — как у будильника."""
    e = dict(os.environ)
    e["HUMANX_ROOM"] = _hx_room("codex")
    return e


def _drain_pump(stream, buf):
    """Читает то, что уже пришло (read1 по байтовому буферу), а не ждёт 8192 символа: иначе при канале, который держит
    переживший родителя потомок, вывод родителя не был бы собран до EOF."""
    raw = getattr(stream, "buffer", None)
    dec = codecs.getincrementaldecoder(getattr(stream, "encoding", None) or "utf-8")(getattr(stream, "errors", None) or "replace")
    try:
        if raw is None:                                    # не текстовый поток (стенд) - прежнее чтение
            for chunk in iter(lambda: stream.read(8192), ""):
                buf.append(chunk)
        else:
            while True:
                chunk = raw.read1(8192)
                if not chunk:
                    break
                buf.append(dec.decode(chunk))
            buf.append(dec.decode(b"", final=True))
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except Exception:  # noqa: BLE001
            pass


def _drain_start(proc):
    """Пакет H: stdout/stderr Codex вычитываются потоками с первой секунды. Раньше их читал только communicate() после
    выхода: в обычном режиме Codex пишет в stderr весь ход сессии (эхо промпта ~12 тыс. символов), канал переполнялся,
    Codex вставал на записи до первого хода модели и висел до EXEC_HARD_S (rc -9)."""
    bufs = {"out": [], "err": []}
    ths = []
    for key, stream in (("out", proc.stdout), ("err", proc.stderr)):
        if stream is None:
            continue
        t = threading.Thread(target=_drain_pump, args=(stream, bufs[key]), daemon=True)
        t.start()
        ths.append(t)
    proc._hx_drain = (ths, bufs)


def _drain_finish(proc, timeout=10):
    """Дождаться выхода (при зависании - kill) и собрать вычитанное. Возвращает (out, err, cut): cut=True, если за timeout
    процесс не вышел (убит) или канал не закрылся (его держит переживший родителя потомок, например MCP-сервер Codex) -
    прежний communicate(timeout) в этих случаях давал TimeoutExpired. Ожидание потоков ограничено общим сроком timeout.
    Без _drain_start - прежний communicate()."""
    d = getattr(proc, "_hx_drain", None)
    if d is None:
        try:
            out, err = proc.communicate(timeout=timeout)
            return out, err, False
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            return out, err, True
    ths, bufs = d
    cut = False
    end = time.time() + timeout
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        cut = True
        proc.kill()
        proc.wait(timeout=10)
    for t in ths:
        t.join(max(0.0, end - time.time()))
    if any(t.is_alive() for t in ths):
        cut = True
    return _nl("".join(bufs["out"])), _nl("".join(bufs["err"])), cut


def _nl(text):
    """Те же переводы строк, что давал communicate() в текстовом режиме (universal newlines)."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _wait_exec(proc, room, ids, t0, hard=EXEC_HARD_S, grace=EXEC_GRACE_S):
    """Ждать exit процесса. После reply+topics_put — ещё grace секунд, затем terminate.
    Вторую сессию exec не запускаем. Возвращает (rc, out, err, timed_out, lingering)."""
    deadline = t0 + hard
    replied_at = None
    lingering = False
    while True:
        now = time.time()
        if proc.poll() is not None:
            out, err, _cut = _drain_finish(proc)
            return proc.returncode, out, err, False, lingering
        if _batch_complete(room, ids, t0) and replied_at is None:
            replied_at = now
            log({"event": "reply_and_topics_done", "ids": ids, "exec_s": int(now - t0)})
        if replied_at and now - replied_at >= grace:
            if not lingering:
                lingering = True
                log({"event": "exec_lingering_after_reply", "ids": ids, "grace_s": grace, "exec_s": int(now - t0)})
            proc.terminate()
            out, err, _cut = _drain_finish(proc, timeout=5)          # не успел за 5 с - kill внутри (как прежний communicate+kill)
            rc = proc.returncode if proc.returncode is not None else -15
            return rc, out, err, False, True
        if now >= deadline:
            proc.kill()
            out, err, _cut = _drain_finish(proc)
            return -9, out, err, True, lingering
        time.sleep(1.0)

def wake(msgs, st, retry):
    if not msgs:
        return
    ids = [m["id"] for m in msgs]
    listing = []
    for m in msgs:
        text, atts = m["body"], []
        try:
            text, atts = HA.fetch(ROOM, m["id"], m["body"])
        except Exception as exc:
            log({"event": "attach_error", "id": m["id"], "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
        path = os.path.join(ROOM, "work", f"inbox-{_safe(m['id'])}.json")
        json.dump({"id": m["id"], "from": m["from_addr"], "body": text, "attachments": atts,
                   "reply_to": m["reply_to"], "created_at": m["created_at"]},
                  open(path, "w", encoding="utf-8"), ensure_ascii=False)
        listing.append(f"  {len(listing) + 1}. message id={m['id']}  file={path}")

    context_history = get_recent_room_context(limit=8)
    history_block = (
        f"\n\nRECENT ROOM DIALOGUE CONTEXT (for continuity across messages and arbiters):\n{context_history}\n"
        if context_history else ""
    )
    prompt = (
        f"You are the Read-Only Arbiter of the HumanX room for the operator. "
        f"Read AGENTS.md for database schemas, switch commands, and operational rules. "
        f"Read your new tasks from these files (one file per the operator message, oldest first):\n" + "\n".join(listing) + "\n"
        f"You have MCP tools: room_sql, room_switch, room_host, room_integrity, room_escalate, room_topics_get, room_topics_put, room_history. "
        f"IMPORTANT CONTRACT RULES:\n"
        f"1. You change nothing yourself: do not modify switch configurations, disable/enable ports, or apply changes.\n"
        f"2. If the operator asks to disable a port, change a configuration, or execute changes, do NOT answer that this cannot be done under the room instructions. "
        f"Give a diagnosis from live data plus exact commands with real values (no <placeholders> when the value is already in the tool output), how to verify and how to roll back.\n"
        f"2a. Rings and STP are the operator's zone (room rule): when he asks, give exact STP/MSTP, ERPS, loopdetect and ring-port commands as text for him to apply: (1) current live state with the poll time; (2) the switch model and commands with syntax ONLY from the ring reference for that model (op ring_commands: python -I room_tool.py ring_commands work/<file>.json, the file holds JSON with key model = the model from show switch) — if the model has no entry, write «синтаксис для этой модели не подтверждён» and give no command; (3) order of application; (4) rollback; (5) post-check; (6) a loop warning. Never say the network owner decides. room_tool rejects a ring command reply without model, rollback, check and loop warning. If live data differs from your earlier answer, write «изменилось между HH:MM и HH:MM», never call it an error. Never mention delivery, approvals, rejected calls, memory, hooks or session tools in the answer.\n"
        f"3. Do NOT offer escalation and do NOT call room_escalate unless the operator himself explicitly asks to pass something to the owner.\n"
        f"2b. Short follow-ups («И?», «а дальше?», «Проверь ещё раз») continue the CURRENT/latest topic; "
        f"mark status done only when the operator's question is fully resolved. Statements about what was polled must match tool results exactly. "
        f"Never mention rules, instructions, «правило N», or gateways in replies to the operator.\n"
        f"4. Always use the RECENT ROOM DIALOGUE CONTEXT below to understand pronouns, referenced devices, switches, ports, and previous answers.\n"
        f"5. Before answering about rings (ERPS), re-run room_switch 'show erps' live in this same answer; never answer from memory.\n"
        f"7. Topics are ONE shared list for all arbiters (Gemini, Grok, Codex, Claude): call room_topics_get first, decide continue / return to earlier / new topic, and after answering call room_topics_put (see AGENTS.md). Earlier messages of a topic, even one started by another arbiter: room_history(topic=<id>) on demand, never ask for the whole dialogue.\n"
        f"6. Answer EVERY message in Russian as your FINAL MESSAGE (stdout); the waker delivers it. Do NOT call room_reply: in the room session it needs approval and is rejected. Start with 'Тема: <Тема>' on its own line; if there are several messages, answer them in one text, one section per message.\n"
        f"{history_block}"
    )
    prompt += MR.synth_block(ROOM, ids)

    cmd = _codex_cmd(prompt)                                   # тот же набор флагов, что у Max Reasoning; .py-агент только в стенде

    t0 = time.time()
    try:
        proc = subprocess.Popen(cmd, cwd=ROOM, env=_room_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace",
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        _drain_start(proc)                                     # пакет H: вычитывать вывод сразу, иначе Codex встаёт на переполненном канале
    except OSError as exc:                                     # codex не запустился: письма остаются pending
        for i in ids:
            retry.fail(i, f"launch: {type(exc).__name__}: {exc}")
        log({"event": "launch_failed", "ids": ids, "error": str(exc)[:200]})
        save_state(st)
        return

    try:
        proc.wait(timeout=4)
        early = True                                           # завершился почти сразу
    except subprocess.TimeoutExpired:
        early = False
    acked = False
    if not early:                                              # процесс жив = Арбитр взял задачу: ack ПОСЛЕ запуска
        for i in ids:
            ack(i)
        acked = True
    timed_out = False
    lingering = False
    st["exec_pid"] = proc.pid
    save_state(st)
    try:
        if early:
            out, err, cut = _drain_finish(proc, timeout=5)
            rc = proc.returncode
            if cut:                                            # как прежний communicate(timeout=5) -> TimeoutExpired
                timed_out = True
                proc.kill()
                rc = -9
        else:
            rc, out, err, timed_out, lingering = _wait_exec(proc, ROOM, ids, t0)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out, err, _cut = _drain_finish(proc)
        rc = -9
    st["exec_pid"] = None
    save_state(st)
    if lingering:
        log({"event": "exec_ended_after_linger", "ids": ids, "rc": rc, "exec_s": int(time.time() - t0)})
    stdout_str = DL.clean_text((out or "").strip())      # мусор/U+FFFD в выводе агента не уходит оператору (room_tool отверг бы такой ответ)
    _removed = []
    stdout_str, n_notes = DL.strip_service_notes(stdout_str, _removed)   # пакет K: абзацы о доставке/подтверждении/памяти оператору не уходят
    if n_notes:                                          # текст убранного (до 300 знаков на абзац): видно, не ушла ли полезная фраза
        log({"event": "service_notes_stripped", "ids": ids, "paragraphs": n_notes, "removed": [p.strip()[:300] for p in _removed]})
    stderr_str = (err or "").strip()

    quota_err = detect_quota_error(rc, stdout_str, stderr_str)
    q_status = mark_quota(quota_err) if quota_err else None   # лимит помечаем сразу, независимо от того, ответил ли агент
    replied = DL.replied_ids(ROOM, ids)
    if early and rc != 0 and not quota_err and not replied:   # Арбитр не стартовал: не ackаем, повтор с backoff
        for i in ids:
            retry.fail(i, f"codex exit rc={rc}: {stderr_str[:100]}")
        log({"event": "launch_failed", "ids": ids, "rc": rc, "stderr": stderr_str[:300]})
        save_state(st)
        return
    if not acked:
        for i in ids:
            ack(i)
    for i in ids:
        retry.ok(i)

    unreplied = [i for i in ids if i not in replied]
    stdout_answer = not replied and bool(stdout_str) and rc == 0   # агент ответил текстом в stdout (room_reply отклонён - пакет B)
    if not stdout_answer:                                      # пакет I: фильтр только для сбоя; ответ синтеза из stdout
        unreplied = [i for i in unreplied if not MR.synth_pending(ROOM, i)]   # уходит запасным путём, иначе MR терял синтез
    final_ok = set(replied)
    handed = []
    no_text = not (not replied and stdout_str and rc == 0)    # есть stdout-ответ - это ответ (запасной путь ниже), не сбой
    if unreplied and no_text:                                  # сбой (таймаут, ошибка, лимит) - НЕ ответ: вопрос уходит следующему доступному Арбитру
        why = ("quota: " + quota_err[:100]) if quota_err else ("timeout %ds" % EXEC_HARD_S if timed_out else "rc=%s" % rc)
        by_id = {m["id"]: m for m in msgs}
        for i in unreplied:
            if MR.failover_start(ROOM, "codex", MR_ACC[3](by_id[i]), why):
                handed.append(i)
        if handed:
            log({"event": "failover", "ids": handed, "reason": why})
        unreplied = [i for i in unreplied if i not in handed]
    if unreplied:
        if quota_err:
            if q_status:                                       # статус и heartbeat уже записаны mark_quota (сброс из текста ошибки)
                reset_str = q_status.get("resets") or "время сброса неизвестно"
            else:
                reset_match = re.search(r"(\d{1,2}:\d{2}\s*(?:AM|PM)?)", quota_err, re.IGNORECASE)
                reset_str = reset_match.group(1) if reset_match else "время сброса неизвестно"
                reset_at = time.time() + 3600.0
                q_data = {"vendor": "codex", "state": "quota_exhausted", "plan": "ChatGPT Plus", "quota_exhausted": True,
                          "detail": f"ChatGPT Plus: лимит исчерпан ({quota_err[:120]})", "resets": reset_str, "reset_at": reset_at}
                try:
                    json.dump(q_data, open(os.path.join(ROOM, "work", "quota_status.json"), "w", encoding="utf-8"), ensure_ascii=False)
                except Exception:
                    pass
                send_heartbeat("quota_exhausted", q_data["detail"], reset_at=reset_at)
            body = ("Тема: Квота Арбитра Codex исчерпана\n\n"
                    f"Оператор, лимит запросов Codex исчерпан провайдером OpenAI ({reset_str}).\n\n"
                    "Пожалуйста, переключите Арбитра на «gemini» в правом верхнем углу интерфейса.")
            for i in unreplied:
                if _reply("quota", i, body):
                    final_ok.add(i)
        elif not replied and stdout_str and rc == 0:
            first_line = stdout_str.splitlines()[0].strip()
            body = stdout_str if first_line.startswith("Тема:") else f"Тема: Ответ Арбитра (Codex)\n{stdout_str}"
            if _reply("fallback", unreplied[0], body):
                final_ok.add(unreplied[0])
            for i in unreplied[1:]:
                if _reply("pointer", i, "Тема: Ответ объединён\nОтвет на это письмо дан в сообщении выше (письма обработаны одним запуском)."):
                    final_ok.add(i)
        elif replied:                                          # часть писем получила ответ: остальным короткая отсылка
            for i in unreplied:
                if _reply("pointer", i, "Тема: Ответ объединён\nОтвет на это письмо дан в сообщении выше (письма обработаны одним запуском)."):
                    final_ok.add(i)
        else:
            body = (f"Тема: Ошибка обработки запроса Арбитром Codex\n\n"
                    f"Арбитр Codex не смог сформировать ответ на ваш запрос (код: {rc}{f', таймаут {EXEC_HARD_S} с' if timed_out else ''}).\n"
                    f"Если требовалось изменение настроек (порт/конфиг), напоминаем: Арбитр работает строго в режиме ТОЛЬКО ЧТЕНИЕ.")
            for i in unreplied:
                if _reply("err", i, body):
                    final_ok.add(i)

    st["seen"] = (st["seen"] + ids)[-500:]
    save_state(st)
    log({"event": "codex_exec", "ids": ids, "rc": rc, "latency_s": round(time.time() - t0, 1),
         "replied_by_agent": sorted(replied), "replied_total": len(final_ok), "of": len(ids), "timed_out": timed_out, "failover": handed,
         "stderr": stderr_str[:300]})


def hb_tick():
    if CQ is not None:
        try:                                                   # свежее состояние из журналов Codex / ошибок; после reset_at само возвращается в ready
            cs = CQ.refresh(ROOM)
            send_heartbeat("quota_exhausted" if cs["quota_exhausted"] else "ready", cs["detail"],
                           reset_at=cs["reset_at"] if cs["quota_exhausted"] else 0.0)
            return
        except Exception as exc:  # noqa: BLE001
            log({"event": "quota_refresh_error", "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])})
    qs = get_quota_status()
    ex, det, reset_at = DL.quota_view(os.path.join(ROOM, "work", "quota_status.json"), qs, "ChatGPT Plus: доступно")
    if qs and qs.get("quota_exhausted") and not ex:             # reset_at прошёл: снимаем флаг в файле
        qs["quota_exhausted"] = False
        try:
            json.dump(qs, open(os.path.join(ROOM, "work", "quota_status.json"), "w", encoding="utf-8"), ensure_ascii=False)
        except Exception:
            pass
    send_heartbeat("quota_exhausted" if ex else "ready", det, reset_at=reset_at if ex else 0.0)


def main():
    os.makedirs(os.path.join(ROOM, "work"), exist_ok=True)
    os.makedirs(os.path.join(ROOM, "journal"), exist_ok=True)
    DL.single_instance(os.path.join(ROOM, "journal", "waker.lock"))
    st = load_state()
    st.setdefault("seen", [])
    st.setdefault("retry", {})
    retry = DL.Retry(st["retry"])
    DL.start_thread(hb_tick, 45.0, "heartbeat")               # heartbeat идёт и пока codex exec работает (до 300 с)
    while not os.path.exists(os.path.join(ROOM, "WAKE_STOP")):
        DL.beacon(ROOM)
        try:
            MR.worker_tick(ROOM, "codex", mr_runner)
            pend, _mr_held = MR.intercept(ROOM, "codex", KP.drop_notes(ROOM, new_messages(set(st["seen"])), MR_ACC, ack, log), MR_ACC, MR_CTX)
            n0 = len(retry.d)
            retry.purge({m["id"] for m in pend})
            if len(retry.d) != n0:
                save_state(st)
            now = time.time()
            ready = [m for m in pend if retry.due(m["id"], now)]
            live_pid = st.get("exec_pid")
            if live_pid and _pid_alive(live_pid):
                log({"event": "exec_still_running", "pid": live_pid})
                time.sleep(2)
                continue
            if ready:
                time.sleep(2)
                fresh = {m["id"]: m for m in MR.intercept(ROOM, "codex", KP.drop_notes(ROOM, new_messages(set(st["seen"])), MR_ACC, ack, log), MR_ACC, MR_CTX)[0]}
                ready = [fresh[m["id"]] for m in ready if m["id"] in fresh]
                if ready:
                    DL.beacon(ROOM, 300 + 300)                # codex exec до 300 с + ответы (2 попытки на письмо)
                    wake(ready, st, retry)
            mr_msgs = MR.tick(ROOM, "codex", MR_CTX)
            if mr_msgs:
                DL.beacon(ROOM, 300 + 300)
                wake(mr_msgs, st, retry)
                MR.note_returned(ROOM, [m["id"] for m in mr_msgs])
            late = retry.overdue()
            if late:
                DL.beacon(ROOM, 120)
                ok, info = DL.send_notice(ROOM, PY, RT)
                log({"event": "notice_unavailable", "ids": late, "ok": ok, "info": "" if ok else info[:120]})
                if ok:
                    retry.mark_notified(late)
                    save_state(st)
        except Exception as exc:
            log({"event": "error", "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
            time.sleep(5)
        time.sleep(3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
