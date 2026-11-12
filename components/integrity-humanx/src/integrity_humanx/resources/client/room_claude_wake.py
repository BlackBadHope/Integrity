"""room_claude_wake — будильник Арбитра комнаты HumanX, когда Арбитр — Claude (пилот).

На каждое новое письмо адресу комнаты (room-<operator_id>-claude) от human-<operator_id> или owner:
  1) кладёт письмо в <комната>/work/inbox-<id>.json (тело остаётся только в комнате: журнал комнаты, без Integrity);
  2) будит Арбитра: `claude -p <указатель> --resume <сессия>` с cwd=<комната>, значит под хуком room_ro_guard.py;
  3) пишет попытку в <комната>/journal/wake.jsonl; одно письмо будит один раз, пачка за 10 с склеивается в одно пробуждение.
Источник писем — локальная копия шины (state/bus.sqlite3, только чтение) или ROOM_INBOX_DIR (стенд).
Запуск: python room_claude_wake.py <каталог комнаты> [--once]. Стоп-флаг: <комната>/WAKE_STOP.
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import json, os, re, sqlite3, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import humanx_attach as HA  # noqa: E402
import humanx_delivery as DL  # noqa: E402
import humanx_maxreason as MR  # noqa: E402
import humanx_kparts as KP  # noqa: E402

ROOM = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else os.path.join(os.path.dirname(os.path.abspath(__file__)), "room-claude")
ONCE = "--once" in sys.argv
ADDR = _hx_room("claude")
REPLICA = os.environ.get("BUS_REPLICA") or _integrity_value("bus_replica")
CLAUDE = os.environ.get("CLAUDE_BIN", os.path.expanduser(r"~\.local\bin\claude.exe"))
STATE = os.path.join(ROOM, "journal", "wake-state.json")
ACK_PY = _integrity_value("python")
RT = os.path.join(ROOM, "room_tool.py")
# узкие признаки исчерпанной квоты ("resets"/"overloaded"/"capacity"/"rate limit" давали ложные срабатывания)
QUOTA_PATTERNS = ("hit your limit", "usage limit", "quota exceeded", "quota exhausted", "out of extra usage")


def detect_quota_error(rc, stdout, stderr):
    combined = f"{stdout}\n{stderr}".lower()
    try:
        obj = json.loads(stdout)
        if obj.get("is_error") and any(p in str(obj.get("result", "")).lower() for p in QUOTA_PATTERNS):
            return str(obj.get("result", "")).strip()[:240]
    except Exception:
        pass
    if rc != 0 and any(p in combined for p in QUOTA_PATTERNS):
        for line in combined.splitlines():
            if any(p in line for p in QUOTA_PATTERNS):
                return line.strip()[:240]
        return (stderr or stdout).strip()[:240]
    return None


QUOTA_FALLBACK_S = 3600.0          # срок по умолчанию, если провайдер не назвал время сброса: через час карточка снова «готов»


def quota_reset_from(err, now):
    """Срок сброса из текста ошибки квоты Claude («...limit reached|<epoch>» или 10-значное epoch в тексте), иначе now + 1 ч.
    Берётся только правдоподобный срок: в будущем и не дальше 8 суток."""
    for m in re.finditer(r"(?<!\d)(1[6-9]\d{8})(?!\d)", str(err or "")):
        t = float(m.group(1))
        if now < t <= now + 8 * 86400:
            return t
    return now + QUOTA_FALLBACK_S


def quota_flag_expired(st, now):
    """Флаг «исчерпано» в памяти будильника снимается по сроку (раньше — только успешным запуском, которого карточка
    «исчерпано» не допускала). Старое состояние без срока получает now + 1 ч."""
    rst = float(st.get("reset_at") or 0.0)
    if not rst:
        st["reset_at"] = rst = now + QUOTA_FALLBACK_S
    if now >= rst:
        st["quota_exhausted"] = False
        st["reset_at"] = 0.0
        return True
    return False


def get_quota_status():
    qf = os.path.join(ROOM, "work", "quota_status.json")
    try:
        if os.path.exists(qf):
            return json.load(open(qf, encoding="utf-8"))
    except Exception:
        pass
    return None


def send_heartbeat(state_name, detail="", reset_at=0.0):
    try:
        DL.send_heartbeat(ROOM, ACK_PY, RT, "claude", state_name, detail, reset_at)
    except Exception:
        pass


def load_state():
    try:
        return json.load(open(STATE, encoding="utf-8"))
    except (OSError, ValueError):
        return {"seen": [], "session": None}


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"; json.dump(st, open(tmp, "w", encoding="utf-8")); os.replace(tmp, STATE)


def log(rec):
    with open(os.path.join(ROOM, "journal", "wake.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": int(time.time()), **rec}, ensure_ascii=False) + "\n")


def new_messages(seen):
    d = os.environ.get("ROOM_INBOX_DIR")
    if d:                                                          # стенд: письма файлами
        out = [json.load(open(os.path.join(d, f), encoding="utf-8")) for f in sorted(os.listdir(d)) if f.endswith(".json")]
    else:
        db = sqlite3.connect(f"file:{REPLICA}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        out = [dict(id=r["id"], **{"from": r["sender"], "to": r["recipient"]}, body=r["body"], reply_to=r["reply_to"])
               for r in db.execute("SELECT * FROM messages WHERE recipient=? AND status='pending' ORDER BY seq", (ADDR,))]
        db.close()
    return [m for m in out if m["id"] not in seen and m.get("to") == ADDR and m.get("from") in (_hx_operator(), "owner")]


def ack(mid):
    """«Арбитр взял в работу»: ack письма на шине ядра через room_tool (ключ комнаты). Веб оператора показывает этот статус."""
    ok = DL.ack_message(ROOM, ACK_PY, RT, mid)
    log({"event": "ack", "id": mid, "ok": ok})


def _safe(mid):
    return "".join(c for c in mid if c.isalnum() or c in "-_.")[:80]


def _reply(kind, mid, body):
    """reply через room_tool с проверкой результата; 2 попытки. Возвращает ok."""
    for attempt in (1, 2):
        ok, info = DL.room_call(ROOM, ACK_PY, RT, "reply", f"reply-{kind}-{_safe(mid)}", {"reply_to": mid, "body": body})
        log({"event": "reply_" + kind, "id": mid, "ok": ok, "attempt": attempt, "info": "" if ok else info[:200]})
        if ok:
            return True
        time.sleep(3)
    return False


# --- Max Reasoning (пакет maxreason): письма с флагом уходят в координатор MR; без флага поведение прежнее ---
MR_ACC = (lambda m: m["id"], lambda m: m.get("body", ""), lambda m, b: dict(m, body=b), lambda m: dict(m))
MR_CTX = {"ack": lambda mid: ack(mid), "py": ACK_PY, "rt": RT, "notice": lambda: DL.send_notice(ROOM, ACK_PY, RT)}


def mr_runner(task, job, paths):
    """MR p1/p2/p3x: свежий `claude -p` (без --resume: независимость, сессия Арбитра не трогается) в каталоге комнаты, под хуком."""
    prompt = MR.task_prompt("claude", job, task, paths)
    argv = DL.agent_argv(CLAUDE, ["-p", prompt, "--output-format", "json", "--max-turns", "40"], ACK_PY)   # пакет G: 40, первая версия черновика к 15-му ходу
    left = max(20.0, float(task["deadline"]) - time.time())
    DL.beacon(ROOM, left + 90)
    try:
        proc = subprocess.Popen(argv, cwd=ROOM, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        return {"ok": False, "error": "launch: %s: %s" % (type(exc).__name__, str(exc)[:120])}
    timed = False
    try:
        so, se = proc.communicate(timeout=left)
    except subprocess.TimeoutExpired:
        timed = True
        proc.kill()
        so, se = proc.communicate()
    rc = -9 if timed else proc.returncode
    out_s, err_s = (so or b"").decode("utf-8", "replace"), (se or b"").decode("utf-8", "replace")
    try:
        res = json.loads(out_s)
        res = res if isinstance(res, dict) else {}
    except ValueError:
        res = {}
    q = detect_quota_error(rc, out_s, err_s)
    if q:
        return {"ok": False, "error": "quota: " + q[:120], "meta": {"rc": rc}}
    text, src = MR.harvest(paths, res.get("result"))
    return {"ok": bool(text), "text": text, "error": None if text else ("timeout" if timed else "no_output rc=%s" % rc),
            "meta": {"cost_usd": res.get("total_cost_usd"), "turns": res.get("num_turns"), "src": src, "rc": rc}}


def wake(msgs, st, retry):
    if not msgs:
        return
    stand = bool(os.environ.get("ROOM_INBOX_DIR"))
    ids = [m["id"] for m in msgs]
    for m in msgs:
        mm = dict(m)
        if not stand:                                              # вложения оператора → work/att-* (humanx_attach)
            try:
                mm["body"], mm["attachments"] = HA.fetch(ROOM, m["id"], m["body"])
            except Exception as exc:
                log({"event": "attach_error", "id": m["id"], "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
        json.dump(mm, open(os.path.join(ROOM, "work", f"inbox-{_safe(m['id'])}.json"), "w", encoding="utf-8"), ensure_ascii=False)
    prompt = (f"New room message(s) from the operator: {', '.join(ids)}. Read work/inbox-<id>.json (attachments, if any, are local paths in it: "
              f"Read them). You are the persistent Arbiter of this room: decide whether each message continues the current topic, "
              f"returns to an earlier one or opens a new one (topic list: ONE shared store for all arbiters, ops topics_get before answering and topics_put after; earlier dialogue of a topic on demand: op history; see CLAUDE.md; the old work/topics.json is a read-only fallback); delegate heavy topics to subagents. "
              f"Answer EVERY message with its own reply: python -I room_tool.py reply work/<file>.json, reply_to = the id of THAT exact message "
              f"(mandatory); the reply body starts with the line 'Тема: <short topic name>'. "
              f"You change nothing yourself. Never write that a change 'cannot be done under the room instructions', «нельзя по инструкции» or «не могу внести». Instead give: (a) a diagnosis from live data you just read, (b) exact commands the operator can run himself, using the real values from that data (port numbers, VLAN ids, IPs) — no <placeholders> when the value is already in the tool output; if a value is unknown, say so and give the show/SQL to obtain it; include how to verify and how to roll back. Rings and STP are the operator's zone (room rule): when he asks, give exact STP/MSTP, ERPS, loopdetect and ring-port commands as text for him to apply: (1) current live state with the poll time; (2) the switch model and commands with syntax ONLY from the ring reference for that model (op ring_commands: python -I room_tool.py ring_commands work/<file>.json, the file holds JSON with key model = the model from show switch) — if the model has no entry, write «синтаксис для этой модели не подтверждён» and give no command; (3) order of application; (4) rollback; (5) post-check; (6) a loop warning. Never say the network owner decides. room_tool rejects a ring command reply without model, rollback, check and loop warning. If live data differs from your earlier answer, write «изменилось между HH:MM и HH:MM», never call it an error. Never mention delivery, approvals, rejected calls, memory, hooks or session tools in the answer. Do not offer escalation and do not use op escalate unless the operator himself asks to pass something to the owner. Short follow-ups («И?», «а дальше?», «Проверь ещё раз» and the like) continue the CURRENT/latest topic (same topic id and name); do not open a new topic for a short follow-up. Mark a topic status done only when the operator's question is fully resolved and the series is not ongoing; if you are waiting for his decision, keep it open. When you state what you polled, list only switches/hosts/queries that actually returned a tool result in this turn; if you did not poll a device or it failed, say so. Never mention rules, instructions, «правило N», gateways, or instruction file names in replies to the operator. "
              f"Before answering about rings (ERPS) re-run op switch "
              f"with show erps live.")
    prompt += MR.synth_block(ROOM, ids)
    argv = [CLAUDE, "-p", prompt, "--output-format", "json", "--max-turns", "40"]
    if st.get("session"):
        argv += ["--resume", st["session"]]
    argv = DL.agent_argv(argv[0], argv[1:], ACK_PY)             # .py-агент только в стенде; реальный claude.exe без изменений
    t = time.time()
    try:
        proc = subprocess.Popen(argv, cwd=ROOM, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:                                         # claude.exe не запустился: письма остаются pending
        for i in ids:
            retry.fail(i, f"launch: {type(exc).__name__}: {exc}")
        log({"event": "launch_failed", "ids": ids, "error": str(exc)[:200]})
        save_state(st)
        return
    try:
        proc.wait(timeout=4)
        early = True
    except subprocess.TimeoutExpired:
        early = False
    acked = False
    if not early and not stand:                                    # процесс жив = Арбитр взял задачу: ack ПОСЛЕ запуска
        for i in ids:
            ack(i)
        acked = True
    timed_out = False
    try:
        so, se = proc.communicate(timeout=5 if early else 1800)
    except subprocess.TimeoutExpired:                              # раньше: необработанный TimeoutExpired ронял waker
        timed_out = True
        proc.kill()
        so, se = proc.communicate()
    rc = -9 if timed_out else proc.returncode
    stdout_str = (so or b"").decode("utf-8", "replace")
    stderr_str = (se or b"").decode("utf-8", "replace")
    try:
        res = json.loads(stdout_str)
        if not isinstance(res, dict):
            res = {}
    except ValueError:
        res = {}
    if res.get("session_id"):
        st["session"] = res["session_id"]

    quota_err = detect_quota_error(rc, stdout_str, stderr_str)
    replied = DL.replied_ids(ROOM, ids) if not stand else set()
    if early and rc != 0 and not quota_err and not replied and not stand:   # Арбитр не стартовал: не ackаем, повтор
        for i in ids:
            retry.fail(i, f"claude exit rc={rc}: {stderr_str[:100]}")
        log({"event": "launch_failed", "ids": ids, "rc": rc, "stderr": stderr_str[:300]})
        save_state(st)
        return
    if not acked and not stand:
        for i in ids:
            ack(i)
    for i in ids:
        retry.ok(i)

    unreplied = [i for i in ids if i not in replied]
    unreplied = [i for i in unreplied if not MR.synth_pending(ROOM, i)]   # MR: ошибка первой (синтезирующей) попытки оператору не уходит, дальше запасной путь
    final_ok = set(replied)
    if quota_err:
        st["reset_at"] = quota_reset_from(quota_err, time.time())   # срок обязателен: без него флаг держался вечно
        send_heartbeat("quota_exhausted", quota_err, reset_at=st["reset_at"])
        st["quota_exhausted"] = True
        st["quota_err"] = quota_err
        if not stand:
            body = (
                "Тема: Статус Арбитра Claude\n"
                f"К сожалению, лимит (квота) Claude сейчас исчерпан провайдером Anthropic ({quota_err}).\n\n"
                "Ваш вопрос сохранён и НЕ потерян. Пожалуйста, выберите в правом блоке Арбитра «gemini» (Antigravity) "
                "и отправьте вопрос ему — карточка Claude временно заблокирована до восстановления квоты."
            )
            for i in unreplied:
                if _reply("quota", i, body):
                    final_ok.add(i)
    else:
        st["quota_exhausted"] = False
        st["reset_at"] = 0.0
        if unreplied and not stand:
            if replied:                                            # часть писем получила ответ: остальным короткая отсылка
                for i in unreplied:
                    if _reply("pointer", i, "Тема: Ответ объединён\nОтвет на это письмо дан в сообщении выше (письма обработаны одним запуском)."):
                        final_ok.add(i)
            elif KP.on(ROOM, "noreply") and rc == 0 and not timed_out and res.get("subtype") == "success":
                # K «код: 0»: запуск прошёл, Арбитр сознательно не ответил. Записка («агентам не реагировать» и т. п.) —
                # тишина. Иначе не «Ошибка (код: 0)», а честная строка: письмо прочитано, ответа нет (письмо не теряется молча).
                bodies = {m["id"]: str(m.get("body") or "") for m in msgs}
                for i in unreplied:
                    # K: «записка» — письмо, на которое ответ не нужен; если Арбитр не ответил, карточку не шлём
                    if KP.on(ROOM, "note") and KP.is_note(bodies.get(i, "")):
                        log({"event": "no_reply_note", "id": i})
                        final_ok.add(i)
                        continue
                    log({"event": "no_reply_by_agent", "id": i})
                    if _reply("noreply", i, "Тема: Без ответа Арбитра\n\nАрбитр Claude прочитал письмо, но ответа не написал. "
                                             "Если ответ нужен, уточните вопрос или повторите его."):
                        final_ok.add(i)
            else:                                                  # раньше при rc != 0 / таймауте оператор не получал ничего
                body = (f"Тема: Ошибка обработки запроса Арбитром Claude\n\n"
                        f"Арбитр Claude не смог ответить на ваш запрос (код: {rc}{', таймаут 30 мин' if timed_out else ''}). "
                        f"Повторите вопрос или выберите другого Арбитра.")
                for i in unreplied:
                    if _reply("err", i, body):
                        final_ok.add(i)

    st["seen"] = (st["seen"] + ids)[-500:]
    cost_total = res.get("total_cost_usd")                         # K: claude -p --resume отдаёт накопленное по сессии
    cost_run = None
    if KP.on(ROOM, "cost_run") and isinstance(cost_total, (int, float)):
        prev = st.get("cost_total") if st.get("cost_session") == st.get("session") else 0.0
        cost_run = round(cost_total - (prev or 0.0), 4) if cost_total >= (prev or 0.0) else round(cost_total, 4)
        st["cost_total"], st["cost_session"] = cost_total, st.get("session")
    save_state(st)
    log({"ids": ids, "rc": rc, "latency_s": round(time.time() - t, 1),
         "result": res.get("subtype"), "turns": res.get("num_turns"), "cost_usd": cost_total, "cost_usd_run": cost_run,
         "session": st.get("session"), "quota_err": quota_err, "timed_out": timed_out,
         "replied_by_agent": sorted(replied), "replied_total": len(final_ok), "of": len(ids)})


def hb_tick(st):
    qs = get_quota_status()
    q_ex, q_detail, q_reset = DL.quota_view(os.path.join(ROOM, "work", "quota_status.json"), qs, "waker online")
    if q_ex:
        hb_state = "quota_exhausted"
        hb_detail = q_detail
        hb_reset = q_reset
    elif st.get("quota_exhausted") and not quota_flag_expired(st, time.time()):
        hb_state = "quota_exhausted"
        hb_detail = st.get("quota_err", "waker online")
        hb_reset = float(st.get("reset_at", 0.0) or 0.0)
    else:
        hb_state = "ready"
        hb_detail = q_detail if qs else "waker online"
        hb_reset = 0.0
    send_heartbeat(hb_state, hb_detail, reset_at=hb_reset)


def main():
    os.makedirs(os.path.join(ROOM, "work"), exist_ok=True); os.makedirs(os.path.join(ROOM, "journal"), exist_ok=True)
    if not ONCE:
        DL.single_instance(os.path.join(ROOM, "journal", "waker.lock"))
    st = load_state()
    st.setdefault("seen", [])
    st.setdefault("retry", {})
    retry = DL.Retry(st["retry"])
    if not ONCE:
        DL.start_thread(lambda: hb_tick(st), 45.0, "heartbeat")   # heartbeat идёт и пока claude работает (до 30 мин)
    else:
        hb_tick(st)
    while not os.path.exists(os.path.join(ROOM, "WAKE_STOP")):
        DL.beacon(ROOM)
        try:
            MR.worker_tick(ROOM, "claude", mr_runner)
            pend, _mr_held = MR.intercept(ROOM, "claude", KP.drop_notes(ROOM, new_messages(set(st["seen"])), MR_ACC, ack, log), MR_ACC, MR_CTX)
            n0 = len(retry.d)
            retry.purge({m["id"] for m in pend})
            if len(retry.d) != n0:
                save_state(st)
            now = time.time()
            ready = [m for m in pend if retry.due(m["id"], now)]
            if ready:
                time.sleep(0 if ONCE else 10)                      # склейка пачки писем оператора в одно пробуждение
                fresh = {m["id"]: m for m in MR.intercept(ROOM, "claude", KP.drop_notes(ROOM, new_messages(set(st["seen"])), MR_ACC, ack, log), MR_ACC, MR_CTX)[0]}
                ready = [fresh[m["id"]] for m in ready if m["id"] in fresh]
                if ready:
                    DL.beacon(ROOM, 1800 + 300)               # claude -p до 30 мин + ответы
                    wake(ready, st, retry)
            mr_msgs = MR.tick(ROOM, "claude", MR_CTX)
            if mr_msgs:
                DL.beacon(ROOM, 1800 + 300)
                wake(mr_msgs, st, retry)
                MR.note_returned(ROOM, [m["id"] for m in mr_msgs])
            late = retry.overdue()
            if late:
                DL.beacon(ROOM, 120)
                ok, info = DL.send_notice(ROOM, ACK_PY, RT)
                log({"event": "notice_unavailable", "ids": late, "ok": ok, "info": "" if ok else info[:120]})
                if ok:
                    retry.mark_notified(late)
                    save_state(st)
        except Exception as exc:
            log({"event": "error", "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
            time.sleep(5)
        if ONCE:
            break
        time.sleep(3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
