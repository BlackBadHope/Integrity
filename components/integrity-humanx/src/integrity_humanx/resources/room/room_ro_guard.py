"""room_ro_guard — хук PreToolUse Арбитра комнаты HumanX (Claude) и всех его субагентов.

«Только чтение» держится механизмом, а не персоной: запрещено всё, кроме белого списка.
  * Read / Glob / Grep — только внутри каталога комнаты (секреты, ~/.ssh, прод-конфиги клиентской машины недоступны).
  * Write / Edit — только в <комната>/work/ (заметки, черновики, JSON-аргументы для room_tool).
  * Bash — ровно `python -I room_tool.py <op> [work/<файл>.json]`: без пробелов в аргументах, без ; | & $ ` > < и т.п.
    room_tool.py — единственный выход наружу: шина (как room-<operator_id>-claude, room_acl) и RO-шлюзы (SQL, свичи, копия Integrity).
  * Субагенты (Agent/Task), TodoWrite, ToolSearch — можно: они сами под этим же хуком.
  * Integrity — только admission и close (их требует общий шлюз Integrity), без append (ПДн и запись).
  * Всё остальное (PowerShell, Web*, SendMessage, сессии, браузер, computer-use, прочие MCP, новые инструменты) — deny.
Любое изменение — эскалация администратору письмом в шину (room_tool send → owner), не действие.
Каждое решение пишется в <комната>/journal/guard.jsonl (хеш-цепочка).
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import hashlib, json, os, re, sys, time

ROOM = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(ROOM, "work")
BASH_OK = re.compile(r"python -I room_tool\.py (send|reply|poll|get|ack|cards|arbiter|sql|switch|integrity|escalate|host|history|topics_get|topics_put)"
                     r"( work/[A-Za-z0-9_.-]{1,80}\.json)?\Z")
FREE = {"TodoWrite", "ToolSearch", "Agent", "Task"}
INTEGRITY_OK = {"mcp__" + _integrity_value("integrity_mcp_server") + "__integrity_context_admission_current_turn",
                "mcp__" + _integrity_value("integrity_mcp_server") + "__integrity_turn_memory_close"}


def inside(path, base):
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    p = path
    if re.match(r"^/[a-zA-Z]/", p):                      # git-bash /c/... → C:/...
        p = p[1] + ":" + p[2:]
    if not os.path.isabs(p):
        p = os.path.join(ROOM, p)
    rp = os.path.realpath(p)
    return rp == base or rp.startswith(base + os.sep)


def decide(tool, ti):
    if tool in FREE:
        return True, "subagent/meta tool (runs under this same hook)"
    if tool in INTEGRITY_OK:
        return True, "integrity gate (admission/close only)"
    if tool in ("Read", "NotebookRead"):
        return inside(ti.get("file_path") or ti.get("notebook_path"), ROOM), "read only inside the room"
    if tool in ("Glob", "Grep", "LS"):
        ok = inside(ti.get("path") or ROOM, ROOM)
        pat = str(ti.get("pattern") or "") + str(ti.get("glob") or "")
        if ".." in pat or re.search(r"^[a-zA-Z]:|^/|^~", pat):
            ok = False
        return ok, "search only inside the room"
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return inside(ti.get("file_path") or ti.get("notebook_path"), WORK), "write only into room/work"
    if tool == "Bash":
        cmd = ti.get("command")
        ok = isinstance(cmd, str) and bool(BASH_OK.fullmatch(cmd)) and not ti.get("run_in_background")
        return ok, "shell: only `python -I room_tool.py <op> [work/<file>.json]`"
    return False, "tool not allowed for the room Arbiter (read-only by mechanism; escalate to the owner via the bus)"


def journal(rec):
    d = os.path.join(ROOM, "journal"); os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "guard.jsonl")
    prev = "0" * 64
    try:
        with open(f, "rb") as h:
            last = h.read().splitlines()[-1]
            prev = json.loads(last)["hash"]
    except (OSError, IndexError, ValueError, KeyError):
        pass
    rec = {"ts": int(time.time()), "prev": prev, **rec}
    rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    with open(f, "a", encoding="utf-8") as h:
        h.write(json.dumps(rec, ensure_ascii=False) + "\n")


def main():
    try:
        ev = json.loads(sys.stdin.read() or "{}")
        tool, ti = ev.get("tool_name", ""), ev.get("tool_input") or {}
        ok, why = decide(tool, ti if isinstance(ti, dict) else {})
    except Exception as exc:                               # ошибка разбора — запрет, не пропуск
        tool, ti, ok, why = "?", {}, False, f"guard error: {type(exc).__name__}"
    try:
        journal({"tool": tool, "decision": "allow" if ok else "deny", "why": why,
                 "input_sha256": hashlib.sha256(json.dumps(ti, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest(),
                 "cmd": (ti.get("command") or "")[:200] if isinstance(ti, dict) else ""})
    except Exception:
        pass
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": "allow" if ok else "deny",
                                             "permissionDecisionReason": f"room read-only guard: {why}"}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
