"""vendor_room_guard — RO-сторож Арбитра комнаты HumanX для Codex и Antigravity (Gemini). Хук PreToolUse.

Хуки этих вендоров глобальные, поэтому сторож включается ТОЛЬКО для бесед комнаты. Остальным сессиям он отвечает тем же,
что они получают сейчас (Codex — пусто; Antigravity — {"decision":"allow"} для всех инструментов, включая MCP).

Кто считается комнатой:
  * codex: cwd вызова внутри каталога комнаты room-codex (запуск `codex exec -s read-only -C <комната>`);
  * antigravity: conversationId есть в <комната>/conversations.txt ИЛИ первое сообщение беседы (транскрипт) содержит
    метку `HUMANX-ROOM-v1:<nonce>`, где nonce выдан будильником комнаты (<комната>/nonces/<nonce>).
Правила для комнаты те же, что у Claude (room_ro_guard): deny по умолчанию;
  * shell — ровно `python -I room_tool.py <op> [work/<файл>.json]`, рабочий каталог — комната;
  * запись файлов — только <комната>/work; чтение — только в комнате;
  * вложенные агенты, web, сообщения, задачи, MCP (кроме admission/close Integrity) — deny.
Запуск: python -I vendor_room_guard.py --vendor codex|antigravity --room <каталог комнаты>
"""
from integrity_humanx.configuration import value as _integrity_value, operator_id as _hx_operator_id, operator_address as _hx_operator, room_address as _hx_room, room_prefix as _hx_room_prefix  # noqa: E402,F401
import hashlib, json, os, re, shlex, sys, time

A = sys.argv
VENDOR = A[A.index("--vendor") + 1] if "--vendor" in A else "codex"
ROOM = os.path.realpath(A[A.index("--room") + 1]) if "--room" in A else ""
WORK = os.path.join(ROOM, "work")
OPS = r"(send|reply|poll|get|ack|cards|arbiter|sql|switch|integrity|escalate|subchat|follow|report|host|heartbeat|history|topics_get|topics_put)"
CMD_OK = re.compile(r"python -I room_tool\.py " + OPS + r"( work/[A-Za-z0-9_.-]{1,80}\.json)?\Z")
SHELLS = {"bash", "sh", "zsh", "pwsh", "powershell", "powershell.exe", "pwsh.exe", "cmd", "cmd.exe", "bash.exe"}
MARK = re.compile(r"HUMANX-ROOM-v1:([0-9a-f]{32})")
INTEGRITY_OK = ("integrity_context_admission_current_turn", "integrity_turn_memory_close")


def norm(path):
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    p = path.strip()
    if re.match(r"^/[a-zA-Z]/", p):
        p = p[1] + ":" + p[2:]
    if p.startswith("file:///"):
        p = p[8:]
    if not os.path.isabs(p):
        p = os.path.join(ROOM, p)
    return os.path.realpath(p)


def inside(path, base):
    rp = norm(path)
    if not rp:
        return False
    rp, b = os.path.normcase(rp), os.path.normcase(base)        # Windows: D:\ и d:\ — один путь
    return rp == b or rp.startswith(b + os.sep)


def same(path, base):
    rp = norm(path)
    return bool(rp) and os.path.normcase(rp) == os.path.normcase(base)


SYS_STEPS_ROOT = _integrity_value("antigravity_steps_root")


def is_own_step_output(path_str, conv_id):
    if not conv_id:
        return False
    rp = norm(path_str)
    if not rp:
        return False
    expected_base = os.path.join(SYS_STEPS_ROOT, conv_id, ".system_generated", "steps")
    expected_base_norm = os.path.normcase(os.path.realpath(expected_base))
    rp_norm = os.path.normcase(rp)
    if not (rp_norm == expected_base_norm or rp_norm.startswith(expected_base_norm + os.sep)):
        return False
    return os.path.basename(rp_norm) == "output.txt"



ROOM_PY = _integrity_value("python")
ABS_TAIL = re.compile(OPS + r"( work[\\/][A-Za-z0-9_.-]{1,80}\.json)?\Z")


def abs_room_cmd(cmd):
    """Ровно: <ROOM_PY> -I <ROOM>\\room_tool.py <op> [work\\x.json]; слэши любые, регистр не важен, без лишних символов."""
    if not isinstance(cmd, str) or re.search(r"[;&|`$<>\r\n\"'(){}]", cmd):
        return False
    c = cmd.strip()
    head = (ROOM_PY + " -I " + os.path.join(ROOM, "room_tool.py") + " ").replace("/", "\\").lower()
    if not c.replace("/", "\\").lower().startswith(head):
        return False
    return bool(ABS_TAIL.fullmatch(c[len(head):]))


def shell_text(cmd):
    """Codex даёт команду списком argv; оболочку (bash -lc / powershell -Command) разворачиваем до строки."""
    if isinstance(cmd, list):
        parts = [str(x) for x in cmd]
        if parts and os.path.basename(parts[0]).lower() in SHELLS and len(parts) >= 3 and parts[-2].lower() in ("-c", "-lc", "-command", "/c"):
            return parts[-1]
        return " ".join(parts)
    return cmd if isinstance(cmd, str) else None


def journal(rec):
    d = os.path.join(ROOM, "journal"); os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "guard.jsonl"); prev = "0" * 64
    try:
        with open(f, "rb") as h:
            prev = json.loads(h.read().splitlines()[-1])["hash"]
    except (OSError, IndexError, ValueError, KeyError):
        pass
    rec = {"ts": int(time.time()), "vendor": VENDOR, "prev": prev, **rec}
    rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    with open(f, "a", encoding="utf-8") as h:
        h.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------- кто комната ----------

def is_room_antigravity(p):
    conv = str(p.get("conversationId") or "")
    try:
        if conv and conv in open(os.path.join(ROOM, "conversations.txt"), encoding="utf-8").read().split():
            return True
    except OSError:
        pass
    tp = p.get("transcriptPath")
    if isinstance(tp, str) and tp:
        try:
            with open(tp, "rb") as h:
                head = h.read(256 * 1024)
            for line in head.splitlines():
                r = json.loads(line)
                if r.get("type") == "USER_INPUT":
                    m = MARK.search(str(r.get("content") or ""))
                    return bool(m and os.path.exists(os.path.join(ROOM, "nonces", m.group(1))))
        except (OSError, ValueError):
            pass
    return False


def is_room_codex(p):
    return inside(p.get("cwd") or "", ROOM)


# ---------- правила комнаты ----------

def decide_codex(p):
    tool, ti = str(p.get("tool_name") or ""), p.get("tool_input") or {}
    if not isinstance(ti, dict):
        return False, "bad tool_input"
    if tool in ("update_plan",):
        return True, "plan only"
    if tool in ("shell", "exec_command", "local_shell", "Bash", "container.exec", "unified_exec"):
        cmd = shell_text(ti.get("command") if "command" in ti else ti.get("cmd"))
        wd = ti.get("workdir") or ti.get("cwd") or p.get("cwd")
        ok = isinstance(cmd, str) and bool(CMD_OK.fullmatch(cmd.strip())) and same(wd or "", ROOM)
        return ok, "shell: only `python -I room_tool.py <op> [work/<file>.json]` in the room"
    if tool == "apply_patch":
        text = ti.get("input") or ti.get("patch") or ti.get("command") or ""
        if isinstance(text, list):
            text = "\n".join(map(str, text))
        paths = re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", str(text), re.M)
        flat = [a or b for a, b in paths]
        ok = bool(flat) and all(inside(x.strip(), WORK) for x in flat)
        return ok, "file edits only inside room/work"
    if tool.startswith("mcp__") and tool.endswith(INTEGRITY_OK):
        return True, "integrity admission/close"
    return False, "tool not allowed for the room Arbiter (read-only by mechanism; escalate to the owner via the bus)"


READ_TOOLS = {"view_file", "read_file", "view_file_outline", "view_code_item", "list_dir", "grep_search", "find_by_name"}
WRITE_TOOLS = {"write_to_file", "write_file", "replace_file_content", "multi_replace_file_content", "edit_file"}


def path_args(args):
    out = []
    for k, v in (args or {}).items():
        if isinstance(v, str) and re.search(r"(path|file|dir|directory|uri)$", k, re.I):
            out.append(v)
    return out


def decide_antigravity(p):
    tc = p.get("toolCall") or {}
    name, args = str(tc.get("name") or ""), tc.get("args") or {}
    if not isinstance(args, dict):
        return False, "bad args"
    if name in ("run_command", "bash", "command"):
        # Antigravity не передаёт Cwd в хук (проверено: только CommandLine, WaitMsBeforeAsync, toolSummary),
        # поэтому разрешена только полностью абсолютная форма, не зависящая от каталога запуска:
        #   <python.exe по абсолютному пути> -I <комната>\room_tool.py <op> [work\<файл>.json]
        cmd = shell_text(args.get("CommandLine") or args.get("command") or args.get("cmd"))
        return abs_room_cmd(cmd), f"shell: only `{ROOM_PY} -I {os.path.join(ROOM, 'room_tool.py')} <op> [work\\<file>.json]`"
    if name in READ_TOOLS:
        ps = path_args(args)
        conv = p.get("conversationId") or ""
        return bool(ps) and all(inside(x, ROOM) or is_own_step_output(x, conv) for x in ps), "read only inside the room or own step output"
    if name in WRITE_TOOLS:
        ps = path_args(args)
        return bool(ps) and all(inside(x, WORK) for x in ps), "write only into room/work"
    if name == "call_mcp_tool":
        blob = json.dumps(args, ensure_ascii=False)
        return any(t in blob for t in INTEGRITY_OK) and "append" not in blob, "integrity admission/close only"
    return False, "tool not allowed for the room Arbiter (subagents, web, messages, tasks are off; escalate via the bus)"


def neutral_antigravity(p):
    return json.dumps({"decision": "allow"})


def main():
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    try:
        p = json.loads(raw or "{}")
        if not isinstance(p, dict):
            raise ValueError("payload")
    except ValueError:
        p = None
    if VENDOR == "antigravity":
        if p is None or not ROOM or not is_room_antigravity(p):
            print(neutral_antigravity(p or {}))
            return 0
        try:
            ok, why = decide_antigravity(p)
        except Exception as exc:
            ok, why = False, f"guard error: {type(exc).__name__}"
        tc = p.get("toolCall") or {}
        journal({"tool": tc.get("name"), "conv": p.get("conversationId"), "decision": "allow" if ok else "deny", "why": why,
                 "arg_keys": sorted((tc.get("args") or {}).keys()) if isinstance(tc.get("args"), dict) else None,
                 "cmd": str((tc.get("args") or {}).get("CommandLine") or "")[:200]})
        print(json.dumps({"decision": "allow"} if ok else {"decision": "deny", "reason": f"room read-only guard: {why}"}))
        return 0
    # codex
    if os.path.exists(os.path.join(ROOM, "DEBUG")):
        try:
            with open(os.path.join(ROOM, "..", "logs", "codex-hook-debug.log"), "a", encoding="utf-8") as h:
                h.write(json.dumps({"ts": int(time.time()), "keys": sorted((p or {}).keys()), "tool": (p or {}).get("tool_name"),
                                    "cwd": (p or {}).get("cwd"), "room": is_room_codex(p) if p else None}) + "\n")
        except OSError:
            pass
    if p is None or not ROOM or not is_room_codex(p):
        return 0
    try:
        ok, why = decide_codex(p)
    except Exception as exc:
        ok, why = False, f"guard error: {type(exc).__name__}"
    ti = p.get("tool_input") or {}
    journal({"tool": p.get("tool_name"), "decision": "allow" if ok else "deny", "why": why,
             "cmd": str(shell_text(ti.get("command")) if isinstance(ti, dict) else "")[:200]})
    if ok:
        return 0
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": f"room read-only guard: {why}"},
                      "decision": "block", "reason": f"room read-only guard: {why}"}))
    sys.stderr.write(f"room read-only guard: {why}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
