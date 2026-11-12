#!/usr/bin/env python3
"""Uroboros repeat hook (PreToolUse/PostToolUse, shell tools). Advisory only; it never blocks or runs anything.

Notices the same remote chain (ssh/plink to the same host with the same command shape) the 2nd time in one
session and tells the model, without blocking anything:
  * if a compiled route already covers it: «run <run_prefix> <route-id> instead (one call)»;
  * otherwise: «this is a repeat; draft a route» + a ready `uroboros_routes draft` skeleton, and the candidate is
    appended to <state>/candidates.jsonl so it can be compiled later.
Write-shaped chains (restart/install/apply/mv/cp/sed -i/...) are only reported as write candidates: plan-only,
operator GO required; the hook never runs anything.

Fingerprint = target host + the ordered command words of the remote part (systemctl/journalctl/grep/...) +
stable nouns (unit names, /var/log|/etc|/opt paths, show-commands), with IPs, numbers, times and hashes masked.
State: one small JSON per session under INTEGRITY_UROBOROS_STATE (default <guards state root>/uroboros-repeat).

Host names come from the ``uroboros`` section of the guards configuration (INTEGRITY_GUARDS_CONFIG):
  hosts              {"<address or name substring>": "<canonical host>"}
  aliases            ["<ssh alias matched as a word>", ...]
  host_patterns      {"<canonical host>": "<regex>"}           e.g. a switch address range
  host_route_markers {"<canonical host>": ["<text in a route's argv that marks that host>"]}
  ignore_words       ["<login names and other words that are not part of the command shape>"]
  run_prefix         how a compiled route is run (default: integrity-guards uroboros run)
  pin_guard          optional advisory for writes to pinned files on one host (see README)
An unconfigured hook still fingerprints chains, with "?" as the host.

Usage as a hook: stdin = hook JSON; stdout = {"hookSpecificOutput": {...additionalContext}} or nothing.
Stand mode:     integrity-guards uroboros-repeat-hook replay <recorded-calls.json>
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from integrity_guards import config as _config

_CFG = _config.section("uroboros")


def _default_state() -> str:
    return str(_config.state_root() / "uroboros-repeat")


def _str_map(value) -> dict[str, str]:
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


STATE = Path(os.environ.get("INTEGRITY_UROBOROS_STATE") or _CFG.get("state_dir") or _default_state())
_COMPILED = os.environ.get("INTEGRITY_COMPILED_ROUTES") or _CFG.get("compiled_routes")
COMPILED = Path(_COMPILED) if _COMPILED else None
REMOTE = re.compile(r"\b(?:ssh(?:\.exe)?|plink(?:\.exe)?)\b")
WRITE = re.compile(r"\b(install|mv|cp|rm|tee|restart|reload|start|stop|enable|disable|apply|--apply|chmod|chown|"
                   r"patch|INSERT|UPDATE|DELETE|DROP|scp|config\s+\w+|save)\b|sed\s+-i|>\s*/", re.I)
HOSTS = _str_map(_CFG.get("hosts"))
ALIASES = tuple(str(a) for a in (_CFG.get("aliases") or []) if str(a).strip())
HOST_PATTERNS = {name: re.compile(p) for name, p in _str_map(_CFG.get("host_patterns")).items()}
HOST_ROUTE_MARKERS = {str(k): [str(x) for x in v] for k, v in (_CFG.get("host_route_markers") or {}).items()
                      if isinstance(v, list)}
IGNORE_WORDS = {str(w).lower() for w in (_CFG.get("ignore_words") or [])}
WORD = re.compile(r"(?:^|[;&|(]\s*|\$\(\s*|sudo\s+-n\s+(?:-u\s+\S+\s+)?)([a-z][a-z0-9_.-]{1,30})")
NOUN = re.compile(r"[\w@-]+\.(?:service|timer)\b|/(?:var/log|etc|opt|var/lib)/[\w.-]+(?:/[\w.-]+){0,3}|"
                  r"(?<!systemctl )\bshow [a-z_]+(?: [a-z_]+)?|\b[\w-]+\.py\b")
UNIT = re.compile(r"(?:journalctl\s+(?:-\w+\s+)*-u\s+|systemctl\s+(?:show|status|is-active|cat|list-timers)\s+(?:--\S+\s+)*)"
                  r"([a-z][\w@.-]{2,60})")
SHELL_WORDS = {"for", "do", "done", "then", "else", "fi", "if", "while", "set", "export", "sleep", "date", "id",
               "true", "false", "test", "read", "local", "return", "exit", "print", "open", "len", "type"}


def nouns_of(text: str) -> list[str]:
    found = set(NOUN.findall(text))
    for unit in UNIT.findall(text):
        found.add(unit if unit.endswith((".service", ".timer")) else unit + ".service")
    # a path prefix is enough to name the thing; drop numbers/hashes inside it
    found = {n for n in found if "ssh-config" not in n}  # the transport profile is not the thing being checked
    return sorted({re.sub(r"[0-9a-f]{12,}|(?<![\w-])\d+(?![\w-])", "#", n) for n in found})[:12]


def host_of(cmd: str) -> str:
    for addr, name in HOSTS.items():
        if addr in cmd:
            return name
    for alias in ALIASES:
        if re.search(rf"\b{re.escape(alias)}\b", cmd):
            return alias
    for name, rx in HOST_PATTERNS.items():
        if rx.search(cmd):
            return name
    return "?"


def remote_part(cmd: str) -> str:
    m = REMOTE.search(cmd)
    return cmd[m.end():] if m else ""


def fingerprint(cmd: str) -> tuple[str, str, list[str]] | None:
    if not REMOTE.search(cmd):
        return None
    host = host_of(cmd)
    body = remote_part(cmd)
    body = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{12,}\b|\b\d+\b|\d\d:\d\d(?::\d\d)?", "#", body)
    skip = {"ssh", "o", "f", "j", "batchmode", "connecttimeout", "bash", "sh", "echo", "cd", "head", "tail",
            "cut", "tr", "sed", "awk", "wc", "sort", "uniq", "printf", "timeout", "python", "python3", "cat", "sudo",
            "grep", "ls"} | SHELL_WORDS | IGNORE_WORDS
    nouns = nouns_of(body)
    if nouns:  # the same things looked at on the same host = the same check, whatever the shell glue around it
        shape = host + "|N|" + " ".join(nouns)
        return hashlib.sha256(shape.encode()).hexdigest()[:16], host, nouns
    words = sorted({w for w in WORD.findall(body) if w.lower() not in skip})[:8]
    if len(words) < 2:
        return None
    shape = host + "|W|" + " ".join(words)
    return hashlib.sha256(shape.encode()).hexdigest()[:16], host, words


def compiled_match(host: str, tokens: list[str]) -> str | None:
    best, score = None, 0
    if COMPILED is None:
        return None
    try:
        files = list(COMPILED.glob("*.json"))
    except OSError:
        return None
    for f in files:
        try:
            route = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if route.get("safety") != "read":
            continue
        text = " ".join(" ".join(map(str, s.get("argv", []))) for s in route.get("steps", []))
        same_host = (any(addr in text for addr, n in HOSTS.items() if n == host)
                     or re.search(rf"\b{re.escape(host)}\b", text)
                     or any(marker in text for marker in HOST_ROUTE_MARKERS.get(host, [])))
        if not same_host:
            continue
        # the route covers this call when most of what the call looks at is also named by the route
        names = [t[:-len(".service")] if t.endswith(".service") else t for t in tokens
                 if (t.startswith(("/", "show ")) or "." in t or "-" in t)
                 # config/credential sources are inputs of many checks, not the thing being checked
                 and not re.search(r"^/etc/default/|\.env$|cred|secret|\.ssh/", t)]
        hits = sum(1 for n in names if n in text)
        route_objects = max(1, len(nouns_of(text)))
        # both ways: the call is mostly covered, and it touches a real part of the route (not one passing input)
        if names and hits > score and hits / len(names) >= 0.5 and hits / route_objects >= 0.3:
            best, score = route["route_id"], hits
    return best


def observe(session: str, cmd: str, now: float | None = None) -> dict | None:
    fp = fingerprint(cmd)
    if fp is None:
        return None
    key, host, tokens = fp
    STATE.mkdir(parents=True, exist_ok=True)
    path = STATE / (re.sub(r"[^A-Za-z0-9_.-]", "_", session or "unknown")[:80] + ".json")
    try:
        seen = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        seen = {}
    entry = seen.setdefault(key, {"n": 0, "host": host, "tokens": tokens[:8]})
    entry["n"] += 1
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(seen), encoding="utf-8")
    os.replace(tmp, path)
    if entry["n"] != 2:
        return None
    write = bool(WRITE.search(remote_part(cmd)))
    route = None if write else compiled_match(host, tokens)
    advice = {"key": key, "host": host, "write": write, "route": route, "tokens": tokens[:8]}
    if route is None:
        with open(STATE / "candidates.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": now or time.time(), "session": session, **advice,
                                     "sample": cmd[:600]}, ensure_ascii=False) + "\n")
    return advice


RUN_PREFIX = os.environ.get("UROBOROS_RUN_PREFIX") or str(_CFG.get("run_prefix") or "integrity-guards uroboros run")
ROUTE_RUN = re.compile(r"(?:uroboros-run\.sh|uroboros\s+run)\s+([a-z0-9][a-z0-9-]{1,60})")
VENDOR = "claude"   # set from --vendor; one module, one catalog, per-vendor protocol adapters below


def message(advice: dict) -> str:
    if advice["route"]:
        return (f"UROBOROS REPEAT: this {advice['host']} chain ran twice in this session and a compiled read route "
                f"covers it. Next time run: {RUN_PREFIX} {advice['route']} "
                "(one call; not authority).")
    if advice["write"]:
        return (f"UROBOROS REPEAT (write-shaped, {advice['host']}): recorded as a write candidate only; a write route "
                "is plan-only and needs an operator GO. Nothing was run by this hook.")
    return (f"UROBOROS REPEAT: same {advice['host']} chain twice in this session ({' '.join(advice['tokens'][:5])}). "
            "Record it: python -m integrity_guardian.uroboros_routes draft --route-id <id> --title ... "
            "--trigger ... --trigger ... --step ... --safety read, then compile it into the compiled routes "
            "directory. Candidate saved for review.")


def log_metric(session: str, kind: str, host: str, route: str | None) -> None:
    """One line per remote call for the daily share metric (uroboros_route_share reads it)."""
    try:
        day = time.strftime("%Y-%m-%d")
        (STATE / "metrics").mkdir(parents=True, exist_ok=True)
        with open(STATE / "metrics" / f"{day}.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": round(time.time(), 3), "session": session[:40], "kind": kind,
                                     "host": host, "route": route, "vendor": VENDOR}) + "\n")
    except OSError:
        pass


SHELL_TOOLS = {"Bash", "PowerShell", "shell", "exec_command", "local_shell", "run_command", "bash", "command"}


def _command_text(value) -> str:
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value or "")


def parse_payload(payload: dict) -> tuple[str, str, str] | None:
    """(event, session, command) for Claude Code, Codex and Antigravity hook payloads; None if not a shell call."""
    tool_call = payload.get("toolCall")
    if isinstance(tool_call, dict):  # Antigravity: {"toolCall": {"name", "args": {"CommandLine"|"command"}}}
        if str(tool_call.get("name") or "") not in SHELL_TOOLS:
            return None
        args = tool_call.get("args") or {}
        cmd = _command_text(args.get("CommandLine") or args.get("command") or args.get("cmd"))
        session = str(payload.get("conversationId") or payload.get("conversation_id") or payload.get("session_id") or "")
        return "PreToolUse", session, cmd
    if str(payload.get("tool_name") or "") not in SHELL_TOOLS:
        return None
    tool_input = payload.get("tool_input") or {}
    cmd = _command_text(tool_input.get("command") or tool_input.get("cmd"))
    return str(payload.get("hook_event_name") or "PostToolUse"), str(payload.get("session_id") or ""), cmd


AG_NEUTRAL = json.dumps({"decision": "allow"})  # Antigravity PreToolUse only


def render(event: str, text: str) -> dict:
    """Vendor output. Advisory only: this hook never denies.
    Antigravity treats a PreToolUse reply without "decision" as a silent DENY, so its neutral reply is
    "allow"; a deny from another gate still wins. The advisory text is not delivered to Antigravity."""
    if VENDOR == "antigravity":
        return {"decision": "allow"}
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}


_PIN = _CFG.get("pin_guard") if isinstance(_CFG.get("pin_guard"), dict) else {}
_PINS_FILE = os.environ.get("INTEGRITY_UROBOROS_PINS") or _PIN.get("pins_file")
PINS = Path(_PINS_FILE) if _PINS_FILE else None
PIN_HOST = str(_PIN.get("host") or "")
PIN_PREFIXES = tuple(str(p) for p in (_PIN.get("prefixes") or []))   # whole trees that are pinned
PIN_LABEL = str(_PIN.get("label") or "pinned files")
LOCAL_INPUT = re.compile(r"(?:<|\bscp\s+(?:-\S+\s+)*)\s*['\"]?([^\s'\"|;&<>]+\.(?:sh|py|nft|conf|json|service|timer))")
CWD = ""  # payload cwd, set in hook()


def _pins() -> tuple[str, list[str]]:
    if PINS is None:
        return "", []
    try:
        data = json.loads(PINS.read_text(encoding="utf-8"))
        return str(data.get("authority", ""))[:12], [str(p) for p in data.get("paths", [])]
    except (OSError, ValueError, AttributeError):
        return "", []


def _local_inputs(cmd: str) -> str:
    """Text of local scripts fed to the remote side (`bash -s < apply.sh`, `scp x.sh host:`), max 256 KiB each."""
    texts = []
    for name in LOCAL_INPUT.findall(cmd)[:4]:
        for cand in (Path(name), Path(CWD or ".") / name):
            try:
                if cand.is_file():
                    texts.append(cand.read_text(encoding="utf-8", errors="replace")[:262144])
                    break
            except OSError:
                continue
    return "\n".join(texts)


def pin_guard(cmd: str) -> str | None:
    """A write on the configured host that touches a file pinned by a boot/release authority -> advisory."""
    if not PIN_HOST or PINS is None or host_of(cmd) != PIN_HOST:
        return None
    body = remote_part(cmd) + "\n" + _local_inputs(cmd)
    authority, paths = _pins()
    # pinned names may contain write words ("x-apply-y.sh"): judge write-ness without them
    bare = body
    for p in sorted(paths, key=len, reverse=True):
        bare = bare.replace(p, " ").replace(Path(p).name, " ")
    if not WRITE.search(bare):
        return None
    hits = sorted({p for p in paths if not p.startswith(PIN_PREFIXES)
                   and (p in body or re.search(rf"(?<![\w.-]){re.escape(Path(p).name)}(?![\w.-])", body))})
    hits += [p + "*" for p in PIN_PREFIXES if p in body]
    if not hits:
        return None
    pre = str(_PIN.get("pre_check_route") or "")
    post = str(_PIN.get("post_check_route") or "")
    return (f"PIN GUARD ({PIN_HOST}): this write touches {', '.join(hits[:4])}"
            f"{' …' if len(hits) > 4 else ''} - {PIN_LABEL} pinned by authority {authority or '?'}. "
            "Changing a pinned file breaks the pin check of the service that relies on it; ship a re-pin "
            "in the same approved change."
            + (f" PRE: {RUN_PREFIX} {pre}." if pre else "")
            + (f" POST: {RUN_PREFIX} {post}." if post else "")
            + " Advisory; nothing is blocked.")


def pre_tool(session: str, cmd: str) -> str | None:
    """PreToolUse: pin guard + route hint before a remote chain runs; demand a route on the 2nd repeat."""
    guard = pin_guard(cmd)
    text = _pre_tool_routes(session, cmd)
    return "\n".join(t for t in (guard, text) if t) or None


def _pre_tool_routes(session: str, cmd: str) -> str | None:
    m = ROUTE_RUN.search(cmd)
    if m:
        log_metric(session, "route", "-", m.group(1))
        return None
    fp = fingerprint(cmd)
    if fp is None:
        return None
    key, host, tokens = fp
    write = bool(WRITE.search(remote_part(cmd)))
    route = None if write else compiled_match(host, tokens)
    advice = observe(session, cmd)  # counts; returns only on the 2nd occurrence
    log_metric(session, "raw", host, route)
    if route:
        return (f"UROBOROS: a verified read route covers this {host} chain. Run it instead, one call: "
                f"{RUN_PREFIX} {route} (not authority; this hook blocks nothing).")
    if advice and advice["write"]:
        return (f"UROBOROS: same write-shaped {host} chain a 2nd time in this session. Record it as a write route "
                "candidate (plan only, operator GO for --apply) in this turn; this hook blocks nothing.")
    if advice:
        return (f"UROBOROS REQUIRED: the same {host} chain ({' '.join(tokens[:5])}) runs a 2nd time "
                "in this session without a route. In THIS turn record it: python -m integrity_guardian.uroboros_routes "
                "draft --route-id <id> --title ... --trigger ... --trigger ... --step <exact command> --safety read, "
                f"compile it into the compiled routes directory and run it via {RUN_PREFIX}. "
                "Advisory: the command itself is not blocked.")
    return None


def hook() -> int:
    event = "PostToolUse"
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        parsed = parse_payload(payload) if isinstance(payload, dict) else None
        if not parsed:
            if VENDOR == "antigravity":
                print(AG_NEUTRAL)  # Antigravity: no decision = silent deny
            return 0
        event, session, cmd = parsed
        global CWD
        CWD = str(payload.get("cwd") or "") if isinstance(payload, dict) else ""
        if event == "PreToolUse":
            text = pre_tool(session, cmd)
        else:
            advice = observe(session, cmd)
            text = message(advice) if advice else None
    except Exception:  # noqa: BLE001 - a broken advisory hook must never stop the tool call
        if VENDOR == "antigravity":
            print(AG_NEUTRAL)
        return 0
    if text:
        print(json.dumps(render(event, text), ensure_ascii=False))
    elif VENDOR == "antigravity":
        print(AG_NEUTRAL)
    return 0


def replay(path: str) -> int:
    """Stand: replay recorded calls [{"session","ts","cmd"}] in time order (point INTEGRITY_UROBOROS_STATE at a
    temporary directory first)."""
    with open(path, encoding="utf-8") as handle:
        rows = json.load(handle)
    rows.sort(key=lambda r: (r["session"], r["ts"]))
    stats = {"calls": 0, "remote": 0, "advice": 0, "route": 0, "write": 0, "draft": 0, "by_route": {}, "ms": []}
    for r in rows:
        stats["calls"] += 1
        stats["remote"] += bool(REMOTE.search(r["cmd"]))
        t0 = time.perf_counter()
        advice = observe(r["session"], r["cmd"], now=0)
        stats["ms"].append((time.perf_counter() - t0) * 1000)
        if advice:
            stats["advice"] += 1
            kind = "route" if advice["route"] else ("write" if advice["write"] else "draft")
            stats[kind] += 1
            if advice["route"]:
                stats["by_route"][advice["route"]] = stats["by_route"].get(advice["route"], 0) + 1
    ms = sorted(stats.pop("ms")) or [0.0]
    stats["p50_ms"], stats["p95_ms"] = round(ms[len(ms) // 2], 2), round(ms[int(len(ms) * 0.95)], 2)
    print(json.dumps(stats, ensure_ascii=False))
    return 0


def main(argv: list[str]) -> int:
    """argv without the program name."""
    global VENDOR
    if len(argv) > 1 and argv[0] == "replay":
        return replay(argv[1])
    if "--vendor" in argv:
        i = argv.index("--vendor")
        candidate = argv[i + 1] if i + 1 < len(argv) else ""
        if candidate in {"claude", "codex", "antigravity", "grok", "bus"}:
            VENDOR = candidate
    return hook()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
