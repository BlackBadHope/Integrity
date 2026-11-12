#!/usr/bin/env python3
"""Antigravity (Gemini) adapter for the rule guard: same rule core, Antigravity hook contract.

Antigravity PreToolUse input: {"toolCall": {"name": "run_command", "args": {"CommandLine": "..."}}, ...}
Antigravity treats an EMPTY reply as a silent deny, so this adapter ALWAYS prints an explicit
{"decision": "allow"} (warn-only), on any error and after a 0.9 s watchdog too.
"""
import json
import os
import sys
import threading

ALLOW = {"decision": "allow"}


def _emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.stdout.flush()


def main() -> int:
    done = {"v": False}

    def watchdog():
        if not done["v"]:
            _emit(ALLOW)
            os._exit(0)

    t = threading.Timer(0.9, watchdog)
    t.daemon = True
    t.start()
    out = ALLOW
    try:
        from integrity_guards import rule_guard as g
        payload = json.load(sys.stdin)
        call = payload.get("toolCall") or {}
        name, args = call.get("name", ""), call.get("args") or {}
        if name in ("run_command", "run_terminal_command", "shell"):
            probs = g.evaluate({"tool_name": "Bash", "tool_input": {"command": str(args.get("CommandLine") or args.get("command") or "")}})
        elif name in ("view_file", "read_file", "grep_search", "find_by_name"):
            path = str(args.get("AbsolutePath") or args.get("SearchPath") or args.get("path") or "")
            probs = g.evaluate({"tool_name": "Read", "tool_input": {"file_path": path}})
        else:
            probs = g.evaluate({"tool_name": name, "tool_input": args})
        if probs:
            out = {"decision": "allow", "reason": "RULE GUARD (warn): " + " | ".join(probs)}
    except Exception:
        out = ALLOW
    done["v"] = True
    _emit(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
