"""Optional Codex hook adapter for the cloud journal.

Codex documents command hooks (``hooks.json``) but not whether they run in
cloud tasks, where nobody can review and trust a non-managed hook. The journal
therefore never depends on hooks: the agent drives it from the repository
skill. When hooks do run they add ``observation`` records (tool name, input
digest, exit code; never the raw command or prompt), remind the agent at
session start, and block a Stop once while a turn is still open.

Every hook path exits 0 on internal errors so a broken journal can never break
the agent's tool calls.
"""
from __future__ import annotations

import hashlib
import json
import shlex
import sys
from pathlib import Path

from .journal import Journal, JournalError, canonical

HOOK_EVENTS = ("SessionStart", "UserPromptSubmit", "PostToolUse", "Stop")
MARKER = "integrity_cloud hook"
REMINDER = (
    "Integrity cloud journal: this environment records your work as a signed turn journal. "
    "Follow the repository skill `integrity-cloud-journal` (.agents/skills/integrity-cloud-journal/"
    "SKILL.md): `integrity-cloud open`, then `turn-open` / `event` / `turn-close` for each "
    "request, and `integrity-cloud seal --out integrity-journal/` before you finish."
)


def _sha(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _exit_code(response: object) -> int | None:
    if isinstance(response, dict):
        for key in ("exit_code", "exitCode", "returncode"):
            if isinstance(response.get(key), int):
                return response[key]
    return None


def handle(event: str, payload: dict, journal: Journal) -> tuple[str, int]:
    """Return (stdout, exit status) for one hook invocation."""
    state = journal.state()
    live = state["open"] and not state["sealed"]
    turn_ref = payload.get("turn_id")
    if event == "SessionStart":
        if live:
            journal.observation("hook:SessionStart", turn_ref=payload.get("source"))
            return "", 0
        return REMINDER, 0
    if not live:
        return (REMINDER, 0) if event == "UserPromptSubmit" else ("", 0)
    if event == "UserPromptSubmit":
        if state["open_turn"] is None:
            prompt_digest = _sha(payload.get("prompt", ""))
            journal.turn_open(f"user prompt {prompt_digest} (opened by hook)", implicit=True)
        journal.observation("hook:UserPromptSubmit", turn_ref=turn_ref)
        return "", 0
    if event == "PostToolUse":
        journal.observation("hook:PostToolUse", tool_name=payload.get("tool_name"),
                            input_sha256=_sha(payload.get("tool_input")),
                            exit_code=_exit_code(payload.get("tool_response")),
                            turn_ref=turn_ref)
        return "", 0
    if event == "Stop":
        journal.observation("hook:Stop", turn_ref=turn_ref)
        if state["open_turn"] is not None and not payload.get("stop_hook_active"):
            reason = (f"Integrity turn {state['open_turn']} is still open. Record what you did "
                      "with `integrity-cloud event`, then `integrity-cloud turn-close`.")
            return json.dumps({"decision": "block", "reason": reason}), 0
        return "", 0
    return "", 0


def run_hook(event: str, stdin: str, journal: Journal | None = None) -> tuple[str, int]:
    try:
        payload = json.loads(stdin) if stdin.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
        return handle(event, payload, journal or Journal())
    except (JournalError, OSError, ValueError) as error:
        print(f"integrity-cloud hook ignored: {error}", file=sys.stderr)
        return "", 0


def hooks_config(python: str | None = None) -> dict:
    python = python or sys.executable
    groups = {}
    for event in HOOK_EVENTS:
        command = f"{shlex.quote(python)} -m {MARKER} {event}"
        handler = {"type": "command", "command": command, "timeout": 20}
        group = {"hooks": [handler]}
        if event == "PostToolUse":
            group["matcher"] = "*"
        groups[event] = [group]
    return {"description": "Integrity cloud journal observations (integrity-cloud)",
            "hooks": groups}


def install(codex_home: Path, python: str | None = None) -> dict:
    """Merge our handlers into <codex_home>/hooks.json without touching others."""
    path = Path(codex_home) / "hooks.json"
    current = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    if not isinstance(current, dict):
        raise JournalError(f"{path} is not a JSON object")
    hooks = current.setdefault("hooks", {})
    ours = hooks_config(python)["hooks"]
    added = []
    for event, groups in ours.items():
        existing = hooks.setdefault(event, [])
        if not any(MARKER in h.get("command", "") for g in existing for h in g.get("hooks", [])):
            existing.extend(groups)
            added.append(event)
    current.setdefault("description", hooks_config(python)["description"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    return {"hooks_json": str(path), "added": added}
