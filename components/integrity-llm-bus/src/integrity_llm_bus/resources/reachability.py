# SPDX-License-Identifier: BUSL-1.1
"""P0-2: tell a sender whether a recipient is reachable right now. Read-only, no network sends.

Reasons (first match wins): unregistered, relay_stopped, no_consumer, host_link_down.
A message is still stored when deliverable is false; the sender just knows it will wait.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import agent_registry
import autoreg

HOST_LINK_PORT = None  # read from configuration when first needed
PUSH_HARNESSES = ("codex", "grok")  # need the relay; claude/gemini pull via hooks


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def relay_state(state_dir: Path) -> dict:
    if (state_dir / "RELAY_STOP").exists():
        return {"running": False, "why": "RELAY_STOP"}
    try:
        pid = int((state_dir / "relay.pid").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return {"running": False, "why": "no_pid"}
    if not _pid_alive(pid):
        return {"running": False, "why": "pid_dead"}
    try:
        targets = json.loads((state_dir / "relay-targets.json").read_text(encoding="utf-8")).get("targets")
    except (OSError, ValueError):
        targets = None
    return {"running": True, "targets": targets if isinstance(targets, list) else None}


def host_link_listening(port: int | None = None) -> bool | None:
    """Passive check (netstat listing); never opens a connection to the Host Link."""
    if port is None:
        port = int(_integrity_value('native_peer_port_49481'))
    try:
        out = subprocess.run(["netstat", "-an", "-p", "TCP"] if os.name == "nt" else ["ss", "-ltn"],
                             capture_output=True, text=True, encoding="oem" if os.name == "nt" else "utf-8", errors="replace", timeout=5,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return None
    needle = f":{port}"
    return any(needle in line and ("LISTEN" in line.upper()) for line in out.splitlines())


def harness_of(recipient: str, state_dir: Path) -> str | None:
    if recipient == "grok":
        return "grok"
    if recipient in agent_registry.BUILTIN_CODEX or recipient in agent_registry.codex_threads(state_dir):
        return "codex"
    if recipient in agent_registry.all_agents(state_dir):
        return "pull"
    return None


def assess(recipient: str, state_dir: Path, *, relay=None, host_link=None) -> dict:
    """Adds route = wake|pull|dormant|webhook. pull means 'waits for the recipient's own turn', not delivered."""
    if recipient == agent_registry.OWNER:  # owner/1: read in the owner console, never woken
        return {"deliverable": True, "reason": None, "route": "console"}
    try:
        r = autoreg.route(recipient, state_dir)["route"]
    except Exception:
        r = None
    if harness_of(recipient, state_dir) is not None and r == "dormant":
        return {"deliverable": False, "reason": "dormant", "route": "dormant"}
    if harness_of(recipient, state_dir) == "codex" and r == "pull":
        return {"deliverable": True, "reason": None, "route": "pull"}
    result = _assess(recipient, state_dir, relay=relay, host_link=host_link)
    if r and result.get("route") == "relay":
        result["route"] = r
    return result


def _assess(recipient: str, state_dir: Path, *, relay=None, host_link=None) -> dict:
    harness = harness_of(recipient, state_dir)
    if harness is None:
        return {"deliverable": False, "reason": "unregistered"}
    if harness not in PUSH_HARNESSES:
        return {"deliverable": True, "reason": None, "route": "pull"}
    relay = relay_state(state_dir) if relay is None else relay
    if not relay.get("running"):
        return {"deliverable": False, "reason": "relay_stopped"}
    targets = relay.get("targets")
    if targets is not None and recipient not in targets:
        return {"deliverable": False, "reason": "no_consumer"}
    if harness == "codex":
        up = host_link_listening() if host_link is None else host_link
        if up is False:
            return {"deliverable": False, "reason": "host_link_down"}
    return {"deliverable": True, "reason": None, "route": "relay"}


def notify_stale(state_dir: Path, store, minutes: int = 15, now: float | None = None) -> dict | None:
    """Emit ONE event per distinct stale set while the relay is stopped. No polling loop, no bus send."""
    now = time.time() if now is None else now
    if relay_state(state_dir).get("running"):
        return None
    cutoff = int(now - minutes * 60)
    with store._connection() as db:
        rows = db.execute("SELECT id, recipient, created_at FROM messages WHERE status='pending' AND created_at<? "
                          "AND expires_at>? ORDER BY seq", (cutoff, int(now))).fetchall()
    push = [r for r in rows if harness_of(r["recipient"], state_dir) in PUSH_HARNESSES]
    if not push:
        return None
    digest = hashlib.sha256(",".join(sorted(r["id"] for r in push)).encode()).hexdigest()
    marker = state_dir / "stale-notice.json"
    try:
        if json.loads(marker.read_text(encoding="utf-8")).get("digest") == digest:
            return None
    except (OSError, ValueError):
        pass
    by = {}
    for r in push:
        by[r["recipient"]] = by.get(r["recipient"], 0) + 1
    event = {"event": "undeliverable_pending", "ts": int(now), "reason": "relay_stopped", "older_than_min": minutes,
             "count": len(push), "by_recipient": by, "oldest_created_at": min(r["created_at"] for r in push),
             "ids_sha256": digest}
    with (state_dir / "bus-events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    marker.write_text(json.dumps({"digest": digest, "ts": int(now)}), encoding="utf-8")
    return event



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path(_integrity_value('state_directory')))
    parser.add_argument("--notify-stale", type=int, metavar="MINUTES")
    parser.add_argument("--recipient")
    args = parser.parse_args()
    if args.notify_stale:
        from local_cli import open_store
        print(json.dumps(notify_stale(args.state_dir, open_store(args.state_dir), args.notify_stale)))
    elif args.recipient:
        print(json.dumps(assess(args.recipient, args.state_dir)))
