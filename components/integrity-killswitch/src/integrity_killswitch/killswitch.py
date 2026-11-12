#!/usr/bin/env python3
"""LLM Safe Switch / Killswitch for local agent processes.

Controls access permissions for LLM agents (Claude, Codex, Antigravity, Grok
and any vendor added in the configuration) that run on this workstation.

State file: INTEGRITY_KILLSWITCH_STATE, the configuration key "state_file",
            or killswitch.json in the per-user state directory.
Audit log:  INTEGRITY_KILLSWITCH_LOG, the key "log_file", or killswitch.log
            next to the state file.

Commands:
  status               Show current switch states for all vendors and scopes
  on VENDOR            Enable access for a specific vendor
  off VENDOR           Disable access for a specific vendor (immediate kill)
  panic                MASTER RED BUTTON: kill access for ALL LLMs immediately
  resume               Clear master panic, returning to per-vendor settings
  check [--vendor V]   Exit 0 if allowed, exit 3 if blocked (for scripts/gates)
  serve [--port PORT]  Start local web UI dashboard with interactive toggles
  sync-bus [--apply]   Mirror the switch state to bus principals on a bus host

Security model (read before trusting it):
  * The caller is identified by its process ancestry. Git's msys ssh breaks the
    Windows parent chain, so the msys process table is used to bridge it.
  * Tightening access (off, panic) is open to every caller. Restoring access
    (on, resume, un-revoking on the bus host) is owner-only: an interactive
    shell or a browser without an LLM ancestor.
  * This is a local, cooperative gate. Any process of this user can still edit
    the state file or skip the gate. Real enforcement is the revocation on the
    bus host (sync-bus). It does not terminate running processes.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

if os.name == "nt":
    import ctypes.wintypes

SCHEMA = "integrity-killswitch/v1"
ENV_CONFIG = "INTEGRITY_KILLSWITCH_CONFIG"
ENV_STATE = "INTEGRITY_KILLSWITCH_STATE"
ENV_LOG = "INTEGRITY_KILLSWITCH_LOG"

EXIT_ALLOWED = 0
EXIT_REFUSED = 3
LOG_ROTATE_BYTES = 5 * 1024 * 1024
VENDOR_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
REMOTE_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]{1,200}")
DEFAULT_PORT = 8890

BUILTIN_VENDORS = {
    "claude": {"title": "Anthropic Claude", "markers": ["claude"]},
    "codex": {"title": "OpenAI Codex", "markers": ["codex"]},
    "antigravity": {"title": "Google Antigravity", "markers": ["antigravity", "language_server"]},
    "grok": {"title": "xAI Grok", "markers": ["grok"]},
}

# Configured at import from the defaults and again by configure().
KNOWN_VENDORS: tuple[str, ...] = ()
DEFAULT_VENDORS: dict[str, dict[str, Any]] = {}
LLM_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = ()
CONFIG: dict[str, Any] = {}

# Process-tree roots that mark a non-interactive background service.
SERVICE_ROOTS = ("svchost.exe", "services.exe", "taskhostw.exe")

DEFAULT_SCOPES = {
    "secret_get": True,      # Credential / password retrieval through a credential helper
    "direct_ssh": True,      # Direct SSH access to managed devices
    "llm_bus": True,         # Sending/receiving messages on an agent bus
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- configuration


def default_state_dir() -> Path:
    """Per-user state directory; nothing here names a particular machine."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "integrity-killswitch"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "integrity-killswitch"


def load_config(path: str | None = None) -> dict[str, Any]:
    """Reads the JSON configuration named by --config or INTEGRITY_KILLSWITCH_CONFIG.

    No configuration file is required: the built-in defaults name only the
    public agent products above.
    """
    source = path or os.environ.get(ENV_CONFIG)
    if not source:
        return {}
    data = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("killswitch configuration must be a JSON object")
    return data


def configure(config: dict[str, Any] | None = None) -> None:
    """Builds the vendor table and the process markers from the configuration."""
    global KNOWN_VENDORS, DEFAULT_VENDORS, LLM_MARKERS, CONFIG
    CONFIG = dict(config or {})
    vendors: dict[str, dict[str, Any]] = {k: dict(v) for k, v in BUILTIN_VENDORS.items()}
    for name, meta in (CONFIG.get("vendors") or {}).items():
        name = str(name).lower().strip()
        if not VENDOR_NAME_RE.fullmatch(name) or name in ("owner", "service", "unknown_llm"):
            raise ValueError(f"invalid vendor name in configuration: {name!r}")
        meta = meta if isinstance(meta, dict) else {}
        markers = [str(m).lower() for m in (meta.get("markers") or [name]) if str(m).strip()]
        vendors[name] = {"title": str(meta.get("title") or name), "markers": markers or [name]}
    KNOWN_VENDORS = tuple(vendors)
    LLM_MARKERS = tuple((name, tuple(meta["markers"])) for name, meta in vendors.items())
    DEFAULT_VENDORS = {
        name: {"enabled": True, "title": meta["title"], "reason": "Initial default"}
        for name, meta in vendors.items()
    }
    DEFAULT_VENDORS["service"] = {"enabled": True, "title": "Background services (bus sync, bridges)",
                                  "reason": "Initial default"}


configure()


# --------------------------------------------------------------------------- process tree & vendor detection


def get_process_ancestor_names(start_pid: int | None = None) -> list[str]:
    """Inspects the Windows process tree and returns executable names of ancestors.

    Starts at this process, or at ``start_pid`` (used for dashboard clients).
    Returns an empty list on other platforms, which detect_vendor treats as unknown.
    """
    if os.name != "nt":
        return []

    try:
        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.wintypes.DWORD),
                ("cntUsage", ctypes.wintypes.DWORD),
                ("th32ProcessID", ctypes.wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.wintypes.ULONG)),
                ("th32ModuleID", ctypes.wintypes.DWORD),
                ("cntThreads", ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase", ctypes.wintypes.LONG),
                ("dwFlags", ctypes.wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        hSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if hSnap == -1:
            return []

        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        procs: dict[int, tuple[int, str]] = {}

        if ctypes.windll.kernel32.Process32First(hSnap, ctypes.byref(pe)):
            while True:
                procs[pe.th32ProcessID] = (
                    pe.th32ParentProcessID,
                    pe.szExeFile.decode("ansi", errors="ignore").lower(),
                )
                if not ctypes.windll.kernel32.Process32Next(hSnap, ctypes.byref(pe)):
                    break
        ctypes.windll.kernel32.CloseHandle(hSnap)

        ancestors: list[str] = []
        chain: list[int] = []
        pid = start_pid or os.getpid()
        visited = set()
        msys: dict[int, int] | None = None
        while True:
            while pid in procs and pid != 0 and pid not in visited:
                visited.add(pid)
                chain.append(pid)
                ppid, name = procs[pid]
                ancestors.append(name)
                pid = ppid
            # Dead end. Git (msys) ssh/sh break the Windows parent chain on
            # fork/exec, so ask the msys process table for the real parent.
            if ancestors and ancestors[-1] == "explorer.exe":
                break
            if msys is None:
                msys = _msys_parent_winpids()
            nxt = 0
            for known in chain:
                cand = msys.get(known, 0)
                if cand and cand in procs and cand not in visited:
                    nxt = cand
                    break
            if not nxt:
                break
            pid = nxt
        return ancestors
    except Exception:
        return []


MSYS_PS_CANDIDATES = (
    r"C:\Program Files\Git\usr\bin\ps.exe",
    r"C:\Program Files (x86)\Git\usr\bin\ps.exe",
)


def _msys_parent_winpids() -> dict[int, int]:
    """Maps a Windows PID to the Windows PID of its msys parent.

    Returns an empty map when Git's ps.exe is missing or fails, which keeps
    the old fail-closed behaviour (the chain stays truncated). The key
    "msys_ps" in the configuration names a ps.exe in another location.
    """
    candidates = ([str(CONFIG["msys_ps"])] if CONFIG.get("msys_ps") else []) + list(MSYS_PS_CANDIDATES)
    ps = next((p for p in candidates if os.path.exists(p)), None)
    if not ps:
        return {}
    try:
        import subprocess

        out = subprocess.run(
            [ps, "-e"], capture_output=True, text=True, timeout=5,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except Exception:
        return {}
    return _parse_msys_ps(out)


def _parse_msys_ps(out: str) -> dict[int, int]:
    """Turns msys `ps -e` output into {winpid: winpid of its msys parent}."""
    win_of: dict[int, int] = {}
    parent_of: dict[int, int] = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if parts and not parts[0].isdigit():
            parts = parts[1:]  # leading status column (S/I)
        if len(parts) < 4 or not all(x.isdigit() for x in parts[:4]):
            continue
        mpid, mppid, winpid = int(parts[0]), int(parts[1]), int(parts[3])
        win_of[mpid] = winpid
        parent_of[mpid] = mppid
    result: dict[int, int] = {}
    for mpid, winpid in win_of.items():
        parent_win = win_of.get(parent_of.get(mpid, 0), 0)
        if parent_win and parent_win != winpid:
            result[winpid] = parent_win
    return result


INTERACTIVE_SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe"}
UI_ANCHORS = {"explorer.exe", "windowsterminal.exe", "mintty.exe"}
MSYS_SHELLS = {"bash.exe", "sh.exe"}
SYSTEM_ROOTS = {"wininit.exe", "winlogon.exe", "userinit.exe", "sihost.exe", "runtimebroker.exe",
                "system", "[system process]"}
NEUTRAL_NAMES = INTERACTIVE_SHELLS | UI_ANCHORS | MSYS_SHELLS | SYSTEM_ROOTS | set(SERVICE_ROOTS) | {
    "python.exe", "py.exe", "conhost.exe", "openconsole.exe", "git-bash.exe", "git.exe",
    "ssh.exe", "scp.exe", "sftp.exe", "plink.exe",
}


def detect_vendor(ancestors: list[str] | None = None, env: Any = None) -> str:
    """Detects who is invoking this process.

    Order matters and is security relevant:
      1. an LLM executable anywhere in the process ancestry wins, so an LLM
         cannot relabel itself through the environment;
      2. LLM_VENDOR may only select a known vendor, never the owner;
      3. windowless daemons are "service";
      4. "owner" needs a chain made only of neutral system/shell processes.
    Everything else is unknown and blocked.
    """
    if ancestors is None:
        ancestors = get_process_ancestor_names()
    if env is None:
        env = os.environ
    joined = " ".join(ancestors)
    for vendor, markers in LLM_MARKERS:
        if any(marker in joined for marker in markers):
            return vendor

    env_vendor = str(env.get("LLM_VENDOR", "")).strip().lower()
    if env_vendor in KNOWN_VENDORS:
        return env_vendor

    if not ancestors:
        return "unknown_llm"
    if "pythonw.exe" in ancestors:
        return "service"
    # A chain that dead-ends inside Git's msys layer was not bridged.
    if ancestors[-1] in MSYS_SHELLS:
        return "unknown_llm"
    if not all(name in NEUTRAL_NAMES for name in ancestors):
        return "unknown_llm"
    if any(name in UI_ANCHORS for name in ancestors):
        return "owner"
    if any(name in SERVICE_ROOTS for name in ancestors):
        return "service"
    if any(name in INTERACTIVE_SHELLS for name in ancestors):
        return "owner"
    return "unknown_llm"


# --------------------------------------------------------------------------- state management


def state_path(custom: str | None = None) -> Path:
    if custom:
        return Path(custom)
    env = os.environ.get(ENV_STATE)
    if env:
        return Path(env)
    if CONFIG.get("state_file"):
        return Path(str(CONFIG["state_file"]))
    return default_state_dir() / "killswitch.json"


def log_path(custom: str | None = None) -> Path:
    if custom:
        return Path(custom)
    env = os.environ.get(ENV_LOG)
    if env:
        return Path(env)
    if CONFIG.get("log_file"):
        return Path(str(CONFIG["log_file"]))
    return state_path().with_name("killswitch.log")


def log_audit_event(action: str, details: dict[str, Any], path: Path | None = None) -> None:
    target_log = path or log_path()
    try:
        target_log.parent.mkdir(parents=True, exist_ok=True)
        try:
            if target_log.stat().st_size > LOG_ROTATE_BYTES:
                os.replace(target_log, target_log.with_name(target_log.name + ".1"))
        except OSError:
            pass
        entry = {
            "ts": utc_now(),
            "action": action,
            **details,
        }
        with open(target_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as exc:
        print(f"killswitch: warning: failed to write audit log: {exc}", file=sys.stderr)


def init_state() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "master_panic": False,
        "updated_at": utc_now(),
        "updated_by": "system-init",
        "note": "Initial baseline killswitch configuration",
        "vendors": json.loads(json.dumps(DEFAULT_VENDORS)),
        "scopes": json.loads(json.dumps(DEFAULT_SCOPES)),
    }


def _read_text_retry(path: Path, attempts: int = 3) -> str:
    """Reads the state file; a concurrent atomic replace can lock it for a moment."""
    for attempt in range(attempts):
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)
    return ""


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        state = init_state()
        save_state(path, state, "init")
        return state
    try:
        data = json.loads(_read_text_retry(path))
        if data.get("schema") != SCHEMA:
            # Upgrade or ensure schema
            data.setdefault("schema", SCHEMA)
        data.setdefault("master_panic", False)
        data.setdefault("vendors", {})
        for v, meta in DEFAULT_VENDORS.items():
            data["vendors"].setdefault(v, dict(meta))
        data.setdefault("scopes", json.loads(json.dumps(DEFAULT_SCOPES)))
        return data
    except Exception as exc:
        # A killswitch that cannot read its state must not wave everyone through.
        print(f"killswitch: error reading state from {path}: {exc}; failing CLOSED", file=sys.stderr)
        state = init_state()
        state["master_panic"] = True
        state["updated_by"] = "state-error"
        state["note"] = (f"State file unreadable ({type(exc).__name__}); failing closed. "
                         "Owner: run 'integrity-killswitch resume' to rewrite it.")
        return state


def save_state(path: Path, state: dict[str, Any], actor: str = "owner") -> None:
    state["updated_at"] = utc_now()
    state["updated_by"] = actor
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- evaluation


def is_allowed(
    vendor: str | None = None,
    action: str = "any",
    target: str = "",
    state_file: Path | None = None,
) -> tuple[bool, str]:
    """Evaluates whether an action is permitted by the killswitch.

    Returns:
      (allowed: bool, reason: str)
    """
    path = state_file or state_path()
    state = load_state(path)

    detected = vendor or detect_vendor()

    # Human owner is always allowed to perform operations
    if detected == "owner":
        return True, "owner: human execution unrestricted"

    # Master Panic blocks ALL LLM actions unconditionally
    if state.get("master_panic", False):
        reason = f"MASTER PANIC ACTIVE: All LLM infrastructure access is blocked by owner ({state.get('note', '')})"
        log_audit_event("block", {"vendor": detected, "action": action, "target": target, "reason": reason}, log_path())
        return False, reason

    # Check vendor toggle
    vendors = state.get("vendors", {})
    vendor_info = vendors.get(detected)

    if detected == "unknown_llm":
        reason = "UNKNOWN_LLM: Execution context has unrecognized LLM ancestor in process tree"
        log_audit_event("block", {"vendor": detected, "action": action, "target": target, "reason": reason,
                                  "ancestors": get_process_ancestor_names()}, log_path())
        return False, reason

    if not vendor_info or not vendor_info.get("enabled", True):
        v_reason = vendor_info.get("reason", "Vendor switch turned off") if vendor_info else "Vendor not registered"
        reason = f"KILLSWITCH OFF: Access for vendor '{detected}' is DISABLED by owner ({v_reason})"
        log_audit_event("block", {"vendor": detected, "action": action, "target": target, "reason": reason}, log_path())
        return False, reason

    # Check action scope
    scopes = state.get("scopes", {})
    if action in scopes and not scopes[action]:
        reason = f"SCOPE DISABLED: Scope '{action}' is currently disabled for all LLMs"
        log_audit_event("block", {"vendor": detected, "action": action, "target": target, "reason": reason}, log_path())
        return False, reason

    return True, f"allowed for {detected}"


def check_or_refuse(action: str = "any", target: str | None = None, entry_id: str | None = None) -> None:
    """Helper for credential helpers and other tools to call directly.

    Raises RuntimeError if not allowed.
    """
    allowed, reason = is_allowed(action=action, target=target or entry_id or "")
    if not allowed:
        raise RuntimeError(f"KILLSWITCH REFUSAL: {reason}")


# --------------------------------------------------------------------------- CLI commands


def admin_actor(action: str, owner_only: bool) -> str | None:
    """Returns who runs an admin command, or None when it must be refused.

    Restoring access is owner-only; tightening it is open to every caller.
    """
    actor = detect_vendor()
    if owner_only and actor != "owner":
        log_audit_event("admin_denied", {"actor": actor, "admin_action": action,
                                         "ancestors": get_process_ancestor_names()})
        print(f"killswitch: REFUSED: '{action}' restores access and is owner-only "
              f"(caller detected as {actor}). Use an interactive shell or the dashboard.",
              file=sys.stderr)
        return None
    return actor


def cmd_status(args: argparse.Namespace) -> int:
    path = state_path(args.state)
    state = load_state(path)
    detected = detect_vendor()

    master = state.get("master_panic", False)
    status_label = "[MASTER PANIC: ALL LLMs BLOCKED]" if master else "[NORMAL: PER-VENDOR POLICY]"

    print("=" * 64)
    print("  Integrity LLM Safe Switch / Killswitch")
    print(f"  Status: {status_label}")
    print(f"  Updated: {state.get('updated_at')} by {state.get('updated_by')}")
    if state.get("note"):
        print(f"  Note:    {state.get('note')}")
    print("=" * 64)
    print(f"  Current caller detected as: [{detected.upper()}]")
    print(f"  Process chain: {' <- '.join(get_process_ancestor_names()) or 'n/a'}")
    print("-" * 64)
    print(f"  {'VENDOR':<16} {'TITLE':<24} {'STATE':<10} {'REASON'}")
    print("-" * 64)

    for v, info in state.get("vendors", {}).items():
        enabled = info.get("enabled", True) and not master
        raw_enabled = info.get("enabled", True)
        state_str = "ENABLED" if enabled else ("BLOCKED(PANIC)" if master and raw_enabled else "DISABLED")
        title = info.get("title", v)
        reason = info.get("reason", "")
        print(f"  {v:<16} {title:<24} {state_str:<10} {reason}")

    print("-" * 64)
    print("  Scopes:")
    for scope, sc_en in state.get("scopes", {}).items():
        sc_str = "ACTIVE" if sc_en and not master else "DISABLED"
        print(f"    - {scope:<16}: {sc_str}")
    print("=" * 64)
    return 0


def cmd_set_vendor(args: argparse.Namespace, enabled: bool) -> int:
    vendor = args.vendor.lower().strip()
    if not VENDOR_NAME_RE.fullmatch(vendor):
        print(f"killswitch: invalid vendor name {vendor!r}", file=sys.stderr)
        return 2
    actor = admin_actor(("on " if enabled else "off ") + vendor, owner_only=enabled)
    if actor is None:
        return EXIT_REFUSED
    path = state_path(args.state)
    state = load_state(path)

    if vendor not in state.get("vendors", {}):
        state.setdefault("vendors", {})[vendor] = {
            "title": vendor.capitalize(),
            "enabled": enabled,
            "reason": args.reason or ("Enabled by CLI" if enabled else "Disabled by CLI"),
            "updated_at": utc_now(),
        }
    else:
        state["vendors"][vendor]["enabled"] = enabled
        state["vendors"][vendor]["updated_at"] = utc_now()
        if args.reason:
            state["vendors"][vendor]["reason"] = args.reason
        else:
            state["vendors"][vendor]["reason"] = f"Turned {'ON' if enabled else 'OFF'} by {actor}"

    save_state(path, state, actor=f"{actor}-cli")
    action_name = "vendor_enable" if enabled else "vendor_disable"
    log_audit_event(action_name, {"vendor": vendor, "reason": state["vendors"][vendor]["reason"], "actor": actor})

    status_str = "ENABLED (ON)" if enabled else "DISABLED (OFF - KILLSWITCH ACTIVE)"
    print(f"killswitch: vendor '{vendor}' is now {status_str}")

    if getattr(args, "sync", False):
        sync_args = argparse.Namespace(state=args.state, apply=True)
        cmd_sync_bus(sync_args)
    return 0


def cmd_panic(args: argparse.Namespace) -> int:
    path = state_path(args.state)
    state = load_state(path)
    actor = detect_vendor()
    state["master_panic"] = True
    state["note"] = args.reason or f"EMERGENCY PANIC TRIGGERED BY {actor.upper()}"
    save_state(path, state, actor=f"{actor}-panic")
    log_audit_event("panic_triggered", {"reason": state["note"], "actor": actor})

    print("!" * 64)
    print("  MASTER KILLSWITCH ACTIVATED: ALL LLM ACCESS IS NOW CUT OFF!")
    print(f"  Reason: {state['note']}")
    print("!" * 64)

    if getattr(args, "sync", False):
        sync_args = argparse.Namespace(state=args.state, apply=True)
        cmd_sync_bus(sync_args)
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    if admin_actor("resume", owner_only=True) is None:
        return EXIT_REFUSED
    path = state_path(args.state)
    state = load_state(path)
    state["master_panic"] = False
    state["note"] = args.reason or "Normal operations resumed by owner"
    save_state(path, state, actor="owner-resume")
    log_audit_event("panic_cleared", {"reason": state["note"]})

    print("=" * 64)
    print("  Master Panic CLEARED. Returned to per-vendor policy.")
    print("=" * 64)

    if getattr(args, "sync", False):
        sync_args = argparse.Namespace(state=args.state, apply=True)
        cmd_sync_bus(sync_args)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    # A caller may ask about a vendor, but may not claim to be the owner.
    claimed = args.vendor if args.vendor and args.vendor.lower() != "owner" else None
    try:
        allowed, reason = is_allowed(
            vendor=claimed,
            action=args.action or "any",
            target=args.target or "",
            state_file=state_path(args.state),
        )
    except Exception as exc:  # a broken gate must be visible and closed
        allowed, reason = False, f"KILLSWITCH ERROR: {type(exc).__name__}: {exc}"
        log_audit_event("check_error", {"action": args.action or "any", "target": args.target or "",
                                        "reason": reason})
    if args.match_blocked:
        # For OpenSSH Match exec: returns 0 if BLOCKED so Match applies
        if not allowed:
            print(f"KILLSWITCH BLOCKED: {reason}", file=sys.stderr)
            return 0
        return 1

    if allowed:
        if args.verbose:
            print(f"ALLOWED: {reason}")
        return EXIT_ALLOWED
    else:
        print(f"REFUSED BY KILLSWITCH: {reason}", file=sys.stderr)
        return EXIT_REFUSED


# --------------------------------------------------------------------------- Web UI Dashboard


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Integrity — LLM Safe Switch</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --success: #22c55e;
      --danger: #ef4444;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 2rem; max-width: 900px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid var(--card-border); padding-bottom: 1rem; }
    h1 { font-size: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }
    .badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }
    .badge-ok { background: rgba(34, 197, 94, 0.2); color: var(--success); border: 1px solid var(--success); }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }

    .panic-box {
      background: rgba(239, 68, 68, 0.1);
      border: 2px solid var(--danger);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .panic-text h2 { font-size: 1.25rem; color: var(--danger); margin-bottom: 0.25rem; }
    .panic-text p { color: var(--text-muted); font-size: 0.9rem; }
    .btn-panic {
      background: var(--danger);
      color: white;
      border: none;
      padding: 0.75rem 1.75rem;
      font-size: 1rem;
      font-weight: 700;
      border-radius: 8px;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .btn-panic:hover { opacity: 0.9; }
    .btn-resume {
      background: var(--success);
      color: white;
      border: none;
      padding: 0.75rem 1.75rem;
      font-size: 1rem;
      font-weight: 700;
      border-radius: 8px;
      cursor: pointer;
    }

    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: border-color 0.2s;
    }
    .card.disabled { opacity: 0.65; border-color: rgba(239, 68, 68, 0.3); }
    .vendor-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 0.25rem; }
    .vendor-desc { font-size: 0.85rem; color: var(--text-muted); }
    .vendor-reason { font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem; }

    /* Switch CSS */
    .switch { position: relative; display: inline-block; width: 54px; height: 30px; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
      background-color: #475569; transition: .3s; border-radius: 30px;
    }
    .slider:before {
      position: absolute; content: ""; height: 22px; width: 22px; left: 4px; bottom: 4px;
      background-color: white; transition: .3s; border-radius: 50%;
    }
    input:checked + .slider { background-color: var(--success); }
    input:checked + .slider:before { transform: translateX(24px); }
    input:disabled + .slider { opacity: 0.4; cursor: not-allowed; }

    .audit-box {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem;
    }
    .audit-box h3 { font-size: 1rem; margin-bottom: 0.75rem; color: var(--text-muted); }
    .log-list { font-family: monospace; font-size: 0.8rem; max-height: 180px; overflow-y: auto; color: #cbd5e1; }
    .log-entry { margin-bottom: 0.35rem; padding-bottom: 0.35rem; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .log-entry.block { color: var(--danger); }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Integrity Safe Switch</h1>
      <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.25rem;">Аварийный тумблер доступа LLM к инфраструктуре</p>
    </div>
    <div id="masterBadge" class="badge badge-ok">NORMAL</div>
  </header>

  <div class="panic-box">
    <div class="panic-text">
      <h2 id="panicHeader">MASTER KILLSWITCH</h2>
      <p id="panicDesc">Мгновенное отключение доступа ВСЕХ LLM к инфраструктуре, шине и секретам</p>
    </div>
    <div id="panicAction">
      <button class="btn-panic" onclick="togglePanic(true)">🚨 PANIC STOP</button>
    </div>
  </div>

  <h2 style="font-size: 1.15rem; margin-bottom: 1rem; color: var(--text-muted);">Тумблеры по вендорам</h2>
  <div class="grid" id="vendorGrid">
    <!-- Populated by JS -->
  </div>

  <div class="audit-box">
    <h3>Последние события безопасности</h3>
    <div class="log-list" id="auditList">
      <div class="log-entry">Загрузка журнала...</div>
    </div>
  </div>

  <script>
    let currentState = null;

    // State and log text can be written by any local caller (for example an
    // `off --reason` from an agent), so it is escaped before it reaches HTML.
    function esc(value) {
      return String(value == null ? '' : value).replace(/[&<>"'`]/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
      })[c]);
    }

    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        currentState = await res.json();
        render();
      } catch (err) {
        console.error('Failed to load status', err);
      }
    }

    function render() {
      if (!currentState) return;
      const isPanic = currentState.master_panic;

      const badge = document.getElementById('masterBadge');
      const panicAction = document.getElementById('panicAction');
      const panicHeader = document.getElementById('panicHeader');

      if (isPanic) {
        badge.className = 'badge badge-danger';
        badge.textContent = 'ALL LLMS CUT OFF';
        panicHeader.textContent = '🚨 MASTER PANIC ACTIVE';
        panicAction.innerHTML = '<button class="btn-resume" onclick="togglePanic(false)">🟢 Восстановить доступ</button>';
      } else {
        badge.className = 'badge badge-ok';
        badge.textContent = 'NORMAL';
        panicHeader.textContent = 'MASTER KILLSWITCH';
        panicAction.innerHTML = '<button class="btn-panic" onclick="togglePanic(true)">🚨 PANIC STOP</button>';
      }

      const grid = document.getElementById('vendorGrid');
      grid.innerHTML = '';

      for (const [key, v] of Object.entries(currentState.vendors || {})) {
        if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(key)) continue;
        const card = document.createElement('div');
        const isEnabled = v.enabled && !isPanic;
        card.className = 'card' + (isEnabled ? '' : ' disabled');

        card.innerHTML = `
          <div>
            <div class="vendor-title">${esc(v.title || key)}</div>
            <div class="vendor-desc">Vendor ID: <code>${esc(key)}</code></div>
            <div class="vendor-reason">${esc(v.reason || '')}</div>
          </div>
          <div>
            <label class="switch">
              <input type="checkbox" ${v.enabled ? 'checked' : ''} ${isPanic ? 'disabled' : ''} onchange="toggleVendor('${key}', this.checked)">
              <span class="slider"></span>
            </label>
          </div>
        `;
        grid.appendChild(card);
      }

      const logList = document.getElementById('auditList');
      if (currentState.logs && currentState.logs.length) {
        logList.innerHTML = currentState.logs.map(l => {
          const isBlock = l.action === 'block' || l.action === 'panic_triggered';
          return `<div class="log-entry ${isBlock ? 'block' : ''}">[${esc(String(l.ts || '').replace('T', ' ').slice(0, 19))}] <strong>${esc(String(l.action || '').toUpperCase())}</strong>: ${esc(l.vendor || '')} ${l.target ? '@' + esc(l.target) : ''} - ${esc(l.reason || '')}</div>`;
        }).join('');
      } else {
        logList.innerHTML = '<div class="log-entry">Событий блокировки нет</div>';
      }
    }

    async function toggleVendor(vendor, enabled) {
      try {
        await fetch('/api/toggle', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({vendor, enabled, reason: 'Toggled via Web UI'})
        });
        await loadStatus();
      } catch (err) {
        alert('Ошибка переключения: ' + err);
      }
    }

    async function togglePanic(activate) {
      if (activate && !confirm('ВНИМАНИЕ! Это полностью заблокирует доступ ВСЕМ моделям к инфраструктуре. Подтверждаете?')) {
        return;
      }
      try {
        await fetch(activate ? '/api/panic' : '/api/resume', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({reason: 'Toggled via Web UI'})
        });
        await loadStatus();
      } catch (err) {
        alert('Ошибка переключения: ' + err);
      }
    }

    loadStatus();
    setInterval(loadStatus, 2000);
  </script>
</body>
</html>
"""


BROWSER_NAMES = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"}


def _tcp_peer_pid(client_port: int, server_port: int) -> int:
    """PID of the local process holding the client end of a loopback connection."""
    if os.name != "nt":
        return 0
    try:
        import socket
        import struct

        iphlpapi = ctypes.windll.iphlpapi
        size = ctypes.wintypes.DWORD(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)
        buf = ctypes.create_string_buffer(size.value + 8192)
        size = ctypes.wintypes.DWORD(len(buf))
        if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 5, 0) != 0:
            return 0
        (count,) = struct.unpack_from("<I", buf, 0)
        for i in range(count):
            _state, _laddr, lport, _raddr, rport, pid = struct.unpack_from("<6I", buf, 4 + i * 24)
            if socket.ntohs(lport & 0xFFFF) == client_port and socket.ntohs(rport & 0xFFFF) == server_port:
                return int(pid)
    except Exception:
        pass
    return 0


def web_actor(names: list[str]) -> str:
    """Classifies the process behind a dashboard request.

    A browser with no LLM ancestor counts as the owner. An LLM that drives the
    owner's own browser cannot be told apart here.
    """
    joined = " ".join(names)
    for vendor, markers in LLM_MARKERS:
        if any(marker in joined for marker in markers):
            return vendor
    if any(name in BROWSER_NAMES for name in names):
        return "owner"
    return detect_vendor(names, env={})


class KillswitchHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        u = urlparse(self.path)
        if u.path == "/" or u.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            return
        elif u.path == "/api/status":
            state = load_state(state_path())
            # Attach last 15 log entries
            logs = []
            lpath = log_path()
            if lpath.exists():
                try:
                    lines = lpath.read_text(encoding="utf-8").splitlines()
                    for line in reversed(lines[-15:]):
                        try:
                            logs.append(json.loads(line))
                        except Exception:
                            continue
                except Exception:
                    pass
            state["logs"] = logs
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(state, ensure_ascii=False).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def _json(self, code: int, doc: dict[str, Any]) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(doc, ensure_ascii=False).encode("utf-8"))

    def _same_origin(self) -> bool:
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host", "") not in hosts:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in {f"http://{h}" for h in hosts}

    def _client_actor(self) -> tuple[str, list[str]]:
        pid = _tcp_peer_pid(self.client_address[1], self.server.server_address[1])
        names = get_process_ancestor_names(pid) if pid else []
        return web_actor(names), names

    def do_POST(self) -> None:
        u = urlparse(self.path)
        try:
            length = min(int(self.headers.get("Content-Length", 0) or 0), 65536)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}

        if u.path not in ("/api/toggle", "/api/panic", "/api/resume"):
            self.send_response(404)
            self.end_headers()
            return

        if not self._same_origin():
            log_audit_event("web_denied", {"path": u.path, "reason": "cross-origin request or foreign Host"})
            self._json(403, {"status": "refused", "reason": "cross-origin request"})
            return

        actor, names = self._client_actor()
        enabled = bool(payload.get("enabled", True))
        restoring = u.path == "/api/resume" or (u.path == "/api/toggle" and enabled)
        if restoring and actor != "owner":
            log_audit_event("web_denied", {"path": u.path, "actor": actor, "ancestors": names,
                                           "reason": "restoring access is owner-only"})
            self._json(403, {"status": "refused",
                             "reason": f"restoring access is owner-only (caller detected as {actor})"})
            return

        path = state_path()
        state = load_state(path)

        if u.path == "/api/toggle":
            vendor = str(payload.get("vendor", "")).lower().strip()
            reason = str(payload.get("reason", "Web UI toggle"))[:200]
            if vendor in state.get("vendors", {}):
                state["vendors"][vendor]["enabled"] = enabled
                state["vendors"][vendor]["reason"] = reason
                state["vendors"][vendor]["updated_at"] = utc_now()
                save_state(path, state, actor=f"{actor}-web-ui")
                log_audit_event("vendor_toggle", {"vendor": vendor, "enabled": enabled,
                                                  "reason": reason, "actor": actor})
        elif u.path == "/api/panic":
            state["master_panic"] = True
            state["note"] = str(payload.get("reason", "Triggered from Web UI"))[:200]
            save_state(path, state, actor=f"{actor}-web-ui")
            log_audit_event("panic_triggered", {"reason": state["note"], "actor": actor})
        else:
            state["master_panic"] = False
            state["note"] = str(payload.get("reason", "Resumed from Web UI"))[:200]
            save_state(path, state, actor=f"{actor}-web-ui")
            log_audit_event("panic_cleared", {"reason": state["note"], "actor": actor})

        self._json(200, {"status": "ok"})

    def log_message(self, format: str, *args) -> None:
        # Silence default terminal request logs to keep terminal quiet
        pass


DEFAULT_REMOTE_COMMAND = ("sudo", "-n", "python3", "-")

# Runs on the bus host (python3 reads it from stdin). One source of truth for
# both the plan and the apply step. It only un-revokes principals that an
# earlier killswitch sync revoked (tracked in a sidecar file), and never
# touches principals without a vendor or with vendor "owner".
BUS_SYNC_SCRIPT = r'''
import json, os, shutil, sys, time

mode, path, panic, dis = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4]
disabled = set() if dis == "-" else set(dis.split(","))
side = os.path.join(os.path.dirname(path), "killswitch-revoked.json")
with open(path, encoding="utf-8") as f:
    data = json.load(f)
try:
    with open(side, encoding="utf-8") as f:
        mine = set(json.load(f))
except (OSError, ValueError):
    mine = set()

principals = {n: i for n, i in data.get("principals", {}).items() if isinstance(i, dict)}
changes = []
for name, info in principals.items():
    vendor = info.get("vendor", "") or ""
    if vendor in ("", "owner"):
        continue
    want = panic or vendor in disabled
    cur = bool(info.get("revoked", False))
    if want and not cur:
        changes.append({"name": name, "vendor": vendor, "to": True})
    elif not want and cur and name in mine:
        changes.append({"name": name, "vendor": vendor, "to": False})

out = {
    "changes": changes,
    "foreign_revoked": sorted(n for n, i in principals.items() if i.get("revoked") and n not in mine),
}
if mode == "apply" and changes:
    for c in changes:
        principals[c["name"]]["revoked"] = c["to"]
        if c["to"]:
            mine.add(c["name"])
        else:
            mine.discard(c["name"])
    st = os.stat(path)
    backup = path + ".bak-killswitch-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    shutil.copy2(path, backup)
    for target, doc in ((side, sorted(mine)), (path, data)):
        tmp = target + ".killswitch.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except (OSError, AttributeError):
            pass
        os.replace(tmp, target)
    out["applied"] = len(changes)
    out["backup"] = backup
print(json.dumps(out))
'''


def bus_sync_settings() -> dict[str, Any]:
    """The "bus_sync" configuration block; raises when sync is not configured."""
    block = CONFIG.get("bus_sync") or {}
    ssh = block.get("ssh_command")
    if not isinstance(ssh, list) or not ssh or not all(isinstance(a, str) and a for a in ssh):
        raise RuntimeError("bus sync is not configured: set bus_sync.ssh_command in the configuration")
    principals = str(block.get("principals_path") or "")
    if not principals:
        raise RuntimeError("bus sync is not configured: set bus_sync.principals_path in the configuration")
    if not REMOTE_PATH_RE.fullmatch(principals) or ".." in principals.split("/"):
        raise RuntimeError("bus_sync.principals_path must be an absolute POSIX path without spaces")
    remote = block.get("remote_command") or list(DEFAULT_REMOTE_COMMAND)
    if not isinstance(remote, list) or not all(isinstance(a, str) and re.fullmatch(r"[A-Za-z0-9_./=-]+", a)
                                               for a in remote):
        raise RuntimeError("bus_sync.remote_command must be a list of plain words")
    return {"ssh_command": list(ssh), "principals_path": principals, "remote_command": list(remote),
            "host_label": str(block.get("host_label") or "the bus host")}


def bus_sync_args(mode: str, is_panic: bool, disabled: set[str],
                  principals_path: str) -> list[str]:
    names = sorted(v for v in disabled if VENDOR_NAME_RE.fullmatch(v))
    return [mode, principals_path, "1" if is_panic else "0", ",".join(names) or "-"]


def _run_bus_sync(mode: str, is_panic: bool, disabled: set[str]) -> dict[str, Any]:
    import subprocess

    settings = bus_sync_settings()
    cmd = settings["ssh_command"] + [
        " ".join(settings["remote_command"]
                 + bus_sync_args(mode, is_panic, disabled, settings["principals_path"])),
    ]
    # Bytes on stdin: text mode would turn LF into CRLF on Windows.
    res = subprocess.run(cmd, input=BUS_SYNC_SCRIPT.encode("utf-8"), capture_output=True, timeout=25)
    lines = res.stdout.decode("utf-8", "replace").strip().splitlines()
    if res.returncode != 0 or not lines:
        err = res.stderr.decode("utf-8", "replace").strip()[:200]
        raise RuntimeError(f"bus host returned code {res.returncode}: {err or 'no output'}")
    return json.loads(lines[-1])


def cmd_sync_bus(args: argparse.Namespace) -> int:
    path = state_path(args.state)
    state = load_state(path)
    is_panic = bool(state.get("master_panic", False))
    disabled = {v for v, info in state.get("vendors", {}).items() if not info.get("enabled", True)}
    label = str((CONFIG.get("bus_sync") or {}).get("host_label") or "the bus host")

    print("=" * 64)
    print("  Integrity LLM Bus Principals Sync")
    print("=" * 64)
    if is_panic:
        print("  State: MASTER PANIC -> every vendor principal will be REVOKED on the bus")
    else:
        print(f"  Disabled vendors: {sorted(disabled) if disabled else 'None (all active)'}")

    print(f"  Checking remote principals on {label}...")
    try:
        plan = _run_bus_sync("plan", is_panic, disabled)
    except Exception as exc:
        print(f"  Notice: bus host is not reachable for sync: {exc}")
        print("  The local killswitch gate on this machine stays active.")
        return 1

    foreign = plan.get("foreign_revoked", [])
    if foreign:
        print(f"  Revoked on the bus host by something else (left untouched): {', '.join(foreign)}")
    changes = plan.get("changes", [])
    if not changes:
        print("  Bus principals are already in sync with killswitch.")
        return 0

    print(f"  Pending sync changes ({len(changes)}):")
    for c in changes:
        arrow = "ACTIVE -> REVOKED" if c["to"] else "REVOKED -> ACTIVE"
        print(f"    - Principal '{c['name']}' (vendor={c['vendor']}): {arrow}")

    if not getattr(args, "apply", False):
        print(f"\n  Run with --apply to push changes to {label}.")
        return 0

    if any(not c["to"] for c in changes) and admin_actor("sync-bus --apply (restore)", owner_only=True) is None:
        return EXIT_REFUSED

    try:
        done = _run_bus_sync("apply", is_panic, disabled)
    except Exception as exc:
        print(f"  Apply failed: {exc}")
        return 1
    print(f"  Applied {done.get('applied', 0)} change(s) on {label}. Backup: {done.get('backup', 'n/a')}")
    log_audit_event("bus_sync", {"applied": done.get("applied", 0), "panic": is_panic,
                                 "disabled": sorted(disabled)})
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    port = args.port or int(CONFIG.get("dashboard_port") or DEFAULT_PORT)
    server = ThreadingHTTPServer(("127.0.0.1", port), KillswitchHTTPHandler)
    print(f"killswitch: Safe Switch Dashboard running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nkillswitch: dashboard server stopped.")
    return 0


# --------------------------------------------------------------------------- CLI parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="integrity-killswitch", description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", help=f"configuration JSON (default: ${ENV_CONFIG}; none is required)")
    parser.add_argument("--state", help=f"path to killswitch.json (default: ${ENV_STATE}, the key state_file, "
                                        "or the per-user state directory)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", help="show current switch state")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("on", help="enable access for a vendor")
    p.add_argument("vendor", help="vendor name (e.g. claude, codex, antigravity, grok)")
    p.add_argument("--reason", help="optional reason note")
    p.add_argument("--sync", action="store_true", help="sync to the configured bus host")
    p.set_defaults(func=lambda args: cmd_set_vendor(args, True))

    p = sub.add_parser("off", help="disable access for a vendor (killswitch)")
    p.add_argument("vendor", help="vendor name (e.g. claude, codex, antigravity, grok)")
    p.add_argument("--reason", help="optional reason note")
    p.add_argument("--sync", action="store_true", help="sync to the configured bus host")
    p.set_defaults(func=lambda args: cmd_set_vendor(args, False))

    p = sub.add_parser("panic", help="MASTER PANIC: kill access for ALL LLMs immediately")
    p.add_argument("--reason", help="emergency reason note")
    p.add_argument("--sync", action="store_true", help="sync to the configured bus host")
    p.set_defaults(func=cmd_panic)

    p = sub.add_parser("resume", help="clear master panic and return to per-vendor policy")
    p.add_argument("--reason", help="optional note")
    p.add_argument("--sync", action="store_true", help="sync to the configured bus host")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("check", help="check if access is allowed (exit 0 if allowed, exit 3 if blocked)")
    p.add_argument("--vendor", help="vendor name to check (if omitted, auto-detected)")
    p.add_argument("--action", help="scope/action name (e.g. secret_get, direct_ssh, llm_bus)")
    p.add_argument("--target", help="target host/device")
    p.add_argument("--match-blocked", action="store_true", help="return exit 0 if blocked (for OpenSSH Match exec)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("serve", help="launch local web UI dashboard")
    p.add_argument("--port", type=int, default=None, help=f"port to bind to (default {DEFAULT_PORT})")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("sync-bus", help="sync killswitch revocation to the configured bus host")
    p.add_argument("--apply", action="store_true", help="apply changes remotely (default: dry-run inspection)")
    p.set_defaults(func=cmd_sync_bus)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    try:
        configure(load_config(args.config))
    except (OSError, ValueError) as exc:
        print(f"killswitch: configuration error: {exc}", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
