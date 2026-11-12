#!/usr/bin/env python3
"""Rule guard: local PreToolUse hook that turns operator rules into mechanisms.

Each check names the rule it enforces. Every value that depends on a particular
network or machine (device registry, device address patterns, protected secret
paths, database names) comes from the ``rule_guard`` section of the guards
configuration (``INTEGRITY_GUARDS_CONFIG``). A rule whose configuration is
missing stays inactive.

Rules covered:
  R-SWITCH  device-command-registry-first. Switch CLI write lines must come from the
            per-model registry profile; the command must declare `registry-profile: <profile>`.
  R-LF      deploy-lf-line-endings. Text scripts uploaded to Linux (scp/pscp/rsync/sftp)
            must not contain CRLF.
  R-SECRET  protected-secret-files. Commands and reads must not open configured secret files;
            values come only through the configured secret tool.
  R-SQL     sql-no-rollback-dry-run. A SQL write to a configured database must not use
            BEGIN/ROLLBACK as a "dry run" and needs a write marker.
  R-BROWSER no-js-in-admin-browser. Browser JavaScript tools get the configured warning.

Modes (env INTEGRITY_RULE_GUARD_MODE or rule_guard.mode):
  warn     (default) never blocks; adds a warning to the model context.
  enforce  denies the tool call with the reason.
  off      does nothing.

Usage:
  hook:      integrity-guards rule-guard hook   < PreToolUse JSON on stdin
  validate:  integrity-guards rule-guard validate --profile vendor-a-access --line "config ports 5 state disable"
The registry file is only read here.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path

from integrity_guards import config as _config

ENV_MODE = "INTEGRITY_RULE_GUARD_MODE"
ENV_REGISTRY = "INTEGRITY_RULE_GUARD_REGISTRY"


def settings() -> dict:
    return _config.section("rule_guard")


def registry_path() -> Path | None:
    value = os.environ.get(ENV_REGISTRY) or settings().get("device_registry")
    return Path(value) if value else None


RULES = {
    "R-SWITCH": {"slug": "device-command-registry-first"},
    "R-LF": {"slug": "deploy-lf-line-endings"},
    "R-SECRET": {"slug": "protected-secret-files"},
    "R-SQL": {"slug": "sql-no-rollback-dry-run"},
    "R-BROWSER": {"slug": "no-js-in-admin-browser"},
}

# Switch CLI lines that change state (D-Link classic, industry-standard, Dell N).
SWITCH_WRITE_RE = re.compile(
    r"(?im)\b(config\s+(ports|traffic\s+control|stp|vlan|ipif|loopdetect|lldp)\b[^\"'\n;|]*"
    r"|enable\s+(loopdetect|stp|lldp)\b[^\"'\n;|]*"
    r"|disable\s+(loopdetect|stp|lldp)\b[^\"'\n;|]*"
    r"|save(\s+(config|all))?\s*$"
    r"|(no\s+)?shutdown\b(?!\s*(-|now|\+|\d))"  # not Linux `shutdown -r now`
    r"|spanning-tree\b[^\"'\n;|]*"
    r"|storm-control\b[^\"'\n;|]*"
    # more writes, so read_only profiles are actually checked
    r"|(create|delete)\s+vlan\b[^\"'\n;|]*|reboot\s*$|reset\s+(config|system)\b[^\"'\n;|]*"
    r"|copy\s+running-config\b[^\"'\n;|]*|write\s+memory\b"
    r"|config\s+(account|snmp|bpdu_protection)\b[^\"'\n;|]*)"
)
# Evidence that the command talks to a network device at all. Local tool names and
# device address ranges are added from rule_guard.device_tool_patterns and
# rule_guard.device_address_patterns.
DEVICE_TRANSPORT_WORDS = r"plink|ssh|telnet|expect|pexpect|netmiko|paramiko|telnetlib"
PROFILE_DECL_RE = re.compile(r"registry-profile:\s*([A-Za-z0-9_.-]+)")

UPLOAD_RE = re.compile(r"(?i)\b(scp|pscp|rsync|sftp)\b")
SCRIPT_EXT = (".pl", ".pm", ".py", ".sh", ".cgi", ".bash", ".conf", ".service")


def _patterns(key: str) -> list[str]:
    value = settings().get(key) or []
    return [str(p) for p in value if isinstance(p, str) and p]


def device_transport_re() -> re.Pattern:
    extra = _patterns("device_tool_patterns") + _patterns("device_address_patterns")
    alternatives = "|".join([DEVICE_TRANSPORT_WORDS] + [f"(?:{p})" for p in extra])
    return re.compile(rf"(?i)\b(?:{alternatives})\b")


def load_registry(path: Path | None = None) -> dict:
    p = path or registry_path()
    if p is None:
        raise FileNotFoundError("no device registry configured")
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _template_to_regex(tpl: str) -> re.Pattern:
    out, pos = "", 0
    for m in re.finditer(r"\{(\w+)\}", tpl):
        out += re.escape(tpl[pos:m.start()]) + r"(?P<%s>[^\s]+)" % m.group(1)
        pos = m.end()
    out += re.escape(tpl[pos:])
    out = out.replace(r"\ ", r"\s+")
    return re.compile(r"^\s*" + out + r"\s*$", re.I)


def profile_templates(reg: dict, profile: str) -> list[tuple[str, str, str]]:
    """Return (key, template, status) for every command the registry knows for a profile."""
    prof = reg.get("profiles", {}).get(profile)
    if prof is None:
        return []
    out = []
    for key in ("paging_off", "identify", "port_state_read"):
        if isinstance(prof.get(key), str):
            out.append((key, prof[key], "verified"))
    # A profile whose note says the write syntax is not live-tested stays unverified.
    port_status = "unverified" if "not yet live-tested" in str(prof.get("note", "")).lower() else "verified"
    for key in ("port_disable", "port_enable"):
        v = prof.get(key)
        for t in (v if isinstance(v, list) else []):
            out.append((key, t, port_status))
    for key, spec in (reg.get("wave", {}).get(profile) or {}).items():
        if isinstance(spec, dict) and isinstance(spec.get("cmd"), str):
            out.append(("wave." + key, spec["cmd"], spec.get("status", "unknown")))
    return out


def validate_lines(reg: dict, profile: str, lines: list[str]) -> list[str]:
    """Return problems; empty list means every line is a registry command for this profile."""
    probs = []
    prof = reg.get("profiles", {}).get(profile)
    if prof is None:
        return [f"profile '{profile}' is not in the registry ({', '.join(reg.get('detect_order', []))})"]
    tpls = [(k, t, s, _template_to_regex(t)) for k, t, s in profile_templates(reg, profile)]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        hit = None
        for k, t, s, rx in tpls:
            m = rx.match(line)
            if m:
                hit = (k, t, s, m)
                break
        if hit is None:
            probs.append(f"line not in registry profile {profile}: {line!r}")
            continue
        k, t, s, m = hit
        is_write = not (k in ("paging_off", "identify", "port_state_read") or k.endswith("_read"))
        if is_write and prof.get("read_only"):
            probs.append(f"profile {profile} is read_only; write line refused: {line!r}")
        if s != "verified":
            probs.append(f"registry command {k} is '{s}' (not live-verified): {line!r}")
        # max_port limits port ON/OFF only: uplink or ring ports on core switches are
        # legitimate targets of "wave" keys.
        port = m.groupdict().get("port")
        if (k in ("port_disable", "port_enable") and port and prof.get("max_port")
                and port.isdigit() and int(port) > int(prof["max_port"])):
            probs.append(f"port {port} > max_port {prof['max_port']} for {profile}: {line!r}")
    return probs


def exempt_res() -> list[re.Pattern]:
    """Sub-commands that are a sanctioned registry path themselves (a runner that reads the
    registry on the remote side). Only the matching segment is skipped, not the whole line."""
    out = []
    for p in _patterns("exempt_command_patterns"):
        try:
            out.append(re.compile(p))
        except re.error:
            continue
    return out


def check_switch(command: str, reg_loader=load_registry) -> list[str]:
    exempt = exempt_res()
    segs = [x for x in re.split(r"\n|;|&&|\|\||\|", command) if not any(rx.search(x) for rx in exempt)]
    command = "\n".join(segs)
    writes = [m.group(0).strip() for m in SWITCH_WRITE_RE.finditer(command)]
    if not writes or not device_transport_re().search(command):
        return []
    decl = PROFILE_DECL_RE.search(command)
    tag = "[R-SWITCH device-command-registry-first]"
    if not decl:
        return [f"{tag} switch CLI write lines found but no 'registry-profile: <profile>' declared; "
                f"take the model profile from the device registry first. Lines: {writes[:4]}"]
    try:
        reg = reg_loader()
    except Exception:  # fail-open: missing/unreadable registry = allow silently
        return []
    return [f"{tag} {p}" for p in validate_lines(reg, decl.group(1), writes)]


def _upload_sources(command: str) -> list[str]:
    try:
        # posix=False keeps Windows backslashes; strip quotes ourselves
        toks = [t.strip("\"'") for t in shlex.split(command, posix=False)]
    except ValueError:
        toks = command.split()
    srcs = []
    for i, t in enumerate(toks):
        if UPLOAD_RE.fullmatch(os.path.basename(t).replace(".exe", "")):
            args = [a for a in toks[i + 1:] if not a.startswith("-")]
            # last arg is the destination; earlier existing local paths are sources
            for a in args[:-1]:
                if a.lower().endswith(SCRIPT_EXT) and ":" not in a[2:]:
                    srcs.append(a)
    return srcs


def check_lf(command: str) -> list[str]:
    if not UPLOAD_RE.search(command):
        return []
    probs = []
    for src in _upload_sources(command):
        p = Path(src)
        if not p.is_file():
            continue
        data = p.read_bytes()
        n_crlf = data.count(b"\r\n")
        if n_crlf:
            probs.append(f"[R-LF deploy-lf-line-endings] {src} has CRLF line endings ({n_crlf} lines); "
                         f"convert to LF and run it as the real user on the target before deploy")
    return probs


def mode() -> str:
    m = os.environ.get(ENV_MODE) or str(settings().get("mode") or "warn")
    return m if m in ("warn", "enforce", "off") else "warn"


# ---- R-SECRET / R-SQL / R-BROWSER ----------------------------------------------------------
READ_VERB_RE = re.compile(r"(?i)\b(cat|type|more|less|head|tail|grep|rg|findstr|select-string|get-content|gc|sed|awk|open|copy|cp|xcopy)\b")
SQL_WRITE_RE = re.compile(r"(?i)\b(delete\s+from|update\s+\w+\s+set|replace\s+into|truncate\s+table|drop\s+table|alter\s+table)\b")


def secret_path_re() -> re.Pattern | None:
    pats = _patterns("protected_secret_paths")
    if not pats:
        return None
    return re.compile("(?i)(" + "|".join(f"(?:{p})" for p in pats) + ")")


def secret_tool() -> str:
    return str(settings().get("secret_tool") or "")


def check_secret_command(cmd: str) -> list[str]:
    rx = secret_path_re()
    tool = secret_tool()
    if rx is None or (tool and tool in cmd) or not rx.search(cmd) or not READ_VERB_RE.search(cmd):
        return []
    use = f"use {tool}" if tool else "use the secret tool"
    return [f"[R-SECRET protected-secret-files] command reads a protected secrets file; "
            f"{use}, never print a value, its part or its length"]


def check_secret_path(path: str) -> list[str]:
    rx = secret_path_re()
    if rx is None or not path:
        return []
    if rx.search(path.replace("/", "\\")) or rx.search(path):
        tool = secret_tool()
        return ["[R-SECRET protected-secret-files] direct read of a protected secrets file; "
                + (f"use {tool} instead" if tool else "use the secret tool instead")]
    return []


def check_sql(cmd: str) -> list[str]:
    targets = _patterns("sql_write_targets")
    if not targets or not SQL_WRITE_RE.search(cmd):
        return []
    if not re.search("(?i)(" + "|".join(f"(?:{p})" for p in targets) + ")", cmd):
        return []
    marker = str(settings().get("sql_write_marker") or "db-write-go:")
    probs = []
    if re.search(r"(?i)\brollback\b", cmd):
        probs.append("[R-SQL sql-no-rollback-dry-run] write + ROLLBACK as a 'dry run': a non-transactional "
                     "engine (MyISAM) ignores rollback, the write is real. Estimate with SELECT COUNT(*) instead")
    elif not re.search(re.escape(marker) + r"\s*\S+", cmd):
        probs.append(f"[R-SQL sql-no-rollback-dry-run] SQL write to a protected database without "
                     f"'# {marker} <ref>' marker; such writes need an operator GO")
    return probs


def check_browser(tool: str, tool_input: dict) -> list[str]:
    warning = settings().get("browser_js_warning")
    if warning and "javascript_tool" in tool:
        return [f"[R-BROWSER no-js-in-admin-browser] {warning}"]
    return []


def evaluate(payload: dict) -> list[str]:
    tool = payload.get("tool_name", "") or ""
    ti = payload.get("tool_input") or {}
    if tool in ("Bash", "PowerShell"):
        cmd = ti.get("command", "") or ""
        return check_switch(cmd) + check_lf(cmd) + check_secret_command(cmd) + check_sql(cmd)
    if tool in ("Read", "Grep", "Glob", "NotebookRead"):
        return check_secret_path(str(ti.get("file_path") or ti.get("path") or ti.get("pattern") or ""))
    return check_browser(tool, ti)


def hook_main(warn_only: bool = False) -> int:
    """Fail-open: any exception, bad input or >0.9 s runtime -> exit 0 with no output (allow)."""
    import threading
    t = threading.Timer(0.9, lambda: os._exit(0))
    t.daemon = True
    t.start()
    try:
        md = "warn" if warn_only else mode()
        if warn_only and mode() == "off":
            md = "off"
        if md == "off":
            return 0
        payload = json.load(sys.stdin)
        probs = evaluate(payload)
    except Exception:
        return 0
    if not probs:
        return 0
    reason = "RULE GUARD: " + " | ".join(probs)
    if md == "enforce":
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                      "permissionDecisionReason": reason}}
    else:
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": reason + " (warn mode)"},
               "systemMessage": reason + " (warn mode)"}
    print(json.dumps(out, ensure_ascii=False))
    return 0


def main(argv: list[str]) -> int:
    """argv[0] is the program name, as in sys.argv."""
    if len(argv) > 1 and argv[1] == "hook":
        # installed form: `hook --warn-only` -> never denies, whatever the mode says (off still honoured)
        return hook_main(warn_only="--warn-only" in argv[2:])
    if len(argv) > 1 and argv[1] == "validate":
        import argparse
        ap = argparse.ArgumentParser(prog="integrity-guards rule-guard")
        ap.add_argument("cmd")
        ap.add_argument("--profile", required=True)
        ap.add_argument("--line", action="append", default=[])
        ap.add_argument("--registry", help="device registry JSON (default: configured)")
        a = ap.parse_args(argv[1:])
        probs = validate_lines(load_registry(Path(a.registry) if a.registry else None), a.profile, a.line)
        print(json.dumps({"ok": not probs, "problems": probs}, ensure_ascii=False, indent=1))
        return 0 if not probs else 2
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
