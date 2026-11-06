# SPDX-License-Identifier: BUSL-1.1
"""integrity-doctor: where Integrity hooks are installed, whether memory answers, and coverage.

Read-only. It reads vendor settings files, starts the registered MCP transport
once for ``initialize`` / ``tools/list`` (and, unless ``--no-coverage``, one
read-only ``integrity_turn_memory_coverage`` call), and reads the local turn
log written by the hooks. It writes nothing, appends no event and never prints
environment values or credentials from the files it reads.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
from typing import Any

from . import turn_guard

HOOK_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
               "SubagentStop", "PreInvocation")
ARG_RE = re.compile(r"--(state-root|transport|profile|envelope-root)(?:=|\s+)(?:\"([^\"]+)\"|'([^']+)'|(\S+))")
MAX_FILE = 8 * 1024 * 1024


def _read_json(path: Path) -> Any:
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            return None
        return json.loads(path.read_text(encoding="utf-8-sig"))  # tolerate a Windows BOM
    except (OSError, ValueError, UnicodeError):
        return None


def _home() -> Path:
    return Path(os.environ.get("INTEGRITY_DOCTOR_HOME") or Path.home())


def _codex_home(home: Path) -> Path:
    explicit = os.environ.get("CODEX_HOME")
    return Path(explicit) if explicit and not os.environ.get("INTEGRITY_DOCTOR_HOME") else home / ".codex"


def candidate_hook_files(project: Path, home: Path | None = None) -> list[tuple[str, str, Path]]:
    """(vendor, scope, path) for every hook file a client may load."""

    home = home or _home()
    rows: list[tuple[str, str, Path]] = [
        ("claude", "user", home / ".claude" / "settings.json"),
        ("claude", "user-local", home / ".claude" / "settings.local.json"),
    ]
    managed = []
    if os.name == "nt":
        managed = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClaudeCode" / "managed-settings.json"]
    elif sys.platform == "darwin":
        managed = [Path("/Library/Application Support/ClaudeCode/managed-settings.json")]
    else:
        managed = [Path("/etc/claude-code/managed-settings.json")]
    rows += [("claude", "managed", path) for path in managed]
    # Claude Code reads project settings from the project folder itself.
    rows.append(("claude", f"project:{project}", project / ".claude" / "settings.json"))
    rows.append(("claude", f"project-local:{project}", project / ".claude" / "settings.local.json"))
    # Codex layers project .codex folders from the project up; a home folder is user scope.
    homes = {home.absolute(), Path.home().absolute()}
    for folder in (project, *project.parents):
        if folder.absolute() in homes:
            break
        label = "project" if folder == project else "parent-project"
        rows.append(("codex", f"{label}:{folder}", folder / ".codex" / "hooks.json"))
    rows.append(("codex", "user", _codex_home(home) / "hooks.json"))
    rows.append(("antigravity", "user-plugin", home / ".gemini" / "config" / "plugins" / "integrity-native" / "hooks.json"))
    return rows


def _hook_tables(vendor: str, document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    tables = []
    if isinstance(document.get("hooks"), dict):
        tables.append(document["hooks"])
    if vendor == "antigravity":
        tables += [value for value in document.values() if isinstance(value, dict)]
    return tables


def _commands(entries: Any) -> list[str]:
    found: list[str] = []
    if not isinstance(entries, list):
        return found
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("command"), str):
            found.append(entry["command"])
        for inner in entry.get("hooks", []) if isinstance(entry.get("hooks"), list) else []:
            if isinstance(inner, dict) and isinstance(inner.get("command"), str):
                found.append(inner["command"])
    return found


def scan_hooks(project: Path, home: Path | None = None) -> list[dict[str, Any]]:
    """Integrity hook registrations, without command bodies beyond their paths."""

    results = []
    for vendor, scope, path in candidate_hook_files(project, home):
        document = _read_json(path)
        if document is None:
            continue
        events: dict[str, int] = {}
        refs: dict[str, set[str]] = {"state-root": set(), "transport": set(), "profile": set()}
        for table in _hook_tables(vendor, document):
            for event, entries in table.items():
                for command in _commands(entries):
                    if "integrity" not in command.lower():
                        continue
                    events[event] = events.get(event, 0) + 1
                    for match in ARG_RE.finditer(command):
                        value = match.group(2) or match.group(3) or match.group(4)
                        if match.group(1) in refs:
                            refs[match.group(1)].add(value)
        if events:
            results.append({"vendor": vendor, "scope": scope, "path": str(path), "events": events,
                            "stop_hook": "Stop" in events,
                            "refs": {key: sorted(value) for key, value in refs.items() if value}})
    return results


def scan_mcp(project: Path, home: Path | None = None) -> list[dict[str, Any]]:
    """Integrity MCP server registrations (names and scope only)."""

    home = home or _home()
    rows = []
    claude = _read_json(home / ".claude.json")
    if isinstance(claude, dict):
        for name in (claude.get("mcpServers") or {}):
            if "integrity" in name.lower():
                rows.append({"vendor": "claude", "scope": "user", "server": name})
        for folder, entry in (claude.get("projects") or {}).items():
            if isinstance(entry, dict):
                for name in (entry.get("mcpServers") or {}):
                    if "integrity" in name.lower():
                        rows.append({"vendor": "claude", "scope": f"local:{folder}", "server": name})
    for folder in (project,):
        document = _read_json(folder / ".mcp.json")
        if isinstance(document, dict):
            for name in (document.get("mcpServers") or {}):
                if "integrity" in name.lower():
                    rows.append({"vendor": "claude", "scope": f"project:{folder}", "server": name})
    config = _codex_home(home) / "config.toml"
    try:
        import tomllib
        if config.is_file() and config.stat().st_size <= MAX_FILE:
            parsed = tomllib.loads(config.read_text(encoding="utf-8-sig"))
            for name, entry in (parsed.get("mcp_servers") or {}).items():
                if "integrity" in name.lower():
                    enabled = not (isinstance(entry, dict) and entry.get("enabled") is False)
                    rows.append({"vendor": "codex", "scope": "user", "server": name, "enabled": enabled})
    except (OSError, ValueError, UnicodeError):
        pass
    return rows


def transport_from(path: Path) -> dict[str, Any]:
    document = _read_json(path)
    if isinstance(document, dict) and document.get("protocol") == "integrity/native-client-profile/v1":
        document = _read_json(path.parent / "transport.json")
    transport = document.get("transport") if isinstance(document, dict) else None
    if not isinstance(transport, dict) or transport.get("type", "stdio") != "stdio" or not isinstance(
            transport.get("command"), str):
        raise ValueError("no stdio transport in " + str(path))
    return transport


class _Stdio:
    def __init__(self, transport: dict[str, Any], timeout: float) -> None:
        env = dict(os.environ)
        env.update({str(k): str(v) for k, v in (transport.get("env") or {}).items()})
        self.timeout = timeout
        self.process = subprocess.Popen(
            [transport["command"], *[str(a) for a in transport.get("args", [])]],
            # stderr must be a real pipe: some brokers exit at once on a NUL stderr handle.
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            # No CREATE_NO_WINDOW: a broker's ssh child needs the inherited console on Windows.
            text=True, encoding="utf-8", env=env, cwd=transport.get("cwd") or None)
        self.lines: queue.Queue[str] = queue.Queue()
        self.stderr_tail = ""
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()
        self.next_id = 1

    def _pump(self) -> None:
        try:
            for line in self.process.stdout:  # type: ignore[union-attr]
                self.lines.put(line)
        except (OSError, ValueError):
            pass
        self.lines.put("")

    def _drain(self) -> None:
        try:
            for line in self.process.stderr:  # type: ignore[union-attr]
                self.stderr_tail = (self.stderr_tail + line)[-600:]
        except (OSError, ValueError):
            pass

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        ident = self.next_id
        self.next_id += 1
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": ident, "method": method,
                                             "params": params}) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                line = self.lines.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                raise TimeoutError(f"{method}: no answer in {self.timeout:.0f}s") from None
            if not line:
                time.sleep(0.2)
                tail = self.stderr_tail.strip().splitlines()[-1:] or [""]
                raise ConnectionError(f"{method}: server closed the stream {tail[0][:200]}".rstrip())
            try:
                response = json.loads(line)
            except ValueError:
                continue
            if response.get("id") != ident:
                continue
            if response.get("error") is not None:
                raise RuntimeError(f"{method}: {str(response['error'])[:160]}")
            return response.get("result") or {}

    def notify(self, method: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": {}}) + "\n")
        self.process.stdin.flush()

    def close(self) -> None:
        try:
            if self.process.stdin:
                self.process.stdin.close()
            self.process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()


def probe(transport: dict[str, Any], *, coverage_limit: int | None, timeout: float = 30) -> dict[str, Any]:
    started = time.monotonic()
    client = None
    result: dict[str, Any] = {"answered": False}
    try:
        client = _Stdio(transport, timeout)
        init = client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                             "clientInfo": {"name": "integrity-doctor", "version": "1"}})
        client.notify("notifications/initialized")
        tools = client.request("tools/list", {}).get("tools") or []
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        result.update(answered=True, server=init.get("serverInfo"), tool_count=len(names),
                      has_admission="integrity_context_admission_current_turn" in names,
                      has_close="integrity_turn_memory_close" in names,
                      latency_seconds=round(time.monotonic() - started, 2))
        if coverage_limit and "integrity_turn_memory_coverage" in names:
            called = client.request("tools/call", {"name": "integrity_turn_memory_coverage",
                                                   "arguments": {"limit": coverage_limit}})
            result["coverage"] = summarize_coverage(called)
    except (OSError, ValueError, TimeoutError, ConnectionError, RuntimeError) as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    finally:
        if client is not None:
            client.close()
    return result


def summarize_coverage(called: dict[str, Any]) -> dict[str, Any]:
    if called.get("isError") is True:
        return {"error": "coverage call refused"}
    try:
        value = json.loads(called["content"][0]["text"])
    except (KeyError, IndexError, TypeError, ValueError):
        return {"error": "coverage result unreadable"}
    counts = value.get("counts") or value.get("known_counts") or {}
    registered = counts.get("registered") or 0
    terminal = counts.get("terminal") or 0
    return {"complete": value.get("complete"), "registered": registered, "terminal": terminal,
            "events": counts.get("events"), "no_event": counts.get("no_event"),
            "unresolved": counts.get("unresolved"),
            "close_rate": round(terminal / registered, 3) if registered else None}


def guard_roots(hooks: list[dict[str, Any]], extra: list[Path]) -> list[Path]:
    roots: list[Path] = []
    for row in hooks:
        for value in row.get("refs", {}).get("state-root", []):
            roots.append(Path(value).parent)
        for value in row.get("refs", {}).get("profile", []):
            roots.append(Path(value).parent)
    roots += extra
    unique = []
    for root in roots:
        if root not in unique:
            unique.append(root)
    return unique


def diagnose(args: argparse.Namespace) -> dict[str, Any]:
    project = Path(args.project).absolute()
    hooks = scan_hooks(project)
    report: dict[str, Any] = {"project": str(project), "hooks": hooks, "mcp": scan_mcp(project),
                              "findings": []}
    findings = report["findings"]
    for vendor in ("claude", "codex"):
        # Admission is wired on UserPromptSubmit; other Integrity hooks do not open memory.
        rows = [row for row in hooks if row["vendor"] == vendor and "UserPromptSubmit" in row["events"]]
        if not rows:
            if any(row["vendor"] == vendor for row in hooks):
                findings.append(f"{vendor}: Integrity hooks found but none on UserPromptSubmit, so no turn is admitted")
            continue
        if not any(row["scope"].startswith(("user", "managed")) for row in rows):
            folders = sorted({row["scope"].split(":", 1)[-1] for row in rows})
            findings.append(f"{vendor}: Integrity hooks are project-scoped only ({', '.join(folders)}); "
                            "sessions started in other folders run without Integrity memory")
        if not any(row["stop_hook"] for row in rows):
            findings.append(f"{vendor}: no Integrity Stop hook, so a missing turn close cannot be enforced")
    if not hooks:
        findings.append("no Integrity hooks found for Claude Code, Codex or Antigravity")
    transports: list[Path] = [Path(p) for p in args.transport]
    for row in hooks:
        transports += [Path(p) for p in row.get("refs", {}).get("transport", [])]
        transports += [Path(p) for p in row.get("refs", {}).get("profile", [])]
    probes = []
    if not args.no_probe:
        for path in dict.fromkeys(transports):
            entry: dict[str, Any] = {"transport_file": str(path)}
            try:
                entry.update(probe(transport_from(path), coverage_limit=None if args.no_coverage else args.last))
            except ValueError as exc:
                entry.update(answered=False, error=str(exc))
            probes.append(entry)
            if not entry.get("answered"):
                findings.append(f"memory server did not answer via {path}: {entry.get('error')}")
            elif not entry.get("has_close"):
                findings.append(f"memory server via {path} has no integrity_turn_memory_close tool")
            coverage = entry.get("coverage") or {}
            if coverage.get("close_rate") is not None and coverage["close_rate"] < 0.8:
                findings.append(f"server coverage: {coverage['terminal']}/{coverage['registered']} registered "
                                f"turns closed, {coverage['unresolved']} unresolved")
    report["probes"] = probes
    report["probe_skipped"] = bool(args.no_probe)
    guards = []
    for root in guard_roots(hooks, [Path(p) for p in args.state_root]):
        environ = {k: v for k, v in os.environ.items() if k != turn_guard.ENV_POLICY}
        policy = turn_guard.load_policy(root, environ)
        summary = turn_guard.summarize_turns(turn_guard.read_turn_log(root, args.last))
        guards.append({"root": str(root), "policy": policy, "last_turns": summary})
        if summary["owner_turns"] and (summary["admission_rate"] or 0) < 0.8:
            findings.append(f"{root}: admission in {summary['admitted']}/{summary['owner_turns']} "
                            "of the last owner turns")
        if summary["state_changing_turns"] and (summary["close_rate_state_changing"] or 0) < 0.8:
            findings.append(f"{root}: turn close in {summary['closed_state_changing']}/"
                            f"{summary['state_changing_turns']} of the last state-changing turns")
    report["turn_guard"] = guards
    return report


def render(report: dict[str, Any]) -> str:
    out = [f"Integrity doctor - project {report['project']}", "", "Hooks:"]
    if not report["hooks"]:
        out.append("  none found")
    for row in report["hooks"]:
        events = ", ".join(sorted(row["events"]))
        out.append(f"  [{row['vendor']}] {row['scope']}: {row['path']}")
        out.append(f"      events: {events}{'' if row['stop_hook'] else '  (no Stop hook)'}")
    out += ["", "MCP registrations:"]
    out += [f"  [{r['vendor']}] {r['scope']}: {r['server']}" + ("" if r.get("enabled", True) else " (disabled)")
            for r in report["mcp"]] or ["  none found"]
    out += ["", "Memory server:"]
    if report.get("probe_skipped"):
        out.append("  not probed (--no-probe)")
    elif not report["probes"]:
        out.append("  not probed (no transport found; pass --transport FILE)")
    for entry in report["probes"]:
        if entry.get("answered"):
            server = entry.get("server") or {}
            # serverInfo carries the broker protocol version, not the package version.
            out.append(f"  OK {entry['transport_file']}: {server.get('name')} (broker protocol {server.get('version')}), "
                       f"{entry['tool_count']} tools, {entry['latency_seconds']}s")
            cov = entry.get("coverage")
            if cov and "error" not in cov:
                out.append(f"     coverage: {cov['terminal']}/{cov['registered']} registered turns closed "
                           f"(events {cov['events']}, no-event {cov['no_event']}, unresolved {cov['unresolved']})")
            elif cov:
                out.append(f"     coverage: {cov['error']}")
        else:
            out.append(f"  FAIL {entry['transport_file']}: {entry.get('error')}")
    out += ["", "Turn guard (local log):"]
    if not report["turn_guard"]:
        out.append("  no hook state root found (pass --state-root DIR)")
    for guard in report["turn_guard"]:
        s = guard["last_turns"]
        out.append(f"  {guard['root']}: mode={guard['policy']['mode']} ({guard['policy']['source']})")
        if s["turns"]:
            out.append(f"     last {s['turns']} turns: admission {s['admitted']}/{s['owner_turns']} owner turns, "
                       f"close {s['closed_state_changing']}/{s['state_changing_turns']} state-changing turns, "
                       f"{s['exempt_turns']} exempt, {s['blocked']} blocked once")
            if s.get("no_event_after_change"):
                out.append(f"     {s['no_event_after_change']} state-changing turn(s) closed with outcome=no-event")
        else:
            out.append("     no turns logged yet")
    out += ["", "Findings:"]
    out += [f"  - {item}" for item in report["findings"]] or ["  none"]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="integrity-doctor", description=__doc__.split("\n\n")[0])
    parser.add_argument("--project", default=os.getcwd(), help="project folder to check (default: cwd)")
    parser.add_argument("--transport", action="append", default=[],
                        help="transport.json, admission-transport.json or profile.json to probe")
    parser.add_argument("--state-root", action="append", default=[],
                        help="directory holding turn-guard.json and turn-guard-log.jsonl")
    parser.add_argument("--last", type=int, default=50, help="turns to summarize (default 50)")
    parser.add_argument("--no-probe", action="store_true", help="do not start any MCP transport")
    parser.add_argument("--no-coverage", action="store_true", help="skip the coverage call")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    if args.last < 1 or args.last > 500:
        parser.error("--last must be 1..500")
    report = diagnose(args)
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render(report))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
