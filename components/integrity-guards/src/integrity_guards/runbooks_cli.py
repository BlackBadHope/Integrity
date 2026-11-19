"""integrity-guards runbooks: install, check, run and remove the event-driven runbook dispatcher.

  integrity-guards runbooks init [--home DIR] [--config FILE] [--systemd-user [--unit-dir DIR]] [--windows-task]
  integrity-guards runbooks doctor [--home DIR] [--json]       read-only self-check (exit 1 on a failed check)
  integrity-guards runbooks validate [--home DIR | FILE]        check the configuration against the compiled routes
  integrity-guards runbooks explain TRIGGER --line TEXT         what a line would do; runs nothing
  integrity-guards runbooks serve [--home DIR]                   the dispatcher loop (systemd or a scheduled task runs it)
  integrity-guards runbooks report [--hours N] [--json]          turns, proposals and spend from the journal
  integrity-guards runbooks proposals                            write routes that wait for an operator GO
  integrity-guards runbooks uninstall [--home DIR] [--yes]       dry run without --yes

The instance folder holds runbooks.json (the configuration, "enabled": false after init),
journal.jsonl (hash-chained decisions) and state.json (offsets, cursors, limits). It is
INTEGRITY_RUNBOOKS_HOME, or integrity-runbooks under the per-user state folder.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from integrity_guards import runbooks as rb

PROFILE = "integrity-runbooks/v1"
ENV_HOME = "INTEGRITY_RUNBOOKS_HOME"
UNIT_NAME = "integrity-runbooks.service"
UNIT_MARK = "# integrity-runbooks: written by integrity-guards runbooks init"
TASK_NAME = "IntegrityRunbooks"


def default_home() -> Path:
    configured = os.environ.get(ENV_HOME)
    if configured:
        return Path(configured)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "integrity-runbooks"


def default_unit_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


def starter_config(compiled_routes: str | None = None) -> dict[str, Any]:
    return {
        "format": rb.CONFIG_FORMAT,
        "enabled": False,
        "compiled_routes": compiled_routes,
        "limits": {"max_concurrent": 1, "max_turns_per_hour": 6, "poll_s": 2},
        "killswitch": {"required": True},
        "listen": {"syslog_udp": None, "webhook_http": None, "webhook_token_env": None},
        "notify": None,
        "event_sinks": {"local_memory_home": None, "command": None, "kinds": list(rb.DEFAULT_SINK_KINDS)},
        "adapters": {},
        "triggers": [],
    }


def serve_argv(home: Path, python: str | None = None) -> list[str]:
    return [python or sys.executable, "-m", "integrity_guards", "runbooks", "serve", "--home", str(home)]


def unit_text(home: Path, python: str | None = None) -> str:
    def quote(arg: str) -> str:
        return arg if re.fullmatch(r"[A-Za-z0-9_.@%+=:/-]+", arg) else '"' + arg.replace('"', '\\"') + '"'

    quoted = " ".join(quote(a.replace("\\", "/")) for a in serve_argv(home, python))
    return "\n".join([
        UNIT_MARK,
        "[Unit]",
        "Description=Integrity runbook dispatcher (event-driven Uroboros routes)",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={quoted}",
        "Restart=on-failure",
        "RestartSec=30",
        "NoNewPrivileges=yes",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ])


def windows_task_command(home: Path, python: str | None = None) -> str:
    py = python or sys.executable
    pyw = str(Path(py).with_name("pythonw.exe")) if Path(py).name.lower() == "python.exe" else py
    action = f'\\"{pyw}\\" -m integrity_guards runbooks serve --home \\"{home}\\"'
    return f'schtasks /Create /SC ONLOGON /RL LIMITED /TN {TASK_NAME} /TR "{action}"'


def _read_instance(home: Path) -> dict[str, Any] | None:
    try:
        data = json.loads((home / "instance.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("profile") == PROFILE else None


def load_config(home: Path) -> dict[str, Any]:
    return json.loads((home / "runbooks.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- commands


def cmd_init(args: argparse.Namespace) -> int:
    home = (args.home or default_home()).absolute()
    if home.exists() and (not home.is_dir() or any(home.iterdir())):
        print(f"runbooks: {home} exists and is not an empty folder; nothing was changed", file=sys.stderr)
        return 2
    if args.config:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        config["enabled"] = bool(config.get("enabled", False)) and args.enable
    else:
        config = starter_config(args.compiled_routes)
    rb.validate_config(config)  # format only; routes are checked by doctor and serve
    unit_path = None
    if args.systemd_user:
        if os.name == "nt" and not args.unit_dir:
            print("runbooks: --systemd-user is for Linux; use --windows-task on Windows", file=sys.stderr)
            return 2
        unit_path = (args.unit_dir or default_unit_dir()).absolute() / UNIT_NAME
        if unit_path.exists():
            print(f"runbooks: {unit_path} exists; nothing was changed", file=sys.stderr)
            return 2
    home.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        home.chmod(0o700)
    (home / "runbooks.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    instance = {"profile": PROFILE, "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "unit_file": str(unit_path) if unit_path else None}
    (home / "instance.json").write_text(json.dumps(instance, indent=2) + "\n", encoding="utf-8")
    print(f"Created a runbook dispatcher instance in {home}")
    print(f"Configuration: {home / 'runbooks.json'} (enabled: {str(config['enabled']).lower()})")
    if unit_path:
        unit_path.parent.mkdir(parents=True, exist_ok=True)
        unit_path.write_text(unit_text(home), encoding="utf-8")
        print(f"Wrote the systemd user unit {unit_path} (not enabled).")
        print(f"Start it yourself: systemctl --user daemon-reload && systemctl --user enable --now {UNIT_NAME}")
    if args.windows_task:
        print("Register a logon task yourself (not run by init):")
        print("  " + windows_task_command(home))
    print("Next: add triggers, set \"enabled\": true, then: integrity-guards runbooks doctor")
    return 0


def _check(rows: list[dict[str, str]], name: str, result: str, detail: str) -> None:
    rows.append({"check": name, "result": result, "detail": detail})


def doctor_report(home: Path) -> dict[str, Any]:
    """Read-only. Creates no file, starts no listener, asks no model."""
    rows: list[dict[str, str]] = []
    instance = _read_instance(home)
    if instance is None:
        _check(rows, "instance", "FAIL", f"no runbook dispatcher instance in {home}")
        return {"home": str(home), "checks": rows, "ok": False}
    _check(rows, "instance", "PASS", str(home))
    try:
        raw = load_config(home)
    except (OSError, ValueError) as exc:
        _check(rows, "config", "FAIL", f"runbooks.json unreadable: {type(exc).__name__}")
        return {"home": str(home), "checks": rows, "ok": False}
    base = rb.routes_dir(raw)
    routes = rb.load_routes(base)
    if base is None:
        _check(rows, "compiled_routes", "WARN", "no compiled routes folder configured")
    elif not base.is_dir():
        _check(rows, "compiled_routes", "FAIL", f"{base} is not a folder")
    else:
        _check(rows, "compiled_routes", "PASS", f"{len(routes)} valid compiled routes in {base}")
    try:
        config = rb.validate_config(raw, routes)
    except rb.RunbookError as exc:
        _check(rows, "config", "FAIL", str(exc))
        return {"home": str(home), "checks": rows, "ok": False}
    triggers = config["triggers"]
    _check(rows, "config", "PASS", f"{len(triggers)} triggers")
    _check(rows, "enabled", "PASS" if config["enabled"] else "WARN",
           "enabled" if config["enabled"] else "enabled is false: serve runs nothing")
    writes = sorted({t["route_id"] for t in triggers if routes[t["route_id"]]["safety"] == "write"})
    if writes:
        _check(rows, "write_routes", "PASS", "proposal only, never executed: " + ", ".join(writes))
    used = {t["adapter"] for t in triggers if t["enabled"]}
    for name in sorted(used):
        adapter = config["adapters"][name]
        if adapter["kind"] == "command":
            exe = adapter["argv"][0]
            found = shutil.which(exe)
            _check(rows, f"adapter:{name}", "PASS" if found else "WARN",
                   f"{exe} found" if found else f"{exe} is not on PATH")
    vendors = sorted({config["adapters"][n]["vendor"] for n in used} or {"service"})
    try:
        from integrity_killswitch import killswitch as ks
    except ImportError:
        if config["killswitch"]["required"]:
            _check(rows, "killswitch", "FAIL", "integrity-killswitch is not installed; nothing would run")
        else:
            _check(rows, "killswitch", "WARN", "not installed; killswitch.required is false")
    else:
        try:
            ks.configure(ks.load_config())
        except (OSError, ValueError):
            ks.configure({})
            _check(rows, "killswitch_config", "WARN", "the kill switch configuration is unreadable")
        path = ks.state_path()
        if not path.exists():
            _check(rows, "killswitch", "PASS", f"no state file yet ({path}); vendors are on by default")
        else:
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
                blocked = ["master panic"] if state.get("master_panic") else []
                for vendor in vendors:
                    info = (state.get("vendors") or {}).get(vendor)
                    if info is not None and not info.get("enabled", True):
                        blocked.append(f"{vendor} off")
                    elif info is None and vendor not in ks.DEFAULT_VENDORS:
                        blocked.append(f"{vendor} not registered")
                _check(rows, "killswitch", "WARN" if blocked else "PASS",
                       ("blocks: " + ", ".join(blocked)) if blocked else "allows " + ", ".join(vendors))
            except (OSError, ValueError):
                _check(rows, "killswitch", "WARN", "state file unreadable: the switch fails closed")
    kinds = {t["source"]["kind"] for t in triggers}
    if "journald" in kinds:
        if not sys.platform.startswith("linux"):
            _check(rows, "journald", "FAIL", "journald sources work on Linux only")
        else:
            _check(rows, "journald", "PASS" if shutil.which("journalctl") else "FAIL",
                   "journalctl found" if shutil.which("journalctl") else "journalctl is not on PATH")
    for key in ("syslog_udp", "webhook_http"):
        if config["listen"].get(key):
            _check(rows, f"listen:{key}", "PASS", f"{config['listen'][key]} (loopback only)")
    if config["listen"].get("webhook_http") and not config["listen"].get("webhook_token_env"):
        _check(rows, "listen:webhook_token", "WARN",
               "webhook listener without a token: any local process can post events; "
               "set listen.webhook_token_env")
    ok, detail = rb.Journal(home / "journal.jsonl").verify()
    _check(rows, "journal", "PASS" if ok else "FAIL", detail)
    unit = instance.get("unit_file")
    if unit:
        _check(rows, "systemd_unit", "PASS" if Path(unit).is_file() else "WARN",
               unit if Path(unit).is_file() else f"{unit} is missing")
    return {"home": str(home), "checks": rows, "ok": not any(r["result"] == "FAIL" for r in rows)}


def cmd_doctor(args: argparse.Namespace) -> int:
    report = doctor_report((args.home or default_home()).absolute())
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for row in report["checks"]:
            print(f"{row['result']:<5} {row['check']:<22} {row['detail']}")
    return 0 if report["ok"] else 1


def _config_and_routes(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], Path]:
    home = (args.home or default_home()).absolute()
    path = Path(args.file) if getattr(args, "file", None) else home / "runbooks.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    return raw, rb.load_routes(rb.routes_dir(raw)), home


def cmd_validate(args: argparse.Namespace) -> int:
    raw, routes, _home = _config_and_routes(args)
    config = rb.validate_config(raw, routes)
    for trigger in config["triggers"]:
        safety = routes[trigger["route_id"]]["safety"]
        effect = "runs" if safety == "read" else "proposal only"
        print(f"ok: {trigger['trigger_id']} -> {trigger['route_id']} [{safety}, {effect}] "
              f"via {trigger['adapter']} ({trigger['source']['kind']})")
    print(f"-- {len(config['triggers'])} triggers valid")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    """The decision a line would get, without the kill switch, the limits or any execution."""
    raw, routes, _home = _config_and_routes(args)
    config = rb.validate_config(raw, routes)
    trigger = next((t for t in config["triggers"] if t["trigger_id"] == args.trigger), None)
    if trigger is None:
        print(json.dumps({"ok": False, "error": f"no trigger {args.trigger}"}))
        return 2
    match = re.search(trigger["match"], args.line[:rb.MAX_LINE])
    if match is None:
        print(json.dumps({"trigger_id": trigger["trigger_id"], "matched": False}))
        return 1
    route = routes[trigger["route_id"]]
    values, problem = rb.extract_params(trigger, route, match)
    out: dict[str, Any] = {"trigger_id": trigger["trigger_id"], "matched": True, "route_id": route["route_id"],
                           "safety": route["safety"]}
    if values is None:
        out.update({"decision": "rejected", "reason": problem})
    else:
        out.update({"params": values, "decision": "turn" if route["safety"] == "read" else "proposal",
                    "command": rb.route_command(route["route_id"], values)})
    print(json.dumps(out, ensure_ascii=False))
    return 0 if values is not None else 1


def cmd_serve(args: argparse.Namespace) -> int:
    home = (args.home or default_home()).absolute()
    if _read_instance(home) is None:
        print(f"runbooks: no instance in {home}; run: integrity-guards runbooks init", file=sys.stderr)
        return 2
    return rb.Dispatcher(load_config(home), home).serve()


def cmd_report(args: argparse.Namespace) -> int:
    home = (args.home or default_home()).absolute()
    report = rb.spend_report(rb.Journal(home / "journal.jsonl").records(), hours=args.hours)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    window = f"last {args.hours} h" if args.hours else "all time"
    print(f"Runbook dispatcher, {window}: {report['records']} decisions")
    for kind, count in sorted(report["by_kind"].items()):
        print(f"  {kind:<13} {count}")
    for name, slot in sorted(report["by_adapter"].items()):
        print(f"  adapter {name}: {slot['turns']} turns, {slot['ok']} ok, {slot['seconds']} s, "
              f"{slot['model_turns']} model turns")
    print(f"  model cost reported: {report['model_cost_usd']} USD over {report['model_turns_with_cost']} turns; "
          f"{report['model_turns_without_cost']} model turns reported no cost")
    return 0


def cmd_proposals(args: argparse.Namespace) -> int:
    home = (args.home or default_home()).absolute()
    rows = [r for r in rb.Journal(home / "journal.jsonl").records() if r.get("kind") == "proposal"]
    for row in rows[-args.limit:]:
        print(f"{row['ts']} {row['trigger_id']} -> {row['route_id']}: {row.get('route_summary', '')}")
        print(f"    with GO: {row['go_command']}")
    print(f"-- {len(rows)} proposals in the journal (nothing was executed)")
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    home = (args.home or default_home()).absolute()
    instance = _read_instance(home)
    if instance is None:
        if home.exists():
            print(f"runbooks: {home} is not a runbook dispatcher instance; nothing was removed", file=sys.stderr)
            return 2
        print(f"No runbook dispatcher instance in {home}.")
        return 0
    unit = Path(instance["unit_file"]) if instance.get("unit_file") else None
    owned_unit = unit if unit and unit.is_file() and UNIT_MARK in unit.read_text(encoding="utf-8") else None
    if not args.yes:
        print(f"Dry run. --yes removes {home} (configuration, journal, state)"
              + (f" and {owned_unit}" if owned_unit else "") + ".")
        if owned_unit:
            print(f"Stop the service first: systemctl --user disable --now {UNIT_NAME}")
        return 0
    if owned_unit:
        owned_unit.unlink()
        print(f"Removed {owned_unit}. Run: systemctl --user daemon-reload")
    shutil.rmtree(home)
    print(f"Removed {home}. A Windows logon task, if you registered one: schtasks /Delete /TN {TASK_NAME} /F")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="integrity-guards runbooks", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def command(name: str, text: str) -> argparse.ArgumentParser:
        item = sub.add_parser(name, help=text)
        item.add_argument("--home", type=Path, default=None,
                          help=f"instance folder (default: ${ENV_HOME} or the per-user state folder)")
        return item

    item = command("init", "create an instance (disabled) and optionally a systemd user unit")
    item.add_argument("--config", help="start from this configuration file instead of the empty one")
    item.add_argument("--enable", action="store_true", help="keep enabled: true from --config")
    item.add_argument("--compiled-routes", help="compiled routes folder for the starter configuration")
    item.add_argument("--systemd-user", action="store_true", help="write a systemd user unit (not enabled)")
    item.add_argument("--unit-dir", type=Path, help="folder for the unit (default: ~/.config/systemd/user)")
    item.add_argument("--windows-task", action="store_true", help="print the logon task command for Windows")
    item = command("doctor", "read-only self-check")
    item.add_argument("--json", action="store_true")
    item = command("validate", "check the configuration against the compiled routes")
    item.add_argument("file", nargs="?", help="a configuration file instead of the instance's")
    item = command("explain", "show what a line would do; runs nothing")
    item.add_argument("trigger")
    item.add_argument("--line", required=True)
    item.add_argument("--file", help="a configuration file instead of the instance's")
    command("serve", "run the dispatcher loop")
    item = command("report", "turns, proposals and spend from the journal")
    item.add_argument("--hours", type=float)
    item.add_argument("--json", action="store_true")
    item = command("proposals", "write routes that wait for an operator GO")
    item.add_argument("--limit", type=int, default=20)
    item = command("uninstall", "remove the instance (dry run without --yes)")
    item.add_argument("--yes", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"init": cmd_init, "doctor": cmd_doctor, "validate": cmd_validate, "explain": cmd_explain,
                "serve": cmd_serve, "report": cmd_report, "proposals": cmd_proposals, "uninstall": cmd_uninstall}
    try:
        return handlers[args.cmd](args)
    except (rb.RunbookError, OSError, ValueError) as exc:
        print(f"runbooks: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
