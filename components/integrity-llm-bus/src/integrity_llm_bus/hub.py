# SPDX-License-Identifier: BUSL-1.1
"""integrity-llm-bus-hub - install, check and remove the bus hub on one Linux machine.

  install    creates the bus account, the gateway account and the socket group, the
             configuration folder, the state folder and the socket folder (run as root)
  doctor     reads accounts, owners and modes, configuration, keys, journal chain,
             installed files against the wheel record; sends the daemon one request
             without a key, which it must refuse (its journal records the refusal)
  uninstall  says what it would remove; with --yes removes what install created

It starts no service. The hub daemon is started with the command that install and doctor
print; this tool installs no systemd unit, no SSH gateway and no journal seal.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time

from .configuration import COMPONENT, SCHEMA, ConfigurationError, read_config

RECORD = "hub.json"
RECORD_PROTOCOL = "integrity-llm-bus/hub-install/v1"
FILES = ("configuration.json", "core.json", "principals.json", RECORD)
NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
PRINCIPAL = re.compile(r"[a-z0-9-]{2,32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SECRET_FIELD = re.compile(r"(?i)token|secret|password|passwd|private")
# The daemon refuses every request of a key whose vendor is not one of these (VENDORS in bus_core_daemon.py).
VENDORS = ("antigravity", "bus", "claude", "codex", "grok", "human")
PACKAGE = Path(__file__).resolve().parent
DAEMON = PACKAGE / "resources" / "core" / "bus_core_daemon.py"
JOURNAL = PACKAGE / "resources" / "core" / "bus_journal.py"


class HubError(Exception):
    """The request cannot be carried out; nothing more is changed."""


def check_principals(document) -> list[str]:
    """Problems of a principals document; an empty list means it may be installed.

    The hub stores keys only as sha256. A field that looks like it holds a key itself is refused.
    """
    problems = []
    if not isinstance(document, dict) or not isinstance(document.get("principals"), dict):
        return ["principals.json must be an object with a 'principals' object"]
    if set(document) - {"principals", "accounts"}:
        problems.append("principals.json: only 'principals' and 'accounts' are allowed at the top")
    for name, entry in document["principals"].items():
        if not PRINCIPAL.match(name):
            problems.append(f"principal {name!r}: name must match [a-z0-9-]{{2,32}}")
            continue
        if not isinstance(entry, dict):
            problems.append(f"principal {name}: must be an object")
            continue
        for field in entry:
            if field != "key_sha256" and SECRET_FIELD.search(field):
                problems.append(f"principal {name}: field {field!r} may hold a secret; store key_sha256 only")
        key = entry.get("key_sha256")
        if key is not None and not (isinstance(key, str) and HEX64.match(key)):
            problems.append(f"principal {name}: key_sha256 must be 64 lowercase hex characters")
        if entry.get("vendor") not in VENDORS:
            problems.append(f"principal {name}: vendor must be one of {', '.join(VENDORS)} "
                            "(the hub refuses every request of a key without one)")
    if not isinstance(document.get("accounts", {}), dict):
        problems.append("principals.json: 'accounts' must be an object")
    return problems


def start_command(record: dict) -> dict:
    """How to start the daemon as the bus account, without systemd."""
    etc = Path(record["etc"])
    return {
        "user": record["bus_user"],
        "environment": {"INTEGRITY_LLM_BUS_CONFIG": str(etc / "configuration.json"),
                        "BUS_CORE_CONF": str(etc / "core.json")},
        "argv": [record["python"], "-I", "-B", str(DAEMON)],
    }


def _accounts():
    import grp
    import pwd
    return pwd, grp


def _run(argv: list[str]) -> None:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    if done.returncode != 0:
        raise HubError(f"{argv[0]} exited {done.returncode}: {done.stderr.strip()[:200]}")


def _tool(name: str) -> str:
    for folder in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        path = Path(folder) / name
        if path.is_file():
            return str(path)
    raise HubError(f"{name} not found")


def _write(path: Path, text: str, mode: int, gid: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chown(path, 0, gid)
    os.chmod(path, mode)


def _mkdir(path: Path, mode: int, uid: int, gid: int) -> None:
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def install(args) -> dict:
    if sys.platform != "linux":
        raise HubError("the hub runs on Linux only")
    if os.geteuid() != 0:
        raise HubError("install needs root: it creates accounts and folders owned by them")
    pwd, grp = _accounts()
    names = {"bus user": args.bus_user, "gateway user": args.gateway_user, "socket group": args.socket_group}
    for label, value in names.items():
        if not NAME.match(value):
            raise HubError(f"{label} {value!r}: use [a-z_][a-z0-9_-]{{0,31}}")
    if len(set(names.values())) != 3:
        raise HubError("bus user, gateway user and socket group must be three different names")
    etc, state, runtime = (Path(p) for p in (args.etc, args.state, args.runtime))
    for path in (etc, state, runtime):
        if not path.is_absolute():
            raise HubError(f"{path}: use an absolute path")
        if os.path.lexists(path):
            raise HubError(f"{path} exists; install creates it and refuses to reuse it")
    for user in (args.bus_user, args.gateway_user):
        try:
            pwd.getpwnam(user)
            raise HubError(f"account {user} exists; install creates its own accounts")
        except KeyError:
            pass
    for group in (args.socket_group, args.bus_user):
        try:
            grp.getgrnam(group)
            raise HubError(f"group {group} exists; install creates its own groups")
        except KeyError:
            pass
    try:
        principals = json.loads(Path(args.principals).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HubError(f"principals file: {type(exc).__name__}") from None
    problems = check_principals(principals)
    if problems:
        raise HubError("; ".join(problems))

    nologin = _tool("nologin")
    done: list[tuple[str, str]] = []
    try:
        _run([_tool("groupadd"), "--system", args.socket_group])
        done.append(("group", args.socket_group))
        done.append(("group-if-left", args.bus_user))   # undone after the account: userdel may remove it
        _run([_tool("useradd"), "--system", "--user-group", "--groups", args.socket_group, "--no-create-home",
              "--home-dir", "/nonexistent", "--shell", nologin, args.bus_user])
        done.append(("user", args.bus_user))
        _run([_tool("useradd"), "--system", "--gid", args.socket_group, "--no-create-home",
              "--home-dir", "/nonexistent", "--shell", nologin, args.gateway_user])
        done.append(("user", args.gateway_user))
        bus = pwd.getpwnam(args.bus_user)
        socket_gid = grp.getgrnam(args.socket_group).gr_gid
        record = {
            "protocol": RECORD_PROTOCOL, "bus_user": args.bus_user, "gateway_user": args.gateway_user,
            "socket_group": args.socket_group, "etc": str(etc), "state": str(state), "runtime": str(runtime),
            "python": sys.executable,
        }
        _mkdir(etc, 0o750, 0, bus.pw_gid)
        done.append(("dir", str(etc)))
        _mkdir(state, 0o700, bus.pw_uid, bus.pw_gid)
        done.append(("dir", str(state)))
        for sub in ("state", "journal"):
            _mkdir(state / sub, 0o700, bus.pw_uid, bus.pw_gid)
        _mkdir(runtime, 0o750, bus.pw_uid, socket_gid)
        done.append(("dir", str(runtime)))
        configuration = {
            "schema": SCHEMA, "component": COMPONENT, "configured": True,
            "guardian_version": "6.1.0", "memory_api_version": "2.11.0", "owner_local_catalogue": None,
            "values": {"state_directory": str(state / "state"), "core_config": str(etc / "core.json")},
        }
        core = {"state_dir": str(state / "state"), "principals": str(etc / "principals.json"),
                "journal_dir": str(state / "journal"), "socket": str(runtime / "core.sock"),
                "socket_group": args.socket_group, "gateway_user": args.gateway_user, "ttl_hours": 168}
        _write(etc / "configuration.json", json.dumps(configuration, indent=1) + "\n", 0o640, bus.pw_gid)
        _write(etc / "core.json", json.dumps(core, indent=1) + "\n", 0o640, bus.pw_gid)
        _write(etc / "principals.json", json.dumps(principals, indent=1) + "\n", 0o640, bus.pw_gid)
        _write(etc / RECORD, json.dumps(record, indent=1) + "\n", 0o600, 0)
    except BaseException:
        _undo(done)
        raise
    return {"status": "installed", "start": start_command(record),
            "not_installed": ["systemd unit", "SSH gateway", "journal seal"]}


def _undo(done: list[tuple[str, str]]) -> None:
    for kind, value in reversed(done):
        try:
            if kind == "dir":
                shutil.rmtree(value)
            elif kind == "user":
                _run([_tool("userdel"), value])
            else:
                _remove_group(value)
        except (OSError, HubError):
            pass


def _remove_group(name: str) -> None:
    """Remove a group if it still exists (userdel removes a user's own group on most systems)."""
    try:
        _accounts()[1].getgrnam(name)
    except KeyError:
        return
    _run([_tool("groupdel"), name])


def read_record(etc: Path) -> dict | None:
    path = etc / RECORD
    if not os.path.lexists(path):
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HubError(f"{path}: {type(exc).__name__}") from None
    if not isinstance(record, dict) or record.get("protocol") != RECORD_PROTOCOL:
        raise HubError(f"{path}: not a hub install record")
    return record


def _mode_check(path: Path, uid: int, gid: int, mode: int, kind) -> str | None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        return f"{path}: {type(exc).__name__}"
    if not kind(info.st_mode):
        return f"{path}: wrong file type"
    found = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
    if found != (uid, gid, mode):
        return f"{path}: owner {found[0]}:{found[1]} mode {found[2]:o}, expected {uid}:{gid} mode {mode:o}"
    return None


def _installed_files() -> list[str]:
    """Files of the installed wheel whose sha256 differs from its RECORD (empty: all match)."""
    from importlib import metadata
    import base64
    changed = []
    files = metadata.distribution(COMPONENT).files or []
    for item in files:
        if item.hash is None or item.hash.mode != "sha256":
            continue
        data = Path(item.locate()).read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if digest != item.hash.value:
            changed.append(str(item))
    return changed


DAEMON_TIMEOUT = 3.0
DAEMON_PROBE = b'{"v": 1, "op": "status"}\n'


def daemon_problem(sock: Path, timeout: float = DAEMON_TIMEOUT) -> str | None:
    """Send the daemon one request without a key; None when it refuses it with 'no key'.

    The request carries no key, so it reads and changes nothing in the bus; the daemon writes
    one 'denied' line to its journal, as for any refused request.
    """
    if not os.path.lexists(sock):
        return f"the daemon does not run: {sock} is missing"
    deadline = time.monotonic() + timeout
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    answer = b""
    try:
        client.settimeout(timeout)
        client.connect(str(sock))
        client.sendall(DAEMON_PROBE)
        while not answer.endswith(b"\n") and len(answer) < 65536:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout
            client.settimeout(left)
            chunk = client.recv(4096)
            if not chunk:
                break
            answer += chunk
    except socket.timeout:
        return f"the daemon does not answer within {timeout:g} s"
    except OSError as exc:
        return f"the daemon does not answer: {type(exc).__name__}"
    finally:
        client.close()
    try:
        document = json.loads(answer.decode("utf-8"))
    except ValueError:
        return "the daemon's answer is not JSON"
    if not isinstance(document, dict) or document.get("ok") is not False or document.get("error") != "no key":
        return "the daemon did not refuse a request without a key with 'no key'"
    return None


def doctor(args) -> tuple[dict, int]:
    etc = Path(args.etc)
    record = read_record(etc)
    if record is None:
        if os.path.lexists(etc):
            return {"status": "broken", "checks": [{"check": "record", "ok": False,
                                                    "detail": f"{etc} exists without {RECORD}"}]}, 1
        return {"status": "not-installed", "checks": []}, 3
    pwd, grp = _accounts()
    checks = []

    def add(name, problem=None, warning=False):
        checks.append({"check": name, "ok": problem is None or warning, "detail": problem or "ok",
                       **({"warning": True} if problem and warning else {})})

    try:
        bus = pwd.getpwnam(record["bus_user"])
        gateway = pwd.getpwnam(record["gateway_user"])
        group = grp.getgrnam(record["socket_group"])
    except KeyError as exc:
        add("accounts", f"missing: {exc.args[0]}")
        return {"status": "failed", "checks": checks}, 1
    problems = []
    if gateway.pw_gid != group.gr_gid:
        problems.append("gateway account is not in the socket group")
    if record["bus_user"] not in group.gr_mem:
        problems.append("bus account is not in the socket group")
    for account in (bus, gateway):
        if not account.pw_shell.endswith("nologin"):
            problems.append(f"{account.pw_name} has a login shell")
    add("accounts", "; ".join(problems) or None)

    problems = [p for p in (_mode_check(etc, 0, bus.pw_gid, 0o750, stat.S_ISDIR),
                            *(_mode_check(etc / f, 0, bus.pw_gid, 0o640, stat.S_ISREG) for f in FILES[:3]),
                            _mode_check(etc / RECORD, 0, 0, 0o600, stat.S_ISREG)) if p]
    extra = sorted(set(os.listdir(etc)) - set(FILES))
    if extra:
        problems.append(f"{etc}: unexpected files {extra}")
    add("configuration folder", "; ".join(problems) or None)

    try:
        configuration = read_config(str(etc / "configuration.json"))
        values = configuration.get("values", {})
        core = json.loads((etc / "core.json").read_text(encoding="utf-8"))
        expected = {"state_dir": str(Path(record["state"]) / "state"), "journal_dir": str(Path(record["state"]) / "journal"),
                    "principals": str(etc / "principals.json"), "socket": str(Path(record["runtime"]) / "core.sock"),
                    "socket_group": record["socket_group"], "gateway_user": record["gateway_user"]}
        wrong = sorted(k for k, v in expected.items() if core.get(k) != v)
        if values.get("core_config") != str(etc / "core.json"):
            wrong.append("configuration core_config")
        add("configuration", f"values differ from the install record: {wrong}" if wrong else None)
    except (ConfigurationError, OSError, ValueError) as exc:
        add("configuration", f"{type(exc).__name__}: {exc}")

    try:
        problems = check_principals(json.loads((etc / "principals.json").read_text(encoding="utf-8")))
        add("keys", "; ".join(problems) or None)
    except (OSError, ValueError) as exc:
        add("keys", type(exc).__name__)

    state = Path(record["state"])
    problems = [p for p in (_mode_check(d, bus.pw_uid, bus.pw_gid, 0o700, stat.S_ISDIR)
                            for d in (state, state / "state", state / "journal")) if p]
    add("state folder", "; ".join(problems) or None)

    runtime = Path(record["runtime"])
    if os.path.lexists(runtime):
        add("socket folder", _mode_check(runtime, bus.pw_uid, group.gr_gid, 0o750, stat.S_ISDIR))
        sock = runtime / "core.sock"
        if os.path.lexists(sock):
            add("socket", _mode_check(sock, bus.pw_uid, group.gr_gid, 0o660, stat.S_ISSOCK))
    else:
        add("socket folder", f"{runtime} is missing (it does not survive a reboot; install created it)", warning=True)
    problem = daemon_problem(runtime / "core.sock")
    add("daemon", f"{problem}; start it with the command under 'start'" if problem else None)
    if problem is None:
        checks[-1]["detail"] = "answers: refused a request without a key with 'no key'"

    try:
        spec = importlib.util.spec_from_file_location("integrity_llm_bus_hub_journal", JOURNAL)
        journal = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(journal)
        result = journal.verify(str(state / "journal"))
        add("journal chain", None if result.get("ok") else f"chain breaks in {result.get('file')} line {result.get('line')}")
        if result.get("ok"):
            checks[-1]["detail"] = f"{result['records']} records, chain intact"
    except (OSError, ValueError, KeyError) as exc:
        add("journal chain", f"{type(exc).__name__}")

    try:
        changed = _installed_files()
        add("installed files", f"differ from the wheel record: {changed[:5]}" if changed else None)
    except Exception as exc:  # metadata missing or unreadable
        add("installed files", f"{type(exc).__name__}")

    failed = [c for c in checks if not c["ok"]]
    return {"status": "failed" if failed else "passed", "checks": checks, "start": start_command(record)}, 1 if failed else 0


def _processes_of(uid: int) -> list[int]:
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                if os.stat(f"/proc/{entry}").st_uid == uid:
                    found.append(int(entry))
            except OSError:
                pass
    return found


def uninstall(args) -> tuple[dict, int]:
    etc = Path(args.etc)
    record = read_record(etc)
    if record is None:
        return {"status": "not-installed", "removed": []}, 0
    targets = [record["runtime"], record["state"], str(etc),
               f"account {record['gateway_user']}", f"account {record['bus_user']}", f"group {record['socket_group']}"]
    if not args.yes:
        return {"status": "dry-run", "would_remove": targets,
                "note": "--yes deletes the bus database and the request journal"}, 0
    if os.geteuid() != 0:
        raise HubError("uninstall --yes needs root")
    pwd, _grp = _accounts()
    # Both accounts are checked before anything is removed: userdel refuses an account with a
    # running process, and by then the folders would already be gone.
    for user in (record["bus_user"], record["gateway_user"]):
        try:
            running = _processes_of(pwd.getpwnam(user).pw_uid)
        except KeyError:
            running = []
        if running:
            return {"status": "refused", "reason": f"{len(running)} process(es) of {user} run; stop them first"}, 3
    extra = sorted(set(os.listdir(etc)) - set(FILES))
    if extra:
        return {"status": "refused", "reason": f"{etc} holds files install did not write: {extra}"}, 3
    for folder in (record["runtime"], record["state"], str(etc)):
        if os.path.lexists(folder):
            shutil.rmtree(folder)
    for user in (record["gateway_user"], record["bus_user"]):
        try:
            pwd.getpwnam(user)
            _run([_tool("userdel"), user])
        except KeyError:
            pass
    for group in (record["bus_user"], record["socket_group"]):
        _remove_group(group)
    return {"status": "removed", "removed": targets,
            "left": "the integrity-llm-bus wheel: remove it with pip uninstall integrity-llm-bus"}, 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="integrity-llm-bus-hub", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    step = commands.add_parser("install", help="create accounts, folders and configuration (root)")
    step.add_argument("--etc", required=True, help="new configuration folder")
    step.add_argument("--state", required=True, help="new state folder (database and journal)")
    step.add_argument("--runtime", required=True, help="new socket folder")
    step.add_argument("--bus-user", required=True)
    step.add_argument("--gateway-user", required=True)
    step.add_argument("--socket-group", required=True)
    step.add_argument("--principals", required=True, help="keys file you wrote (key_sha256 only)")
    step = commands.add_parser("doctor", help="read-only check")
    step.add_argument("--etc", required=True)
    step = commands.add_parser("uninstall", help="remove what install created")
    step.add_argument("--etc", required=True)
    step.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            report, code = install(args), 0
        elif args.command == "doctor":
            report, code = doctor(args)
        else:
            report, code = uninstall(args)
    except HubError as exc:
        report, code = {"status": "error", "error": str(exc)}, 2
    print(json.dumps(report, indent=1, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
