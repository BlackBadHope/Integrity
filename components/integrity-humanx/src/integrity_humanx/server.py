# SPDX-License-Identifier: BUSL-1.1
"""integrity-humanx-server - install, check and remove the HumanX server side on one Linux machine.

  install    creates the web account, the read-only gateway account and the gateway socket
             group; adds the web account to the bus socket group and the bus SSH gateway
             account to the gateway socket group; writes the configuration folder, the state
             folder and the socket folder (run as root)
  doctor     only reads: accounts and groups, owners and modes, the values install wrote,
             the web key file (never its content), installed files against the wheel record;
             an install that stopped half way is reported as partial
  uninstall  says what it would remove; with --yes removes what the install record lists as
             created by install, and nothing else

install refuses any account, group or folder that already exists under a name it would create.
Before each step it writes the step to its record (<etc>/humanx-server.json), so an install that
was killed half way can still be removed by uninstall --yes.

It starts no service and installs no systemd unit. The bus hub (integrity-llm-bus-hub) must be
installed first: its socket group and its SSH gateway account are named here, not created.
install configures the web and the gateway's Integrity snapshot reads. SQL, switch reads, the
storm reader, the snapshot job and the ring map are left to the owner; the ring and storm
screens stay off.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys

from .configuration import COMPONENT, SCHEMA, ConfigurationError, _OPERATOR_ID, read_config

RECORD = "humanx-server.json"
RECORD_PROTOCOL = "integrity-humanx/server-install/v1"
CONFIGURATION, WEB, GATEWAY, WEB_KEY = "configuration.json", "web.json", "gateway.json", "web.key"
STOP_FILES = ("web-rings.off", "web-storm.off")
FILES = (CONFIGURATION, WEB, GATEWAY, WEB_KEY, *STOP_FILES, RECORD)
# A file is written to .<name>.tmp with its final owner and mode, then renamed; a killed install
# can leave one behind.
TEMPORARY = tuple(f".{name}.tmp" for name in FILES)
# Files the owner adds for the parts install leaves unconfigured. doctor accepts them;
# uninstall refuses while they are there, so it never deletes a credential it did not write.
OWNER_FILES = ("my.cnf", "switch.cred", "storm.key", "storm.known_hosts", "sw-share.off")
NOT_CONFIGURED = ["sql (my.cnf)", "switch reads (switch_nets, switch.cred)", "storm reader", "Integrity snapshot job",
                  "ring map (ring and storm screens stay off)"]
NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
VENDOR = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
KEY_MAX = 4096
DEFAULT_BIND = "127.0.0.1"


class ServerError(Exception):
    """The request cannot be carried out; nothing more is changed."""


def _accounts():
    import grp
    import pwd
    return pwd, grp


def _run(argv: list[str]) -> None:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    if done.returncode != 0:
        raise ServerError(f"{argv[0]} exited {done.returncode}: {done.stderr.strip()[:200]}")


def _tool(name: str) -> str:
    for folder in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        path = Path(folder) / name
        if path.is_file():
            return str(path)
    raise ServerError(f"{name} not found")


def check_install_args(args) -> list[str]:
    """Problems of the install arguments that need no system access; an empty list means go on."""
    problems = []
    names = {"web user": args.web_user, "gateway user": args.gateway_user, "socket group": args.socket_group,
             "bus group": args.bus_group, "bus gateway user": args.bus_gateway_user}
    for label, value in names.items():
        if not NAME.match(value or ""):
            problems.append(f"{label} {value!r}: use [a-z_][a-z0-9_-]{{0,31}}")
    new = (args.web_user, args.gateway_user, args.socket_group)
    if len(set(new)) != 3:
        problems.append("web user, gateway user and socket group must be three different names")
    if set(new) & {args.bus_group, args.bus_gateway_user}:
        problems.append("the new names must differ from the bus group and the bus gateway user")
    for label, value in (("--etc", args.etc), ("--state", args.state), ("--runtime", args.runtime),
                         ("--bus-socket", args.bus_socket)):
        if not PurePosixPath(value).is_absolute():
            problems.append(f"{label} {value}: use an absolute path")
    if not _OPERATOR_ID.fullmatch(args.operator_id or ""):
        problems.append(f"operator id must match {_OPERATOR_ID.pattern}")
    try:
        if ipaddress.ip_address(args.bind).is_unspecified and not getattr(args, "allow_any_address", False):
            problems.append(f"--bind {args.bind} listens on every address of the machine; "
                            "give --allow-any-address if that is meant")
    except ValueError:
        problems.append(f"--bind {args.bind!r}: use an IP address")
    if not 1 <= args.port <= 65535:
        problems.append("--port must be 1..65535")
    if not args.allow:
        problems.append("give at least one --allow address")
    for address in args.allow or ():
        try:
            ipaddress.ip_address(address)
        except ValueError:
            problems.append(f"--allow {address!r}: use an IP address")
    if not args.vendor:
        problems.append("give at least one --vendor (bus vendor id of a room Arbiter)")
    for vendor in args.vendor or ():
        if not VENDOR.match(vendor):
            problems.append(f"--vendor {vendor!r}: use [a-z][a-z0-9-]{{0,31}}")
    return problems


def key_owners() -> set[int]:
    """Who may own the web key file: root and the user who runs install (through sudo, SUDO_UID)."""
    owners = {0, os.getuid()}
    sudo_uid = os.environ.get("SUDO_UID", "")
    if sudo_uid.isdigit():
        owners.add(int(sudo_uid))
    return owners


def read_web_key(path: str, owners: set[int] | None = None) -> str:
    """The web's bus key from the owner's file. It is never printed; only the file is checked.

    The file is opened without following a symbolic link and must be a regular file that neither
    the group nor others can read or write; with owners given, its owner must be one of them."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ServerError("web key file is a symbolic link; give the file itself") from None
        raise ServerError(f"web key file: {type(exc).__name__}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ServerError("web key file must be a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ServerError(f"web key file has mode {stat.S_IMODE(info.st_mode):o}: the group or others can "
                              "read or write it; use chmod 600")
        if owners is not None and info.st_uid not in owners:
            raise ServerError(f"web key file is owned by uid {info.st_uid}; it must belong to root "
                              "or to the user who runs install")
        data = os.read(fd, KEY_MAX + 2)
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8").strip()
    except UnicodeError:
        raise ServerError("web key file: UnicodeDecodeError") from None
    if not text or len(text) > KEY_MAX or any(c.isspace() for c in text):
        raise ServerError("web key file must hold one key on one line")
    return text


def component_configuration(record: dict) -> dict:
    etc, state, runtime = (Path(record[k]) for k in ("etc", "state", "runtime"))
    return {
        "schema": SCHEMA, "component": COMPONENT, "configured": True,
        "guardian_version": "6.1.0", "memory_api_version": "2.11.0", "owner_local_catalogue": None,
        "values": {"operator_id": record["operator_id"], "web_config": str(etc / WEB),
                   "web_state_dir": str(state / "web"), "ro_gateway_socket": str(runtime / "gw.sock"),
                   "ro_gateway_config": str(etc / GATEWAY), "ro_group": record["gateway_user"]},
    }


def web_configuration(record: dict) -> dict:
    return {"bind": record["bind"], "port": record["port"], "allow": list(record["allow"]),
            "socket": record["bus_socket"], "token_file": str(Path(record["etc"]) / WEB_KEY)}


def gateway_configuration(record: dict) -> dict:
    etc, state, runtime = (Path(record[k]) for k in ("etc", "state", "runtime"))
    return {
        "socket": str(runtime / "gw.sock"), "socket_group": record["socket_group"],
        "gateway_user": record["bus_gateway_user"], "web_user": record["web_user"],
        "vendors": list(record["vendors"]),
        "mysql_defaults_file": str(etc / "my.cnf"),
        "integrity_snapshot": str(state / "gateway" / "integrity" / "seed.sqlite3"),
        "log": str(state / "gateway" / "gw.jsonl"),
        "switch_nets": [], "switch_cred": str(etc / "switch.cred"), "sw_share_off": str(etc / "sw-share.off"),
        "web_rings_ips": [], "web_rings_off": str(etc / "web-rings.off"), "web_storm_off": str(etc / "web-storm.off"),
        "storm_key": str(etc / "storm.key"), "storm_known_hosts": str(etc / "storm.known_hosts"), "storm_host": "",
    }


# The gateway fields doctor compares with the record; the others are the owner's to change.
GATEWAY_OWNED = ("socket", "socket_group", "gateway_user", "web_user", "integrity_snapshot", "log",
                 "web_rings_off", "web_storm_off")


def start_commands(record: dict) -> dict:
    """How to start the web and the gateway as their accounts, without systemd."""
    environment = {"INTEGRITY_HUMANX_CONFIG": str(Path(record["etc"]) / CONFIGURATION)}
    argv = [record["python"], "-I", "-B", "-m", "integrity_humanx"]
    return {"web": {"user": record["web_user"], "environment": environment, "argv": [*argv, "humanx-web"]},
            "gateway": {"user": record["gateway_user"], "environment": environment,
                        "argv": [*argv, "humanx-ro-gateway"]}}


def _write(path: Path, text: str, mode: int, uid: int, gid: int) -> None:
    """Write through .<name>.tmp that has its final owner and mode before any byte, then rename."""
    temporary = path.with_name(f".{path.name}.tmp")
    if os.path.lexists(temporary):
        os.unlink(temporary)   # left by a killed run; the folder is install's own
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        data = text.encode("utf-8")
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(temporary, path)


def _mkdir(path: Path, mode: int, uid: int, gid: int) -> None:
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _json(document) -> str:
    return json.dumps(document, indent=1, ensure_ascii=False) + "\n"


def _save(record: dict) -> None:
    _write(Path(record["etc"]) / RECORD, _json(record), 0o600, 0, 0)


def _step(record: dict, entry: dict, action) -> None:
    """Record the step as planned, carry it out, record it as created."""
    entry = {**entry, "state": "planned"}
    record["created"].append(entry)
    _save(record)
    action()
    entry["state"] = "created"
    _save(record)


def _exists(kind: str, name: str) -> bool:
    pwd, grp = _accounts()
    try:
        (pwd.getpwnam if kind == "user" else grp.getgrnam)(name)
        return True
    except KeyError:
        return False


def install(args) -> dict:
    if sys.platform != "linux":
        raise ServerError("the HumanX server side runs on Linux only")
    if os.geteuid() != 0:
        raise ServerError("install needs root: it creates accounts and folders owned by them")
    problems = check_install_args(args)
    if problems:
        raise ServerError("; ".join(problems))
    pwd, grp = _accounts()
    etc, state, runtime = (Path(p) for p in (args.etc, args.state, args.runtime))
    for path in (etc, state, runtime):
        if os.path.lexists(path):
            raise ServerError(f"{path} exists; install creates it and refuses to reuse it")
    for user in (args.web_user, args.gateway_user):
        if _exists("user", user):
            raise ServerError(f"account {user} exists; install creates its own accounts and does not take over "
                              "existing ones")
    for group in (args.socket_group, args.web_user, args.gateway_user):
        if _exists("group", group):
            raise ServerError(f"group {group} exists; install creates its own groups and does not take over "
                              "existing ones")
    try:
        grp.getgrnam(args.bus_group)
        pwd.getpwnam(args.bus_gateway_user)
    except KeyError as exc:
        raise ServerError(f"{exc.args[0]}: install the bus hub first (integrity-llm-bus-hub)") from None
    key = read_web_key(args.web_key, key_owners())

    nologin = _tool("nologin")
    record = {
        "protocol": RECORD_PROTOCOL, "complete": False, "web_user": args.web_user, "gateway_user": args.gateway_user,
        "socket_group": args.socket_group, "bus_group": args.bus_group, "bus_gateway_user": args.bus_gateway_user,
        "bus_socket": args.bus_socket, "operator_id": args.operator_id, "vendors": sorted(set(args.vendor)),
        "bind": args.bind, "port": args.port, "allow": list(args.allow),
        "etc": str(etc), "state": str(state), "runtime": str(runtime), "python": sys.executable,
        # What was there before install; uninstall never removes these.
        "existed": {"bus_group": args.bus_group, "bus_gateway_user": args.bus_gateway_user,
                    "bus_gateway_groups": sorted(_groups_of(args.bus_gateway_user, pwd, grp))},
        # What install created, in order; uninstall removes these in reverse order.
        "created": [{"kind": "dir", "name": str(etc), "state": "created"}],
    }
    _mkdir(etc, 0o755, 0, 0)
    try:
        _save(record)
        _step(record, {"kind": "group", "name": args.socket_group},
              lambda: _run([_tool("groupadd"), "--system", args.socket_group]))
        for user, groups in ((args.web_user, f"{args.socket_group},{args.bus_group}"),
                             (args.gateway_user, args.socket_group)):
            _step(record, {"kind": "user", "name": user, "user_group": True},
                  lambda user=user, groups=groups: _run([
                      _tool("useradd"), "--system", "--user-group", "--groups", groups, "--no-create-home",
                      "--home-dir", "/nonexistent", "--shell", nologin, user]))
        _step(record, {"kind": "membership", "name": args.bus_gateway_user, "group": args.socket_group},
              lambda: _run([_tool("usermod"), "--append", "--groups", args.socket_group, args.bus_gateway_user]))
        web, gateway = pwd.getpwnam(args.web_user), pwd.getpwnam(args.gateway_user)
        socket_gid = grp.getgrnam(args.socket_group).gr_gid

        def state_folders():
            _mkdir(state, 0o755, 0, 0)
            _mkdir(state / "web", 0o700, web.pw_uid, web.pw_gid)
            _mkdir(state / "gateway", 0o700, gateway.pw_uid, gateway.pw_gid)
            _mkdir(state / "gateway" / "integrity", 0o750, 0, gateway.pw_gid)

        _step(record, {"kind": "dir", "name": str(state)}, state_folders)
        _step(record, {"kind": "dir", "name": str(runtime)},
              lambda: _mkdir(runtime, 0o750, gateway.pw_uid, socket_gid))
        _write(etc / CONFIGURATION, _json(component_configuration(record)), 0o644, 0, 0)
        _write(etc / WEB, _json(web_configuration(record)), 0o640, 0, web.pw_gid)
        _write(etc / GATEWAY, _json(gateway_configuration(record)), 0o640, 0, gateway.pw_gid)
        _write(etc / WEB_KEY, key + "\n", 0o400, web.pw_uid, web.pw_gid)
        for name in STOP_FILES:
            _write(etc / name, "off\n", 0o644, 0, 0)
        record["complete"] = True
        _save(record)
    except BaseException:
        try:
            _remove(record)
        except (OSError, ServerError):
            pass   # what is left stays in the record; doctor reports it as partial
        raise
    finally:
        key = None
    return {"status": "installed", "start": start_commands(record), "not_configured": NOT_CONFIGURED,
            "not_installed": ["systemd units", "firewall rules", "the bus room file (<hub state>/state/room.json)"]}


def _remove(record: dict) -> None:
    """Remove what the record lists as created, newest first, and nothing else.

    A step recorded as planned is removed when it is there: install checked that the name was
    free right before the step. Each removal is written to the record, so a removal that stops
    half way can be run again. The configuration folder, which holds the record, goes last."""
    etc = record["etc"]
    for entry in reversed(record["created"]):
        if entry.get("state") == "removed":
            continue
        kind, name = entry["kind"], entry["name"]
        if kind == "dir":
            if os.path.lexists(name):
                shutil.rmtree(name)
            if name == etc:
                return
        elif kind == "membership":
            pwd, grp = _accounts()
            if _exists("user", name) and _exists("group", entry["group"]) and name in grp.getgrnam(entry["group"]).gr_mem:
                _run([_tool("gpasswd"), "--delete", name, entry["group"]])
        elif kind == "user":
            if _exists("user", name):
                _run([_tool("userdel"), name])
            if entry.get("user_group"):
                _remove_group(name)
        elif kind == "group":
            _remove_group(name)
        entry["state"] = "removed"
        _save(record)


def _remove_group(name: str) -> None:
    """Remove a group if it still exists (userdel removes a user's own group on most systems)."""
    if _exists("group", name):
        _run([_tool("groupdel"), name])


def read_record(etc: Path) -> dict | None:
    path = etc / RECORD
    if not os.path.lexists(path):
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ServerError(f"{path}: {type(exc).__name__}") from None
    if (not isinstance(record, dict) or record.get("protocol") != RECORD_PROTOCOL
            or not isinstance(record.get("created"), list) or record.get("etc") != str(etc)):
        raise ServerError(f"{path}: not a HumanX server install record")
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
    for item in metadata.distribution(COMPONENT).files or []:
        if item.hash is None or item.hash.mode != "sha256":
            continue
        data = Path(item.locate()).read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if digest != item.hash.value:
            changed.append(str(item))
    return changed


def _groups_of(name: str, pwd, grp) -> set[str]:
    account = pwd.getpwnam(name)
    found = {g.gr_name for g in grp.getgrall() if name in g.gr_mem}
    try:
        found.add(grp.getgrgid(account.pw_gid).gr_name)
    except KeyError:
        pass
    return found


def _pending(record: dict) -> list[str]:
    return [f"{e['kind']} {e['name']}" + (f" in {e['group']}" if e.get("group") else "")
            for e in reversed(record["created"]) if e.get("state") != "removed"]


def doctor(args) -> tuple[dict, int]:
    etc = Path(args.etc)
    record = read_record(etc)
    if record is None:
        if os.path.lexists(etc):
            return {"status": "broken", "checks": [{"check": "record", "ok": False,
                                                    "detail": f"{etc} exists without {RECORD}"}]}, 1
        return {"status": "not-installed", "checks": []}, 3
    if not record.get("complete"):
        return {"status": "partial", "checks": [{
            "check": "install", "ok": False,
            "detail": "install did not finish; uninstall --yes removes what it created: " + ", ".join(_pending(record))}],
        }, 1
    pwd, grp = _accounts()
    checks = []

    def add(name, problem=None, warning=False, detail=None):
        checks.append({"check": name, "ok": problem is None or warning, "detail": problem or detail or "ok",
                       **({"warning": True} if problem and warning else {})})

    try:
        web = pwd.getpwnam(record["web_user"])
        gateway = pwd.getpwnam(record["gateway_user"])
        socket_group = grp.getgrnam(record["socket_group"])
        pwd.getpwnam(record["bus_gateway_user"])
        grp.getgrnam(record["bus_group"])
    except KeyError as exc:
        add("accounts", f"missing: {exc.args[0]}")
        return {"status": "failed", "checks": checks}, 1
    problems = []
    for user, needed in ((record["web_user"], {record["socket_group"], record["bus_group"]}),
                         (record["gateway_user"], {record["socket_group"]})):
        missing = needed - _groups_of(user, pwd, grp)
        if missing:
            problems.append(f"{user} is not in {sorted(missing)}")
    for account in (web, gateway):
        if not account.pw_shell.endswith("nologin"):
            problems.append(f"{account.pw_name} has a login shell")
    add("accounts", "; ".join(problems) or None)

    bus_gateway = record["bus_gateway_user"]
    add("bus gateway membership",
        None if record["socket_group"] in _groups_of(bus_gateway, pwd, grp)
        else f"{bus_gateway} is not in {record['socket_group']}: the bus cannot reach the read-only gateway",
        detail=f"{bus_gateway} is in {record['socket_group']} (added by install; uninstall takes it out)")

    bind = ipaddress.ip_address(record["bind"])
    add("web address", None if bind.is_loopback else
        f"the web listens on {record['bind']}:{record['port']}, not on loopback; only the allow list "
        f"{record['allow']} and your firewall limit who reaches it", warning=True,
        detail=f"{record['bind']}:{record['port']}, loopback")

    problems = [p for p in (_mode_check(etc, 0, 0, 0o755, stat.S_ISDIR),
                            _mode_check(etc / CONFIGURATION, 0, 0, 0o644, stat.S_ISREG),
                            _mode_check(etc / WEB, 0, web.pw_gid, 0o640, stat.S_ISREG),
                            _mode_check(etc / GATEWAY, 0, gateway.pw_gid, 0o640, stat.S_ISREG),
                            *(_mode_check(etc / n, 0, 0, 0o644, stat.S_ISREG) for n in STOP_FILES),
                            _mode_check(etc / RECORD, 0, 0, 0o600, stat.S_ISREG)) if p]
    extra = sorted(set(os.listdir(etc)) - set(FILES) - set(OWNER_FILES))
    if extra:
        problems.append(f"{etc}: unexpected files {extra}")
    add("configuration folder", "; ".join(problems) or None)

    problem = _mode_check(etc / WEB_KEY, web.pw_uid, web.pw_gid, 0o400, stat.S_ISREG)
    if problem is None and os.lstat(etc / WEB_KEY).st_size == 0:
        problem = f"{etc / WEB_KEY} is empty"
    add("web key file", problem)

    try:
        configuration = read_config(str(etc / CONFIGURATION))
        wrong = sorted(k for k, v in component_configuration(record)["values"].items()
                       if configuration.get("values", {}).get(k) != v)
        web_doc = json.loads((etc / WEB).read_text(encoding="utf-8"))
        wrong += [f"web {k}" for k, v in web_configuration(record).items() if web_doc.get(k) != v]
        gateway_doc = json.loads((etc / GATEWAY).read_text(encoding="utf-8"))
        expected = gateway_configuration(record)
        wrong += [f"gateway {k}" for k in GATEWAY_OWNED if gateway_doc.get(k) != expected[k]]
        add("configuration", f"values differ from the install record: {wrong}" if wrong else None)
    except (ConfigurationError, OSError, ValueError) as exc:
        add("configuration", f"{type(exc).__name__}: {exc}")

    state = Path(record["state"])
    problems = [p for p in (_mode_check(state, 0, 0, 0o755, stat.S_ISDIR),
                            _mode_check(state / "web", web.pw_uid, web.pw_gid, 0o700, stat.S_ISDIR),
                            _mode_check(state / "gateway", gateway.pw_uid, gateway.pw_gid, 0o700, stat.S_ISDIR),
                            _mode_check(state / "gateway" / "integrity", 0, gateway.pw_gid, 0o750, stat.S_ISDIR)) if p]
    add("state folder", "; ".join(problems) or None)

    runtime = Path(record["runtime"])
    if os.path.lexists(runtime):
        add("socket folder", _mode_check(runtime, gateway.pw_uid, socket_group.gr_gid, 0o750, stat.S_ISDIR))
        sock = runtime / "gw.sock"
        if os.path.lexists(sock):
            add("gateway socket", _mode_check(sock, gateway.pw_uid, socket_group.gr_gid, 0o660, stat.S_ISSOCK))
    else:
        add("socket folder", f"{runtime} is missing (it does not survive a reboot; install created it)", warning=True)

    try:
        changed = _installed_files()
        add("installed files", f"differ from the wheel record: {changed[:5]}" if changed else None)
    except Exception as exc:  # metadata missing or unreadable
        add("installed files", f"{type(exc).__name__}")

    failed = [c for c in checks if not c["ok"]]
    return ({"status": "failed" if failed else "passed", "checks": checks, "start": start_commands(record),
             "not_configured": NOT_CONFIGURED}, 1 if failed else 0)


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
        if os.path.lexists(etc):
            return {"status": "refused", "reason": f"{etc} exists without {RECORD}; with no record of what install "
                                                   "created, nothing is removed"}, 3
        return {"status": "not-installed", "removed": []}, 0
    targets = _pending(record)
    kept = sorted({record["existed"]["bus_group"], record["existed"]["bus_gateway_user"]})
    if not args.yes:
        return {"status": "dry-run", "would_remove": targets, "kept": kept,
                "note": "--yes deletes the room's sent messages, replies, attachments and the gateway log"}, 0
    if os.geteuid() != 0:
        raise ServerError("uninstall --yes needs root")
    pwd, _grp = _accounts()
    # The accounts are checked before anything is removed: userdel refuses an account with a
    # running process, and by then the folders would already be gone.
    for entry in record["created"]:
        if entry["kind"] == "user" and entry.get("state") != "removed":
            try:
                running = _processes_of(pwd.getpwnam(entry["name"]).pw_uid)
            except KeyError:
                running = []
            if running:
                return {"status": "refused",
                        "reason": f"{len(running)} process(es) of {entry['name']} run; stop them first"}, 3
    extra = sorted(set(os.listdir(etc)) - set(FILES) - set(TEMPORARY))
    if extra:
        return {"status": "refused", "reason": f"{etc} holds files install did not write: {extra}; "
                                               "move or delete them yourself first"}, 3
    _remove(record)
    return {"status": "removed", "removed": targets, "kept": kept,
            "left": "the integrity-humanx wheel: remove it with pip uninstall integrity-humanx"}, 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="integrity-humanx-server", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    step = commands.add_parser("install", help="create accounts, folders and configuration (root)")
    step.add_argument("--etc", required=True, help="new configuration folder")
    step.add_argument("--state", required=True, help="new state folder (web history, gateway log and snapshot)")
    step.add_argument("--runtime", required=True, help="new folder of the gateway socket")
    step.add_argument("--web-user", required=True)
    step.add_argument("--gateway-user", required=True, help="account of the read-only gateway")
    step.add_argument("--socket-group", required=True, help="group that may use the gateway socket")
    step.add_argument("--bus-group", required=True, help="socket group of the installed bus hub")
    step.add_argument("--bus-gateway-user", required=True, help="SSH gateway account of the installed bus hub")
    step.add_argument("--bus-socket", required=True, help="socket of the bus hub")
    step.add_argument("--web-key", required=True,
                      help="file with the web's bus key (the hub has its sha256): a regular file, mode 600 or "
                           "stricter, owned by root or by you")
    step.add_argument("--operator-id", required=True)
    step.add_argument("--vendor", action="append", help="bus vendor id of a room Arbiter the gateway serves")
    step.add_argument("--bind", default=DEFAULT_BIND, help=f"address the web listens on (default {DEFAULT_BIND})")
    step.add_argument("--allow-any-address", action="store_true",
                      help="allow --bind 0.0.0.0 or ::, which listens on every address of the machine")
    step.add_argument("--port", required=True, type=int)
    step.add_argument("--allow", action="append", help="client address the web accepts")
    step = commands.add_parser("doctor", help="read-only check")
    step.add_argument("--etc", required=True)
    step = commands.add_parser("uninstall", help="remove what install created")
    step.add_argument("--etc", required=True)
    step.add_argument("--yes", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install":
            report, code = install(args), 0
        elif args.command == "doctor":
            report, code = doctor(args)
        else:
            report, code = uninstall(args)
    except ServerError as exc:
        report, code = {"status": "error", "error": str(exc)}, 2
    print(json.dumps(report, indent=1, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
