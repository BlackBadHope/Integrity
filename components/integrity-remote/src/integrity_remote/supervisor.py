"""Bounded supervisor for one forced-command core session (Linux, stdlib only).

``run-mcp`` executes this file with ``python -I`` after ``verify-release``
passes. It never reads or writes the MCP byte stream: the core server inherits
the SSH channel's stdin/stdout directly. The supervisor only

* caps concurrent sessions with ``flock`` slots in a private runtime directory;
* builds a minimal child environment (no ``SSH_ORIGINAL_COMMAND``, no client
  environment) and binds the device id fixed by the ``authorized_keys`` line;
* runs the server in its own process group and, when the session ends,
  terminates that group and any descendants it adopted as a subreaper.

The server argv, environment and limits come only from the release's
``server.json``. Nothing the SSH client sends can select them.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import time

PROTOCOL = "integrity-remote/release/v1"
DEVICE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}\Z")
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
DENIED_ENV = frozenset({"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME",
                        "PYTHONSTARTUP", "PYTHONINSPECT", "SSH_ORIGINAL_COMMAND",
                        "INTEGRITY_REMOTE_DEVICE_ID", "INTEGRITY_REMOTE_RELEASE"})
PLACEHOLDER = "{device_id}"
EX_USAGE, EX_TEMPFAIL, EX_CONFIG = 64, 75, 78
PR_SET_CHILD_SUBREAPER = 36


class ConfigError(ValueError):
    pass


def load_config(release: Path) -> dict:
    """Load and validate ``server.json``; reject anything not produced by ``core init``."""
    try:
        config = json.loads((release / "server.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ConfigError("server.json unreadable") from error
    expected = {"protocol", "argv", "env", "runtime_dir", "max_sessions",
                "queue_wait_seconds", "device_required"}
    if not isinstance(config, dict) or set(config) != expected or config["protocol"] != PROTOCOL:
        raise ConfigError("server.json shape mismatch")
    argv = config["argv"]
    if (not isinstance(argv, list) or not argv or not all(isinstance(a, str) and "\0" not in a for a in argv)
            or not os.path.isabs(argv[0])):
        raise ConfigError("server argv invalid")
    env = config["env"]
    if not isinstance(env, dict) or any(
            not isinstance(k, str) or not ENV_NAME.match(k) or k in DENIED_ENV
            or not isinstance(v, str) or "\0" in v for k, v in env.items()):
        raise ConfigError("server env invalid")
    if not isinstance(config["runtime_dir"], str) or not os.path.isabs(config["runtime_dir"]):
        raise ConfigError("runtime_dir invalid")
    if type(config["max_sessions"]) is not int or not 1 <= config["max_sessions"] <= 64:
        raise ConfigError("max_sessions invalid")
    wait = config["queue_wait_seconds"]
    if type(wait) not in (int, float) or not 0 <= wait <= 300:
        raise ConfigError("queue_wait_seconds invalid")
    if type(config["device_required"]) is not bool:
        raise ConfigError("device_required invalid")
    return config


def private_directory(path: Path) -> None:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ConfigError("runtime directory custody mismatch")


def acquire_slot(directory: Path, count: int, wait_seconds: float) -> int | None:
    """Return a locked slot descriptor, or ``None`` when every slot stays busy."""
    private_directory(directory)
    descriptors = []
    for index in range(count):
        fd = os.open(directory / f"slot-{index}.lock",
                     os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            for other in [*descriptors, fd]:
                os.close(other)
            raise ConfigError("slot custody mismatch")
        descriptors.append(fd)
    deadline = time.monotonic() + wait_seconds
    try:
        while True:
            for fd in descriptors:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                descriptors.remove(fd)
                return fd
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.1)
    finally:
        for fd in descriptors:
            os.close(fd)


def child_environment(config: dict, device: str, release: Path) -> dict:
    account = pwd.getpwuid(os.getuid())
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": account.pw_dir,
           "USER": account.pw_name, "LOGNAME": account.pw_name}
    env.update(config["env"])
    env["INTEGRITY_REMOTE_DEVICE_ID"] = device
    env["INTEGRITY_REMOTE_RELEASE"] = str(release)
    return env


def become_subreaper() -> bool:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def adopted_children() -> list[int]:
    """PIDs whose parent is this process (orphans adopted as subreaper)."""
    me, found = os.getpid(), []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return found
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        fields = data[data.rfind(b")") + 2:].split()
        if len(fields) > 1 and int(fields[1]) == me:
            found.append(int(entry))
    return found


def _signal_group(pgid: int, signum: int) -> bool:
    try:
        os.killpg(pgid, signum)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def cleanup(pgid: int, grace: float = 2.0) -> None:
    """Terminate the session's process group and adopted descendants, then reap."""
    _signal_group(pgid, signal.SIGTERM)
    for pid in adopted_children():
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        _reap()
        if not _signal_group(pgid, 0) and not adopted_children():
            return
        time.sleep(0.05)
    _signal_group(pgid, signal.SIGKILL)
    for pid in adopted_children():
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.05)
    _reap()


def _reap() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def run(release: Path, device: str) -> int:
    try:
        config = load_config(release)
    except ConfigError as error:
        print(f"integrity-remote: {error}", file=sys.stderr)
        return EX_CONFIG
    if device and not DEVICE.match(device):
        print("integrity-remote: invalid device id", file=sys.stderr)
        return EX_USAGE
    if config["device_required"] and not device:
        print("integrity-remote: this core requires a per-device key", file=sys.stderr)
        return EX_USAGE
    argv = [part.replace(PLACEHOLDER, device) for part in config["argv"]]
    try:
        slot = acquire_slot(Path(config["runtime_dir"]), config["max_sessions"],
                            float(config["queue_wait_seconds"]))
    except (ConfigError, OSError) as error:
        print(f"integrity-remote: {error}", file=sys.stderr)
        return EX_CONFIG
    if slot is None:
        print("integrity-remote: core busy; every session slot is in use", file=sys.stderr)
        return EX_TEMPFAIL
    become_subreaper()
    try:
        child = subprocess.Popen(argv, env=child_environment(config, device, release),
                                 start_new_session=True, close_fds=True)
    except OSError as error:
        os.close(slot)
        print(f"integrity-remote: server start failed: {error.strerror}", file=sys.stderr)
        return EX_CONFIG

    def forward(signum, _frame):
        _signal_group(child.pid, signal.SIGTERM)

    for signum in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, forward)
    try:
        code = child.wait()
    finally:
        cleanup(child.pid)
        os.close(slot)
    return code if code >= 0 else 128 - code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--device", default="")
    args = parser.parse_args(argv)
    return run(args.release, args.device)


if __name__ == "__main__":
    raise SystemExit(main())
