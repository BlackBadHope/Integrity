"""Build and verify immutable forced-command releases for an Integrity core.

A release is a directory named after the SHA-256 of its ``SHA256SUMS`` file::

    <root>/releases/<digest>/
        run-mcp          forced command (POSIX sh)
        verify-release   custody and digest check (POSIX sh, GNU coreutils)
        supervisor.py    session cap and process-group cleanup
        server.json      the exact server argv, env and limits
        SHA256SUMS       digests of the four files above
        artifact.sha256  the release digest

The directory is mode 0555 and its files 0444/0555, owned by root (``hardened``)
or by the core user (``user``). ``verify-release`` refuses a renamed directory,
a changed, added, linked or writable file, before any server code starts.
Changing the server means building a new release and switching the
``authorized_keys`` lines to it; old releases stay intact for rollback.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

PROTOCOL = "integrity-remote/release/v1"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
SAFE_PATH = re.compile(r"/[A-Za-z0-9._/+-]*\Z")
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
DENIED_ENV = frozenset({"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME",
                        "PYTHONSTARTUP", "PYTHONINSPECT", "SSH_ORIGINAL_COMMAND",
                        "INTEGRITY_REMOTE_DEVICE_ID", "INTEGRITY_REMOTE_RELEASE"})
HASHED = ("run-mcp", "server.json", "supervisor.py", "verify-release")
ALL_FILES = (*HASHED, "SHA256SUMS", "artifact.sha256")
EXECUTABLE = frozenset({"run-mcp", "verify-release"})

RUN_MCP = """#!/bin/sh
# OpenSSH runs this file as an exact forced command (authorized_keys command=).
# The client's requested command and environment are ignored: only the
# --device value written into the authorized_keys line is accepted.
set -eu
umask 077
PATH=/usr/bin:/bin
export PATH
unset SSH_ORIGINAL_COMMAND PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT VIRTUAL_ENV
export LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RELEASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
"$RELEASE/verify-release" || exit 125
DEVICE=
case $# in
  0) ;;
  2) [ "$1" = --device ] || exit 64; DEVICE=$2 ;;
  *) exit 64 ;;
esac
exec @PYTHON@ -I "$RELEASE/supervisor.py" --release "$RELEASE" --device "$DEVICE"
"""

VERIFY_RELEASE = """#!/bin/sh
# Refuse to start unless this directory is exactly the release it claims to be.
set -eu
PATH=/usr/bin:/bin
export PATH
EXPECTED_UID=@UID@
RELEASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
DIGEST=${RELEASE##*/}
case "$DIGEST" in *[!0-9a-f]*|'') exit 125 ;; esac
[ "${#DIGEST}" -eq 64 ] || exit 125
[ "$(stat -c '%u:%a' -- "$RELEASE")" = "$EXPECTED_UID:555" ] || exit 125
PARENT=$(dirname -- "$RELEASE")
case "$(stat -c '%u' -- "$PARENT")" in 0|"$EXPECTED_UID") ;; *) exit 125 ;; esac
[ -z "$(find "$PARENT" -maxdepth 0 -perm /022)" ] || exit 125
for name in run-mcp verify-release supervisor.py server.json SHA256SUMS artifact.sha256; do
  file=$RELEASE/$name
  [ -f "$file" ] && [ ! -L "$file" ] || exit 125
  case "$(stat -c '%u:%a:%h' -- "$file")" in
    "$EXPECTED_UID:444:1"|"$EXPECTED_UID:555:1") ;;
    *) exit 125 ;;
  esac
done
[ "$(ls -A -- "$RELEASE" | wc -l)" -eq 6 ] || exit 125
[ "$(sha256sum < "$RELEASE/SHA256SUMS" | cut -d ' ' -f 1)" = "$DIGEST" ] || exit 125
[ "$(cat -- "$RELEASE/artifact.sha256")" = "$DIGEST" ] || exit 125
(cd "$RELEASE" && sha256sum --check --status --strict SHA256SUMS) || exit 125
"""


class ReleaseError(ValueError):
    pass


def _require_posix() -> None:
    if os.name != "posix" or sys.platform == "darwin":
        raise ReleaseError("the core side runs on Linux (GNU coreutils); clients may run anywhere")


def validate_server(argv: list[str], env: dict[str, str]) -> None:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a and "\0" not in a
                                                         for a in argv):
        raise ReleaseError("server argv must be a non-empty list of strings")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise ReleaseError("server argv[0] must be an absolute path")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ReleaseError("server argv[0] is not an executable file")
    if not isinstance(env, dict):
        raise ReleaseError("server env must be an object")
    for name, value in env.items():
        if not ENV_NAME.match(name) or name in DENIED_ENV:
            raise ReleaseError(f"server env name not allowed: {name}")
        if not isinstance(value, str) or "\0" in value:
            raise ReleaseError(f"server env value invalid: {name}")


def render(*, argv: list[str], env: dict[str, str], runtime_dir: Path, max_sessions: int,
           queue_wait_seconds: float, device_required: bool, python: str, owner_uid: int) -> dict[str, bytes]:
    """Return the exact release file bytes (pure; no filesystem effects)."""
    validate_server(argv, env)
    if not os.path.isabs(python):
        raise ReleaseError("python must be an absolute path")
    if not 1 <= max_sessions <= 64:
        raise ReleaseError("max sessions must be 1..64")
    if not 0 <= queue_wait_seconds <= 300:
        raise ReleaseError("queue wait must be 0..300 seconds")
    if not runtime_dir.is_absolute():
        raise ReleaseError("runtime dir must be absolute")
    server = {"protocol": PROTOCOL, "argv": argv, "env": dict(sorted(env.items())),
              "runtime_dir": str(runtime_dir), "max_sessions": max_sessions,
              "queue_wait_seconds": queue_wait_seconds, "device_required": device_required}
    files = {
        "run-mcp": RUN_MCP.replace("@PYTHON@", shlex.quote(python)).encode(),
        "verify-release": VERIFY_RELEASE.replace("@UID@", str(int(owner_uid))).encode(),
        "supervisor.py": Path(__file__).with_name("supervisor.py").read_bytes(),
        "server.json": (json.dumps(server, indent=2, sort_keys=True) + "\n").encode(),
    }
    sums = "".join(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n" for name in HASHED).encode()
    digest = hashlib.sha256(sums).hexdigest()
    files["SHA256SUMS"] = sums
    files["artifact.sha256"] = (digest + "\n").encode()
    return files


def release_digest(files: dict[str, bytes]) -> str:
    return hashlib.sha256(files["SHA256SUMS"]).hexdigest()


def _secure_directory(path: Path, mode: int, uid: int | None = None) -> None:
    path.mkdir(mode=mode, parents=False, exist_ok=True)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseError(f"not a directory: {path}")
    if uid is not None and info.st_uid != uid:
        os.chown(path, uid, -1)
    os.chmod(path, mode)


def init_core(*, root: Path, argv: list[str], env: dict[str, str] | None = None, mode: str = "user",
              service_user: str | None = None, max_sessions: int = 2, queue_wait_seconds: float = 10,
              device_required: bool = True, python: str | None = None) -> dict:
    """Create ``root``/releases/<digest> and ``root``/run; idempotent for identical input."""
    _require_posix()
    if not root.is_absolute() or not SAFE_PATH.match(str(root)):
        raise ReleaseError("root must be an absolute path of [A-Za-z0-9._/+-] characters")
    if mode not in {"user", "hardened"}:
        raise ReleaseError("mode must be user or hardened")
    euid = os.geteuid()
    if mode == "hardened":
        if euid != 0:
            raise ReleaseError("hardened mode builds a root-owned release; run it as root")
        if not service_user:
            raise ReleaseError("hardened mode needs --service-user (the account in authorized_keys)")
        import pwd
        service_uid = pwd.getpwnam(service_user).pw_uid
        if service_uid == 0:
            raise ReleaseError("the service user must not be root")
        owner_uid = 0
    else:
        if service_user:
            raise ReleaseError("--service-user applies only to hardened mode")
        owner_uid = service_uid = euid
    runtime_dir = root / "run"
    files = render(argv=argv, env=env or {}, runtime_dir=runtime_dir, max_sessions=max_sessions,
                   queue_wait_seconds=queue_wait_seconds, device_required=device_required,
                   python=python or sys.executable, owner_uid=owner_uid)
    digest = release_digest(files)
    if not root.exists():
        root.mkdir(mode=0o755, parents=True)
    _secure_directory(root, 0o755)
    releases = root / "releases"
    _secure_directory(releases, 0o755)
    _secure_directory(runtime_dir, 0o700, uid=service_uid)
    target = releases / digest
    if target.exists():
        for name in ALL_FILES:
            if (target / name).read_bytes() != files[name]:
                raise ReleaseError("an existing release with this digest differs; refusing to touch it")
        created = False
    else:
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
        try:
            for name in ALL_FILES:
                path = staging / name
                path.write_bytes(files[name])
                os.chmod(path, 0o555 if name in EXECUTABLE else 0o444)
            os.chmod(staging, 0o555)
            os.rename(staging, target)
        except BaseException:
            os.chmod(staging, 0o700)
            shutil.rmtree(staging, ignore_errors=True)
            raise
        created = True
    result = verify(target)
    if not result["ok"]:
        raise ReleaseError("the new release failed its own verification")
    return {"protocol": PROTOCOL, "release": str(target), "digest": digest,
            "forced_command": str(target / "run-mcp"), "mode": mode, "created": created,
            "runtime_dir": str(runtime_dir), "device_required": device_required}


def verify(release: Path) -> dict:
    """Run the release's own ``verify-release`` (the same check the forced command runs)."""
    _require_posix()
    script = release / "verify-release"
    if not script.is_file():
        return {"ok": False, "release": str(release), "exit_code": None}
    completed = subprocess.run([str(script)], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    return {"ok": completed.returncode == 0, "release": str(release), "exit_code": completed.returncode}
