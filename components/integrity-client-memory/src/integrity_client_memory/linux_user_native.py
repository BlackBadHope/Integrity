# SPDX-License-Identifier: Apache-2.0
"""Linux user-custody Native head: same-uid, pinned vendor ancestor, 0700/0600.

The pinned hook runner publishes the current Native turn head that the vendor
process delivered on the hook's stdin. A reader (the local broker, or a later
hook) accepts that head only while it still descends from the same live vendor
process: same PID, same kernel start time, same euid, and an executable whose
resolved path and SHA-256 equal the profile pin.

Trust boundary, stated plainly: this is user custody. Root and any process
running as the same uid can read or replace these files, exactly as they could
read DPAPI CurrentUser data on Windows. The system-custody mode (root-owned
factory and Unix owner socket) remains the option for managed hosts.
No model-supplied value is ever accepted as a head.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

PROTOCOL = "integrity/linux-user-native-head/v1"
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
STATUSES = {"inProgress", "completed", "failed", "interrupted"}
MAX_ANCESTRY = 16
MAX_HEAD_BYTES = 4096
MAX_EXECUTABLE = 1024 * 1024 * 1024
_DIGESTS: dict[tuple, str] = {}


class LinuxNativeError(ValueError):
    """Fail-closed Native custody/ancestry refusal with a stable code."""


def need(ok, code):
    if not ok:
        raise LinuxNativeError(code)


def supported():
    return os.name == "posix" and Path("/proc/self/stat").is_file()


def process_source(pid):
    """Return (parent PID, kernel start time) from /proc/<pid>/stat."""
    text = (Path("/proc") / str(int(pid)) / "stat").read_text(encoding="ascii", errors="replace")
    fields = text[text.rfind(")") + 2:].split()
    return int(fields[1]), fields[19]


def process_uids(pid):
    for line in (Path("/proc") / str(int(pid)) / "status").read_text(encoding="ascii", errors="replace").splitlines():
        if line.startswith("Uid:"):
            return tuple(int(x) for x in line.split()[1:5])
    raise LinuxNativeError("linux_native_process_uid_unavailable")


def process_executable(pid):
    return Path(os.readlink(Path("/proc") / str(int(pid)) / "exe"))


def file_digest(path):
    """SHA-256 of a regular file, cached by its exact inode identity."""
    info = os.stat(path)
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_EXECUTABLE, "linux_native_executable_invalid")
    key = (str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    cached = _DIGESTS.get(key)
    if cached is None:
        with open(path, "rb") as stream:
            cached = hashlib.file_digest(stream, "sha256").hexdigest()
        _DIGESTS.clear()
        _DIGESTS[key] = cached
    return cached


def pin_executable(value):
    """Resolve an owner-selected vendor executable to the image the kernel runs."""
    candidate = Path(str(value))
    need(candidate.is_absolute(), "linux_native_executable_not_absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise LinuxNativeError("linux_native_executable_missing") from None
    info = resolved.stat()
    need(stat.S_ISREG(info.st_mode) and not stat.S_IMODE(info.st_mode) & 0o022, "linux_native_executable_custody_invalid")
    return str(resolved), file_digest(resolved)


def _pinned(pid, executable, executable_sha256):
    try:
        image = process_executable(pid)
    except OSError:
        return False
    if str(image) != executable:
        return False
    uids = process_uids(pid)
    return (all(uid == os.geteuid() for uid in uids)
            and file_digest(executable) == executable_sha256)


def find_vendor_ancestor(executable, executable_sha256, *, start=None):
    """Nearest live ancestor running the pinned vendor image as this euid."""
    need(supported(), "linux_native_platform_unavailable")
    current = os.getppid() if start is None else int(start)
    for _ in range(MAX_ANCESTRY):
        if current <= 1:
            break
        try:
            parent, birth = process_source(current)
        except (OSError, ValueError, IndexError):
            break
        if _pinned(current, executable, executable_sha256):
            return current, birth
        current = parent
    raise LinuxNativeError("linux_native_vendor_ancestor_missing")


def is_live_ancestor(pid, birth, executable, executable_sha256):
    """True only if exact (pid, birth) is still an ancestor running the pin."""
    current = os.getppid()
    for _ in range(MAX_ANCESTRY):
        if current <= 1:
            return False
        try:
            parent, observed = process_source(current)
        except (OSError, ValueError, IndexError):
            return False
        if current == pid:
            return observed == birth and _pinned(pid, executable, executable_sha256)
        current = parent
    return False


def private_directory(path):
    """Create or accept only an owner-only directory; refuse links and wider modes."""
    path = Path(path)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077,
         "linux_native_head_root_custody_invalid")
    return path


def _head_path(root, thread_id):
    return Path(root) / (hashlib.sha256(thread_id.encode("utf-8")).hexdigest() + ".json")


def publish_head(root, *, thread_id, turn_id, status, pid, birth, executable_sha256, prompt_sha256=None):
    need(UUID.fullmatch(str(thread_id)) and UUID.fullmatch(str(turn_id)) and status in STATUSES
         and (prompt_sha256 is None or re.fullmatch(r"[a-f0-9]{64}", str(prompt_sha256))),
         "linux_native_head_subject_invalid")
    directory = private_directory(root)
    value = {"protocol": PROTOCOL, "thread_id": thread_id, "turn_id": turn_id, "status": status,
             "native_pid": int(pid), "native_birth": str(birth),
             "native_executable_sha256": executable_sha256, "published_epoch": time.time()}
    if prompt_sha256 is not None:
        value["prompt_sha256"] = prompt_sha256
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    target = _head_path(directory, thread_id)
    temporary = directory / ("." + target.name + "." + os.urandom(8).hex() + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return value


def read_head(root, thread_id):
    need(UUID.fullmatch(str(thread_id)), "linux_native_subject_invalid")
    directory = Path(root)
    info = directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and not stat.S_IMODE(info.st_mode) & 0o077, "linux_native_head_root_custody_invalid")
    path = _head_path(directory, thread_id)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise LinuxNativeError("linux_native_head_missing") from None
    except OSError:
        raise LinuxNativeError("linux_native_head_custody_invalid") from None
    with os.fdopen(fd, "rb") as stream:
        details = os.fstat(stream.fileno())
        need(stat.S_ISREG(details.st_mode) and details.st_uid == os.geteuid()
             and not stat.S_IMODE(details.st_mode) & 0o077
             and 0 < details.st_size <= MAX_HEAD_BYTES, "linux_native_head_custody_invalid")
        raw = stream.read(MAX_HEAD_BYTES + 1)
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError):
        raise LinuxNativeError("linux_native_head_invalid") from None
    need(isinstance(value, dict) and value.get("protocol") == PROTOCOL
         and value.get("thread_id") == thread_id and UUID.fullmatch(str(value.get("turn_id")))
         and value.get("status") in STATUSES and type(value.get("native_pid")) is int
         and isinstance(value.get("native_birth"), str), "linux_native_head_invalid")
    return value


def claude_transcript_custody(path, session_id):
    """Accept only the session's own transcript: same name, euid-owned, not writable by others.

    Claude Code persists JSONL asynchronously, so content is not a required
    join here; a foreign, linked or shared-writable transcript is refused.
    """
    if path is None:
        return None
    candidate = Path(str(path))
    need(candidate.is_absolute() and candidate.name == str(session_id) + ".jsonl",
         "linux_native_transcript_subject_invalid")
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
         and not stat.S_IMODE(info.st_mode) & 0o022, "linux_native_transcript_custody_invalid")
    return True


def verified_head(root, thread_id, executable, executable_sha256):
    """Return {'id','status'} only for a head delivered by a live pinned ancestor."""
    need(supported(), "linux_native_platform_unavailable")
    value = read_head(root, thread_id)
    need(value.get("native_executable_sha256") == executable_sha256, "linux_native_executable_pin_changed")
    need(is_live_ancestor(value["native_pid"], value["native_birth"], executable, executable_sha256),
         "linux_native_vendor_ancestor_missing")
    return {"id": value["turn_id"], "status": value["status"]}
