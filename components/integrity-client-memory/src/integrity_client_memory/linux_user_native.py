# SPDX-License-Identifier: BUSL-1.1
"""Linux user-custody Native head: same-uid, pinned vendor ancestor, 0700/0600.

The pinned hook runner publishes the current Native turn head that the vendor
process delivered on the hook's stdin. A reader (the local broker, or a later
hook) accepts that head only while it still descends from the same live vendor
process: same PID, same kernel start time, same euid, and a trusted vendor
image. The image is trusted when its resolved path and SHA-256 equal the
profile pin, or when it lies under one of the profile's trusted vendor roots
(for Claude Code ``~/.local/share/claude/versions``) and the file and every
directory from that root down to it are owned by this euid or root and not
writable by group or others. Vendor auto-updates install a new version beside
the old one, so a root keeps the profile valid across updates without widening
the user-custody boundary stated below. A published head records the digest of
the image that delivered it; a later reader accepts it only from the same live
process still running that exact image.

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


def _custody_owner(info):
    return info.st_uid in (os.geteuid(), 0) and not stat.S_IMODE(info.st_mode) & 0o022


def trusted_root(value):
    """Validate one owner-selected vendor root: absolute, a real directory, owner-only writes."""
    candidate = Path(str(value))
    need(candidate.is_absolute(), "linux_native_trusted_root_not_absolute")
    try:
        info = candidate.lstat()
    except OSError:
        raise LinuxNativeError("linux_native_trusted_root_missing") from None
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and _custody_owner(info),
         "linux_native_trusted_root_custody_invalid")
    return str(candidate)


def _under_trusted_root(image, roots):
    """True when ``image`` is a regular file below a root through a custody-clean chain."""
    for root in roots or ():
        root = Path(root)
        try:
            relative = image.relative_to(root)
        except ValueError:
            continue
        if not relative.parts:
            continue
        chain, current = [root], root
        for part in relative.parts:
            current = current / part
            chain.append(current)
        try:
            infos = [path.lstat() for path in chain]
        except OSError:
            continue
        if (all(not stat.S_ISLNK(i.st_mode) and _custody_owner(i) for i in infos)
                and all(stat.S_ISDIR(i.st_mode) for i in infos[:-1])
                and stat.S_ISREG(infos[-1].st_mode)):
            return True
    return False


def image_digest(pid, executable, executable_sha256, trusted_roots=()):
    """Digest of ``pid``'s image when it is a trusted vendor image run by this euid, else None."""
    try:
        image = process_executable(pid)
        uids = process_uids(pid)
    except (OSError, LinuxNativeError):
        return None
    if not all(uid == os.geteuid() for uid in uids):
        return None
    try:
        if str(image) == executable and file_digest(executable) == executable_sha256:
            return executable_sha256
        if _under_trusted_root(image, trusted_roots):
            return file_digest(image)
    except (OSError, LinuxNativeError):
        return None
    return None


def _pinned(pid, executable, executable_sha256, trusted_roots=()):
    return image_digest(pid, executable, executable_sha256, trusted_roots) is not None


def find_vendor_image_ancestor(executable, executable_sha256, *, start=None, trusted_roots=()):
    """Nearest live ancestor running a trusted vendor image: (pid, birth, image digest)."""
    need(supported(), "linux_native_platform_unavailable")
    current = os.getppid() if start is None else int(start)
    for _ in range(MAX_ANCESTRY):
        if current <= 1:
            break
        try:
            parent, birth = process_source(current)
        except (OSError, ValueError, IndexError):
            break
        digest = image_digest(current, executable, executable_sha256, trusted_roots)
        if digest is not None:
            return current, birth, digest
        current = parent
    raise LinuxNativeError("linux_native_vendor_ancestor_missing")


def find_vendor_ancestor(executable, executable_sha256, *, start=None, trusted_roots=()):
    """Nearest live ancestor running a trusted vendor image as this euid."""
    pid, birth, _ = find_vendor_image_ancestor(executable, executable_sha256, start=start,
                                               trusted_roots=trusted_roots)
    return pid, birth


def is_live_ancestor(pid, birth, executable, executable_sha256, trusted_roots=(), image_sha256=None):
    """True only if exact (pid, birth) is still an ancestor running the same trusted image."""
    current = os.getppid()
    for _ in range(MAX_ANCESTRY):
        if current <= 1:
            return False
        try:
            parent, observed = process_source(current)
        except (OSError, ValueError, IndexError):
            return False
        if current == pid:
            if observed != birth:
                return False
            digest = image_digest(pid, executable, executable_sha256, trusted_roots)
            return digest is not None and (image_sha256 is None or digest == image_sha256)
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


def verified_head(root, thread_id, executable, executable_sha256, trusted_roots=()):
    """Return {'id','status'} only for a head delivered by a live trusted ancestor."""
    need(supported(), "linux_native_platform_unavailable")
    value = read_head(root, thread_id)
    recorded = value.get("native_executable_sha256")
    need(recorded == executable_sha256 or (bool(trusted_roots) and isinstance(recorded, str)
                                           and re.fullmatch(r"[a-f0-9]{64}", recorded) is not None),
         "linux_native_executable_pin_changed")
    need(is_live_ancestor(value["native_pid"], value["native_birth"], executable, executable_sha256,
                          trusted_roots, image_sha256=recorded),
         "linux_native_vendor_ancestor_missing")
    return {"id": value["turn_id"], "status": value["status"]}
