# SPDX-License-Identifier: BUSL-1.1
"""Fail-closed boundary for this offline toolkit; not an OS security sandbox."""
from __future__ import annotations
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).absolute().parent.parent


def _expected_root() -> Path | None:
    """The fixed LAB root: INTEGRITY_LAB_ROOT, else the "root" key of lab.json; None if unset."""
    configured = os.environ.get("INTEGRITY_LAB_ROOT")
    if configured:
        return Path(configured)
    sys.path.insert(0, str(Path(__file__).absolute().parent))
    try:
        import lab_config
        return Path(lab_config.setting("root"))
    except (LookupError, OSError, ValueError):
        return None


EXPECTED_ROOT = _expected_root()
_installed = False


def checked(value: str | Path, *, base: Path = ROOT) -> Path:
    p = Path(value)
    if ".." in p.parts or (not p.is_absolute() and p.drive):
        raise PermissionError("parent traversal or drive-relative path refused")
    p = p if p.is_absolute() else base / p
    if EXPECTED_ROOT is None:
        raise PermissionError("LAB root not configured; set INTEGRITY_LAB_ROOT or \"root\" in lab.json")
    if not p.is_relative_to(ROOT) or ROOT != EXPECTED_ROOT:
        raise PermissionError("outside the fixed LAB root")
    for component in [p, *p.parents]:
        if component.exists() or component.is_symlink():
            details = component.lstat()
            if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & 0x400:
                raise PermissionError("reparse point or symlink refused")
            if component.is_file() and details.st_nlink != 1:
                raise PermissionError("hard-linked file refused")
    if not p.resolve().is_relative_to(ROOT.resolve()):
        raise PermissionError("resolved path outside LAB")
    for part in p.relative_to(ROOT).parts:
        if ":" in part or part.endswith((".", " ")):
            raise PermissionError("alternate stream or ambiguous name refused")
    return p


def actor_path(case_id: str, actor: str, member: str) -> Path:
    if not re.fullmatch(r"S(?:0[1-9]|1[0-9]|2[0-4])", case_id) or actor not in {"LAB-A", "LAB-B"}:
        raise PermissionError("unknown case or participant")
    base = checked(Path("workspaces") / case_id / actor)
    requested = Path(member)
    if requested.is_absolute() or requested.drive or ".." in requested.parts:
        raise PermissionError("actor traversal refused")
    result = checked(base / requested)
    if not result.is_relative_to(base):
        raise PermissionError("outside actor workspace")
    return result


def install() -> None:
    global _installed
    if _installed:
        return
    checked(ROOT)
    stdlib = Path(sys.base_prefix).resolve()

    def audit(event, args):
        if event.startswith(("subprocess.", "os.exec", "os.spawn")) or event in {"os.system", "os.startfile", "os.putenv"}:
            raise PermissionError("process launch and environment mutation disabled")
        if event.startswith("socket.") and event != "socket.gethostname":
            raise PermissionError("network disabled")
        if event == "sqlite3.connect":
            if str(args[0]) != ":memory:":
                raw = str(args[0])
                if raw.startswith("file:"):
                    # URI opens are generated only from prechecked paths in this toolkit.
                    from urllib.parse import unquote, urlsplit
                    raw = unquote(urlsplit(raw).path).lstrip("/")
                checked(raw)
        if event == "open" and not isinstance(args[0], int):
            p = Path(os.fsdecode(args[0])).absolute()
            mode = args[1] or ""
            flags = args[2] if len(args) > 2 else 0
            writing = any(x in mode for x in "wax+") or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if not writing and p.is_relative_to(stdlib):
                return
            checked(p)
        if event in {"os.listdir", "os.scandir"} and args and args[0] is not None and not isinstance(args[0], int):
            p = Path(os.fsdecode(args[0])).absolute()
            if not p.is_relative_to(stdlib):
                checked(p)
        if event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.chdir", "os.truncate", "os.utime"}:
            checked(os.fsdecode(args[0]))
        if event in {"os.rename", "os.link", "os.symlink"}:
            checked(os.fsdecode(args[0]))
            checked(os.fsdecode(args[1]))
    sys.addaudithook(audit)
    _installed = True


def readonly_db(path: str | Path):
    import sqlite3
    p = checked(path)
    if not p.is_file():
        raise FileNotFoundError(p.name)
    # This helper is only for sealed, quiescent preparation databases, never live WAL readers.
    db = sqlite3.connect(p.as_uri() + "?mode=ro&immutable=1", uri=True)
    db.execute("PRAGMA query_only=ON")
    return db
