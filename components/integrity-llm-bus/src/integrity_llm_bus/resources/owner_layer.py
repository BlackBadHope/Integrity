# SPDX-License-Identifier: BUSL-1.1
"""One-command rollback-to-zero for the owner-channel layer.

The installer records exactly what it changed (paths relative to the bus directory):
    python owner_layer.py record --backup <dir with preimage copies> --preimage PREIMAGE.sha256
        --replace bus.py --replace local_cli.py ... --add owner_verify.py --add owner_layer.py ...
Every --replace needs its copy in the backup (matching PREIMAGE.sha256 when given); every --add must have none.

`record` prints the journal sha256; the installer puts it in its bus report and Integrity event.

One command takes the bus back to the recorded preimage:
    python owner_layer.py rollback            # dry run (default)
    python owner_layer.py rollback --apply --preimage PREIMAGE.sha256 --expect-journal <sha256>

Guards:
- the backup must be a real directory <bus>/backup-owner-* (no link or junction);
- with --preimage / --expect-journal the journal is checked against anchors kept outside state/ (without them the
  journal is trusted as written: same-user tampering is then NOT excluded);
- every path from the record is re-validated as a plain file under the exact bus/backup directory (no escape,
  no symlink or junction) before planning and again before mutating;
- the plan is recomputed after relay and bridge are quiesced; any drift aborts before the first change;
- quiescence must be positive (no relay.py / file_bridge.py process of this bus found); an unknown state aborts,
  including a relay.py / file_bridge.py launched by a relative path or a python process whose command line is unreadable;
- a restored copy is hashed before it replaces the live file;
- re-runnable: files already restored or deleted by an interrupted run are skipped.
"applied" means the files are restored. Relay/bridge restart is left to the watchdog and must be post-checked.
The owner_nonces table, owner_keys.json and the Hello key are kept (inert without the gate).
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
RECORD = "owner-layer.json"
BACKUP_PREFIX = "backup-owner-"
SERVICES = ("relay.py", "file_bridge.py")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(text.encode("utf-8"))  # exact bytes: the reported journal sha256 must match the file
    os.replace(tmp, path)


def _backup_dir(bus: Path, backup: Path) -> Path:
    """The backup must be a real directory directly under the bus: <bus>/backup-owner-*."""
    if not backup.name.startswith(BACKUP_PREFIX) or _is_link(backup) or not backup.is_dir():
        raise ValueError(f"backup must be a real directory {BACKUP_PREFIX}* directly under the bus")
    if backup.resolve().parent != bus.resolve():
        raise ValueError(f"backup {backup} is not directly under {bus}")
    return backup.resolve()


def _inside(base: Path, name: str) -> Path:
    """name must be a plain relative path whose every component under base is a real (non-link) entry."""
    if not isinstance(name, str) or not name or Path(name).is_absolute() or ":" in name or ".." in Path(name).parts:
        raise ValueError(f"unsafe path in record: {name!r}")
    base = base.resolve()
    path = base
    for part in Path(name).parts:
        path = path / part
        if _is_link(path):
            raise ValueError(f"{name}: link in path")
    if base not in path.resolve().parents:
        raise ValueError(f"{name}: resolves outside {base}")
    return path


def _preimage_hashes(path: Path | None) -> dict:
    if path is None:
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(None, 1)
            out[name.lstrip("*").strip()] = digest.lower()
    return out


def record(bus: Path, backup: Path, replace: list, add: list, preimage: Path | None = None) -> dict:
    if set(replace) & set(add):
        raise ValueError("a file cannot be both replaced and added")
    backup, expected, entries = _backup_dir(bus, backup), _preimage_hashes(preimage), {}
    for name in replace:
        live, pre = _inside(bus, name), _inside(backup, name)
        if not live.is_file() or not pre.is_file():
            raise ValueError(f"{name}: a replaced file needs both the installed copy and its backup")
        if expected and expected.get(name) != sha(pre):
            raise ValueError(f"{name}: backup does not match the declared preimage hash")
        entries[name] = {"installed": sha(live), "preimage": sha(pre)}
    for name in add:
        live = _inside(bus, name)
        if not live.is_file():
            raise ValueError(f"{name}: added file is not installed")
        if _inside(backup, name).exists() or name in expected:
            raise ValueError(f"{name}: declared as added but a preimage exists")
        entries[name] = {"installed": sha(live), "preimage": None}
    doc = {"layer": "owner-channel", "state": "installed", "recorded_at": int(time.time()),
           "backup": str(backup.resolve()), "files": entries}
    _inside(bus, "state").mkdir(exist_ok=True)
    text = json.dumps(doc, indent=1)
    _write_atomic(bus / "state" / RECORD, text)
    return {**doc, "journal_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def plan(bus: Path, preimage: Path | None = None, expect_journal: str | None = None) -> dict:
    raw = (bus / "state" / RECORD).read_bytes()
    doc = json.loads(raw)
    actions, problems = [], []
    if doc.get("state") != "installed":
        problems.append(f"layer state is {doc.get('state')!r}, not installed")
    if expect_journal is not None and hashlib.sha256(raw).hexdigest() != expect_journal.lower():
        problems.append("journal differs from the sha256 reported at install")
    if preimage is not None:
        recorded = {n: e.get("preimage") for n, e in doc.get("files", {}).items() if e.get("preimage")}
        if recorded != _preimage_hashes(preimage):
            problems.append("journal preimages differ from the declared PREIMAGE")
    try:
        backup = _backup_dir(bus, Path(doc.get("backup", "")))
    except (ValueError, OSError) as exc:
        return {"doc": doc, "actions": [], "problems": problems + [str(exc)]}
    for name, e in doc.get("files", {}).items():
        try:
            live = _inside(bus, name)
            pre = _inside(backup, name) if e.get("preimage") else None
        except ValueError as exc:
            problems.append(str(exc))
            continue
        current = sha(live) if live.is_file() else None
        if e.get("preimage") is None:
            if current is None:
                continue  # already deleted by an interrupted earlier run
            if current != e.get("installed"):
                problems.append(f"{name}: changed after install; not touching it")
            actions.append({"file": name, "action": "delete", "sha256": current})
            continue
        if current == e["preimage"]:
            continue  # already restored by an interrupted earlier run
        if current != e.get("installed"):
            problems.append(f"{name}: {'missing' if current is None else 'changed after install; not touching it'}")
        if not pre.is_file() or sha(pre) != e["preimage"]:
            problems.append(f"{name}: backup copy missing or altered")
        actions.append({"file": name, "action": "restore", "sha256": e["preimage"]})
    return {"doc": doc, "actions": actions, "problems": problems}


def _ours(command_lines: list, bus: Path) -> list | None:
    """relay.py / file_bridge.py launches of THIS bus; None when one cannot be attributed (relative or unreadable)."""
    root = os.path.normcase(str(bus.resolve()))
    ours = []
    for line in command_lines:
        if not isinstance(line, str):
            return None  # a python process whose command line cannot be read
        for token in line.replace('"', " ").split():
            token = token.replace("/", "\\")
            if os.path.basename(token).lower() not in SERVICES:
                continue
            if not (token[1:3] == ":\\" or token.startswith("\\\\")):
                return None  # relative launch: its working directory is unknown
            if os.path.normcase(os.path.dirname(os.path.normpath(token))) == root:
                ours.append(line)
                break
    return ours


def running_services(bus: Path) -> list | None:
    """Command lines of relay.py / file_bridge.py processes of THIS bus; None if the state cannot be read."""
    # -InputObject keeps the array shape: zero processes -> [], one unreadable command line -> [null]
    script = ("$ErrorActionPreference = 'Stop'; ConvertTo-Json -Compress -InputObject "
              "@(Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" -ErrorAction Stop | "
              "ForEach-Object { $_.CommandLine })")
    try:
        out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script],
                             capture_output=True, text=True, encoding="oem", errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode:
        return None
    lines = _parse_probe(out.stdout)
    return None if lines is None else _ours(lines, bus)


def _parse_probe(stdout: str | None) -> list | None:
    """Only an explicit JSON array counts; empty output, null or any other shape is UNKNOWN."""
    try:
        lines = json.loads(stdout or "")
    except ValueError:
        return None
    return lines if isinstance(lines, list) else None


def stop_services(bus: Path, timeout: int = 60, probe=running_services) -> list:
    """Raise the watchdog stop flags and wait for a POSITIVE stopped state. Returns the flags this call created."""
    created = []
    for flag in (bus / "state" / "RELAY_STOP", bus / "bridge-state" / "STOP"):
        if not flag.exists():
            flag.parent.mkdir(exist_ok=True)
            flag.touch()
            created.append(flag)
    deadline = time.time() + timeout
    while True:
        state = probe(bus)
        if state == []:
            return created
        if time.time() >= deadline:
            raise RuntimeError("relay/bridge not confirmed stopped (still running or state unknown); "
                               "nothing restored, stop flags left in place")
        time.sleep(2)


def rollback(bus: Path, apply: bool, stop=stop_services, preimage: Path | None = None,
             expect_journal: str | None = None) -> dict:
    first = plan(bus, preimage, expect_journal)
    if first["problems"] or not apply:
        return {"applied": False, "actions": first["actions"], "problems": first["problems"]}
    created = stop(bus)
    p = plan(bus, preimage, expect_journal)  # re-check after quiesce: anything that moved while stopping aborts before any change
    if p["problems"] or p["actions"] != first["actions"]:
        return {"applied": False, "actions": p["actions"], "stop_flags_left": [str(f) for f in created],
                "problems": p["problems"] or ["files changed while relay/bridge were stopping"]}
    backup = _backup_dir(bus, Path(p["doc"]["backup"]))
    for a in p["actions"]:
        live = _inside(bus, a["file"])
        if a["action"] == "delete":
            live.unlink()
        else:
            tmp = live.with_name(live.name + ".rollback-tmp")
            shutil.copyfile(_inside(backup, a["file"]), tmp)
            if sha(tmp) != a["sha256"]:  # verify the copy BEFORE it can land live
                tmp.unlink()
                raise RuntimeError(f"{a['file']}: backup changed during rollback; stop flags left in place, re-run to resume")
            os.replace(tmp, live)
    doc = p["doc"]
    doc.update(state="rolled_back", rolled_back_at=int(time.time()))
    _write_atomic(bus / "state" / RECORD, json.dumps(doc, indent=1))
    for flag in created:  # only the flags this run created; the watchdog then restarts relay and bridge
        flag.unlink(missing_ok=True)
    return {"applied": True, "files_restored": True, "actions": p["actions"], "problems": [],
            "services": "restart left to the watchdog: post-check relay/bridge and one legacy send"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bus", type=Path, required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record"); r.add_argument("--backup", type=Path, required=True)
    r.add_argument("--preimage", type=Path, help="PREIMAGE.sha256 of the replaced files")
    r.add_argument("--replace", action="append", default=[]); r.add_argument("--add", action="append", default=[])
    st = sub.add_parser("status")
    rb = sub.add_parser("rollback"); rb.add_argument("--apply", action="store_true")
    for sp in (st, rb):
        sp.add_argument("--preimage", type=Path, help="the package PREIMAGE.sha256 (anchor outside state/)")
        sp.add_argument("--expect-journal", help="journal sha256 printed by record and kept in the install report")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "record":
            out = record(a.bus, a.backup, a.replace, a.add, a.preimage)
        elif a.cmd == "status":
            p = plan(a.bus, a.preimage, a.expect_journal)
            out = {"state": p["doc"].get("state"), "actions": p["actions"], "problems": p["problems"]}
        else:
            out = rollback(a.bus, a.apply, preimage=a.preimage, expect_journal=a.expect_journal)
            out["journal_anchor"] = ("checked" if a.preimage and a.expect_journal
                                     else "not checked (pass --preimage and --expect-journal)")
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if not out.get("problems") else 1



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
