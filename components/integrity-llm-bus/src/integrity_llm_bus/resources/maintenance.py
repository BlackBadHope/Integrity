# SPDX-License-Identifier: BUSL-1.1
"""P0-3: owned, expiring maintenance lock and FREEZE record.

state/MAINTENANCE.lock : watchdog, launcher.py and relay.py start/dispatch nothing while it is active.
state/FREEZE.json      : same effect, used for an owner-declared freeze.
Both are JSON {owner, reason, created, expires}. An unreadable record counts as ACTIVE (fail safe).
An expired record is inactive. Only the owner may release before expiry.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import os
from pathlib import Path
import re
import sys
import time

HERE = Path(__file__).resolve().parent
FILES = {"maintenance": "MAINTENANCE.lock", "freeze": "FREEZE.json"}
OWNER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,63}")
MAX_TTL_MIN = 24 * 60


def _path(state_dir: Path, kind: str) -> Path:
    return state_dir / FILES[kind]


def read(state_dir: Path, kind: str, now: float | None = None) -> dict | None:
    """Active record, or None. Corrupt record -> {'owner': None, 'invalid': True} (treated as active)."""
    path = _path(state_dir, kind)
    if not path.exists():
        return None
    now = time.time() if now is None else now
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        expires = float(record["expires"])
        if not isinstance(record.get("owner"), str):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        return {"kind": kind, "owner": None, "invalid": True}
    return {"kind": kind, **record} if expires > now else None


def blocking(state_dir: Path, now: float | None = None) -> dict | None:
    for kind in FILES:
        record = read(state_dir, kind, now)
        if record is not None:
            return record
    return None


def acquire(state_dir: Path, kind: str, owner: str, reason: str, ttl_min: int, now: float | None = None) -> dict:
    if not OWNER_RE.fullmatch(owner) or not reason.strip() or len(reason) > 200:
        raise ValueError("owner [a-z0-9._-] and reason (1-200 chars) required")
    if not 1 <= ttl_min <= MAX_TTL_MIN:
        raise ValueError(f"ttl 1-{MAX_TTL_MIN} minutes")
    now = time.time() if now is None else now
    current = read(state_dir, kind, now)
    if current is not None and current.get("owner") != owner:
        raise ValueError(f"{kind} held by {current.get('owner')!r}")
    record = {"owner": owner, "reason": reason, "created": int(now), "expires": int(now + ttl_min * 60)}
    path = _path(state_dir, kind)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return {"kind": kind, **record}


def release(state_dir: Path, kind: str, owner: str, now: float | None = None) -> bool:
    current = read(state_dir, kind, now)
    if current is not None and current.get("owner") not in (owner,):
        raise ValueError(f"{kind} held by {current.get('owner')!r}")
    path = _path(state_dir, kind)
    existed = path.exists()
    path.unlink(missing_ok=True)
    return existed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path(_integrity_value('state_directory')))
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("acquire", "release"):
        p = sub.add_parser(name)
        p.add_argument("--kind", choices=tuple(FILES), default="maintenance")
        p.add_argument("--owner", required=True)
        if name == "acquire":
            p.add_argument("--reason", required=True)
            p.add_argument("--ttl-min", type=int, default=30)
    sub.add_parser("status", help="exit 3 when anything blocks")
    args = parser.parse_args(argv)
    try:
        if args.command == "acquire":
            out = acquire(args.state_dir, args.kind, args.owner, args.reason, args.ttl_min)
        elif args.command == "release":
            out = {"released": release(args.state_dir, args.kind, args.owner)}
        else:
            out = blocking(args.state_dir)
            print(json.dumps(out, ensure_ascii=False))
            return 3 if out else 0
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False))
    return 0



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
