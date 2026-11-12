#!/usr/bin/env python3
"""Route-share metric: share of remote production calls that went through a known Uroboros route, per day.

prod call  = a Bash/PowerShell tool call that ssh/plink-es to a configured host (uroboros.hosts, aliases,
             host_patterns) or matches uroboros.prod_patterns, or that runs a compiled route;
via route  = the call runs a compiled route (`uroboros run <route-id>` or `uroboros-run.sh <route-id>`).
Source: Claude Code transcripts (retroactive, no hook needed) - `transcripts [days]`;
        or the repeat hook's daily logs - `hook [day]`.
Days are counted in UTC shifted by uroboros.timezone_offset_hours (default 0).
Transcripts are read from uroboros.transcripts_dir (default ~/.claude/projects).
Output: one JSON line per day: {"day", "prod_calls", "via_route", "share_pct", "top_unrouted_hosts"}.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from integrity_guards import config as _config
from integrity_guards import uroboros_repeat_hook as _hook

_CFG = _config.section("uroboros")
LOCAL_TZ = timezone(timedelta(hours=float(_CFG.get("timezone_offset_hours") or 0)))
PROJECTS = Path(_CFG.get("transcripts_dir") or (Path.home() / ".claude" / "projects")).expanduser()
HOOK_STATE = _hook.STATE / "metrics"
REMOTE = re.compile(r"\b(?:ssh(?:\.exe)?|plink(?:\.exe)?)\b")
PROD_PATTERNS = [re.compile(p) for p in (_CFG.get("prod_patterns") or []) if isinstance(p, str) and p]
ROUTE = _hook.ROUTE_RUN


def host_of(cmd: str) -> str:
    host = _hook.host_of(cmd)
    return "other" if host == "?" else host


def is_prod(cmd: str) -> bool:
    return _hook.host_of(cmd) != "?" or any(rx.search(cmd) for rx in PROD_PATTERNS)


def from_transcripts(days: int) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    per = collections.defaultdict(lambda: {"prod": 0, "route": 0, "hosts": collections.Counter()})
    for path in PROJECTS.glob("*/*.jsonl"):
        try:
            if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < since:
                continue
            handle = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for line in handle:
                if '"tool_use"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                    ts = datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00"))
                except (ValueError, KeyError, TypeError):
                    continue
                if ts < since:
                    continue
                for block in rec.get("message", {}).get("content", []) or []:
                    if not isinstance(block, dict) or block.get("name") not in ("Bash", "PowerShell"):
                        continue
                    cmd = str((block.get("input") or {}).get("command") or "")
                    day = ts.astimezone(LOCAL_TZ).strftime("%Y-%m-%d")
                    if ROUTE.search(cmd):
                        per[day]["prod"] += 1
                        per[day]["route"] += 1
                    elif REMOTE.search(cmd) and is_prod(cmd):
                        per[day]["prod"] += 1
                        per[day]["hosts"][host_of(cmd)] += 1
    return per


def from_hook(day: str) -> dict:
    per = collections.defaultdict(lambda: {"prod": 0, "route": 0, "hosts": collections.Counter()})
    try:
        lines = (HOOK_STATE / f"{day}.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return per
    for line in lines:
        row = json.loads(line)
        for key in (day, f"{day} {row.get('vendor', 'claude')}"):  # total plus one line per vendor
            per[key]["prod"] += 1
            if row["kind"] == "route":
                per[key]["route"] += 1
            else:
                per[key]["hosts"][row["host"]] += 1
    return per


def main(argv: list[str]) -> int:
    mode = argv[0] if argv else "transcripts"
    per = from_hook(argv[1] if len(argv) > 1 else datetime.now(LOCAL_TZ).strftime("%Y-%m-%d")) if mode == "hook" \
        else from_transcripts(int(argv[1]) if len(argv) > 1 else 3)
    for day in sorted(per):
        d = per[day]
        share = round(100 * d["route"] / d["prod"], 1) if d["prod"] else 0.0
        print(json.dumps({"day": day, "prod_calls": d["prod"], "via_route": d["route"], "share_pct": share,
                          "top_unrouted_hosts": d["hosts"].most_common(4)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
