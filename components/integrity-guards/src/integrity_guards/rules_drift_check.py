#!/usr/bin/env python3
"""Rule drift check: rule files in a memory directory vs the last exported/recorded sha.

Usage: integrity-guards rules-drift [--memory-dir DIR] [export.json]
         -> prints RULE_DRIFT / RULE_NEW lines, exit 0 always.
Hook form (SessionStart, warn-only): integrity-guards rules-drift --hook
         -> additionalContext when drift found.

The memory directory and the export come from --memory-dir / the positional
argument, or from rules_drift.memory_dir / rules_drift.export in the guards
configuration. Without them the check reports nothing.
The export is a JSON object {"owner_rules": [{"rule_id", "source": {"sha256"}}]}.
"""
import hashlib
import json
import sys
from pathlib import Path

from integrity_guards import config as _config


def _configured(key: str) -> Path | None:
    value = _config.section("rules_drift").get(key)
    return Path(value).expanduser() if value else None


def drift(export_path: Path | None = None, memory_dir: Path | None = None) -> list[str]:
    export_path = export_path or _configured("export")
    memory_dir = memory_dir or _configured("memory_dir")
    if export_path is None or memory_dir is None:
        return []
    try:
        known = {r["rule_id"]: r.get("source", {}).get("sha256")
                 for r in json.loads(export_path.read_text(encoding="utf-8"))["owner_rules"]}
    except Exception:
        return []
    out = []
    for p in sorted(memory_dir.glob("*.md")):
        if p.stem == "MEMORY":
            continue
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        if p.stem not in known:
            out.append(f"RULE_NEW: {p.stem} (not in the exported rule set)")
        elif known[p.stem] and known[p.stem] != sha:
            out.append(f"RULE_DRIFT: {p.stem} changed after export ({known[p.stem][:12]} -> {sha[:12]}); record a supersede event")
    return out


def main(argv: list[str]) -> int:
    args = list(argv)
    memory_dir = None
    if "--memory-dir" in args:
        i = args.index("--memory-dir")
        memory_dir = Path(args[i + 1]) if i + 1 < len(args) else None
        del args[i:i + 2]
    if "--hook" in args:
        try:
            lines = drift(memory_dir=memory_dir)
            if lines:
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                  "additionalContext": "RULE DRIFT (warn): " + " | ".join(lines[:10])}}))
        except Exception:
            pass
        return 0
    positional = [a for a in args if not a.startswith("--")]
    for line in drift(Path(positional[0]) if positional else None, memory_dir):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
