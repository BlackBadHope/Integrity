"""Install / roll back the rule guard as a warn-only PreToolUse hook in a Claude Code settings.json.

install:  integrity-guards install-rule-guard install  [--settings PATH]
          (backup -> settings.json.bak-rule-guard-<ts>, adds one entry)
rollback: integrity-guards install-rule-guard rollback [--settings PATH]
          (removes only the rule guard entry; other hooks untouched)

The default settings file is ~/.claude/settings.json. The hook command uses the
Python interpreter that runs this installer.
"""
import json
import os
import shutil
import sys
import time
from pathlib import Path

DEFAULT_SETTINGS = Path("~") / ".claude" / "settings.json"
MARK = "integrity_guards rule-guard hook"
MATCHER = "Bash|PowerShell|Read|Grep|Glob|mcp__.*javascript_tool"


def hook_command(python: str | None = None) -> str:
    py = (python or sys.executable).replace("\\", "/")
    return f'"{py}" -B -m {MARK} --warn-only'


def load(settings: Path) -> dict:
    if not settings.exists():
        return {}
    return json.loads(settings.read_text(encoding="utf-8"))


def save(settings: Path, s: dict) -> None:
    settings.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings.with_suffix(".json.tmp-rule-guard")
    tmp.write_text(json.dumps(s, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    json.loads(tmp.read_text(encoding="utf-8"))  # validate before replace
    os.replace(tmp, settings)


def strip(s: dict) -> dict:
    pre = s.get("hooks", {}).get("PreToolUse", [])
    new = []
    for h in pre:
        h = dict(h)
        h["hooks"] = [c for c in h.get("hooks", []) if MARK not in c.get("command", "")]
        if h["hooks"]:
            new.append(h)
    if "hooks" in s:
        s["hooks"]["PreToolUse"] = new
    return s


def install(settings: Path, python: str | None = None) -> dict:
    bak = None
    if settings.exists():
        bak = settings.with_name(f"settings.json.bak-rule-guard-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(settings, bak)
    cmd = hook_command(python)
    s = strip(load(settings))
    s.setdefault("hooks", {}).setdefault("PreToolUse", []).append(
        {"matcher": MATCHER, "hooks": [{"type": "command", "command": cmd, "timeout": 2}]})
    save(settings, s)
    return {"installed": True, "backup": str(bak) if bak else None, "command": cmd}


def rollback(settings: Path) -> dict:
    save(settings, strip(load(settings)))
    return {"rolled_back": True, "remaining_guard_entries": json.dumps(load(settings)).count(MARK)}


def main(argv: list[str]) -> int:
    args = list(argv)
    settings = DEFAULT_SETTINGS
    if "--settings" in args:
        i = args.index("--settings")
        if i + 1 >= len(args):
            print("--settings needs a path", file=sys.stderr)
            return 2
        settings = Path(args[i + 1])
        del args[i:i + 2]
    settings = Path(os.path.expanduser(str(settings)))
    actions = {"install": lambda: install(settings), "rollback": lambda: rollback(settings)}
    if not args or args[0] not in actions:
        print(__doc__)
        return 1
    print(json.dumps(actions[args[0]]()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
