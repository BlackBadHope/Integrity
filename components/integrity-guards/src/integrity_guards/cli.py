"""integrity-guards: one entry point for the hook-side guards.

  integrity-guards lock-guard [--enforce] [--exit-code] [record]   PreToolUse lock guard (stdin: hook JSON)
  integrity-guards rule-guard hook [--warn-only]                    PreToolUse rule guard (stdin: hook JSON)
  integrity-guards rule-guard validate --profile P --line L ...     check device lines against the registry
  integrity-guards rule-guard-antigravity                           rule guard with the Antigravity contract
  integrity-guards rules-drift [--hook] [--memory-dir DIR] [export.json]
  integrity-guards install-rule-guard install|rollback [--settings PATH]
  integrity-guards uroboros run <route> key=value ... [--apply]     run a compiled route
  integrity-guards uroboros validate <route.json>
  integrity-guards uroboros list [text]
  integrity-guards uroboros-repeat-hook [--vendor claude|codex|antigravity|grok|bus]
  integrity-guards uroboros-repeat-hook replay <recorded-calls.json>
  integrity-guards uroboros-share [transcripts [days] | hook [day]]

Configuration: INTEGRITY_GUARDS_CONFIG names a JSON file (see configuration.example.json).
Nothing here installs itself; the installer only runs when asked.
"""
from __future__ import annotations

import os
import sys


def _uroboros(argv: list[str]) -> int:
    from integrity_guards import uroboros_exec, uroboros_list

    if argv[:1] in (["list"], ["find"]):
        return uroboros_list.main(argv[1:])
    if argv[:1] == ["run"] and len(argv) > 1:
        route = argv[1]
        if not route.startswith("-") and not route.endswith(".json") and "/" not in route and "\\" not in route:
            base = uroboros_list.routes_dir()
            if base is None or not (base / f"{route}.json").is_file():
                return uroboros_list.main(["--missing", route])
            os.environ.setdefault("INTEGRITY_COMPILED_ROUTES", str(base))
    return uroboros_exec.main(argv)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0 if args else 1
    command, rest = args[0], args[1:]
    if command == "lock-guard":
        from integrity_guards import lock_guard
        return lock_guard.main(rest)
    if command == "rule-guard":
        from integrity_guards import rule_guard
        return rule_guard.main(["rule-guard", *rest])
    if command == "rule-guard-antigravity":
        from integrity_guards import antigravity_adapter
        return antigravity_adapter.main()
    if command == "rules-drift":
        from integrity_guards import rules_drift_check
        return rules_drift_check.main(rest)
    if command == "install-rule-guard":
        from integrity_guards import install
        return install.main(rest)
    if command == "uroboros":
        return _uroboros(rest)
    if command == "uroboros-repeat-hook":
        from integrity_guards import uroboros_repeat_hook
        return uroboros_repeat_hook.main(rest)
    if command == "uroboros-share":
        from integrity_guards import uroboros_route_share
        return uroboros_route_share.main(rest)
    print(f"integrity-guards: unknown command {command!r}", file=sys.stderr)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
