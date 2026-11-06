#!/usr/bin/env python3
"""Fail a Linux CI job when Native client-memory coverage silently disappears.

Reads pytest JUnit XML. Every skipped test whose identifier contains --scope
must carry one of the reviewed reasons below; any other reason (for example a
reintroduced "Windows-only" gate) fails the job. Each --require fragment must
match at least one test that actually passed.
"""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ElementTree

# Reviewed Linux skip reasons: platform-absent tools, other vendors' parametrised
# cases, Windows cmd-launcher specifics with POSIX counterparts, and static
# analysis limits. Native profile execution itself is never on this list.
ALLOWED_LINUX_SKIPS = frozenset({
    "PowerShell is not installed on this platform",
    "star import makes module-level names non-static",
    "Antigravity hook uses its conversation broker rather than McpClient",
    "Claude owning hook resolves the sibling catalogue",
    "separate observed Antigravity transport",
    "Antigravity-only schema",
    "observed Windows cmd launcher",
    "Windows hook shell",
})


def outcomes(paths):
    for path in paths:
        for case in ElementTree.parse(path).iter("testcase"):
            ident = ".".join(x for x in (case.get("classname"), case.get("name")) if x)
            skipped = case.find("skipped")
            failed = case.find("failure") is not None or case.find("error") is not None
            if skipped is not None:
                yield ident, "skipped", (skipped.get("message") or "").strip()
            else:
                yield ident, "failed" if failed else "passed", ""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit", nargs="+")
    parser.add_argument("--scope", default="integrity-client-memory")
    parser.add_argument("--require", action="append", default=[])
    args = parser.parse_args(argv)
    rows = list(outcomes(args.junit))
    problems = []
    scoped = [row for row in rows if args.scope in row[0]]
    for ident, outcome, reason in scoped:
        if outcome == "skipped" and reason not in ALLOWED_LINUX_SKIPS:
            problems.append(f"unreviewed skip: {ident}: {reason or '<no reason>'}")
    for fragment in args.require:
        if not any(fragment in ident and outcome == "passed" for ident, outcome, _ in rows):
            problems.append(f"required Linux coverage did not pass: {fragment}")
    passed = sum(outcome == "passed" for _, outcome, _ in scoped)
    skipped = sum(outcome == "skipped" for _, outcome, _ in scoped)
    print(f"{args.scope}: {passed} passed, {skipped} skipped (reviewed reasons only)" if not problems else "")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
