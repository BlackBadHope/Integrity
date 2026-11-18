#!/usr/bin/env python3
"""Uroboros: list compiled routes, or explain a route id that is not compiled here. Read-only, local files only.

  integrity-guards uroboros list [text]   routes whose id, target (argv) or summary contains every word of `text`
  (internal) --missing <id>               JSON error for the runner: the id is not a compiled one-call route here

Why: agents could otherwise learn about routes only from admission hints, which follow the words of the
prompt. A route for a host is easy to miss, and an agent may then report "no access" although a route exists.

The compiled routes directory is INTEGRITY_COMPILED_ROUTES or uroboros.compiled_routes in the guards
configuration.
"""
from __future__ import annotations

import difflib
import json
import os
import sys
from pathlib import Path

from integrity_guards import config as _config

PROTOCOL = "integrity-guardian/uroboros-route-run/v1"


def routes_dir() -> Path | None:
    value = os.environ.get("INTEGRITY_COMPILED_ROUTES") or _config.section("uroboros").get("compiled_routes")
    return Path(value) if value else None


def _validator():
    """The executor's validator, so that list marks routes the executor would refuse."""
    try:
        from integrity_guards.uroboros_exec import validate_compiled_route
    except Exception:  # noqa: BLE001 - list must work even if the executor cannot be imported
        return None
    return validate_compiled_route


def _row(path: Path, validate) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("route file is not a JSON object")
    steps = [s for s in (data.get("preconditions") or []) + (data.get("steps") or []) if isinstance(s, dict)]
    argv_text = " ".join(" ".join(str(a) for a in (s.get("argv") or [])) for s in steps)
    safety = str(data.get("safety"))
    if validate is not None:
        try:
            validate(dict(data))
        except Exception as exc:  # noqa: BLE001 - report the route, do not crash the whole list
            safety = "INVALID " + safety
            print(f"warning: {path.name}: not runnable: {str(exc)[:120]}", file=sys.stderr)
    params = data.get("params")
    return {"id": str(data.get("route_id") or path.stem), "version": data.get("version"), "safety": safety,
            "params": sorted(params.keys()) if isinstance(params, dict) else [],
            "summary": str(data.get("summary") or ""), "text": argv_text}


def load() -> list[dict]:
    """Every route file gives one row. A file that cannot be read is BROKEN, one the executor refuses is INVALID;
    neither hides the other routes (a route whose preconditions were prose, not steps, used to crash list)."""
    rows = []
    base = routes_dir()
    if base is None:
        return rows
    validate = _validator()
    for path in sorted(base.glob("*.json")):
        try:
            rows.append(_row(path, validate))
        except Exception as exc:  # noqa: BLE001 - one broken file must not hide the other routes
            print(f"warning: {path.name}: skipped: {type(exc).__name__}: {str(exc)[:120]}", file=sys.stderr)
            rows.append({"id": path.stem, "version": "?", "safety": "BROKEN", "params": [], "summary": "", "text": ""})
    return rows


def main(argv: list[str]) -> int:
    rows = load()
    if argv[:1] == ["--missing"]:
        wanted = argv[1] if len(argv) > 1 else ""
        near = difflib.get_close_matches(wanted, [r["id"] for r in rows], n=4, cutoff=0.5)
        near += [r["id"] for r in rows if any(w and w in r["id"] for w in wanted.split("-")) and r["id"] not in near][:4]
        print(json.dumps({"protocol": PROTOCOL, "ok": False,
                          "error": f"route '{wanted}' is not a compiled one-call route on this machine",
                          "hint": "If an Integrity hint named it as ROUTE (not MACRO), its steps live in that event: "
                                  "read the event, do not expect the route runner to know it. "
                                  "List what is compiled: integrity-guards uroboros list [text].",
                          "closest_compiled": near[:6]}, ensure_ascii=False))
        return 2
    words = [w.lower() for w in argv]
    shown = 0
    for r in rows:
        hay = " ".join((r["id"], r["text"], r["summary"])).lower()
        if all(w in hay for w in words):
            params = (" params=" + ",".join(r["params"])) if r["params"] else ""
            print(f"{r['id']} v{r['version']} [{r['safety']}]{params} - {r['summary'][:90]}")
            shown += 1
    print(f"-- {shown} of {len(rows)} compiled routes" + (f" match: {' '.join(argv)}" if argv else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
