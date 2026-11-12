"""Uroboros compiled routes: run a verified route at machine speed.

A route that already worked once can be *compiled*: its steps become argv
commands with a parameter schema, preconditions (the self-check), value
extraction and a per-step timeout. The agent then makes one call,
``run <route> key=value``. The executor runs every step without model
reasoning in between and returns one compact JSON result.

Safety:

* ``safety: read`` routes run directly.
* ``safety: write`` routes need ``apply=True`` **and** the route id listed in
  ``INTEGRITY_ROUTE_WRITE_GO`` (the operator's GO for that route class). A write
  route must declare a ``backup`` step, and it runs before any write step.
* Preconditions must be read-only. They run before a dry run as well, so a
  parameterised write macro validates every new value (inventory guard)
  before it even plans.
* Parameters are validated with a full-match regex before substitution, and
  substitution only fills placeholders inside argv elements. Nothing goes
  through a local shell.
* Secrets never pass through the executor: steps reach hosts where the secret
  is already in custody (for example a service EnvironmentFile on the target).

A failed precondition returns ``fallback: "agent"``, so a stale route fails
fast and the caller falls back to the normal agent path.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

FORMAT = "uroboros-compiled-route/v1"
RESULT_PROTOCOL = "integrity-guardian/uroboros-route-run/v1"
ENV_WRITE_GO = "INTEGRITY_ROUTE_WRITE_GO"
ENV_ROUTES_DIR = "INTEGRITY_COMPILED_ROUTES"
MAX_STEPS = 20
MAX_OUTPUT_CHARS = 64 * 1024
_PLACEHOLDER = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]{0,40})\}\}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,159}")


class CompiledRouteError(ValueError):
    """The compiled route or its parameters are invalid."""


Runner = Callable[[Sequence[str], float], tuple[int, str, str]]


def _default_runner(argv: Sequence[str], timeout: float) -> tuple[int, str, str]:
    completed = subprocess.run(  # noqa: S603 - argv list, no shell
        list(argv), capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, stdin=subprocess.DEVNULL, check=False,
    )
    return completed.returncode, completed.stdout[:MAX_OUTPUT_CHARS], completed.stderr[:MAX_OUTPUT_CHARS]


def _check_step(step: Any, where: str) -> None:
    if not isinstance(step, dict):
        raise CompiledRouteError(f"{where} must be an object")
    name = step.get("name")
    if not isinstance(name, str) or not _ID.fullmatch(name.replace(" ", "-")):
        raise CompiledRouteError(f"{where}.name is invalid")
    argv = step.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise CompiledRouteError(f"{where}.argv must be a non-empty list of strings")
    timeout = step.get("timeout_s", 15)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
        raise CompiledRouteError(f"{where}.timeout_s must be in (0, 300]")
    for key in ("expect",):
        if key in step:
            re.compile(step[key])
    extract = step.get("extract", {})
    if not isinstance(extract, dict):
        raise CompiledRouteError(f"{where}.extract must be an object")
    for out, pattern in extract.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", str(out)) or not isinstance(pattern, str):
            raise CompiledRouteError(f"{where}.extract has an invalid entry")
        if re.compile(pattern).groups < 1:
            raise CompiledRouteError(f"{where}.extract.{out} needs one capture group")


def validate_compiled_route(route: Any) -> dict[str, Any]:
    """Return the route if it is a well-formed ``uroboros-compiled-route/v1``."""

    if not isinstance(route, dict) or route.get("format") != FORMAT:
        raise CompiledRouteError(f"format must be {FORMAT}")
    if not isinstance(route.get("route_id"), str) or not _ID.fullmatch(route["route_id"]):
        raise CompiledRouteError("route_id is invalid")
    if route.get("safety") not in {"read", "write"}:
        raise CompiledRouteError("safety must be read or write")
    params = route.get("params", {})
    if not isinstance(params, dict) or not all(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", str(k)) and isinstance(v, str) for k, v in params.items()
    ):
        raise CompiledRouteError("params must map names to regex strings")
    for pattern in params.values():
        re.compile(pattern)
    steps = route.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise CompiledRouteError(f"steps must hold 1..{MAX_STEPS} steps")
    for index, step in enumerate(route.get("preconditions", [])):
        _check_step(step, f"preconditions[{index}]")
    for index, step in enumerate(steps):
        _check_step(step, f"steps[{index}]")
        if step.get("writes") and route["safety"] != "write":
            raise CompiledRouteError("a read route cannot have a writing step")
    if route["safety"] == "write":
        backup = route.get("backup")
        if not isinstance(backup, list) or not backup:
            raise CompiledRouteError("a write route must declare a backup step")
        for index, step in enumerate(backup):
            _check_step(step, f"backup[{index}]")
    total = route.get("timeout_s", 60)
    if isinstance(total, bool) or not isinstance(total, (int, float)) or not 0 < total <= 900:
        raise CompiledRouteError("timeout_s must be in (0, 900]")
    summary = route.get("summary", "")
    if not isinstance(summary, str) or len(summary) > 400:
        raise CompiledRouteError("summary must be a string up to 400 characters")
    return route


def _fill(text: str, values: Mapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            raise CompiledRouteError(f"placeholder {key} has no value")
        return values[key]

    return _PLACEHOLDER.sub(replace, text)


def _fill_pattern(pattern: str, values: Mapping[str, str]) -> str:
    """Placeholders in a regex take the literal (escaped) parameter value."""

    return _PLACEHOLDER.sub(lambda match: re.escape(values.get(match.group(1), "")), pattern)


def run_compiled_route(
    route: Mapping[str, Any],
    params: Mapping[str, str],
    *,
    apply: bool = False,
    runner: Runner | None = None,
    environ: Mapping[str, str] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run ``route`` with ``params``; never raises for target failures."""

    route = validate_compiled_route(dict(route))
    runner = runner or _default_runner
    environ = os.environ if environ is None else environ
    started = clock()
    result: dict[str, Any] = {
        "protocol": RESULT_PROTOCOL,
        "route_id": route["route_id"],
        "version": route.get("version", 1),
        "safety": route["safety"],
        "ok": False,
        "fallback": None,
        "outputs": {},
        "steps": [],
        "production_authority": False,
    }

    def finish(**extra: Any) -> dict[str, Any]:
        result.update(extra)
        result["elapsed_s"] = round(clock() - started, 3)
        return result

    unknown = sorted(set(params) - set(route.get("params", {})))
    if unknown:
        return finish(error="unknown parameters: " + ", ".join(unknown))
    values: dict[str, str] = {}
    for name, pattern in route.get("params", {}).items():
        value = params.get(name)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            return finish(error=f"parameter {name} is missing or does not match its schema")
        values[name] = value
    deadline = started + float(route.get("timeout_s", 60))

    def run_step(step: Mapping[str, Any], phase: str) -> bool:
        remaining = deadline - clock()
        if remaining <= 0:
            result["steps"].append({"phase": phase, "name": step["name"], "ok": False, "error": "route timeout"})
            return False
        argv = [_fill(arg, values) for arg in step["argv"]]
        t0 = clock()
        try:
            code, out, err = runner(argv, min(float(step.get("timeout_s", 15)), remaining))
        except subprocess.TimeoutExpired:
            code, out, err = 124, "", "step timeout"
        except OSError as exc:
            code, out, err = 127, "", f"cannot start: {exc.__class__.__name__}"
        record = {"phase": phase, "name": step["name"], "rc": code, "elapsed_s": round(clock() - t0, 3)}
        expect = _fill_pattern(step["expect"], values) if step.get("expect") else ""
        ok = code == 0 and (not expect or re.search(expect, out) is not None)
        for key, pattern in (step.get("extract") or {}).items():
            match = re.search(_fill_pattern(pattern, values), out, re.MULTILINE)
            if match:
                values[key] = match.group(1).strip()
                result["outputs"][key] = values[key]
            elif step.get("required", True):
                ok = False
                record.setdefault("missing", key)
        if not ok:
            record["stderr_tail"] = err.strip()[-300:]
        record["ok"] = ok
        result["steps"].append(record)
        return ok

    # Preconditions are read-only checks (inventory guard, reachability). They also run
    # before a dry run, so a plan is only shown for values the route accepts.
    for step in route.get("preconditions", []):
        if not run_step(step, "precondition"):
            return finish(fallback="agent", error=f"precondition failed: {step['name']}")
    if route["safety"] == "write":
        allowed = {item.strip() for item in environ.get(ENV_WRITE_GO, "").split(",") if item.strip()}
        if not apply:
            # Values extracted later (by the backup step) are shown as <name> in the plan.
            planned = [_PLACEHOLDER.sub(lambda m: values.get(m.group(1), f"<{m.group(1)}>"), " ".join(step["argv"]))
                       for step in route["backup"] + route["steps"]]
            return finish(error="write route: dry run only (pass apply)", dry_run=True, planned=planned)
        if route["route_id"] not in allowed:
            return finish(error=f"write route needs an operator GO: set {ENV_WRITE_GO} to include {route['route_id']}")
        for step in route["backup"]:
            if not run_step(step, "backup"):
                return finish(error=f"backup failed: {step['name']}; nothing written")
    for step in route["steps"]:
        if not run_step(step, "step"):
            return finish(fallback="agent", error=f"step failed: {step['name']}")
    summary = route.get("summary") or ""
    try:
        result["summary"] = _fill(summary, values) if summary else ""
    except CompiledRouteError:
        result["summary"] = summary
    return finish(ok=True)


def load_route(reference: str, routes_dir: str | None = None) -> dict[str, Any]:
    """Load a compiled route by path or by id from ``INTEGRITY_COMPILED_ROUTES``."""

    path = Path(reference)
    if not path.suffix:
        base = routes_dir or os.environ.get(ENV_ROUTES_DIR, "")
        if not base:
            raise CompiledRouteError(f"route id given but {ENV_ROUTES_DIR} is not set")
        if not _ID.fullmatch(reference):
            raise CompiledRouteError("route id is invalid")
        path = Path(base) / f"{reference}.json"
    return validate_compiled_route(json.loads(path.read_text(encoding="utf-8")))


def main(argv: Sequence[str] | None = None) -> int:
    """``integrity-guards uroboros run <route> key=value ... [--apply]``."""

    import argparse

    parser = argparse.ArgumentParser(prog="integrity-guards uroboros")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run a compiled route")
    run.add_argument("route", help="route id (from INTEGRITY_COMPILED_ROUTES) or a .json path")
    run.add_argument("params", nargs="*", help="key=value")
    run.add_argument("--apply", action="store_true", help="allow a write route to write (needs an operator GO)")
    check = sub.add_parser("validate", help="validate a compiled route file")
    check.add_argument("path")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            route = load_route(args.path)
            print(f"ok: {route['route_id']} ({route['safety']})")
            return 0
        params = {}
        for item in args.params:
            key, sep, value = item.partition("=")
            if not sep:
                raise CompiledRouteError(f"parameter {item!r} must be key=value")
            params[key] = value
        result = run_compiled_route(load_route(args.route), params, apply=args.apply)
    except (CompiledRouteError, OSError, ValueError) as exc:
        print(json.dumps({"protocol": RESULT_PROTOCOL, "ok": False, "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
