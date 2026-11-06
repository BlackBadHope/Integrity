# SPDX-License-Identifier: Apache-2.0
"""Uroboros known-route retrieval: pure, bounded, authority-free.

A *route* is a path to a result that already worked once. The next agent
should find it at admission instead of rediscovering it. This module only
selects candidates from Seed events already admitted by the caller. It never
reads files or the network, never runs anything and grants no authority. A
route is a hint to check against current state, not permission to act.

Two sources are recognised:

``explicit``
    The event carries ``details.uroboros_route`` in the ``uroboros-route/v1``
    format: an agent recorded a reusable path on purpose. Versions of the same
    ``route_id`` supersede each other; ``superseded`` routes are not offered,
    and ``stale`` ones are offered with a "verify first" label.
``bundle``
    ``details.uroboros_routes`` holds a list of up to 32 explicit records, so
    one append can register a whole runbook catalogue.
``observed``
    Any verified, completed unit of work: an agent-log close with
    ``truth_status=verified`` and ``result=done``, or an event tagged
    ``uroboros-route``. Every Integrity Seed therefore yields routes from its
    own history, with no migration.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

PROTOCOL = "integrity-guardian/uroboros-known-routes/v1"
ROUTE_FORMAT = "uroboros-route/v1"
CHECK_FORMAT = "uroboros-route-check/v1"
CHECK_RESULTS = ("pass", "fail")
ROUTE_TAG = "uroboros-route"
ROUTE_STATUSES = ("candidate", "verified", "stale", "superseded")
MAX_ROUTES = 3
MAX_BUNDLE_ROUTES = 32
MAX_HINT_CHARS = 200
MAX_TERMS = 32
COMPLETION_ACTIONS = frozenset({"agent_change_complete"})
DONE_RESULTS = frozenset({"done", "complete", "completed", "success", "pass"})
_STATUS_BONUS = {"verified": 3.0, "candidate": 1.0, "stale": 0.5, "observed": 1.0}
_FIELD_WEIGHTS = (("triggers", 4.0), ("title", 3.0), ("scope", 2.0), ("steps", 1.0))
_MIN_SCORE = 6.0
_MIN_OBSERVED_SCORE = 9.0
_WORD = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|[^\W_][\w.:@/\-]*", re.UNICODE)


_SECRET_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*[^\s,;]{6,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\bgh[pousr]_[A-Za-z0-9]{20,}",
    r"\bsk-[A-Za-z0-9_-]{20,}",
    r"\bxox[abposr]-[A-Za-z0-9-]{10,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
))
MAX_FIELD_CHARS = 2000
MAX_LIST_ITEMS = 40
_RECORD_FIELDS = frozenset({
    "format", "route_id", "version", "status", "title", "triggers", "preconditions",
    "steps", "postchecks", "rollback", "verified_at", "provenance_event_ids", "scope",
})


class RouteRecordError(ValueError):
    """A route record is malformed or carries secret-like text."""


def looks_secret(text: str) -> bool:
    """True when ``text`` contains a credential-like literal. Never echo it."""

    return any(pattern.search(text) for pattern in _SECRET_PATTERNS)


def validate_route_record(record: Any) -> dict[str, Any]:
    """Return a normalised ``uroboros-route/v1`` record or raise ``RouteRecordError``.

    Error messages name the field, never its content.
    """

    if not isinstance(record, dict):
        raise RouteRecordError("route record must be an object")
    unknown = sorted(set(record) - _RECORD_FIELDS)
    if unknown:
        raise RouteRecordError("unknown route fields: " + ", ".join(unknown))
    if record.get("format") != ROUTE_FORMAT:
        raise RouteRecordError(f"format must be {ROUTE_FORMAT}")
    route_id = record.get("route_id")
    if not isinstance(route_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}", route_id):
        raise RouteRecordError("route_id must match [A-Za-z0-9][A-Za-z0-9._:/-]{2,159}")
    title = record.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > 400:
        raise RouteRecordError("title must be 1..400 characters")
    status = record.get("status", "candidate")
    if status not in ROUTE_STATUSES:
        raise RouteRecordError("status must be one of " + ", ".join(ROUTE_STATUSES))
    version = record.get("version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RouteRecordError("version must be a positive integer")
    for name in ("triggers", "preconditions", "steps", "postchecks", "provenance_event_ids"):
        value = record.get(name, [])
        if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
            raise RouteRecordError(f"{name} must be a list of at most {MAX_LIST_ITEMS} items")
    if any(isinstance(n, bool) or not isinstance(n, int) or n < 1 for n in record.get("provenance_event_ids", [])):
        raise RouteRecordError("provenance_event_ids must be positive integers")
    if len(record.get("triggers", [])) < 2:
        raise RouteRecordError("give at least two triggers so the route can be found")
    for name in ("rollback", "verified_at", "scope"):
        if name in record and not isinstance(record[name], str):
            raise RouteRecordError(f"{name} must be a string")
    texts = [title, str(record.get("rollback", "")), str(record.get("scope", ""))]
    for name in ("triggers", "preconditions", "steps", "postchecks"):
        for item in record.get(name, []):
            if not isinstance(item, str) or not item.strip() or len(item) > MAX_FIELD_CHARS:
                raise RouteRecordError(
                    f"{name} items must be non-empty strings up to {MAX_FIELD_CHARS} characters")
            texts.append(item)
    if any(looks_secret(text) for text in texts):
        raise RouteRecordError("route carries secret-like text; reference the secret store instead")
    return {**record, "format": ROUTE_FORMAT, "status": status, "version": version}


def draft_route_record(
    *,
    route_id: str,
    title: str,
    triggers: Sequence[str],
    steps: Sequence[str] = (),
    preconditions: Sequence[str] = (),
    postchecks: Sequence[str] = (),
    rollback: str = "",
    status: str = "candidate",
    version: int = 1,
    provenance_event_ids: Sequence[int] = (),
    verified_at: str = "",
    scope: str = "",
) -> dict[str, Any]:
    """Build and validate a record ready for ``details.uroboros_route``."""

    record: dict[str, Any] = {
        "format": ROUTE_FORMAT, "route_id": route_id, "version": version, "status": status,
        "title": title, "triggers": list(triggers), "preconditions": list(preconditions),
        "steps": list(steps), "postchecks": list(postchecks), "rollback": rollback,
        "provenance_event_ids": list(provenance_event_ids),
    }
    if verified_at:
        record["verified_at"] = verified_at
    if scope:
        record["scope"] = scope
    return validate_route_record(record)


def validate_route_check(record: Any) -> dict[str, Any]:
    """Validate one ``uroboros-route-check/v1`` record (a verify result)."""

    if not isinstance(record, dict):
        raise RouteRecordError("route check must be an object")
    unknown = sorted(set(record) - {"format", "route_id", "version", "result", "checked_at", "note"})
    if unknown:
        raise RouteRecordError("unknown check fields: " + ", ".join(unknown))
    if record.get("format") != CHECK_FORMAT:
        raise RouteRecordError(f"format must be {CHECK_FORMAT}")
    route_id = record.get("route_id")
    if not isinstance(route_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}", route_id):
        raise RouteRecordError("route_id must match [A-Za-z0-9][A-Za-z0-9._:/-]{2,159}")
    if record.get("result") not in CHECK_RESULTS:
        raise RouteRecordError("result must be pass or fail")
    version = record.get("version")
    if version is not None and (isinstance(version, bool) or not isinstance(version, int) or version < 1):
        raise RouteRecordError("version must be a positive integer")
    for name in ("checked_at", "note"):
        if name in record and (not isinstance(record[name], str) or len(record[name]) > MAX_FIELD_CHARS):
            raise RouteRecordError(f"{name} must be a string up to {MAX_FIELD_CHARS} characters")
    if looks_secret(str(record.get("note", ""))):
        raise RouteRecordError("check note carries secret-like text")
    return dict(record)


def draft_route_check(
    *, route_id: str, result: str, version: int | None = None, checked_at: str = "", note: str = ""
) -> dict[str, Any]:
    """Build and validate a check record ready for ``details.uroboros_route_check``."""

    record: dict[str, Any] = {"format": CHECK_FORMAT, "route_id": route_id, "result": result,
                              "checked_at": checked_at or dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if version is not None:
        record["version"] = version
    if note:
        record["note"] = note
    return validate_route_check(record)


def _check_from_event(event: Mapping[str, Any], details: dict[str, Any]) -> dict[str, Any] | None:
    raw = details.get("uroboros_route_check")
    try:
        check = validate_route_check(raw)
    except RouteRecordError:
        return None
    check["event_id"] = _int(event.get("id")) or 0
    check.setdefault("checked_at", str(event.get("ts_utc") or "")[:32])
    return check


def _details(event: Mapping[str, Any]) -> dict[str, Any]:
    details = event.get("details")
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            return {}
    return details if isinstance(details, dict) else {}


def _strings(value: Any, *, limit: int = 40) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in items:
        if isinstance(item, (dict, list)):
            text = json.dumps(item, ensure_ascii=False, sort_keys=True)
        else:
            text = str(item)
        text = text.strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _tags(event: Mapping[str, Any]) -> list[str]:
    tags = event.get("tags")
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except ValueError:
            tags = re.split(r"[,;\s]+", tags)
    return [str(tag) for tag in tags or [] if str(tag).strip()]


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _explicit(raw: Any, details: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or raw.get("format") != ROUTE_FORMAT:
        return None
    route_id = str(raw.get("route_id") or "").strip()
    title = str(raw.get("title") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}", route_id) or not title:
        return None
    status = str(raw.get("status") or "candidate").strip().lower()
    if status not in ROUTE_STATUSES:
        status = "candidate"
    version = _int(raw.get("version")) or 1
    return {
        "source": "explicit",
        "route_id": route_id,
        "version": version,
        "status": status,
        "title": title,
        "triggers": _strings(raw.get("triggers")),
        "scope": " ".join(_strings(raw.get("scope")) + _strings(details.get("subsystem"))),
        "steps": _strings(raw.get("steps")) + _strings(raw.get("preconditions")) + _strings(raw.get("postchecks")),
        "step_count": len(_strings(raw.get("steps"))),
        "run_steps": _strings(raw.get("steps"))[:3],
        "has_rollback": bool(str(raw.get("rollback") or "").strip()),
        "verified_at": str(raw.get("verified_at") or "")[:32],
        "provenance_event_ids": [n for n in (_int(v) for v in raw.get("provenance_event_ids") or []) if n],
    }


def _observed(event: Mapping[str, Any], details: dict[str, Any]) -> dict[str, Any] | None:
    tags = _tags(event)
    tagged = ROUTE_TAG in tags
    action = str(event.get("action") or "")
    verified = str(details.get("truth_status") or "").strip().lower() == "verified"
    done = str(details.get("result") or "").strip().lower() in DONE_RESULTS
    completed = action in COMPLETION_ACTIONS or str(details.get("kind") or "") == "task-complete"
    if not (tagged or (completed and verified and done)):
        return None
    summary = str(event.get("summary") or "").strip()
    if not summary:
        return None
    task_id = str(details.get("task_id") or "").strip()
    return {
        "source": "observed",
        "route_id": task_id or f"event:{event.get('id')}",
        "version": 1,
        "status": "observed",
        "title": summary,
        "triggers": [tag for tag in tags if tag != ROUTE_TAG],
        "scope": " ".join(_strings(details.get("scope")) + _strings(details.get("subsystem"))),
        "steps": _strings(details.get("commands")) + _strings(details.get("verification")),
        "step_count": len(_strings(details.get("commands"))),
        "run_steps": _strings(details.get("commands"))[:3],
        "has_rollback": bool(str(details.get("rollback") or "").strip()),
        "verified_at": str(event.get("ts_utc") or "")[:32] if verified else "",
        "provenance_event_ids": [],
    }


def routes_from_event(event: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return every route view carried by one Seed event (possibly none)."""

    details = _details(event)
    routes: list[dict[str, Any]] = []
    single = _explicit(details.get("uroboros_route"), details)
    if single is not None:
        routes.append(single)
    bundle = details.get("uroboros_routes")
    if isinstance(bundle, list):
        for raw in bundle[:MAX_BUNDLE_ROUTES]:
            route = _explicit(raw, details)
            if route is not None:
                routes.append(route)
    if not routes:
        observed = _observed(event, details)
        if observed is not None:
            routes.append(observed)
    for route in routes:
        route["event_id"] = _int(event.get("id"))
        route["ts_utc"] = str(event.get("ts_utc") or "")[:32]
    return routes


def route_from_event(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return the first route view of one Seed event, or ``None``."""

    routes = routes_from_event(event)
    return routes[0] if routes else None


def _normalise_terms(terms: Iterable[str]) -> list[str]:
    result: list[str] = []
    for term in terms:
        folded = str(term).casefold().strip(".:/@-_")
        if len(folded) < 3 or folded.isdigit():
            continue
        # Light stemming for inflected languages: "абонента" ~ "абонент".
        if len(folded) >= 7 and not re.search(r"\d", folded):
            folded = folded[: len(folded) - 2]
        if folded not in result:
            result.append(folded)
        if len(result) >= MAX_TERMS:
            break
    return result


def _score(route: dict[str, Any], terms: Sequence[str]) -> tuple[float, list[str]]:
    fields = {
        "triggers": " ".join(route["triggers"]).casefold(),
        "title": route["title"].casefold(),
        "scope": route["scope"].casefold(),
        "steps": " ".join(route["steps"]).casefold(),
    }
    score = 0.0
    matched: list[str] = []
    for term in terms:
        best = 0.0
        for name, weight in _FIELD_WEIGHTS:
            if term in fields[name]:
                best = max(best, weight)
        if best:
            score += best
            matched.append(term)
    return score, matched


def _age_days(ts: str, now: dt.datetime) -> float:
    try:
        stamp = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return 365.0
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.UTC)
    return max(0.0, (now - stamp).total_seconds() / 86_400)


def route_hint(route: Mapping[str, Any]) -> str:
    """One capsule line, at most 200 characters, explicitly not authority.

    Short enough that three routes still fit the rendered capsule text.
    """

    status = str(route.get("status") or "")
    if route.get("check_failed_at"):
        label = f"check failed {str(route['check_failed_at'])[:10]}: repair, then new version"
    elif status in {"stale", "observed", "candidate"}:
        label = "verify first"
    else:
        label = "re-check"
    head = f"ROUTE #{route.get('event_id')} {status}"
    if route.get("source") == "explicit":
        head += f" {route.get('route_id')} v{route.get('version')}"
    date = str(route.get("verified_at") or route.get("ts_utc") or "")[:10]
    if date:
        head += f" {date}"
    event_id = route.get("event_id")
    fetch = f"; steps: read_events after_id={event_id - 1}" if isinstance(event_id, int) and event_id > 1 else ""
    tail = f" [{label}; not authority{fetch}]"
    room = MAX_HINT_CHARS - len(head) - len(tail) - 2
    title = re.sub(r"\s+", " ", str(route.get("title") or "")).strip()
    if len(title) > room:
        title = title[: max(0, room - 1)].rstrip() + "…"
    return f"{head}: {title}{tail}"


def render_routes_block(projection: Mapping[str, Any], *, max_chars: int = 1500) -> str:
    """Compact text block with the runnable steps, placed right after the capsule lead."""

    routes = projection.get("routes") if isinstance(projection, Mapping) else None
    if not routes:
        return ""
    lines = ["KNOWN ROUTES (re-check state first; not authority):"]
    for route in routes:
        lines.append(f"#{route.get('event_id')} {route.get('route_id')} v{route.get('version')} "
                     f"{route.get('status')}: {str(route.get('title') or '')[:120]}")
        for number, step in enumerate(route.get("run_steps") or [], start=1):
            lines.append(f"  {number}) {step}")
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    return text


def build_known_routes(
    terms: Iterable[str],
    events: Iterable[Mapping[str, Any]],
    *,
    limit: int = MAX_ROUTES,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Select up to ``limit`` routes that match ``terms``.

    ``terms`` are already-derived search terms (service wrappers stripped).
    ``events`` is the caller's admitted snapshot. The result is a projection:
    deterministic for the same input and ``now``, with no authority.
    """

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10:
        raise ValueError("limit must be an integer from 1 to 10")
    clock = now or dt.datetime.now(dt.UTC)
    search = _normalise_terms(terms)
    superseded_ids: set[int] = set()
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    route_count = 0
    rejected_count = 0
    checks: dict[str, dict[str, Any]] = {}
    for event in events:
        details = _details(event)
        check = _check_from_event(event, details)
        if check is not None:
            previous_check = checks.get(check["route_id"])
            if previous_check is None or check["event_id"] >= previous_check["event_id"]:
                checks[check["route_id"]] = check
        for raw in _strings(details.get("supersedes_event_ids")):
            target = _int(raw)
            if target:
                superseded_ids.add(target)
        for route in routes_from_event(event):
            route_count += 1
            if looks_secret(" ".join([route["title"], route["scope"], *route["triggers"], *route["steps"]])):
                rejected_count += 1
                continue
            key = (route["source"], route["route_id"])
            previous = latest.get(key)
            if previous is None or (route["version"], route["event_id"] or 0) >= (
                previous["version"], previous["event_id"] or 0
            ):
                latest[key] = route
    for key, route in list(latest.items()):
        check = checks.get(route["route_id"]) if route["source"] == "explicit" else None
        if check is None or (check.get("version") is not None and check["version"] != route["version"]):
            continue
        if (check["event_id"] or 0) < (route["event_id"] or 0):
            continue  # a newer version or record arrived after this check
        updated = dict(route)
        updated["checked_event_id"] = check["event_id"]
        if check["result"] == "pass":
            if updated["status"] in {"candidate", "stale"}:
                updated["status"] = "verified"
            updated["verified_at"] = check["checked_at"]
        else:
            updated["status"] = "stale"
            updated["check_failed_at"] = check["checked_at"]
        latest[key] = updated
    ranked: list[tuple[float, int, dict[str, Any]]] = []
    if search:
        for route in latest.values():
            if route["status"] == "superseded" or route["event_id"] in superseded_ids:
                continue
            score, matched = _score(route, search)
            if score < _MIN_SCORE or len(matched) < 2:
                continue
            if route["source"] == "observed" and (score < _MIN_OBSERVED_SCORE or len(matched) < 3):
                continue
            score += _STATUS_BONUS.get(route["status"], 0.0)
            score += 1.0 if route["has_rollback"] else 0.0
            score -= min(3.0, _age_days(route["ts_utc"], clock) / 60.0)
            ranked.append((round(score, 3), route["event_id"] or 0, {**route, "matched_terms": matched}))
    ranked.sort(key=lambda item: (-item[0], -item[1], item[2]["route_id"]))
    routes = []
    for score, _event_id, route in ranked[:limit]:
        routes.append({
            "event_id": route["event_id"],
            "source": route["source"],
            "route_id": route["route_id"][:160],
            "version": route["version"],
            "status": route["status"],
            "title": route["title"][:400],
            "ts_utc": route["ts_utc"],
            "verified_at": route["verified_at"],
            "step_count": route["step_count"],
            "run_steps": [step[:300] for step in route.get("run_steps", [])],
            "has_rollback": route["has_rollback"],
            "check_failed_at": route.get("check_failed_at", ""),
            "matched_terms": route["matched_terms"][:8],
            "score": score,
            "hint": route_hint(route),
        })
    return {
        "protocol": PROTOCOL,
        "route_format": ROUTE_FORMAT,
        "authority": "none",
        "production_authority": False,
        "search_only": True,
        "terms": search[:16],
        "route_count": route_count,
        "rejected_secret_like": rejected_count,
        "check_count": len(checks),
        "routes": routes,
        "status": "searched" if search else "empty-terms",
    }


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m integrity_guardian.uroboros_routes draft|validate|check``.

    ``draft`` prints a validated ``{"uroboros_route": ...}`` details object to
    pass to an Integrity append. ``validate`` checks a JSON file holding one
    record, a list, or a details object. Nothing is written or sent.
    """

    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="uroboros-routes")
    commands = parser.add_subparsers(dest="command", required=True)
    draft = commands.add_parser("draft", help="build a route record")
    draft.add_argument("--route-id", required=True)
    draft.add_argument("--title", required=True)
    draft.add_argument("--trigger", action="append", required=True)
    draft.add_argument("--step", action="append", default=[])
    draft.add_argument("--precondition", action="append", default=[])
    draft.add_argument("--postcheck", action="append", default=[])
    draft.add_argument("--rollback", default="")
    draft.add_argument("--status", default="candidate", choices=ROUTE_STATUSES)
    draft.add_argument("--version", type=int, default=1)
    draft.add_argument("--provenance", type=int, action="append", default=[])
    draft.add_argument("--verified-at", default="")
    draft.add_argument("--scope", default="")
    check = commands.add_parser("validate", help="validate route records in a JSON file")
    check.add_argument("path")
    verify = commands.add_parser("check", help="record a pass/fail check of a route against current state")
    verify.add_argument("--route-id", required=True)
    verify.add_argument("--result", required=True, choices=CHECK_RESULTS)
    verify.add_argument("--version", type=int)
    verify.add_argument("--checked-at", default="")
    verify.add_argument("--note", default="")
    args = parser.parse_args(argv)
    try:
        if args.command == "draft":
            record = draft_route_record(
                route_id=args.route_id, title=args.title, triggers=args.trigger, steps=args.step,
                preconditions=args.precondition, postchecks=args.postcheck, rollback=args.rollback,
                status=args.status, version=args.version, provenance_event_ids=args.provenance,
                verified_at=args.verified_at, scope=args.scope,
            )
            print(json.dumps({"uroboros_route": record}, ensure_ascii=False, indent=2))
            return 0
        if args.command == "check":
            record = draft_route_check(route_id=args.route_id, result=args.result, version=args.version,
                                       checked_at=args.checked_at, note=args.note)
            print(json.dumps({"uroboros_route_check": record}, ensure_ascii=False, indent=2))
            return 0
        with open(args.path, encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict) and ("uroboros_route" in payload or "uroboros_routes" in payload):
            records = ([payload["uroboros_route"]] if "uroboros_route" in payload else []) + list(
                payload.get("uroboros_routes") or [])
        elif isinstance(payload, list):
            records = payload
        else:
            records = [payload]
        if len(records) > MAX_BUNDLE_ROUTES:
            raise RouteRecordError(f"at most {MAX_BUNDLE_ROUTES} routes per event")
        for index, record in enumerate(records):
            try:
                validate_route_record(record)
            except RouteRecordError as exc:
                raise RouteRecordError(f"route {index}: {exc}") from None
        print(f"ok: {len(records)} route(s)")
        return 0
    except (RouteRecordError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
