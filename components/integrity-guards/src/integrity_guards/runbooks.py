"""Event-driven runbooks: an infrastructure event starts a turn that follows a compiled Uroboros route.

A *trigger* watches one source (a log file, journald, a loopback syslog socket, a loopback
webhook or a timer) for a regular expression. On a match it extracts the route parameters
from the named groups, checks each one with the same full-match regex as the compiled
route's ``params``, and hands the turn to an adapter:

* ``route``      runs the compiled route itself, without a model (``uroboros_exec``);
* ``claude-p``   starts a headless ``claude -p`` turn that is told to run the route;
* ``codex-exec`` starts a headless ``codex exec`` turn the same way;
* any adapter you declare yourself (an argv list, no shell).

Safety, in this order, for every match:

1. the regex of the trigger, then the regex of every route parameter (a value that does
   not match is rejected, and the adapter is never started);
2. the kill switch (``integrity-killswitch``), asked for the adapter's vendor; without
   the kill switch package nothing runs unless the configuration says it is not required;
3. dedup / suppression window, the trigger's hourly limit, the global hourly limit and the
   number of turns running at once;
4. route safety: only ``safety: read`` routes run. A ``safety: write`` route becomes a
   *proposal*: an event and a notification that ask for an operator GO, never an execution.
   The dispatcher never passes ``--apply`` and never sets ``INTEGRITY_ROUTE_WRITE_GO``.

Every decision is appended to a hash-chained journal in the instance folder; turns,
proposals and rejections can also go to an event sink (a local memory instance or a
command that reads the event as JSON on stdin). A model turn goes through the client's
own hooks (Integrity admission, guards), because it runs as an ordinary headless client in
the working directory you configure; adapters that would skip permissions are refused.

Nothing runs until an instance exists (``integrity-guards runbooks init``) and its
configuration says ``"enabled": true``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from integrity_guards import config as _config
from integrity_guards import uroboros_exec as ux

CONFIG_FORMAT = "integrity-runbooks/v1"
TRIGGER_FORMAT = "uroboros-event-trigger/v1"
RECORD_PROTOCOL = "integrity-guardian/runbook-dispatch/v1"
SOURCES = ("file", "journald", "syslog", "webhook", "timer")
KINDS = ("turn", "proposal", "rejected", "blocked", "suppressed", "rate-limited", "busy", "error")
DEFAULT_SINK_KINDS = ("turn", "proposal", "rejected")
MAX_LINE = 8192
MAX_VALUE = 200
MAX_DRAIN = 65536  # an oversized webhook body up to this size is read before the 413 reply
MAX_TAIL = 2000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,159}")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,40}")
_PLACEHOLDER = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]{0,40})\}\}")
# Text that would let a headless client skip its own permission prompts and hooks. It is
# looked for anywhere inside each argv element (case-insensitive), so "--flag=value",
# "-c key=value" and quoted forms are refused too.
BYPASS_MARKERS = ("dangerously-", "bypasspermissions", "danger-full-access", "yolo")
# Kill switch vendors and markers when integrity-killswitch is not installed.
FALLBACK_VENDOR_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("claude", ("claude",)), ("codex", ("codex",)), ("antigravity", ("antigravity", "language_server")),
    ("grok", ("grok",)))
# Words of an argv element: split on blanks, quotes and shell punctuation; "{{...}}" is dropped.
_ANY_PLACEHOLDER = re.compile(r"\{\{[^}]*\}\}")
_WORD_SPLIT = re.compile(r"[\s\"'`;&|(),<>=]+")
_PROGRAM_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1", ".sh", ".js", ".mjs", ".py")
NOISE_KINDS = ("rejected", "blocked", "busy", "suppressed", "rate-limited")
DEFAULT_PROMPT = (
    "An infrastructure event matched the Integrity runbook trigger {{trigger_id}} at {{ts}}.\n"
    "Follow the verified Uroboros route {{route_id}} (safety: read): {{route_summary}}\n"
    "Run it in one call: {{route_command}}\n"
    "Do not run write routes and do not change anything. If the route fails, report the "
    "failure and stop; do not improvise another path.\n"
    "Event terms: {{terms}}"
)
BUILTIN_ADAPTERS: dict[str, dict[str, Any]] = {
    "route": {"kind": "route", "vendor": "service"},
    "claude-p": {"kind": "command", "vendor": "claude", "argv": ["claude", "-p", "{{prompt}}"],
                 "timeout_s": 600},
    "codex-exec": {"kind": "command", "vendor": "codex", "argv": ["codex", "exec", "{{prompt}}"],
                   "timeout_s": 600},
}


class RunbookError(ValueError):
    """The runbook configuration or a trigger is invalid."""


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(text: str | bytes) -> str:
    data = text.encode("utf-8", "replace") if isinstance(text, str) else text
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _no_floats(value: Any) -> Any:
    """Seed canonical JSON has no floats; seconds and costs are kept as decimal strings."""
    if isinstance(value, float):
        return format(value, ".6g")
    if isinstance(value, Mapping):
        return {str(k): _no_floats(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_no_floats(v) for v in value]
    return value


def _positive(value: Any, where: str, *, maximum: float, integer: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= maximum:
        raise RunbookError(f"{where} must be a number in (0, {maximum}]")
    if integer and int(value) != value:
        raise RunbookError(f"{where} must be a whole number")
    return value


def loopback_address(text: str, where: str) -> tuple[str, int]:
    """``host:port`` on a loopback address; anything else is refused."""
    host, sep, port = str(text).rpartition(":")
    host = host.strip("[]")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise RunbookError(f"{where} must be host:port")
    try:
        loopback = ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        raise RunbookError(f"{where} must listen on a loopback address only")
    return ("127.0.0.1" if host == "localhost" else host), int(port)


# --------------------------------------------------------------------------- configuration


def _check_argv(argv: Any, where: str) -> list[str]:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise RunbookError(f"{where} must be a non-empty list of strings")
    for arg in argv:
        lowered = arg.lower()
        if any(marker in lowered for marker in BYPASS_MARKERS):
            raise RunbookError(f"{where} would bypass the client's permissions or hooks; refused")
    return argv


def _program_name(word: str) -> str:
    """The last path component of a word, lowercase, without an executable suffix."""
    name = re.split(r"[\\/]", word)[-1].lower()
    for suffix in _PROGRAM_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def argv_words(argv: list[str]) -> list[str]:
    """Program-like words of every argv element, including a command string given to ``sh -c``,
    ``cmd /c`` or ``pwsh -Command``. Only the last path component of a word counts, so an
    install folder name does not look like a program."""
    words: list[str] = []
    for arg in argv:
        for word in _WORD_SPLIT.split(_ANY_PLACEHOLDER.sub(" ", arg)):
            name = _program_name(word)
            if name:
                words.append(name)
    return words


def vendor_markers() -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Vendor -> markers from integrity-killswitch (with its configuration), else the fallback."""
    try:
        from integrity_killswitch import killswitch as ks

        ks.configure(ks.load_config())
        markers = tuple(ks.LLM_MARKERS)
    except Exception:  # noqa: BLE001 - absent or misconfigured package: the fallback still binds
        markers = ()
    return markers or FALLBACK_VENDOR_MARKERS


def argv_vendors(argv: list[str]) -> list[str]:
    """Every kill switch vendor whose marker appears in a word of the argv, in marker order."""
    words = argv_words(argv)
    return [vendor for vendor, markers in vendor_markers()
            if any(marker and marker in word for word in words for marker in markers)]


def validate_adapter(name: str, adapter: Any) -> dict[str, Any]:
    if not isinstance(adapter, dict):
        raise RunbookError(f"adapters.{name} must be an object")
    kind = adapter.get("kind", "command")
    if kind not in ("route", "command"):
        raise RunbookError(f"adapters.{name}.kind must be route or command")
    vendor = adapter.get("vendor")
    if not isinstance(vendor, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", vendor) or vendor == "owner":
        raise RunbookError(f"adapters.{name}.vendor must name a kill switch vendor")
    out = {"kind": kind, "vendor": vendor}
    if kind == "command":
        out["argv"] = _check_argv(adapter.get("argv"), f"adapters.{name}.argv")
        # The kill switch is asked for this vendor, so a command must not borrow another one's switch.
        if vendor in ("service", "unknown_llm"):
            raise RunbookError(f"adapters.{name}.vendor {vendor!r} is reserved; a command adapter "
                               "names the vendor of the program it starts")
        # Every word of every element counts, so "cmd /c claude", "sh -c 'claude -p ...'" and
        # "npx -y claude" all name the program they start. More than one vendor is ambiguous.
        found = argv_vendors(out["argv"])
        if len(found) > 1:
            raise RunbookError(f"adapters.{name} names programs of several vendors ({', '.join(found)}); "
                               "one adapter starts one vendor's program")
        if found and found[0] != vendor:
            raise RunbookError(f"adapters.{name} starts a {found[0]} program but names vendor {vendor!r}; "
                               f"it must be {found[0]!r}")
        out["timeout_s"] = _positive(adapter.get("timeout_s", 600), f"adapters.{name}.timeout_s", maximum=3600)
        cwd = adapter.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise RunbookError(f"adapters.{name}.cwd must be a path")
        out["cwd"] = cwd
        prompt = adapter.get("prompt", DEFAULT_PROMPT)
        if not isinstance(prompt, str) or len(prompt) > 4000:
            raise RunbookError(f"adapters.{name}.prompt must be a string up to 4000 characters")
        out["prompt"] = prompt
        out["cost_from_json"] = bool(adapter.get("cost_from_json", False))
    return out


def adapters_of(config: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    declared = config.get("adapters") or {}
    if not isinstance(declared, dict):
        raise RunbookError("adapters must be an object")
    merged = {name: validate_adapter(name, dict(value)) for name, value in BUILTIN_ADAPTERS.items()}
    for name, value in declared.items():
        if not _ID.fullmatch(str(name)) and name not in BUILTIN_ADAPTERS:
            raise RunbookError(f"adapter name {name!r} is invalid")
        base = dict(BUILTIN_ADAPTERS.get(name, {}))
        base.update(value if isinstance(value, dict) else {})
        merged[str(name)] = validate_adapter(str(name), base)
    return merged


def validate_trigger(trigger: Any, routes: Mapping[str, Mapping[str, Any]] | None,
                     adapters: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Check one trigger. With ``routes`` it is also checked against its compiled route."""
    if not isinstance(trigger, dict):
        raise RunbookError("a trigger must be an object")
    tid = trigger.get("trigger_id")
    if not isinstance(tid, str) or not _ID.fullmatch(tid):
        raise RunbookError("trigger_id is invalid")
    where = f"trigger {tid}"
    fmt = trigger.get("format", TRIGGER_FORMAT)
    if fmt != TRIGGER_FORMAT:
        raise RunbookError(f"{where}: format must be {TRIGGER_FORMAT}")
    source = trigger.get("source")
    if not isinstance(source, dict) or source.get("kind") not in SOURCES:
        raise RunbookError(f"{where}: source.kind must be one of {', '.join(SOURCES)}")
    kind = source["kind"]
    if kind == "file" and not isinstance(source.get("path"), str):
        raise RunbookError(f"{where}: a file source needs a path")
    if kind == "journald":
        unit = source.get("unit")
        if unit is not None and (not isinstance(unit, str) or not re.fullmatch(r"[A-Za-z0-9@._:-]{1,120}", unit)):
            raise RunbookError(f"{where}: journald unit is invalid")
    if kind == "timer":
        _positive(source.get("every_s"), f"{where}: timer every_s", maximum=7 * 86400)
        if float(source["every_s"]) < 60:
            raise RunbookError(f"{where}: a timer fires at most once a minute")
    match = trigger.get("match", ".*" if kind == "timer" else None)
    if not isinstance(match, str) or not match:
        raise RunbookError(f"{where}: match must be a regular expression")
    try:
        compiled = re.compile(match)
    except re.error as exc:
        raise RunbookError(f"{where}: match does not compile: {exc}") from None
    route_id = trigger.get("route_id")
    if not isinstance(route_id, str) or not _ID.fullmatch(route_id):
        raise RunbookError(f"{where}: route_id is invalid")
    adapter = trigger.get("adapter", "route")
    if adapter not in adapters:
        raise RunbookError(f"{where}: adapter {adapter!r} is not declared")
    params = trigger.get("params")
    if params is not None and (not isinstance(params, dict) or not all(
            _NAME.fullmatch(str(k)) and isinstance(v, str) and len(v) <= MAX_VALUE for k, v in params.items())):
        raise RunbookError(f"{where}: params must map route parameter names to templates")
    for key in ("suppress_s", "max_per_hour"):
        if key in trigger:
            _positive(trigger[key], f"{where}: {key}", maximum=86400 if key == "suppress_s" else 3600,
                      integer=key == "max_per_hour")
    dedup = trigger.get("dedup_key")
    if dedup is not None and (not isinstance(dedup, str) or len(dedup) > 200):
        raise RunbookError(f"{where}: dedup_key must be a template string")
    if "enabled" in trigger and not isinstance(trigger["enabled"], bool):
        raise RunbookError(f"{where}: enabled must be true or false")
    groups = set(compiled.groupindex)
    # Without params, each route parameter takes the named group of the same name.
    templates = dict(params) if params is not None else None
    for name, template in (templates or {}).items():
        for ref in _PLACEHOLDER.findall(template):
            if ref not in groups:
                raise RunbookError(f"{where}: params.{name} names group {ref!r}, which match does not define")
    if routes is not None:
        route = routes.get(route_id)
        if route is None:
            raise RunbookError(f"{where}: route {route_id} is not a compiled route here")
        schema = route.get("params", {})
        if templates is None:
            templates = {name: "{{" + name + "}}" for name in schema if name in groups}
        unknown = sorted(set(templates) - set(schema))
        if unknown:
            raise RunbookError(f"{where}: route {route_id} has no parameter {', '.join(unknown)}")
        missing = sorted(set(schema) - set(templates))
        if missing:
            raise RunbookError(f"{where}: no value for route parameter {', '.join(missing)}")
    out = dict(trigger)
    out.update({"format": TRIGGER_FORMAT, "adapter": adapter, "match": match, "params": templates,
                "enabled": trigger.get("enabled", True),
                "suppress_s": float(trigger.get("suppress_s", 900)),
                "max_per_hour": int(trigger.get("max_per_hour", 4))})
    return out


def routes_dir(config: Mapping[str, Any]) -> Path | None:
    value = (config.get("compiled_routes") or os.environ.get(ux.ENV_ROUTES_DIR)
             or _config.section("uroboros").get("compiled_routes"))
    return Path(value) if value else None


def load_routes(base: Path | None) -> dict[str, dict[str, Any]]:
    """Every valid compiled route under ``base`` by id; invalid files are skipped."""
    routes: dict[str, dict[str, Any]] = {}
    if base is None or not base.is_dir():
        return routes
    for path in sorted(base.glob("*.json")):
        try:
            route = ux.validate_compiled_route(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
        routes[route["route_id"]] = route
    return routes


def validate_config(config: Any, routes: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Return a normalised configuration; raises RunbookError on the first problem."""
    if not isinstance(config, dict) or config.get("format") != CONFIG_FORMAT:
        raise RunbookError(f"format must be {CONFIG_FORMAT}")
    if not isinstance(config.get("enabled", False), bool):
        raise RunbookError("enabled must be true or false")
    limits = config.get("limits") or {}
    if not isinstance(limits, dict):
        raise RunbookError("limits must be an object")
    norm_limits = {
        "max_concurrent": int(_positive(limits.get("max_concurrent", 1), "limits.max_concurrent",
                                        maximum=16, integer=True)),
        "max_turns_per_hour": int(_positive(limits.get("max_turns_per_hour", 6), "limits.max_turns_per_hour",
                                            maximum=3600, integer=True)),
        "poll_s": float(_positive(limits.get("poll_s", 2), "limits.poll_s", maximum=300)),
        "noise_window_s": float(_positive(limits.get("noise_window_s", 60), "limits.noise_window_s",
                                          maximum=86400)),
    }
    adapters = adapters_of(config)
    raw = config.get("triggers") or []
    if not isinstance(raw, list) or len(raw) > 200:
        raise RunbookError("triggers must be a list of up to 200 triggers")
    triggers = [validate_trigger(item, routes, adapters) for item in raw]
    ids = [t["trigger_id"] for t in triggers]
    if len(ids) != len(set(ids)):
        raise RunbookError("trigger ids must be unique")
    listen = config.get("listen") or {}
    if not isinstance(listen, dict):
        raise RunbookError("listen must be an object")
    for key in ("syslog_udp", "webhook_http"):
        if listen.get(key) is not None:
            loopback_address(listen[key], f"listen.{key}")
    token_env = listen.get("webhook_token_env")
    if token_env is not None and (not isinstance(token_env, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", token_env)):
        raise RunbookError("listen.webhook_token_env must name an environment variable")
    for kind in ("syslog", "webhook"):
        needs = "syslog_udp" if kind == "syslog" else "webhook_http"
        if any(t["source"]["kind"] == kind for t in triggers) and not listen.get(needs):
            raise RunbookError(f"a {kind} trigger needs listen.{needs}")
    ks = config.get("killswitch") or {}
    if not isinstance(ks, dict) or not isinstance(ks.get("required", True), bool):
        raise RunbookError("killswitch.required must be true or false")
    notify = config.get("notify")
    if notify is not None:
        if not isinstance(notify, dict):
            raise RunbookError("notify must be an object")
        _check_argv(notify.get("argv"), "notify.argv")
    sinks = config.get("event_sinks") or {}
    if not isinstance(sinks, dict):
        raise RunbookError("event_sinks must be an object")
    if sinks.get("command") is not None:
        _check_argv(sinks["command"], "event_sinks.command")
    kinds = sinks.get("kinds", list(DEFAULT_SINK_KINDS))
    if not isinstance(kinds, list) or not set(kinds) <= set(KINDS):
        raise RunbookError("event_sinks.kinds must list record kinds")
    return {
        "format": CONFIG_FORMAT, "enabled": config.get("enabled", False), "limits": norm_limits,
        "adapters": adapters, "triggers": triggers, "listen": listen,
        "killswitch": {"required": ks.get("required", True)}, "notify": notify,
        "event_sinks": {"local_memory_home": sinks.get("local_memory_home"), "command": sinks.get("command"),
                        "kinds": kinds},
        "compiled_routes": config.get("compiled_routes"),
    }


# --------------------------------------------------------------------------- journal and state


class Journal:
    """Append-only JSONL; each line carries the hash of the previous line."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._head: tuple[int, str] | None = None

    def _last_hash(self) -> tuple[int, str]:
        """Read once, on the first append; later appends keep the head in memory."""
        if self._head is None:
            self._head = self._read_head()
        return self._head

    def _read_head(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, "0" * 64
        last = None
        with self.path.open("rb") as stream:
            for line in stream:
                if line.strip():
                    last = line
        if last is None:
            return 0, "0" * 64
        entry = json.loads(last)
        return int(entry["seq"]), str(entry["hash"])

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            seq, prev = self._last_hash()
            entry = {"seq": seq + 1, "prev": prev, "record": dict(record)}
            entry["hash"] = _sha(_canonical({"seq": entry["seq"], "prev": prev, "record": entry["record"]}))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            self._head = (entry["seq"], entry["hash"])
            return entry

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = []
        with self.path.open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    rows.append(json.loads(line)["record"])
        return rows

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "no journal yet"
        prev, count = "0" * 64, 0
        try:
            with self.path.open(encoding="utf-8") as stream:
                for number, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    expected = _sha(_canonical({"seq": entry["seq"], "prev": entry["prev"], "record": entry["record"]}))
                    if entry["prev"] != prev or entry["hash"] != expected or entry["seq"] != count + 1:
                        return False, f"chain broken at line {number}"
                    prev, count = entry["hash"], count + 1
        except (OSError, ValueError, KeyError) as exc:
            return False, f"journal unreadable: {type(exc).__name__}"
        return True, f"{count} records, chain intact"


class State:
    """Offsets, cursors, dedup keys and rate windows; survives a restart."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {"files": {}, "journald": {}, "timers": {}, "dedup": {}, "fired": {}}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    for key in self.data:
                        if isinstance(loaded.get(key), dict):
                            self.data[key] = loaded[key]
            except (OSError, ValueError):
                pass  # a lost state file only means offsets restart at the end of each source
        self._lock = threading.Lock()

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(tmp, self.path)


# --------------------------------------------------------------------------- kill switch


def killswitch_gate(vendor: str, trigger_id: str, *, required: bool) -> tuple[bool, str]:
    """Ask integrity-killswitch whether ``vendor`` may run; fail closed when it is required."""
    try:
        from integrity_killswitch import killswitch as ks
    except ImportError:
        if required:
            return False, "integrity-killswitch is not installed and killswitch.required is true"
        return True, "no kill switch installed (killswitch.required is false)"
    try:
        # The same configuration the switch's own CLI reads (INTEGRITY_KILLSWITCH_CONFIG): vendors, state file.
        ks.configure(ks.load_config())
        allowed, reason = ks.is_allowed(vendor=vendor, action="runbook", target=trigger_id)
    except Exception as exc:  # noqa: BLE001 - a broken gate is closed
        return False, f"kill switch error: {type(exc).__name__}"
    return bool(allowed), str(reason)


# --------------------------------------------------------------------------- sources


class FileTail:
    """Lines appended to a file since the last read; a rotated or truncated file restarts at 0."""

    def __init__(self, trigger_id: str, path: Path, state: State, *, from_start: bool = False) -> None:
        self.trigger_id, self.path, self.state = trigger_id, path, state
        entry = state.data["files"].get(trigger_id)
        if entry is None:
            size = 0
            if not from_start and path.exists():
                size = path.stat().st_size
            state.data["files"][trigger_id] = {"offset": size, "id": self._identity()}

    def _identity(self) -> str:
        try:
            st = self.path.stat()
        except OSError:
            return ""
        return f"{st.st_dev}:{st.st_ino}" if st.st_ino else ""

    def read(self) -> list[str]:
        entry = self.state.data["files"][self.trigger_id]
        try:
            st = self.path.stat()
        except OSError:
            return []
        identity = self._identity()
        if st.st_size < entry["offset"] or (identity and entry.get("id") and identity != entry["id"]):
            entry["offset"] = 0
        entry["id"] = identity
        if st.st_size == entry["offset"]:
            return []
        with self.path.open("rb") as stream:
            stream.seek(entry["offset"])
            data = stream.read(1024 * 1024)
        end = data.rfind(b"\n")
        if end < 0:
            if len(data) < MAX_LINE:
                return []  # wait for the rest of the line
            end = len(data) - 1
        entry["offset"] += end + 1
        return [line.decode("utf-8", "replace").rstrip("\r") for line in data[:end + 1].splitlines()]


Runner = Callable[[Sequence[str], float], tuple[int, str, str]]


def _run(argv: Sequence[str], timeout: float, cwd: str | None = None,
         stdin_text: str | None = None) -> tuple[int, str, str]:
    completed = subprocess.run(
        list(argv), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        cwd=cwd, input=stdin_text, stdin=None if stdin_text is not None else subprocess.DEVNULL, check=False)
    return completed.returncode, completed.stdout[-64 * 1024:], completed.stderr[-64 * 1024:]


class JournaldPoll:
    """New journald entries since the stored cursor (``journalctl -o json --after-cursor``)."""

    def __init__(self, trigger_id: str, unit: str | None, state: State, runner: Runner | None = None) -> None:
        self.trigger_id, self.unit, self.state = trigger_id, unit, state
        self.runner = runner or (lambda argv, timeout: _run(argv, timeout))

    def read(self) -> list[str]:
        cursor = self.state.data["journald"].get(self.trigger_id)
        argv = ["journalctl", "--no-pager", "-o", "json"]
        if self.unit:
            argv += ["-u", self.unit]
        argv += ["--after-cursor", cursor] if cursor else ["-n", "0", "--show-cursor"]
        try:
            code, out, _err = self.runner(argv, 15)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if code != 0:
            return []
        lines = []
        for raw in out.splitlines():
            if raw.startswith("-- cursor: "):
                self.state.data["journald"][self.trigger_id] = raw[len("-- cursor: "):].strip()
                continue
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            if isinstance(entry, dict):
                if entry.get("__CURSOR"):
                    self.state.data["journald"][self.trigger_id] = str(entry["__CURSOR"])
                message = entry.get("MESSAGE")
                if isinstance(message, str):
                    lines.append(message)
        return lines


class SyslogUDP(threading.Thread):
    """Datagrams on a loopback UDP port (an rsyslog/syslog-ng forward rule points here)."""

    def __init__(self, address: tuple[str, int], inbox: queue.Queue) -> None:
        super().__init__(daemon=True, name="runbooks-syslog")
        family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind(address)
        self.sock.settimeout(0.5)
        self.address = self.sock.getsockname()
        self.inbox, self.stopping = inbox, threading.Event()

    def run(self) -> None:
        while not self.stopping.is_set():
            try:
                data, _peer = self.sock.recvfrom(MAX_LINE)
            except TimeoutError:
                continue
            except OSError:
                break
            for line in data.decode("utf-8", "replace").splitlines():
                if line.strip():
                    self.inbox.put(("syslog", None, line))

    def stop(self) -> None:
        self.stopping.set()
        self.sock.close()


class _HookHandler(BaseHTTPRequestHandler):
    server_version = "integrity-runbooks"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _reply(self, code: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _refuse(self, code: int, error: str, length: int) -> None:
        """Answer a refused post. A body up to MAX_DRAIN is read first, so the client sees the
        answer and not a reset connection; a larger one is cut off. The connection is closed."""
        if 0 < length <= MAX_DRAIN:
            self.rfile.read(length)
        self.close_connection = True
        self._reply(code, {"accepted": False, "error": error})

    def do_POST(self) -> None:
        hook = self.server.hook  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        match = re.fullmatch(r"/hook/([A-Za-z0-9][A-Za-z0-9._:-]{2,159})", self.path)
        if not match or match.group(1) not in hook["ids"]:
            self._refuse(404, "unknown trigger", length)
            return
        token = hook["token"]
        offered = self.headers.get("X-Integrity-Token", "").encode("utf-8", "replace")
        if token is not None and not hmac.compare_digest(offered, token.encode("utf-8")):
            self._refuse(403, "token", length)
            return
        if not 0 <= length <= MAX_LINE:
            self._refuse(413, "body too large", length)
            return
        body = self.rfile.read(length).decode("utf-8", "replace")
        line = body
        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                parsed = json.loads(body)
                line = parsed.get("line") if isinstance(parsed, dict) else None
            except ValueError:
                line = None
            if not isinstance(line, str):
                self._reply(400, {"accepted": False, "error": "JSON body needs a string field line"})
                return
        hook["inbox"].put(("webhook", match.group(1), line.strip()))
        self._reply(202, {"accepted": True})

    def do_GET(self) -> None:
        self._reply(405, {"accepted": False, "error": "POST only"})


class Webhook(threading.Thread):
    """``POST /hook/<trigger_id>`` on a loopback port; the line is the body or ``{"line": ...}``."""

    def __init__(self, address: tuple[str, int], ids: set[str], token: str | None, inbox: queue.Queue) -> None:
        super().__init__(daemon=True, name="runbooks-webhook")
        self.httpd = ThreadingHTTPServer(address, _HookHandler)
        self.httpd.hook = {"ids": ids, "token": token, "inbox": inbox}  # type: ignore[attr-defined]
        self.address = self.httpd.server_address

    def run(self) -> None:
        self.httpd.serve_forever(poll_interval=0.5)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------------------- dispatcher


def _fill(template: str, values: Mapping[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), ""), template)


def extract_params(trigger: Mapping[str, Any], route: Mapping[str, Any] | None,
                   match: re.Match[str]) -> tuple[dict[str, str] | None, str]:
    """Route parameters from the named groups, each checked with the route's own full-match regex."""
    groups = {k: (v or "") for k, v in match.groupdict().items()}
    if any(len(v) > MAX_VALUE for v in groups.values()):
        return None, "a captured value is longer than the limit"
    if route is None:
        return None, "route is not compiled here"
    schema = route.get("params", {})
    templates = trigger["params"]
    if templates is None:
        templates = {name: "{{" + name + "}}" for name in schema}
    values = {}
    for name, template in templates.items():
        value = _fill(template, groups)
        pattern = schema.get(name)
        if pattern is None or not re.fullmatch(pattern, value):
            return None, f"parameter {name} does not match the route's schema"
        values[name] = value
    return values, ""


def _quote_param(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z0-9._:/@%+=-]+", value) else json.dumps(value)


def route_command(route_id: str, params: Mapping[str, str]) -> str:
    return " ".join(["integrity-guards uroboros run", route_id,
                     *(f"{k}={_quote_param(v)}" for k, v in sorted(params.items()))])


def _cost(stdout: str) -> float | None:
    """``total_cost_usd`` (or ``cost_usd``) from a JSON reply, as ``claude -p --output-format json`` prints."""
    for candidate in (stdout.strip(), stdout.strip().splitlines()[-1] if stdout.strip() else ""):
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(data, dict):
            for key in ("total_cost_usd", "cost_usd"):
                value = data.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                    return float(value)
    return None


class Dispatcher:
    """Decides, for every matched line, whether and how a turn runs; records every decision."""

    def __init__(self, config: Mapping[str, Any], home: Path, *,
                 routes: Mapping[str, Mapping[str, Any]] | None = None,
                 command_runner: Callable[..., tuple[int, str, str]] | None = None,
                 route_runner: ux.Runner | None = None,
                 journald_runner: Runner | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.home = Path(home)
        base = routes_dir(config)
        self.routes = dict(routes) if routes is not None else load_routes(base)
        self.config = validate_config(dict(config), self.routes)
        self.journal = Journal(self.home / "journal.jsonl")
        self.state = State(self.home / "state.json")
        self.command_runner = command_runner or _run
        self.route_runner = route_runner
        self.journald_runner = journald_runner
        self.clock = clock
        self.triggers = {t["trigger_id"]: t for t in self.config["triggers"] if t["enabled"]}
        self._compiled = {tid: re.compile(t["match"]) for tid, t in self.triggers.items()}
        self._running = 0
        self._lock = threading.Lock()
        self._pool: ThreadPoolExecutor | None = None
        self.futures: list[Future] = []
        self._sources: dict[str, Any] = {}
        self._noise: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._noise_lock = threading.Lock()

    # ---- records

    def record(self, kind: str, trigger: Mapping[str, Any] | None, **fields: Any) -> dict[str, Any]:
        if kind in NOISE_KINDS and trigger is not None:
            folded = self._fold(kind, trigger, fields)
            if folded is not None:
                return folded
        return self._write(kind, trigger, **fields)

    def _fold(self, kind: str, trigger: Mapping[str, Any], fields: Mapping[str, Any]) -> dict[str, Any] | None:
        """At most one journal record per trigger, kind and reason in each noise window.

        The record that opens a window carries ``repeats_before``: how many identical
        events the previous window folded. Folded events go nowhere else (no sink).
        """
        key = (trigger["trigger_id"], kind, str(fields.get("reason", "")))
        now = self.clock()
        window = self.config["limits"]["noise_window_s"]
        with self._noise_lock:
            slot = self._noise.get(key)
            if slot is not None and now - slot["opened"] < window:
                slot["folded"] += 1
                return {"kind": kind, "trigger_id": key[0], "reason": key[2], "folded": True,
                        "count": slot["folded"] + 1}
            repeats = slot["folded"] if slot is not None else 0
            self._noise[key] = {"opened": now, "folded": 0}
        fields = dict(fields)
        fields["repeats_before"] = repeats
        fields["noise_window_s"] = window
        return self._write(kind, trigger, **fields)

    def flush_noise(self) -> None:
        """Records the counts still folded in open windows (on stop)."""
        with self._noise_lock:
            pending = [(key, slot["folded"]) for key, slot in self._noise.items() if slot["folded"]]
            self._noise.clear()
        for (trigger_id, kind, reason), count in pending:
            trigger = self.triggers.get(trigger_id)
            if trigger is not None:
                self._write(kind, trigger, sink=False, reason=reason, folded_count=count, flush=True)

    def _write(self, kind: str, trigger: Mapping[str, Any] | None, *, sink: bool = True,
               **fields: Any) -> dict[str, Any]:
        record = {"protocol": RECORD_PROTOCOL, "kind": kind, "ts": utc_now(), "production_authority": False}
        if trigger is not None:
            record.update({"trigger_id": trigger["trigger_id"], "route_id": trigger["route_id"],
                           "adapter": trigger["adapter"]})
        record.update(fields)
        record["summary"] = self._summary(record)
        self.journal.append(record)
        if sink and kind in self.config["event_sinks"]["kinds"]:
            self._sink(record)
        return record

    @staticmethod
    def _summary(record: Mapping[str, Any]) -> str:
        kind, tid, rid = record["kind"], record.get("trigger_id", "-"), record.get("route_id", "-")
        if kind == "turn":
            state = "ok" if record.get("ok") else "failed"
            return f"Runbook trigger {tid} ran route {rid} via {record.get('adapter')}: {state}."
        if kind == "proposal":
            return (f"Runbook trigger {tid} matched write route {rid}: not executed. "
                    "An operator GO is needed to run it.")
        return f"Runbook trigger {tid} for route {rid}: {kind} ({record.get('reason', '')})."

    def _sink(self, record: Mapping[str, Any]) -> None:
        sinks = self.config["event_sinks"]
        status: dict[str, Any] = {}
        if sinks.get("local_memory_home"):
            try:
                status["local_memory"] = self._local_memory(Path(sinks["local_memory_home"]), record)
            except Exception as exc:  # noqa: BLE001 - a sink failure must not stop the dispatcher
                status["local_memory"] = f"failed: {type(exc).__name__}"
        if sinks.get("command"):
            try:
                code, _out, _err = self.command_runner(sinks["command"], 30, None, json.dumps(record))
                status["command"] = "ok" if code == 0 else f"rc {code}"
            except (OSError, subprocess.TimeoutExpired) as exc:
                status["command"] = f"failed: {type(exc).__name__}"
        if status:
            self.journal.append({"protocol": RECORD_PROTOCOL, "kind": "sink", "ts": utc_now(),
                                 "for_kind": record["kind"], "trigger_id": record.get("trigger_id"),
                                 "status": status})

    @staticmethod
    def _local_memory(home: Path, record: Mapping[str, Any]) -> str:
        from integrity_guardian.local_memory import LocalMemory

        memory = LocalMemory(home)
        try:
            turn = memory.open_turn(declared_agent="runbook-dispatcher", declared_client="integrity-guards",
                                    intent=str(record["summary"]))
            event = memory.append_event(registration_id=turn["registration_id"], kind="task",
                                        summary=str(record["summary"]), details={"runbook": _no_floats(record)},
                                        tags=["runbook", str(record["kind"])],
                                        task=f"runbook:{record.get('trigger_id', '-')}")
            memory.close_turn(registration_id=turn["registration_id"], outcome="events")
        finally:
            memory.close()
        return f"event {event['event_uid']}"

    # ---- decisions

    def _extract(self, trigger: Mapping[str, Any], match: re.Match[str]) -> tuple[dict[str, str] | None, str]:
        return extract_params(trigger, self.routes.get(trigger["route_id"]), match)

    def _limits(self, trigger: Mapping[str, Any], key: str, now: float) -> str | None:
        dedup = self.state.data["dedup"]
        last = dedup.get(key)
        if last is not None and now - float(last) < trigger["suppress_s"]:
            return "suppressed"
        fired = self.state.data["fired"]
        window = [t for t in fired.get(trigger["trigger_id"], []) if now - float(t) < 3600]
        fired[trigger["trigger_id"]] = window
        if len(window) >= trigger["max_per_hour"]:
            return "rate-limited"
        everything = [t for times in fired.values() for t in times if now - float(t) < 3600]
        if len(everything) >= self.config["limits"]["max_turns_per_hour"]:
            return "rate-limited"
        return None

    def handle(self, trigger_id: str, line: str) -> dict[str, Any] | None:
        """One line from the trigger's source. Returns the record, or None when the line does not match."""
        trigger = self.triggers.get(trigger_id)
        if trigger is None:
            return None
        line = line[:MAX_LINE]
        match = self._compiled[trigger_id].search(line)
        if match is None:
            return None
        line_sha = _sha(line)
        values, problem = self._extract(trigger, match)
        if values is None:
            return self.record("rejected", trigger, reason=problem, line_sha256=line_sha)
        route = self.routes[trigger["route_id"]]
        adapter = self.config["adapters"][trigger["adapter"]]
        allowed, why = killswitch_gate(adapter["vendor"], trigger_id, required=self.config["killswitch"]["required"])
        if not allowed:
            return self.record("blocked", trigger, reason=why, params=values, line_sha256=line_sha)
        now = self.clock()
        key = trigger_id + "|" + (_fill(trigger["dedup_key"], {**{k: (v or "") for k, v in match.groupdict().items()},
                                                               **values})
                                  if trigger.get("dedup_key") else json.dumps(values, sort_keys=True))
        with self._lock:
            decision = self._limits(trigger, key, now)
            if decision is None and route["safety"] != "write" and \
                    self._running >= self.config["limits"]["max_concurrent"]:
                decision = "busy"
            if decision is None:
                # Proposals count against the same limits, so a noisy source cannot flood the operator.
                self.state.data["dedup"][key] = now
                self.state.data["fired"].setdefault(trigger_id, []).append(now)
                self._prune(now)
                if route["safety"] != "write":
                    self._running += 1
            self.state.save()
        if decision == "busy":
            return self.record("busy", trigger, reason="max_concurrent turns are running",
                               params=values, line_sha256=line_sha)
        if decision is not None:
            return self.record(decision, trigger, reason=f"{decision} by the trigger's limits",
                               params=values, line_sha256=line_sha)
        if route["safety"] == "write":
            return self._propose(trigger, route, values, line_sha)
        job = (trigger, route, adapter, values, line_sha, line)
        if self._pool is None:
            return self._turn(*job)
        self.futures.append(self._pool.submit(self._turn, *job))
        return {"kind": "turn", "trigger_id": trigger_id, "queued": True}

    def _prune(self, now: float) -> None:
        horizon = max([t["suppress_s"] for t in self.triggers.values()] + [3600])
        self.state.data["dedup"] = {k: v for k, v in self.state.data["dedup"].items() if now - float(v) < horizon}

    def _propose(self, trigger: Mapping[str, Any], route: Mapping[str, Any],
                 values: Mapping[str, str], line_sha: str) -> dict[str, Any]:
        command = route_command(route["route_id"], values)
        record = self.record(
            "proposal", trigger, params=dict(values), line_sha256=line_sha,
            route_summary=_fill(str(route.get("summary") or ""), values)[:400],
            needs="operator GO for this write route",
            go_command=f"{ux.ENV_WRITE_GO}={route['route_id']} {command} --apply")
        notify = self.config.get("notify")
        if notify:
            try:
                code, _out, _err = self.command_runner(notify["argv"], 30, None, json.dumps(record))
                note = "ok" if code == 0 else f"rc {code}"
            except (OSError, subprocess.TimeoutExpired) as exc:
                note = f"failed: {type(exc).__name__}"
            self.journal.append({"protocol": RECORD_PROTOCOL, "kind": "notify", "ts": utc_now(),
                                 "trigger_id": trigger["trigger_id"], "status": note})
        return record

    def _turn(self, trigger: Mapping[str, Any], route: Mapping[str, Any], adapter: Mapping[str, Any],
              values: Mapping[str, str], line_sha: str, line: str) -> dict[str, Any]:
        started = time.monotonic()
        try:
            if adapter["kind"] == "route":
                result = ux.run_compiled_route(route, values, apply=False, runner=self.route_runner,
                                               environ={})
                return self.record(
                    "turn", trigger, params=dict(values), line_sha256=line_sha, model_turn=False,
                    ok=bool(result.get("ok")), error=result.get("error"), outputs=result.get("outputs", {}),
                    route_result=result.get("summary", ""), elapsed_s=round(time.monotonic() - started, 3),
                    cost_usd=None)
            prompt = self._prompt(trigger, route, adapter, values)
            argv = [_fill(arg, {"prompt": prompt, "route_id": route["route_id"]}) for arg in adapter["argv"]]
            try:
                code, out, err = self.command_runner(argv, float(adapter["timeout_s"]), adapter.get("cwd"), None)
            except subprocess.TimeoutExpired:
                code, out, err = 124, "", "turn timeout"
            except OSError as exc:
                code, out, err = 127, "", f"cannot start: {type(exc).__name__}"
            return self.record(
                "turn", trigger, params=dict(values), line_sha256=line_sha, model_turn=True,
                vendor=adapter["vendor"], ok=code == 0, rc=code, prompt_sha256=_sha(prompt),
                stdout_tail=out[-MAX_TAIL:], stderr_tail=err[-300:],
                elapsed_s=round(time.monotonic() - started, 3), cost_usd=_cost(out))
        except Exception as exc:  # noqa: BLE001 - one broken turn must not stop the dispatcher
            return self.record("error", trigger, reason=f"{type(exc).__name__}: {str(exc)[:200]}",
                               line_sha256=line_sha)
        finally:
            with self._lock:
                self._running -= 1

    def _prompt(self, trigger: Mapping[str, Any], route: Mapping[str, Any], adapter: Mapping[str, Any],
                values: Mapping[str, str]) -> str:
        words = [str(route["route_id"]).replace(".", " ").replace("-", " "),
                 *(str(t) for t in trigger.get("terms", []) if isinstance(t, str)), *values.values()]
        return _fill(adapter["prompt"], {
            "trigger_id": trigger["trigger_id"], "ts": utc_now(), "route_id": route["route_id"],
            "route_summary": _fill(str(route.get("summary") or ""), values)[:400],
            "route_command": route_command(route["route_id"], values),
            "terms": " ".join(words)[:400]})

    # ---- sources and loop

    def _source(self, trigger: Mapping[str, Any]) -> Any:
        tid = trigger["trigger_id"]
        if tid not in self._sources:
            source = trigger["source"]
            if source["kind"] == "file":
                self._sources[tid] = FileTail(tid, Path(source["path"]), self.state,
                                              from_start=bool(source.get("from_start", False)))
            elif source["kind"] == "journald":
                self._sources[tid] = JournaldPoll(tid, source.get("unit"), self.state, self.journald_runner)
            else:
                self._sources[tid] = None
        return self._sources[tid]

    def poll_once(self) -> list[dict[str, Any]]:
        """Read every polled source once (files, journald, timers) and handle what matched."""
        out = []
        now = self.clock()
        for tid, trigger in self.triggers.items():
            kind = trigger["source"]["kind"]
            if kind in ("file", "journald"):
                lines = self._source(trigger).read()
            elif kind == "timer":
                last = self.state.data["timers"].get(tid)
                if last is not None and now - float(last) < float(trigger["source"]["every_s"]):
                    continue
                self.state.data["timers"][tid] = now
                lines = [f"timer {tid} {utc_now()}"]
            else:
                continue
            for line in lines:
                result = self.handle(tid, line)
                if result is not None:
                    out.append(result)
        self.state.save()
        return out

    def route_pushed(self, kind: str, trigger_id: str | None, line: str) -> list[dict[str, Any]]:
        """A line from the syslog socket (every syslog trigger) or a webhook (one trigger)."""
        out = []
        for tid, trigger in self.triggers.items():
            if trigger["source"]["kind"] != kind or (trigger_id is not None and tid != trigger_id):
                continue
            result = self.handle(tid, line)
            if result is not None:
                out.append(result)
        return out

    def serve(self, *, stop: threading.Event | None = None, max_loops: int | None = None) -> int:
        if not self.config["enabled"]:
            print("integrity-runbooks: the configuration says enabled: false; nothing runs.", file=sys.stderr)
            return 3
        stop = stop or threading.Event()
        inbox: queue.Queue = queue.Queue(maxsize=1000)
        listeners: list[Any] = []
        listen = self.config["listen"]
        kinds = {t["source"]["kind"] for t in self.triggers.values()}
        if "syslog" in kinds:
            listeners.append(SyslogUDP(loopback_address(listen["syslog_udp"], "listen.syslog_udp"), inbox))
        if "webhook" in kinds:
            token_env = listen.get("webhook_token_env")
            token = os.environ.get(token_env) if token_env else None
            if token_env and not token:
                print(f"integrity-runbooks: {token_env} is not set; webhooks are refused.", file=sys.stderr)
                token = "\0refused"  # matches no header value
            ids = {tid for tid, t in self.triggers.items() if t["source"]["kind"] == "webhook"}
            listeners.append(Webhook(loopback_address(listen["webhook_http"], "listen.webhook_http"), ids, token,
                                     inbox))
        for item in listeners:
            item.start()
        self._pool = ThreadPoolExecutor(max_workers=self.config["limits"]["max_concurrent"],
                                        thread_name_prefix="runbook-turn")
        loops = 0
        try:
            while not stop.is_set():
                self.poll_once()
                deadline = time.monotonic() + self.config["limits"]["poll_s"]
                while time.monotonic() < deadline and not stop.is_set():
                    try:
                        kind, tid, line = inbox.get(timeout=max(0.05, deadline - time.monotonic()))
                    except queue.Empty:
                        break
                    self.route_pushed(kind, tid, line)
                self.futures = [f for f in self.futures if not f.done()]
                loops += 1
                if max_loops is not None and loops >= max_loops:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            for item in listeners:
                item.stop()
            self._pool.shutdown(wait=True)
            self._pool = None
            self.flush_noise()
            self.state.save()
        return 0


# --------------------------------------------------------------------------- report


def spend_report(records: Sequence[Mapping[str, Any]], *, hours: float | None = None,
                 now: datetime | None = None) -> dict[str, Any]:
    """Counts by kind, adapter and trigger; wall time and model cost where the client reported it."""
    now = now or datetime.now(UTC)
    rows = []
    for record in records:
        if record.get("protocol") != RECORD_PROTOCOL or record.get("kind") not in KINDS:
            continue
        if hours is not None:
            try:
                ts = datetime.strptime(str(record["ts"]), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            except (KeyError, ValueError):
                continue
            if (now - ts).total_seconds() > hours * 3600:
                continue
        rows.append(record)
    by_kind: dict[str, int] = {}
    by_adapter: dict[str, dict[str, Any]] = {}
    by_trigger: dict[str, int] = {}
    cost, cost_known, cost_unknown = 0.0, 0, 0
    for record in rows:
        # Noise records stand for the events folded into them (see Dispatcher._fold).
        if record.get("flush"):
            events = int(record.get("folded_count") or 0)
        else:
            events = 1 + int(record.get("repeats_before") or 0)
        by_kind[record["kind"]] = by_kind.get(record["kind"], 0) + events
        if record["kind"] != "turn":
            continue
        tid = str(record.get("trigger_id"))
        by_trigger[tid] = by_trigger.get(tid, 0) + 1
        slot = by_adapter.setdefault(str(record.get("adapter")), {"turns": 0, "ok": 0, "seconds": 0.0,
                                                                  "model_turns": 0})
        slot["turns"] += 1
        slot["ok"] += 1 if record.get("ok") else 0
        slot["seconds"] = round(slot["seconds"] + float(record.get("elapsed_s") or 0), 3)
        slot["model_turns"] += 1 if record.get("model_turn") else 0
        if record.get("model_turn"):
            if isinstance(record.get("cost_usd"), (int, float)):
                cost += float(record["cost_usd"])
                cost_known += 1
            else:
                cost_unknown += 1
    return {"protocol": "integrity-guardian/runbook-spend/v1", "window_hours": hours, "records": len(rows),
            "by_kind": by_kind, "by_adapter": by_adapter, "turns_by_trigger": by_trigger,
            "model_cost_usd": round(cost, 6), "model_turns_with_cost": cost_known,
            "model_turns_without_cost": cost_unknown}
