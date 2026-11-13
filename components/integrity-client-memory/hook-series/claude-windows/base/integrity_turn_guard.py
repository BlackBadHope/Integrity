# SPDX-License-Identifier: Apache-2.0
"""Turn-close guard and memory-status wording shared by the Integrity hooks.

Pure, stdlib-only decisions. The hooks gather evidence (hook state, the hook
payload, probe results) and call these functions; nothing here starts a
process, opens the network or writes canonical memory. The small local turn
log written by ``record_turn`` is diagnostic only and never authority.

Two problems this module fixes:

* A hook that only advises can be ignored. ``stop_decision`` lets the
  ``Stop`` hook block, once, a turn that changed state but never called
  ``integrity_turn_memory_close``. The second stop always ends the turn and the
  hook records the coverage gap as before, so a turn can never loop.
* "Memory offline" was guessed from a skipped call. ``memory_status_notice``
  separates a server that is really unreachable (a broker start failure, or a
  fresh probe the server refused twice) from a model that simply skipped
  admission while the server answered. A probe timeout is inconclusive.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Mapping

PROTOCOL = "integrity-turn-guard/v1"
POLICY_FILE = "turn-guard.json"
TURN_LOG_FILE = "turn-guard-log.jsonl"
TURN_LOG_MAX_LINES = 500
ENV_MODE = "INTEGRITY_TURN_CLOSE_ENFORCEMENT"
ENV_POLICY = "INTEGRITY_TURN_GUARD_CONFIG"
# Set by a profile launcher (the integrity-seats plugin entrypoint sets "block").
ENV_DEFAULT = "INTEGRITY_TURN_GUARD_DEFAULT"
MODES = ("block", "advise", "off")
DEFAULT_MODE = "advise"
OFFLINE_STREAK_THRESHOLD = 2
PROBE_CACHE_SECONDS = 600
# One hook probe run, retry included. A cold broker start over SSH measured
# 31-38 s on a live client; the UserPromptSubmit hook itself has a 60 s timeout.
PROBE_BUDGET_SECONDS = 50.0
# A retry needs at least this much of the budget left to be worth starting.
PROBE_RETRY_MIN_SECONDS = 8.0
# Consecutive conclusive failures before a probe says "unreachable".
PROBE_ATTEMPTS = 2
# A timeout can be a slow cold start: it is never evidence that the server is down.
INCONCLUSIVE_PROBE_RE = re.compile(r"(?i)time[ _-]?out|timed[ _-]out|deadline")
BLOCK_MARKER = "INTEGRITY STOP GUARD"

# Tools that edit files or run commands. Shell is counted as a state change
# because a hook cannot tell a read-only command from a mutating one.
EDIT_TOOL_RE = re.compile(r"(?i)^(?:Edit|MultiEdit|Write|NotebookEdit|apply_patch|ApplyPatch)$")
SHELL_TOOL_RE = re.compile(
    r"(?i)^(?:Bash|PowerShell|shell|local_shell|exec_command|unified_exec|run_shell_command|"
    r"container\.exec|run_in_terminal|exec|functions\.exec|code_execution|run_code)$"
)
# Built-in harness tools that change state outside the file system: messages to
# other sessions or people, schedules, published pages, stopped tasks, worktrees.
NATIVE_WRITE_TOOL_RE = re.compile(
    r"(?i)^(?:SendMessage|SendUserFile|SendToProject|SendToProjectContext|PushNotification|"
    r"CronCreate|CronDelete|ScheduleWakeup|RemoteTrigger|TaskStop|KillShell|KillBash|"
    r"Artifact|ArtifactData|ArtifactComments|EnterWorktree|ExitWorktree|Monitor)$"
)
TERMINAL_RECEIPT_PROTOCOL = "turn-memory-terminal-receipt"
INTEGRITY_TOOL_RE = re.compile(r"(?i)(?:^|__)integrity_[a-z0-9_]+$")
INTEGRITY_WRITE_RE = re.compile(r"(?i)(?:^|__)integrity_append_event$")
CLOSE_TOOL_RE = re.compile(r"(?i)(?:^|__)integrity_turn_memory_close$")
# An MCP tool whose own name says it writes. Read-style names stay read-only.
MCP_WRITE_VERB_RE = re.compile(
    r"(?i)(?:^|_)(?:create|update|delete|remove|write|send|post|put|patch|append|insert|set|"
    r"merge|push|upload|move|rename|edit|apply|exec|execute|run|start|stop|restart|deploy|"
    r"publish|commit|reply|trash|archive|modify|replace|import|enable|disable|grant|revoke|"
    r"share|batch|kill|sync|hand|handoff|computer|form|javascript|clear|detach|unarchive|"
    r"dismiss|approve|reject|cancel|schedule|trigger|notify|invite|assign|fork|install|"
    r"uninstall|register|bind|unbind)(?:_|$)"
)
# Harness UI tools (task list, panes, window layout) never change project state.
# Session management is not UI: it sends messages and deletes or archives sessions,
# so its tools go through the verb check like any other MCP tool.
HARNESS_UI_RE = re.compile(
    r"(?i)^mcp__ccd_(?:(?:turn|view|sidebar|window)__"
    r"|session_mgmt__(?:set_session_title|get_|list_|search_))"
)
NOTIFICATION_TURN_KIND = "harness-notification-probable"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _iso(value: dt.datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


# --- policy -----------------------------------------------------------------

def load_policy(root: Path | str | None, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve the enforcement mode.

    Precedence: the ``INTEGRITY_TURN_CLOSE_ENFORCEMENT`` environment variable,
    then ``turn-guard.json`` (``INTEGRITY_TURN_GUARD_CONFIG`` or ``ROOT/turn-guard.json``),
    then a launcher default (``INTEGRITY_TURN_GUARD_DEFAULT``), then ``advise``. ``block`` enforces; ``advise`` only reports;
    ``off`` disables the guard and its turn log. Invalid values fall back to
    ``advise`` and say so, they never enable blocking.
    """

    environ = os.environ if environ is None else environ
    raw = environ.get(ENV_MODE, "").strip().lower()
    if raw:
        aliases = {"1": "block", "on": "block", "true": "block", "0": "off", "false": "off"}
        mode = aliases.get(raw, raw)
        if mode in MODES:
            return {"mode": mode, "source": "env:" + ENV_MODE}
        return {"mode": DEFAULT_MODE, "source": "env:" + ENV_MODE, "error": "invalid mode " + raw[:20]}
    explicit = environ.get(ENV_POLICY, "").strip()
    path = Path(explicit) if explicit else (Path(root) / POLICY_FILE if root is not None else None)
    if path is not None:
        try:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024:
                document = json.loads(path.read_text(encoding="utf-8"))
                mode = document.get("enforce_turn_close") if isinstance(document, dict) else None
                if mode is True:
                    mode = "block"
                elif mode is False:
                    mode = "off"
                if mode in MODES:
                    return {"mode": mode, "source": str(path)}
                return {"mode": DEFAULT_MODE, "source": str(path), "error": "invalid enforce_turn_close"}
        except (OSError, ValueError, UnicodeError):
            return {"mode": DEFAULT_MODE, "source": str(path), "error": "unreadable policy file"}
    launcher = environ.get(ENV_DEFAULT, "").strip().lower()
    if launcher in MODES:
        return {"mode": launcher, "source": "default:" + ENV_DEFAULT}
    return {"mode": DEFAULT_MODE, "source": "default"}


def guard_root(default: Path | str) -> Path:
    """Directory of the policy file and the local turn log."""

    explicit = os.environ.get(ENV_POLICY, "").strip()
    return Path(explicit).parent if explicit else Path(default)


def policy_document(mode: str) -> dict[str, Any]:
    """The ``turn-guard.json`` an installer writes."""

    if mode not in MODES:
        raise ValueError("unknown turn guard mode")
    return {
        "protocol": PROTOCOL,
        "enforce_turn_close": mode,
        "modes": {
            "block": "Stop blocks once when a state-changing turn has no integrity_turn_memory_close",
            "advise": "Stop only reports the missing close; the turn ends",
            "off": "no guard and no local turn log",
        },
        "override_env": ENV_MODE,
    }


# --- classification ---------------------------------------------------------

def classify_tool(name: object) -> str:
    """Return ``"write"`` for a tool call that may change state, else ``"read"``."""

    if not isinstance(name, str) or not name.strip():
        return "read"
    name = name.strip()
    if HARNESS_UI_RE.search(name):
        return "read"
    if INTEGRITY_TOOL_RE.search(name):
        return "write" if INTEGRITY_WRITE_RE.search(name) else "read"
    if EDIT_TOOL_RE.match(name) or SHELL_TOOL_RE.match(name) or NATIVE_WRITE_TOOL_RE.match(name):
        return "write"
    if name.startswith("mcp__") or "__" in name:
        last = name.rsplit("__", 1)[-1]
        return "write" if MCP_WRITE_VERB_RE.search(last) else "read"
    return "read"


def note_tool(state: dict[str, Any], name: object) -> bool:
    """Record a state-changing tool attempt in hook state. Returns True when recorded."""

    if classify_tool(name) != "write":
        return False
    first = state.get("turn_guard_state_changed") is not True
    state["turn_guard_state_changed"] = True
    if first:
        state["turn_guard_first_write_tool"] = str(name)[:120]
    count = state.get("turn_guard_write_count")
    state["turn_guard_write_count"] = (count if isinstance(count, int) and count >= 0 else 0) + 1
    return True


def note_close(state: dict[str, Any], name: object, response: object) -> bool:
    """Record an ``integrity_turn_memory_close`` that returned its terminal receipt.

    Only a response carrying a terminal receipt for the current registration
    counts. A call moved to the background, an error or any receipt-less text
    stays pending; the Stop hook's own lifecycle check then decides.
    """

    if not isinstance(name, str) or not CLOSE_TOOL_RE.search(name):
        return False
    if response is None or (isinstance(response, dict) and response.get("isError") is True):
        return False
    registration = state.get("turn_memory_registration_id")
    if not isinstance(registration, str) or not registration.startswith("sha256:"):
        return False
    text = json.dumps(response, ensure_ascii=False, default=str)
    if TERMINAL_RECEIPT_PROTOCOL not in text or registration not in text:
        return False
    state["turn_memory_close_observed"] = True
    # Kept for the turn log: a no-event close after a state change is allowed
    # (a shell call may have only read), but it is counted and reported.
    state["turn_memory_close_outcome"] = (
        "no-event" if re.search(r'\\?"outcome\\?"\s*:\s*\\?"no-event', text) else "events"
    )
    return True


def reset_turn(state: dict[str, Any]) -> None:
    """Clear per-turn guard fields when a new owner intent starts."""

    for key in (
        "turn_guard_state_changed",
        "turn_guard_first_write_tool",
        "turn_guard_write_count",
        "turn_memory_close_observed",
        "turn_guard_blocked_generation",
        "turn_guard_last_decision",
        "turn_guard_interrupted_owner",
        "turn_memory_close_outcome",
    ):
        state.pop(key, None)


def interrupted_owner_turn(state: Mapping[str, Any]) -> dict[str, Any] | None:
    """What a new prompt interrupts: an owner turn that never reached ``Stop``.

    Call with the PREVIOUS turn's state, before it is reset. A harness
    notification or a steering prompt can arrive while an owner turn is still
    running; the hook then starts a new generation without a ``Stop``. Returns
    the live registration to record a gap for, and the guard facts to carry,
    or ``None`` when the previous turn ended or was closed.
    """

    status = state.get("turn_memory_status")
    if status not in ("open", "provisional") or state.get("turn_memory_lease") == "expired":
        return None
    if state.get("turn_memory_close_observed") is True:
        return None
    if state.get("turn_kind") == NOTIFICATION_TURN_KIND and state.get("turn_guard_interrupted_owner") is not True:
        return None  # an interrupted notification turn owes nothing
    registration = state.get("turn_memory_registration_id")
    return {
        "registration_id": registration
        if status == "open" and isinstance(registration, str) and registration.startswith("sha256:")
        else None,
        "state_changed": state.get("turn_guard_state_changed") is True,
        "first_write_tool": state.get("turn_guard_first_write_tool"),
        "write_count": state.get("turn_guard_write_count"),
    }


def carry_interrupted(state: dict[str, Any], carried: Mapping[str, Any] | None) -> bool:
    """Keep the guard on for a notification turn that continues an owner turn.

    Call after ``reset_turn``. The model goes on with the owner's work inside
    the notification turn, so that turn is not exempt and keeps the earlier
    state change. Returns True when something was carried.
    """

    if not carried:
        return False
    state["turn_guard_interrupted_owner"] = True
    if carried.get("state_changed"):
        state["turn_guard_state_changed"] = True
        state["turn_guard_first_write_tool"] = str(carried.get("first_write_tool") or "a state-changing tool")[:120]
        count = carried.get("write_count")
        state["turn_guard_write_count"] = count if isinstance(count, int) and count > 0 else 1
    return True


def note_mcp_answer(state: dict[str, Any], name: object, response: object) -> None:
    """Remember that the model-side Integrity MCP server answered in this session."""

    if not isinstance(name, str) or not INTEGRITY_TOOL_RE.search(name):
        return
    if response is None or (isinstance(response, dict) and response.get("isError") is True):
        return
    state["mcp_answered_utc"] = _iso(utc_now())
    state["mcp_answered_tool"] = name.rsplit("__", 1)[-1][:80]
    if state.get("mcp_probe_ok") is False:
        # A newer real answer supersedes an older failed probe.
        for key in ("mcp_probe_ok", "mcp_probe_utc", "mcp_probe_detail"):
            state.pop(key, None)


# --- stop decision ----------------------------------------------------------

def is_exempt(state: Mapping[str, Any], *, notification_now: bool = False) -> str | None:
    if state.get("turn_guard_interrupted_owner") is True:
        return None  # a notification that arrived inside an owner turn continues it
    if notification_now or state.get("turn_kind") == NOTIFICATION_TURN_KIND:
        return "harness-notification-or-peer-event"
    if state.get("prompt_kind") == "subagent":
        return "subagent"
    return None


def stop_decision(
    state: Mapping[str, Any],
    payload: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    event: str = "Stop",
    notification_now: bool = False,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Decide what the Stop hook does about a missing close.

    Returns ``{"action": "block"|"advise"|"none", "reason": str, "why": str}``.
    ``block`` happens at most once per turn generation and never while the
    harness reports ``stop_hook_active`` (it is already continuing because of a
    stop hook). Every other path lets the turn end.
    """

    mode = policy.get("mode", DEFAULT_MODE)
    if mode == "off":
        return {"action": "none", "why": "policy-off"}
    if event != "Stop":
        return {"action": "none", "why": "not-top-level-stop"}
    exempt = is_exempt(state, notification_now=notification_now)
    if exempt:
        return {"action": "none", "why": "exempt:" + exempt}
    if state.get("turn_guard_state_changed") is not True:
        return {"action": "none", "why": "read-only-turn"}
    if state.get("turn_memory_close_observed") is True or state.get("turn_memory_status") == "closed":
        return {"action": "none", "why": "closed"}
    generation = state.get("turn_memory_generation")
    tool = state.get("turn_guard_first_write_tool") or "a state-changing tool"
    registration = state.get("turn_memory_registration_id")
    live = (
        isinstance(registration, str)
        and registration.startswith("sha256:")
        and state.get("turn_memory_status") == "open"
    )
    turn_ref = state.get("turn_ref")
    expires = _parse(state.get("turn_ref_expires_utc"))
    now = now or utc_now()
    ref_usable = (
        isinstance(turn_ref, str)
        and state.get("model_mcp_admission_attempted") is not True
        and (expires is None or expires > now)
    )
    if live:
        instruction = (
            f"call integrity_turn_memory_close with registration_id={registration} - "
            "outcome=events with the receipts of the events you appended in this turn, otherwise "
            "outcome=no-event with an honest no_event_reason (read-only if nothing durable changed)"
        )
    elif ref_usable:
        instruction = (
            f"call integrity_context_admission_current_turn with turn_ref={turn_ref!r} "
            "(omit limit), then close the registration it returns with integrity_turn_memory_close"
        )
    else:
        # Admission was attempted and failed, or the turn_ref expired: there is
        # nothing the model can close. Blocking would only loop.
        return {
            "action": "advise",
            "why": "nothing-closable",
            "reason": (
                f"{BLOCK_MARKER}: this turn changed state ({tool}) without Integrity turn memory, and "
                "no closable registration exists (admission failed, detached or expired). "
                "The turn ends uncovered: without a registration there is no server-side gap to "
                "record; the local turn log counts it."
            ),
        }
    reason = (
        f"{BLOCK_MARKER}: this turn changed state ({tool}) but Integrity turn memory is not closed. "
        f"Before finishing, {instruction}. If the call is refused, finish anyway: the next stop is "
        "not blocked and the hook records the coverage gap."
    )
    already = state.get("turn_guard_blocked_generation") == generation and generation is not None
    if mode != "block":
        return {"action": "advise", "why": "policy-advise", "reason": reason}
    if payload.get("stop_hook_active") is True or payload.get("stopHookActive") is True:
        return {"action": "advise", "why": "stop-hook-active", "reason": _after_block(tool, live)}
    if already:
        return {"action": "advise", "why": "already-blocked-once", "reason": _after_block(tool, live)}
    return {"action": "block", "why": "missing-close", "reason": reason}


def _after_block(tool: str, live: bool = True) -> str:
    ending = (
        "The turn ends now; the hook records the coverage gap for its registration."
        if live
        else "The turn ends now uncovered: no admission was made, so no registration exists and "
        "nothing is recorded on the server; the local turn log counts it."
    )
    return (
        f"{BLOCK_MARKER}: the turn changed state ({tool}) and was asked once to close Integrity turn "
        f"memory, but no close was observed. {ending}"
    )


def stop_output(decision: Mapping[str, Any]) -> dict[str, Any]:
    """Hook JSON for a ``block`` decision (Claude Code and Codex share this shape)."""

    return {"decision": "block", "reason": str(decision.get("reason", BLOCK_MARKER))}


def mark_blocked(state: dict[str, Any]) -> None:
    state["turn_guard_blocked_generation"] = state.get("turn_memory_generation")
    state["turn_guard_last_decision"] = "block"


# --- memory status wording --------------------------------------------------

def unattempted_streak(state: dict[str, Any]) -> int:
    """Update and return the count of consecutive owner turns without admission.

    Call with the PREVIOUS turn's state, before it is reset for the new turn.
    """

    if state.get("turn_kind") == NOTIFICATION_TURN_KIND:
        value = state.get("admission_unattempted_streak")
        return value if isinstance(value, int) and value >= 0 else 0
    never = (
        isinstance(state.get("turn_ref"), str)
        and state.get("model_mcp_admission_attempted") is not True
        and state.get("model_mcp_admission_status") == "required"
    )
    value = state.get("admission_unattempted_streak")
    value = value if isinstance(value, int) and value >= 0 else 0
    value = value + 1 if never else 0
    state["admission_unattempted_streak"] = value
    return value


def probe_due(state: Mapping[str, Any], now: dt.datetime | None = None) -> bool:
    last = _parse(state.get("mcp_probe_utc"))
    now = now or utc_now()
    return last is None or (now - last).total_seconds() >= PROBE_CACHE_SECONDS


def probe_inconclusive(detail: object) -> bool:
    """True when a probe failure is a timeout, which a slow cold start also produces."""

    return bool(INCONCLUSIVE_PROBE_RE.search(str(detail or "")))


def run_probe(
    attempt: Callable[[float], tuple[bool, str]],
    *,
    budget: float = PROBE_BUDGET_SECONDS,
    attempts: int = PROBE_ATTEMPTS,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[bool, str, int, bool]:
    """Run ``attempt(timeout)`` until it answers, within one time budget.

    Only a conclusive failure (the transport refused, the registration is
    missing) is retried. A timeout stops the run as inconclusive: it already
    used the time a retry would need. Returns ``(ok, detail, failures,
    conclusive)``.
    """

    deadline = clock() + budget
    failures = 0
    detail = ""
    for index in range(max(1, attempts)):
        remaining = deadline - clock()
        if index and remaining < PROBE_RETRY_MIN_SECONDS:
            break
        ok, detail = attempt(max(1.0, remaining))
        if ok:
            return True, detail, failures, True
        failures += 1
        if probe_inconclusive(detail):
            return False, detail, failures, False
    return False, detail, failures, True


def record_probe(
    state: dict[str, Any],
    ok: bool,
    detail: str,
    now: dt.datetime | None = None,
    *,
    failures: int = 1,
    conclusive: bool | None = None,
) -> None:
    state["mcp_probe_utc"] = _iso(now or utc_now())
    state["mcp_probe_ok"] = bool(ok)
    state["mcp_probe_detail"] = str(detail)[:200]
    state["mcp_probe_failures"] = 0 if ok else max(1, int(failures))
    state["mcp_probe_conclusive"] = True if ok else (
        not probe_inconclusive(detail) if conclusive is None else bool(conclusive)
    )


def lifecycle_evidence(health: object, now: dt.datetime | None = None) -> str | None:
    """UTC of a recent successful hook lifecycle call, from ``hook-health.json``.

    The hook's own registration, close and gap calls use the same transport as
    the model. A recent success with no failure since shows the server answers,
    so no probe is needed.
    """

    if not isinstance(health, Mapping) or health.get("consecutive_failures") != 0:
        return None
    last = _parse(health.get("last_success_utc"))
    now = now or utc_now()
    if last is None or not 0 <= (now - last).total_seconds() <= PROBE_CACHE_SECONDS:
        return None
    return str(health.get("last_success_utc"))


def memory_status_notice(
    state: Mapping[str, Any],
    streak: int,
    *,
    server_name: str,
    broker_failure: str | None = None,
    threshold: int = OFFLINE_STREAK_THRESHOLD,
    fresh_probe: bool = False,
    lifecycle_ok_utc: str | None = None,
) -> str | None:
    """Wording for a session whose model has not called admission for ``streak`` turns.

    * ``UNREACHABLE`` only on direct evidence: a broker startup failure, or a
      probe run made for this notice (``fresh_probe``) in which the server
      refused ``PROBE_ATTEMPTS`` times. A timeout is never such evidence, and a
      cached failure from an earlier turn is never shown again.
    * ``SKIPPED`` when the server answered in this session (a model tool call,
      the hook's own lifecycle call or the hook probe): reconnecting would not help.
    * ``NOT CALLED`` when neither is known.
    """

    if streak < threshold:
        return None
    probe_ok = state.get("mcp_probe_ok")
    probe_detail = state.get("mcp_probe_detail") or ""
    answered = state.get("mcp_answered_utc")
    answered_at, probed_at = _parse(answered), _parse(state.get("mcp_probe_utc"))
    if probe_ok is False and answered_at and (probed_at is None or answered_at > probed_at):
        probe_ok = None  # the failed probe is older than a real answer
    if probe_ok is False and not fresh_probe:
        probe_ok = None  # a cached failure from an earlier turn is not current evidence
    failures = state.get("mcp_probe_failures")
    failures = failures if isinstance(failures, int) else 1
    refused = (
        probe_ok is False
        and state.get("mcp_probe_conclusive") is not False
        and not probe_inconclusive(probe_detail)
        and failures >= PROBE_ATTEMPTS
    )
    debt = (
        "Turns without admission have no turn-memory registration, so nothing from them is "
        "remembered (canonical_writes=0)."
    )
    if refused or broker_failure:
        evidence = []
        if refused:
            evidence.append(
                f"hook probe failed {failures} times at {state.get('mcp_probe_utc')}: {probe_detail}"
            )
        if broker_failure:
            evidence.append(f"MCP broker startup failure {broker_failure}")
        return (
            f"INTEGRITY MEMORY UNREACHABLE: {'; '.join(evidence)}. "
            f"integrity_context_admission_current_turn was not called in the last {streak} turns. "
            f"{debt} Tell the owner; run /mcp and reconnect {server_name} or restart the session. "
            "If the tool is in fact available, call it as instructed below."
        )
    if answered or probe_ok is True or lifecycle_ok_utc:
        if answered:
            seen = f"the model's {server_name} tools answered at {answered}"
        elif lifecycle_ok_utc:
            seen = f"the hook's own lifecycle call reached the memory server at {lifecycle_ok_utc}"
        else:
            seen = (
                "the hook's own read-only coverage call reached the memory server at "
                f"{state.get('mcp_probe_utc')}"
            )
        return (
            f"INTEGRITY ADMISSION SKIPPED: integrity_context_admission_current_turn was not called "
            f"in the last {streak} turns, although {seen}. This is a skipped call, not a connection "
            f"problem: do not reconnect or restart. {debt} Call it now as instructed below."
        )
    unconfirmed = ""
    if probe_ok is False:
        unconfirmed = (
            f" The hook's check at {state.get('mcp_probe_utc')} did not confirm the server "
            f"({probe_detail}); a timeout or a single refusal can be a slow cold start and is "
            "not evidence that the server is down."
        )
    return (
        f"INTEGRITY ADMISSION NOT CALLED: integrity_context_admission_current_turn was not called in "
        f"the last {streak} turns and this session has no evidence yet that {server_name} is "
        f"connected.{unconfirmed} {debt} If the tool is listed, call it as instructed below; "
        "reconnect with /mcp only if it is missing or failed."
    )


# --- local turn log (diagnostic) --------------------------------------------

def turn_record(state: Mapping[str, Any], decision: Mapping[str, Any], *, vendor: str) -> dict[str, Any]:
    admitted = state.get("model_mcp_admission_status") == "ready" or isinstance(
        state.get("turn_memory_registration_id"), str
    )
    return {
        "protocol": PROTOCOL,
        "utc": _iso(utc_now()),
        "vendor": vendor,
        "turn_kind": state.get("turn_kind") or "owner",
        "admitted": bool(admitted),
        "closed": bool(
            state.get("turn_memory_close_observed") is True or state.get("turn_memory_status") == "closed"
        ),
        "state_changed": state.get("turn_guard_state_changed") is True,
        "decision": decision.get("action"),
        "why": decision.get("why"),
        "turn_memory_status": state.get("turn_memory_status"),
        # The block itself returns before the hook writes its record; the
        # final stop of the same turn carries it.
        "blocked_once": state.get("turn_guard_last_decision") == "block",
        "close_outcome": state.get("turn_memory_close_outcome"),
        "interrupted_owner": state.get("turn_guard_interrupted_owner") is True,
    }


LOCK_WAIT_SECONDS = 5.0
LOCK_STALE_SECONDS = 30.0


def _acquire(lock: Path) -> bool:
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            return True
        except (FileExistsError, PermissionError):
            # Windows reports a lock file that is being deleted as access denied.
            try:
                if time.time() - lock.stat().st_mtime > LOCK_STALE_SECONDS:
                    lock.unlink()
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)


def record_turn(root: Path | str, record: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    """Append one line to the bounded local turn log. Never raises.

    Several sessions of one profile share this file. Each record is one
    append; appends and the occasional compaction run under one lock file, so
    a concurrent Stop cannot drop another session's record. If the lock is not
    obtained in time, the record is still appended and compaction waits.
    """

    if policy.get("mode") == "off":
        return
    try:
        path = Path(root) / TURN_LOG_FILE
        if path.is_symlink():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(dict(record), ensure_ascii=False, sort_keys=True) + "\n"
        lock = path.with_name(path.name + ".lock")
        locked = _acquire(lock)
        try:
            with open(path, "a", encoding="utf-8", newline="\n") as stream:
                stream.write(line)
            if locked and path.stat().st_size > TURN_LOG_MAX_LINES * 2 * 256:
                lines = path.read_text(encoding="utf-8").splitlines()
                if len(lines) > TURN_LOG_MAX_LINES:
                    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
                    temporary.write_text("\n".join(lines[-TURN_LOG_MAX_LINES:]) + "\n", encoding="utf-8")
                    os.replace(temporary, path)
        finally:
            if locked:
                try:
                    lock.unlink()
                except OSError:
                    pass
    except (OSError, ValueError, UnicodeError):
        return


def read_turn_log(root: Path | str, last: int = 50) -> list[dict[str, Any]]:
    path = Path(root) / TURN_LOG_FILE
    try:
        if not path.is_file() or path.is_symlink():
            return []
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines()[-max(1, last):]:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows
    except (OSError, UnicodeError):
        return []


def summarize_turns(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    owner = [row for row in rows if row.get("turn_kind") != NOTIFICATION_TURN_KIND]
    changed = [row for row in owner if row.get("state_changed")]

    def rate(part: int, whole: int) -> float | None:
        return round(part / whole, 3) if whole else None

    return {
        "turns": len(rows),
        "owner_turns": len(owner),
        "exempt_turns": len(rows) - len(owner),
        "admitted": sum(1 for row in owner if row.get("admitted")),
        "admission_rate": rate(sum(1 for row in owner if row.get("admitted")), len(owner)),
        "state_changing_turns": len(changed),
        "closed_state_changing": sum(1 for row in changed if row.get("closed")),
        "close_rate_state_changing": rate(sum(1 for row in changed if row.get("closed")), len(changed)),
        "blocked": sum(1 for row in rows if row.get("decision") == "block" or row.get("blocked_once")),
        "no_event_after_change": sum(
            1 for row in changed if row.get("closed") and row.get("close_outcome") == "no-event"
        ),
    }
