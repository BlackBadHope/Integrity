"""Turn-close guard, memory-status wording and doctor: synthetic, no vendor or model calls."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from integrity_client_memory import doctor, native_runtime, turn_guard as guard

RESOURCES = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources"
REG = "sha256:" + "b" * 64
FUTURE = (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
PAST = (dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
BLOCK = {"mode": "block"}


def live_state(**extra):
    state = {"turn_memory_generation": 3, "turn_memory_registration_id": REG,
             "turn_memory_status": "open", "turn_kind": "owner", "prompt_kind": "text",
             "turn_guard_state_changed": True, "turn_guard_first_write_tool": "Edit",
             "turn_ref": "turnref:" + "a" * 43, "turn_ref_expires_utc": FUTURE,
             "model_mcp_admission_attempted": True}
    state.update(extra)
    return state


# --- classification ---------------------------------------------------------

@pytest.mark.parametrize("name, expected", [
    ("Edit", "write"), ("Write", "write"), ("NotebookEdit", "write"), ("apply_patch", "write"),
    ("Bash", "write"), ("PowerShell", "write"), ("exec_command", "write"), ("shell", "write"),
    ("Read", "read"), ("Grep", "read"), ("Glob", "read"), ("WebFetch", "read"), ("TodoWrite", "read"),
    ("mcp__integrity-x__integrity_append_event", "write"),
    ("exec", "write"), ("functions.exec", "write"), ("code_execution", "write"),
    ("mcp__integrity-x__integrity_turn_memory_close", "read"),
    ("mcp__integrity-x__integrity_context_admission_current_turn", "read"),
    ("integrity_read_events", "read"),
    ("mcp__github__create_pull_request", "write"), ("mcp__mail__send_mail", "write"),
    ("mcp__github__get_issue", "read"), ("mcp__docs__search", "read"),
    ("mcp__ccd_turn__update_plan", "read"), ("mcp__ccd_session_mgmt__set_session_title", "read"),
    ("SendMessage", "write"), ("SendUserFile", "write"), ("CronCreate", "write"), ("ScheduleWakeup", "write"),
    ("TaskStop", "write"), ("Artifact", "write"), ("EnterWorktree", "write"), ("Monitor", "write"),
    ("mcp__ccd_session_mgmt__delete_session", "write"), ("mcp__ccd_session_mgmt__send_message", "write"),
    ("mcp__ccd_session_mgmt__archive_session", "write"),
    ("mcp__ccd_session_mgmt__set_session_permission_mode", "write"),
    ("mcp__ccd_session_mgmt__list_sessions", "read"), ("mcp__ccd_session_mgmt__get_session", "read"),
    ("mcp__ccd_session__hand_off_to_session", "write"), ("mcp__ccd_host__sync_with_base_branch", "write"),
    ("mcp__drive__share_file", "write"), ("mcp__docs__batch", "write"), ("mcp__term__kill_process", "write"),
    ("mcp__claude-in-chrome__computer", "write"), ("mcp__claude-in-chrome__form_input", "write"),
    ("mcp__claude-in-chrome__read_page", "read"), ("Agent", "read"), ("Skill", "read"),
    ("", "read"), (None, "read"),
])
def test_classify_tool(name, expected):
    assert guard.classify_tool(name) == expected


def test_note_tool_and_reset():
    state = {}
    assert guard.note_tool(state, "Read") is False and "turn_guard_state_changed" not in state
    assert guard.note_tool(state, "Bash") and guard.note_tool(state, "Edit")
    assert state["turn_guard_first_write_tool"] == "Bash" and state["turn_guard_write_count"] == 2
    guard.note_close(state, "mcp__s__integrity_turn_memory_close", {"content": [{"text": "{\"receipt_id\":1}"}]})
    guard.mark_blocked({**state, "turn_memory_generation": 1})
    guard.reset_turn(state)
    assert not any(key.startswith("turn_guard") or key == "turn_memory_close_observed" for key in state)


def receipt_response(registration=REG):
    receipt = {"receipt": {"protocol": "integrity-guardian/turn-memory-terminal-receipt/v1",
                           "registration_id": registration, "outcome": "no-event"}}
    return {"content": [{"type": "text", "text": json.dumps(receipt)}]}


def test_note_close_requires_terminal_receipt_for_current_registration():
    state = {"turn_memory_registration_id": REG}
    assert not guard.note_close(state, "integrity_turn_memory_close", {"isError": True})
    assert not guard.note_close(state, "integrity_turn_memory_gap", receipt_response())
    assert not guard.note_close(state, "integrity_turn_memory_close", {"content": []})
    background = {"content": [{"type": "text", "text": "Command running in background with ID: abc123"}]}
    assert not guard.note_close(state, "integrity_turn_memory_close", background)
    assert not guard.note_close(state, "integrity_turn_memory_close", receipt_response("sha256:" + "d" * 64))
    assert not guard.note_close({}, "integrity_turn_memory_close", receipt_response())
    assert "turn_memory_close_observed" not in state
    assert guard.note_close(state, "mcp__s__integrity_turn_memory_close", receipt_response())
    assert state["turn_memory_close_observed"] is True


# --- policy -----------------------------------------------------------------

def test_policy_precedence(tmp_path):
    assert guard.load_policy(tmp_path, {})["mode"] == "advise"
    (tmp_path / guard.POLICY_FILE).write_text(json.dumps(guard.policy_document("block")))
    assert guard.load_policy(tmp_path, {}) == {"mode": "block", "source": str(tmp_path / guard.POLICY_FILE)}
    assert guard.load_policy(tmp_path, {guard.ENV_MODE: "off"})["mode"] == "off"
    assert guard.load_policy(tmp_path, {guard.ENV_MODE: "0"})["mode"] == "off"
    bad = guard.load_policy(tmp_path, {guard.ENV_MODE: "yolo"})
    assert bad["mode"] == "advise" and "error" in bad
    other = tmp_path / "elsewhere.json"
    other.write_text(json.dumps({"enforce_turn_close": False}))
    assert guard.load_policy(None, {guard.ENV_POLICY: str(other)})["mode"] == "off"
    (tmp_path / guard.POLICY_FILE).write_text("{not json")
    assert guard.load_policy(tmp_path, {})["mode"] == "advise"
    with pytest.raises(ValueError):
        guard.policy_document("always")
    (tmp_path / guard.POLICY_FILE).unlink()
    launched = guard.load_policy(tmp_path, {guard.ENV_DEFAULT: "block"})
    assert launched == {"mode": "block", "source": "default:" + guard.ENV_DEFAULT}
    (tmp_path / guard.POLICY_FILE).write_text(json.dumps(guard.policy_document("off")))
    assert guard.load_policy(tmp_path, {guard.ENV_DEFAULT: "block"})["mode"] == "off"


# --- stop decision ----------------------------------------------------------

def test_block_once_then_gap():
    state = live_state()
    first = guard.stop_decision(state, {}, BLOCK)
    assert first["action"] == "block" and REG in first["reason"]
    assert guard.stop_output(first) == {"decision": "block", "reason": first["reason"]}
    guard.mark_blocked(state)
    again = guard.stop_decision(state, {}, BLOCK)
    assert again == {"action": "advise", "why": "already-blocked-once", "reason": again["reason"]}
    active = guard.stop_decision(live_state(), {"stop_hook_active": True}, BLOCK)
    assert active["action"] == "advise" and active["why"] == "stop-hook-active"


def test_new_generation_can_block_again():
    state = live_state()
    guard.mark_blocked(state)
    state["turn_memory_generation"] = 4
    assert guard.stop_decision(state, {}, BLOCK)["action"] == "block"


@pytest.mark.parametrize("extra, why", [
    ({"turn_guard_state_changed": False}, "read-only-turn"),
    ({"turn_memory_close_observed": True}, "closed"),
    ({"turn_memory_status": "closed"}, "closed"),
    ({"turn_kind": guard.NOTIFICATION_TURN_KIND}, "exempt:harness-notification-or-peer-event"),
    ({"prompt_kind": "subagent"}, "exempt:subagent"),
])
def test_no_block(extra, why):
    assert guard.stop_decision(live_state(**extra), {}, BLOCK) == {"action": "none", "why": why}


def test_exemptions_and_modes():
    assert guard.stop_decision(live_state(), {}, BLOCK, notification_now=True)["action"] == "none"
    assert guard.stop_decision(live_state(), {}, BLOCK, event="SubagentStop")["action"] == "none"
    assert guard.stop_decision(live_state(), {}, {"mode": "off"}) == {"action": "none", "why": "policy-off"}
    advise = guard.stop_decision(live_state(), {}, {"mode": "advise"})
    assert advise["action"] == "advise" and advise["reason"].startswith(guard.BLOCK_MARKER)


def test_unadmitted_turn_asks_for_admission_while_turn_ref_is_valid():
    state = live_state(turn_memory_registration_id=None, turn_memory_status="provisional",
                       model_mcp_admission_attempted=False)
    decision = guard.stop_decision(state, {}, BLOCK)
    assert decision["action"] == "block" and state["turn_ref"] in decision["reason"]
    expired = guard.stop_decision({**state, "turn_ref_expires_utc": PAST}, {}, BLOCK)
    assert expired["action"] == "advise" and expired["why"] == "nothing-closable"
    failed = guard.stop_decision({**state, "model_mcp_admission_attempted": True,
                                  "turn_memory_status": "detached"}, {}, BLOCK)
    assert failed["action"] == "advise" and failed["why"] == "nothing-closable"


# --- memory status wording --------------------------------------------------

def unadmitted(**extra):
    return {"turn_ref": "turnref:x", "model_mcp_admission_attempted": False,
            "model_mcp_admission_status": "required", **extra}


def test_streak_counts_and_notifications_leave_it():
    state = unadmitted()
    assert guard.unattempted_streak(state) == 1
    assert guard.unattempted_streak(state) == 2
    note = {**state, "turn_kind": guard.NOTIFICATION_TURN_KIND}
    assert guard.unattempted_streak(note) == 2
    state["model_mcp_admission_attempted"] = True
    assert guard.unattempted_streak(state) == 0


def test_status_notice_needs_threshold():
    assert guard.memory_status_notice({}, 1, server_name="srv") is None


def test_status_notice_skipped_when_server_answered():
    text = guard.memory_status_notice({"mcp_answered_utc": "2026-11-06T10:00:00Z"}, 12, server_name="srv")
    assert text.startswith("INTEGRITY ADMISSION SKIPPED") and "12 turns" in text
    assert "do not reconnect" in text and "offline" not in text.lower()
    probed = guard.memory_status_notice({"mcp_probe_ok": True, "mcp_probe_utc": "t"}, 3, server_name="srv")
    assert probed.startswith("INTEGRITY ADMISSION SKIPPED")


def test_newer_answer_supersedes_failed_probe():
    state = {}
    guard.record_probe(state, False, "HookTransportError: x", dt.datetime(2026, 11, 6, 9, tzinfo=dt.UTC))
    stale = {**state, "mcp_answered_utc": "2026-11-06T10:00:00Z"}
    assert guard.memory_status_notice(stale, 3, server_name="srv").startswith("INTEGRITY ADMISSION SKIPPED")
    older = {**state, "mcp_answered_utc": "2026-11-06T08:00:00Z", "mcp_probe_failures": 2}
    assert guard.memory_status_notice(older, 3, server_name="srv", fresh_probe=True).startswith(
        "INTEGRITY MEMORY UNREACHABLE")
    guard.note_mcp_answer(state, "mcp__s__integrity_read_events", {"content": []})
    assert "mcp_probe_ok" not in state and state["mcp_answered_utc"]
    failed_call = {}
    guard.note_mcp_answer(failed_call, "integrity_read_events", {"isError": True})
    assert "mcp_answered_utc" not in failed_call


def test_status_notice_unreachable_only_on_evidence():
    refused = {"mcp_probe_ok": False, "mcp_probe_detail": "HookTransportError: connection refused",
               "mcp_probe_failures": 2, "mcp_probe_conclusive": True}
    failed = guard.memory_status_notice(refused, 2, server_name="srv", fresh_probe=True)
    assert failed.startswith("INTEGRITY MEMORY UNREACHABLE") and "connection refused" in failed
    assert "failed 2 times" in failed and "/mcp" in failed
    # The same failure is not current evidence on a later turn.
    later = guard.memory_status_notice(refused, 3, server_name="srv")
    assert "UNREACHABLE" not in later and "connection refused" not in later
    # One refusal is not enough; a timeout is never enough.
    once = guard.memory_status_notice({**refused, "mcp_probe_failures": 1}, 2, server_name="srv", fresh_probe=True)
    assert once.startswith("INTEGRITY ADMISSION NOT CALLED") and "not evidence that the server is down" in once
    timeout = {"mcp_probe_ok": False, "mcp_probe_detail": "HookTransportError: response_timeout",
               "mcp_probe_failures": 2}
    slow = guard.memory_status_notice(timeout, 2, server_name="srv", fresh_probe=True)
    assert slow.startswith("INTEGRITY ADMISSION NOT CALLED") and "response_timeout" in slow
    broker = guard.memory_status_notice({}, 2, server_name="srv", broker_failure="at T: boom")
    assert broker.startswith("INTEGRITY MEMORY UNREACHABLE") and "boom" in broker
    unknown = guard.memory_status_notice({}, 2, server_name="srv")
    assert unknown.startswith("INTEGRITY ADMISSION NOT CALLED") and "only if it is missing" in unknown


def test_run_probe_retries_only_conclusive_failures():
    calls = []

    def refuse(timeout):
        calls.append(timeout)
        return False, "HookError: mcp_registration_unavailable"

    assert guard.run_probe(refuse) == (False, "HookError: mcp_registration_unavailable", 2, True)
    assert len(calls) == 2 and calls[0] >= 30  # covers a ~21 s cold broker start
    calls.clear()

    def slow(timeout):
        calls.append(timeout)
        return False, "HookTransportError: response_timeout"

    assert guard.run_probe(slow) == (False, "HookTransportError: response_timeout", 1, False)
    assert len(calls) == 1
    answers = iter([(False, "HookError: refused"), (True, "read-only coverage call answered")])
    assert guard.run_probe(lambda timeout: next(answers)) == (True, "read-only coverage call answered", 1, True)
    ticks = iter([0.0, 45.0])  # the first attempt used most of the budget: no retry
    assert guard.run_probe(refuse, clock=lambda: next(ticks, 45.0))[2] == 1
    state = {}
    guard.record_probe(state, False, "HookTransportError: response_timeout", failures=1)
    assert state["mcp_probe_conclusive"] is False and state["mcp_probe_failures"] == 1


def test_lifecycle_evidence_replaces_the_probe():
    now = dt.datetime(2026, 11, 6, 12, tzinfo=dt.UTC)
    recent = {"consecutive_failures": 0, "last_success_utc": "2026-11-06T11:58:00Z"}
    assert guard.lifecycle_evidence(recent, now) == "2026-11-06T11:58:00Z"
    assert guard.lifecycle_evidence({**recent, "consecutive_failures": 1}, now) is None
    assert guard.lifecycle_evidence({**recent, "last_success_utc": "2026-11-06T10:00:00Z"}, now) is None
    assert guard.lifecycle_evidence(None, now) is None
    text = guard.memory_status_notice({}, 2, server_name="srv", lifecycle_ok_utc="2026-11-06T11:58:00Z")
    assert text.startswith("INTEGRITY ADMISSION SKIPPED") and "lifecycle call" in text


def test_probe_cache():
    state = {}
    assert guard.probe_due(state)
    guard.record_probe(state, True, "ok")
    assert not guard.probe_due(state)
    later = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=guard.PROBE_CACHE_SECONDS + 1)
    assert guard.probe_due(state, later)


# --- turn log ---------------------------------------------------------------

def test_turn_log_is_bounded_and_summarized(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "TURN_LOG_MAX_LINES", 5)
    for index in range(8):
        state = live_state(turn_memory_close_observed=index % 2 == 0)
        guard.record_turn(tmp_path, guard.turn_record(state, {"action": "none", "why": "x"}, vendor="t"), BLOCK)
    guard.record_turn(tmp_path, guard.turn_record({"turn_kind": guard.NOTIFICATION_TURN_KIND},
                                                  {"action": "none"}, vendor="t"), BLOCK)
    rows = guard.read_turn_log(tmp_path, 5)
    assert len(rows) == 5
    summary = guard.summarize_turns(rows)
    assert summary["exempt_turns"] == 1 and summary["owner_turns"] == 4
    assert summary["state_changing_turns"] == 4 and summary["closed_state_changing"] == 2
    for index in range(40):  # realistic record size, so the byte threshold compacts
        guard.record_turn(tmp_path, {"n": index, "pad": "x" * 300}, BLOCK)
    kept = (tmp_path / guard.TURN_LOG_FILE).read_text(encoding="utf-8").splitlines()
    assert len(kept) <= 2 * guard.TURN_LOG_MAX_LINES and json.loads(kept[-1])["n"] == 39
    guard.record_turn(tmp_path / "off", {"x": 1}, {"mode": "off"})
    assert not (tmp_path / "off").exists()


def test_turn_log_concurrent_writers_keep_every_record(tmp_path):
    import threading
    threads = [threading.Thread(target=guard.record_turn, args=(tmp_path, {"n": n}, BLOCK)) for n in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(row["n"] for row in guard.read_turn_log(tmp_path, 100)) == list(range(24))
    assert not (tmp_path / (guard.TURN_LOG_FILE + ".lock")).exists()


def test_turn_log_stale_lock_is_recovered(tmp_path, monkeypatch):
    import os
    lock = tmp_path / (guard.TURN_LOG_FILE + ".lock")
    lock.write_text("")
    old = lock.stat().st_mtime - guard.LOCK_STALE_SECONDS - 5
    os.utime(lock, (old, old))
    guard.record_turn(tmp_path, {"n": 1}, BLOCK)
    assert [row["n"] for row in guard.read_turn_log(tmp_path)] == [1] and not lock.exists()
    lock.write_text("")
    monkeypatch.setattr(guard, "LOCK_WAIT_SECONDS", 0.05)
    guard.record_turn(tmp_path, {"n": 2}, BLOCK)  # fresh foreign lock: still appended
    assert [row["n"] for row in guard.read_turn_log(tmp_path)] == [1, 2] and lock.exists()


# --- hooks in-process -------------------------------------------------------

def load_hook(relative, envelope_dir, name):
    sys.modules.pop("integrity_client_turn_envelope", None)
    sys.path.insert(0, str(RESOURCES / envelope_dir))
    try:
        spec = importlib.util.spec_from_file_location(name, RESOURCES / relative)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


HOOKS = [("claude/admission.py", "common", "integrity_guard_claude_hook"),
         ("windows/native/integrity-client-admission.py", "windows", "integrity_guard_native_hook"),
         ("windows/admission.py", "windows", "integrity_guard_seats_windows_hook"),
         ("linux/admission.py", "linux", "integrity_guard_seats_linux_hook")]


@pytest.fixture(params=HOOKS, ids=["claude-standalone", "native-cohort", "seats-windows", "seats-linux"])
def hook(request, tmp_path, monkeypatch):
    try:
        module = load_hook(*request.param)
    except ImportError as exc:  # a POSIX-only module on Windows, or the reverse
        pytest.skip(f"{request.param[0]} does not import on this platform: {exc}")
    state_dir = tmp_path / "integrity-memory" / "state"
    monkeypatch.setenv("INTEGRITY_CLIENT_STATE_ROOT", str(state_dir))
    monkeypatch.setenv("INTEGRITY_CLIENT_ENVELOPE_ROOT", str(tmp_path / "envelopes"))
    monkeypatch.delenv(guard.ENV_MODE, raising=False)
    monkeypatch.delenv(guard.ENV_POLICY, raising=False)
    calls = []

    def lifecycle(name, arguments, **_owning):
        calls.append(name)
        return {"receipt": {"receipt_id": "sha256:" + "c" * 64}}

    monkeypatch.setattr(module, "lifecycle_call", lifecycle)
    module.calls = calls
    module.guard_dir = state_dir.parent
    return module


def stop(module, capsys, state, payload=None):
    module.handle_stop("Stop", "session-1", state, payload or {})
    out = capsys.readouterr().out.strip()
    return json.loads(out) if out else {}


def enable(module, mode="block"):
    module.guard_dir.mkdir(parents=True, exist_ok=True)
    (module.guard_dir / guard.POLICY_FILE).write_text(json.dumps(guard.policy_document(mode)))


def test_hook_blocks_once_then_records_gap(hook, capsys):
    enable(hook)
    state = live_state()
    first = stop(hook, capsys, state)
    assert first["decision"] == "block" and first["reason"].startswith(guard.BLOCK_MARKER)
    assert hook.calls == []  # the turn continues: no gap was recorded yet
    saved = hook.load_state("session-1")
    assert saved["turn_guard_blocked_generation"] == 3
    second = stop(hook, capsys, saved, {"stop_hook_active": True})
    assert "decision" not in second and second["continue"] is True
    assert hook.calls == ["integrity_turn_memory_gap"]
    assert "was asked once" in second["systemMessage"]
    rows = guard.read_turn_log(hook.guard_dir)
    assert rows[-1]["why"] == "stop-hook-active" and rows[-1]["state_changed"] is True


def test_hook_without_flag_only_advises(hook, capsys):
    out = stop(hook, capsys, live_state())
    assert "decision" not in out and guard.BLOCK_MARKER in out["systemMessage"]
    assert hook.calls == ["integrity_turn_memory_gap"]


@pytest.mark.parametrize("extra", [{"turn_guard_state_changed": False},
                                   {"turn_kind": guard.NOTIFICATION_TURN_KIND},
                                   {"turn_memory_close_observed": True}])
def test_hook_exempt_turns_are_never_blocked(hook, capsys, extra):
    enable(hook)
    out = stop(hook, capsys, live_state(**extra))
    assert out.get("decision") != "block"


def test_hook_off_switch(hook, capsys, monkeypatch):
    enable(hook)
    monkeypatch.setenv(guard.ENV_MODE, "off")
    out = stop(hook, capsys, live_state())
    assert out.get("decision") != "block"
    assert not (hook.guard_dir / guard.TURN_LOG_FILE).exists()


def test_hook_tool_events_feed_the_guard(hook):
    hook.save_state("session-1", {"turn_memory_generation": 1})
    state = hook.load_state("session-1")
    hook.handle_pre_tool({"tool_name": "Bash", "tool_input": {"command": "ls"}}, "session-1", state)
    state = hook.load_state("session-1")
    assert state["turn_guard_state_changed"] is True
    hook.handle_post_tool("PostToolUse", {"tool_name": "mcp__srv__integrity_turn_memory_close",
                                          "tool_input": {}, "tool_response": {"content": []}},
                          "session-1", state)
    state = hook.load_state("session-1")
    assert "turn_memory_close_observed" not in state and state["mcp_answered_utc"]
    state["turn_memory_registration_id"] = REG
    hook.save_state("session-1", state)
    hook.handle_post_tool("PostToolUse", {"tool_name": "mcp__srv__integrity_turn_memory_close",
                                          "tool_input": {}, "tool_response": receipt_response()},
                          "session-1", state)
    assert hook.load_state("session-1")["turn_memory_close_observed"] is True


def test_claude_offline_notice_uses_evidence(monkeypatch, tmp_path):
    module = load_hook(*HOOKS[0])
    original_probe = module.probe_memory_server
    monkeypatch.setattr(module, "last_broker_failure", lambda: None)
    monkeypatch.setattr(module, "read_hook_health", lambda: None)
    probes = []
    monkeypatch.setattr(module, "probe_memory_server", lambda *a: probes.append(1) or (True, "ok"))
    state = unadmitted(admission_unattempted_streak=1, mcp_answered_utc="2026-11-06T09:00:00Z")
    text = module.admission_offline_notice(state)
    assert text.startswith("INTEGRITY ADMISSION SKIPPED") and probes == []
    calls = []

    class Client:
        def __init__(self):
            calls.append("init")

        def call(self, name, arguments):
            calls.append(name)
            return {}

        def close(self):
            calls.append("close")

    monkeypatch.setattr(module, "McpClient", Client)
    assert original_probe() == (True, "read-only coverage call answered")
    assert calls == ["init", "integrity_turn_memory_coverage", "close"]
    state = unadmitted(admission_unattempted_streak=1)
    refusals = []
    monkeypatch.setattr(module, "probe_memory_server",
                        lambda *a: refusals.append(1) or (False, "HookError: mcp_registration_unavailable"))
    text = module.admission_offline_notice(state)
    assert text.startswith("INTEGRITY MEMORY UNREACHABLE") and "mcp_registration_unavailable" in text
    assert "most likely" not in text and len(refusals) == 2
    # The next turn neither probes again (cache) nor repeats the old failure.
    state = {**unadmitted(admission_unattempted_streak=2), **{k: v for k, v in state.items() if k.startswith("mcp_")}}
    again = module.admission_offline_notice(state)
    assert again.startswith("INTEGRITY ADMISSION NOT CALLED") and len(refusals) == 2


def test_claude_offline_notice_timeout_and_notification(monkeypatch):
    module = load_hook(*HOOKS[0])
    monkeypatch.setattr(module, "last_broker_failure", lambda: None)
    monkeypatch.setattr(module, "read_hook_health", lambda: None)
    probes = []
    monkeypatch.setattr(module, "probe_memory_server",
                        lambda *a: probes.append(1) or (False, "HookTransportError: response_timeout"))
    text = module.admission_offline_notice(unadmitted(admission_unattempted_streak=1))
    assert text.startswith("INTEGRITY ADMISSION NOT CALLED") and "response_timeout" in text
    assert "UNREACHABLE" not in text and probes == [1]
    # Notification turns, previous or current, get no notice and no probe.
    assert module.admission_offline_notice(unadmitted(admission_unattempted_streak=1), True) is None
    notified = unadmitted(admission_unattempted_streak=3, turn_kind=module.NOTIFICATION_TURN_KIND)
    assert module.admission_offline_notice(notified) is None and probes == [1]
    # A recent successful lifecycle call of the hook itself is evidence: no probe.
    monkeypatch.setattr(module, "read_hook_health", lambda: {
        "consecutive_failures": 0, "last_success_utc": guard._iso(guard.utc_now())})
    seen = module.admission_offline_notice(unadmitted(admission_unattempted_streak=1))
    assert seen.startswith("INTEGRITY ADMISSION SKIPPED") and probes == [1]


def test_claude_notification_tag_detection():
    module = load_hook(*HOOKS[0])
    assert module.HARNESS_PROMPT_TAG_RE.match("<system-reminder>x</system-reminder>\n<task-notification>\n")
    assert module.HARNESS_PROMPT_TAG_RE.match("[Cross-session idle notice] done")
    assert not module.HARNESS_PROMPT_TAG_RE.match("Please fix <task-notification> parsing")


# --- runtime and installer --------------------------------------------------

def test_runtime_linux_native_guard_only_advises():
    # Linux user custody marks the Native head completed before Stop: a block would
    # continue a turn whose ownership already ended, so Stop never blocks there.
    assert native_runtime.guard_environment({}, True) == {guard.ENV_MODE: "advise"}
    assert native_runtime.guard_environment({guard.ENV_MODE: "off"}, True) == {guard.ENV_MODE: "off"}
    assert native_runtime.guard_environment({}, False) == {}
    reason = guard.BLOCK_MARKER + ": close it"
    assert native_runtime.claude_terminal_output({"decision": "block", "reason": reason,
                                                  "systemMessage": "m"}) == {"continue": True, "systemMessage": "m"}


def test_installer_writes_block_policy_and_scope(tmp_path, capsys):
    from integrity_client_memory import native_install as install
    root = tmp_path / "codex"
    profile = install.build("codex", {"command": sys.executable},
                            {"seed_namespace": "fixture", "namespace_fingerprint": "sha256:" + "a" * 64,
                             "architecture_checkpoint_id": "checkpoint:fixture",
                             "codex_executable": sys.executable}, root)
    assert profile["turn_guard"] == {"policy_file": guard.POLICY_FILE, "mode": "block", "admission_first": "off"}
    assert guard.load_policy(root, {})["mode"] == "block"
    native_runtime.verify(root / "profile.json")
    scope = install.hook_scope("claude", tmp_path / "c")
    assert scope["scope"] == "project" and "~/.claude/settings.json" in scope["all_folders"]
    assert install.hook_scope("antigravity", tmp_path)["scope"].startswith("user")
    with pytest.raises(ValueError):
        install.build("codex", {"command": sys.executable},
                      {"seed_namespace": "f", "namespace_fingerprint": "sha256:" + "a" * 64,
                       "architecture_checkpoint_id": "c", "codex_executable": sys.executable,
                       "turn_guard": "always"}, tmp_path / "bad")


# --- doctor -----------------------------------------------------------------

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def hooks_doc(events, state_root="/x/integrity-memory/state"):
    command = f'python integrity-client-admission.py --event E --state-root "{state_root}" --transport "/x/t.json"'
    return {"hooks": {event: [{"hooks": [{"type": "command", "command": command}]}] for event in events}}


def test_doctor_flags_project_only_hooks(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "work" / "repo"
    monkeypatch.setenv("INTEGRITY_DOCTOR_HOME", str(home))
    write(project / ".claude/settings.json", hooks_doc(["UserPromptSubmit", "Stop"]))
    write(home / ".claude/settings.json", {"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": "other-tool"}]}]}})
    write(home / ".claude.json", {"mcpServers": {"integrity-mem": {}}, "projects": {}})
    rows = doctor.scan_hooks(project, home)
    assert [(r["vendor"], r["scope"].split(":")[0], r["stop_hook"]) for r in rows] == [("claude", "project", True)]
    assert rows[0]["refs"]["transport"] == ["/x/t.json"]
    args = doctor.argparse.Namespace(project=str(project), transport=[], state_root=[], last=10,
                                     no_probe=True, no_coverage=True, json=False)
    report = doctor.diagnose(args)
    assert any("project-scoped only" in item for item in report["findings"])
    assert report["mcp"] == [{"vendor": "claude", "scope": "user", "server": "integrity-mem"}]
    assert "not probed (--no-probe)" in doctor.render(report)


def test_doctor_user_scope_and_missing_stop(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "repo"
    project.mkdir()
    monkeypatch.setenv("INTEGRITY_DOCTOR_HOME", str(home))
    write(home / ".claude/settings.json", hooks_doc(["UserPromptSubmit"]))
    args = doctor.argparse.Namespace(project=str(project), transport=[], state_root=[str(tmp_path / "g")],
                                     last=10, no_probe=True, no_coverage=True, json=False)
    report = doctor.diagnose(args)
    assert not any("project-scoped" in item for item in report["findings"])
    assert any("no Integrity Stop hook" in item for item in report["findings"])


def test_doctor_probe_and_coverage(tmp_path):
    server = tmp_path / "server.py"
    server.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    m = json.loads(line)\n"
        "    if 'id' not in m: continue\n"
        "    if m['method'] == 'initialize': r = {'serverInfo': {'name': 'fake', 'version': '1'}}\n"
        "    elif m['method'] == 'tools/list': r = {'tools': [{'name': n} for n in ("
        "'integrity_context_admission_current_turn', 'integrity_turn_memory_close', "
        "'integrity_turn_memory_coverage')]}\n"
        "    else: r = {'content': [{'type': 'text', 'text': json.dumps({'complete': True, 'counts': "
        "{'registered': 10, 'terminal': 6, 'events': 2, 'no_event': 4, 'unresolved': 4}})}]}\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': r}), flush=True)\n",
        encoding="utf-8")
    write(tmp_path / "t.json", {"transport": {"type": "stdio", "command": sys.executable, "args": [str(server)]}})
    result = doctor.probe(doctor.transport_from(tmp_path / "t.json"), coverage_limit=10, timeout=20)
    assert result["answered"] and result["has_close"] and result["tool_count"] == 3
    assert result["coverage"]["close_rate"] == 0.6 and result["coverage"]["unresolved"] == 4
    dead = tmp_path / "dead.json"
    write(dead, {"transport": {"type": "stdio", "command": sys.executable, "args": ["-c", "pass"]}})
    failed = doctor.probe(doctor.transport_from(dead), coverage_limit=None, timeout=10)
    assert failed["answered"] is False and "closed" in failed["error"]


# --- live findings (06.11): interrupted turns, wording, log fields ----------

def test_interrupted_owner_turn_is_carried_into_a_notification_turn():
    live = {"turn_memory_status": "open", "turn_memory_lease": "live", "turn_kind": "owner",
            "turn_memory_registration_id": REG, "turn_guard_state_changed": True,
            "turn_guard_first_write_tool": "Write", "turn_guard_write_count": 2}
    carried = guard.interrupted_owner_turn(live)
    assert carried == {"registration_id": REG, "state_changed": True, "first_write_tool": "Write", "write_count": 2}
    for ended in ({**live, "turn_memory_lease": "expired"}, {**live, "turn_memory_status": "closed"},
                  {**live, "turn_memory_close_observed": True},
                  {**live, "turn_kind": guard.NOTIFICATION_TURN_KIND}):
        assert guard.interrupted_owner_turn(ended) is None
    provisional = guard.interrupted_owner_turn({**live, "turn_memory_status": "provisional"})
    assert provisional["registration_id"] is None and provisional["state_changed"] is True
    state = {"turn_kind": guard.NOTIFICATION_TURN_KIND, "turn_memory_generation": 2}
    assert guard.carry_interrupted(state, carried)
    assert guard.is_exempt(state) is None and state["turn_guard_state_changed"] is True
    decision = guard.stop_decision({**state, "turn_ref": "turnref:" + "x" * 43}, {}, BLOCK)
    assert decision["action"] == "block"
    guard.reset_turn(state)
    assert "turn_guard_interrupted_owner" not in state and guard.is_exempt(
        {**state, "turn_kind": guard.NOTIFICATION_TURN_KIND})


def test_after_block_wording_matches_what_is_recorded():
    state = {"turn_guard_state_changed": True, "turn_guard_first_write_tool": "Write",
             "turn_ref": "turnref:" + "x" * 43, "turn_memory_generation": 3}
    unregistered = guard.stop_decision(state, {"stop_hook_active": True}, BLOCK)
    assert "no registration exists" in unregistered["reason"] and "gap is recorded" not in unregistered["reason"]
    registered = guard.stop_decision({**state, "turn_memory_registration_id": REG, "turn_memory_status": "open"},
                                     {"stop_hook_active": True}, BLOCK)
    assert "records the coverage gap" in registered["reason"]
    nothing = guard.stop_decision({**state, "model_mcp_admission_attempted": True}, {}, BLOCK)
    assert nothing["why"] == "nothing-closable" and "gap stays recorded" not in nothing["reason"]


def test_turn_log_counts_blocks_and_no_event_after_change():
    state = {"turn_guard_state_changed": True, "turn_memory_registration_id": REG}
    guard.note_close(state, "integrity_turn_memory_close", receipt_response())
    assert state["turn_memory_close_outcome"] == "no-event"
    guard.mark_blocked(state)
    row = guard.turn_record(state, {"action": "advise", "why": "stop-hook-active"}, vendor="hook")
    assert row["blocked_once"] is True and row["close_outcome"] == "no-event"
    summary = guard.summarize_turns([row, {"state_changed": False, "decision": "none"}])
    assert summary["blocked"] == 1 and summary["no_event_after_change"] == 1


def test_claude_prompt_records_gap_for_interrupted_registration(monkeypatch):
    module = load_hook(*HOOKS[0])
    calls = []
    monkeypatch.setattr(module, "lifecycle_call",
                        lambda name, arguments: calls.append((name, arguments)) or {"receipt": {"receipt_id": "sha256:g"}})
    text = module.record_interrupted_gap({"registration_id": REG})
    assert calls == [("integrity_turn_memory_gap", {"registration_id": REG, "stage": "reconciliation"})]
    assert "TURN MEMORY INTERRUPTED" in text and "sha256:g" in text
    assert module.record_interrupted_gap({"registration_id": None}) is None and len(calls) == 1

    def fail(name, arguments):
        raise module.HookError("x")

    monkeypatch.setattr(module, "lifecycle_call", fail)
    assert "failed" in module.record_interrupted_gap({"registration_id": REG})


# --- admission-first gate ---------------------------------------------------

def owner_before_admission(**extra):
    state = {"turn_kind": "owner", "prompt_kind": "text", "turn_ref": "turnref:" + "a" * 43,
             "turn_memory_generation": 4}
    state.update(extra)
    return state


def test_gate_is_off_by_default_and_reads_the_flag(tmp_path, monkeypatch):
    monkeypatch.delenv(guard.ENV_GATE, raising=False)
    monkeypatch.delenv(guard.ENV_POLICY, raising=False)
    assert guard.load_gate_policy(tmp_path)["mode"] == "off"
    (tmp_path / guard.POLICY_FILE).write_text(json.dumps({"enforce_turn_close": "block", "admission_first": "block"}))
    assert guard.load_gate_policy(tmp_path)["mode"] == "block"
    monkeypatch.setenv(guard.ENV_GATE, "off")
    assert guard.load_gate_policy(tmp_path)["mode"] == "off"


def test_gate_denies_with_the_exact_call_and_turn_ref():
    state = owner_before_admission()
    message = guard.admission_gate(state, "Grep", BLOCK)
    assert message.startswith(guard.GATE_MARKER)
    assert "integrity_context_admission_current_turn" in message and state["turn_ref"] in message


@pytest.mark.parametrize("tool", ["ToolSearch", "mcp__integrity-memory__integrity_context_admission_current_turn"])
def test_gate_lets_the_admission_path_through(tool):
    assert guard.admission_gate(owner_before_admission(), tool, BLOCK) is None


@pytest.mark.parametrize("state, failure", [
    (owner_before_admission(model_mcp_admission_attempted=True), None),   # admission tried, even if it failed
    (owner_before_admission(turn_kind=guard.NOTIFICATION_TURN_KIND), None),  # notification / peer turn
    (owner_before_admission(prompt_kind="subagent"), None),
    (owner_before_admission(turn_ref=None), None),                       # no armed envelope: fail-open
    (owner_before_admission(), "at 2026-11-06: broker start failed"),     # broker down: fail-open
    (owner_before_admission(mcp_probe_ok=False), None),                  # probe refused: fail-open
    (owner_before_admission(admission_gate_denials=guard.GATE_MAX_DENIALS), None),
])
def test_gate_opens(state, failure):
    assert guard.admission_gate(state, "Bash", BLOCK, broker_failure=failure) is None


def test_gate_off_mode_never_denies():
    assert guard.admission_gate(owner_before_admission(), "Bash", {"mode": "off"}) is None


def test_gate_denial_counter_resets_with_the_turn():
    state = owner_before_admission()
    guard.note_gate_denial(state)
    guard.note_gate_denial(state)
    assert guard.admission_gate(state, "Bash", BLOCK) is None
    guard.reset_turn(state)
    assert "admission_gate_denials" not in state


def test_hook_gate_blocks_then_admission_unlocks(hook, capsys):
    module = hook
    module.guard_dir.mkdir(parents=True, exist_ok=True)
    (module.guard_dir / guard.POLICY_FILE).write_text(json.dumps({"admission_first": "block"}))
    module.save_state("session-1", owner_before_admission())
    state = module.load_state("session-1")
    with pytest.raises(SystemExit) as stopped:
        module.handle_pre_tool({"tool_name": "Read", "tool_input": {"file_path": "x"}}, "session-1", state)
    assert stopped.value.code == 2
    err = capsys.readouterr().err
    assert err.startswith(guard.GATE_MARKER) and "turnref:" in err
    state = module.load_state("session-1")
    assert state["admission_gate_denials"] == 1
    module.handle_pre_tool({"tool_name": "ToolSearch", "tool_input": {"query": "select:x"}}, "session-1", state)
    state = module.load_state("session-1")
    state["model_mcp_admission_attempted"] = True
    module.save_state("session-1", state)
    module.handle_pre_tool({"tool_name": "Read", "tool_input": {"file_path": "x"}}, "session-1", state)


def test_hook_gate_ignores_notification_turns(hook):
    module = hook
    module.guard_dir.mkdir(parents=True, exist_ok=True)
    (module.guard_dir / guard.POLICY_FILE).write_text(json.dumps({"admission_first": "block"}))
    module.save_state("session-1", owner_before_admission(turn_kind=guard.NOTIFICATION_TURN_KIND))
    state = module.load_state("session-1")
    module.handle_pre_tool({"tool_name": "Bash", "tool_input": {"command": "ls"}}, "session-1", state)


def test_gate_treats_an_interrupted_owner_continuation_as_owner():
    state = owner_before_admission(turn_kind=guard.NOTIFICATION_TURN_KIND, turn_guard_interrupted_owner=True)
    assert guard.admission_gate(state, "Bash", BLOCK).startswith(guard.GATE_MARKER)
