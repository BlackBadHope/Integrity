"""Stand tests for the Uroboros repeat hook (PreToolUse advisory + metric) and the route-share metric.

Every host, route and pinned file here is invented; the configuration is written per test.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import integrity_guards

SRC = str(Path(integrity_guards.__file__).resolve().parents[1])
SSH = "ssh -o BatchMode=yes -o ConnectTimeout=8 -J ops-node "
NODE_A = SSH + "operator@192.0.2.10 "
NODE_B = SSH + "operator@192.0.2.20 "
STATUS = NODE_A + "'systemctl show example-app -p ActiveState'"
PINNED = "/usr/local/sbin/example-apply-egress.sh"
ROUTE = {
    "format": "uroboros-compiled-route/v1", "route_id": "node-a-app-status", "version": 1, "safety": "read",
    "summary": "invented read route", "params": {},
    "steps": [{"name": "state", "argv": ["ssh", "operator@192.0.2.10", "systemctl show example-app -p ActiveState"]}],
}


def setup(tmp_path, pins=False):
    routes = tmp_path / "routes"
    routes.mkdir(exist_ok=True)
    (routes / "node-a-app-status.json").write_text(json.dumps(ROUTE), encoding="utf-8")
    uroboros = {"hosts": {"192.0.2.10": "node-a", "192.0.2.20": "node-b"}, "aliases": ["ops-node"],
                "ignore_words": ["operator"], "compiled_routes": str(routes), "state_dir": str(tmp_path / "state")}
    if pins:
        pins_file = tmp_path / "pins.json"
        pins_file.write_text(json.dumps({"authority": "a" * 64,
                                         "paths": [PINNED, "/etc/example-app/owner", "/opt/example-app/x/a.py"]}),
                             encoding="utf-8")
        uroboros["pin_guard"] = {"host": "node-b", "pins_file": str(pins_file), "prefixes": ["/etc/example-app/"],
                                 "label": "example release files", "pre_check_route": "example-pin-check",
                                 "post_check_route": "example-sync-health"}
    cfg = tmp_path / "guards.json"
    cfg.write_text(json.dumps({"uroboros": uroboros}), encoding="utf-8")
    return cfg


def env_for(cfg) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("INTEGRITY_", "UROBOROS_"))}
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env["INTEGRITY_GUARDS_CONFIG"] = str(cfg)
    return env


def call(cfg, payload, *args, raw=None):
    p = subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "uroboros-repeat-hook", *args],
                       input=raw if raw is not None else json.dumps(payload), capture_output=True, text=True,
                       encoding="utf-8", env=env_for(cfg), timeout=30)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout) if p.stdout.strip() else None


def run(tmp_path, cmd, session="s1", tool="Bash", pins=False, cwd=""):
    cfg = setup(tmp_path, pins=pins)
    payload = {"tool_name": tool, "session_id": session, "hook_event_name": "PreToolUse", "cwd": cwd,
               "tool_input": {"command": cmd}}
    out = call(cfg, payload)
    return out["hookSpecificOutput"]["additionalContext"] if out else None


def metric_rows(tmp_path):
    files = list((tmp_path / "state" / "metrics").glob("*.jsonl"))
    return [json.loads(line) for f in files for line in f.read_text(encoding="utf-8").splitlines()]


def test_known_route_gets_hint_with_route_id(tmp_path):
    text = run(tmp_path, STATUS)
    assert text and "integrity-guards uroboros run node-a-app-status" in text and "blocks nothing" in text


def test_second_unrouted_repeat_demands_route_this_turn(tmp_path):
    cmd = NODE_A + "'sudo -n cat /etc/example-app/agent.env | grep -c KEY'"
    assert run(tmp_path, cmd) is None
    text = run(tmp_path, cmd.replace("grep -c KEY", "grep -c OTHER"))  # same thing, different glue
    assert text and text.startswith("UROBOROS REQUIRED") and "THIS turn" in text and "not blocked" in text
    assert (tmp_path / "state" / "candidates.jsonl").exists()


def test_repeat_is_per_session(tmp_path):
    cmd = NODE_A + "'sudo -n cat /etc/example-app/agent.env'"
    assert run(tmp_path, cmd, session="a") is None
    assert run(tmp_path, cmd, session="b") is None


def test_route_run_is_counted_as_via_route_and_silent(tmp_path):
    assert run(tmp_path, "bash scripts/uroboros-run.sh node-a-app-status") is None
    rows = metric_rows(tmp_path)
    assert rows and rows[-1]["kind"] == "route" and rows[-1]["route"] == "node-a-app-status"


def test_write_chain_repeat_is_plan_only(tmp_path):
    cmd = NODE_B + "'sudo -n systemctl restart example-sync.service'"
    first = run(tmp_path, cmd)
    assert first is None or "uroboros run" not in first  # never points a write at a read route
    text = run(tmp_path, cmd)
    assert text and "write" in text and "operator GO" in text


def test_local_commands_and_other_tools_are_ignored(tmp_path):
    assert run(tmp_path, "git status") is None
    assert run(tmp_path, SSH + "node-a uptime", tool="Read") is None
    assert metric_rows(tmp_path) == []


def test_raw_call_is_logged_for_the_metric(tmp_path):
    run(tmp_path, STATUS)
    rows = metric_rows(tmp_path)
    assert rows[-1]["kind"] == "raw" and rows[-1]["host"] == "node-a" and rows[-1]["route"] == "node-a-app-status"


def test_unconfigured_hook_uses_unknown_host(tmp_path):
    cfg = tmp_path / "empty.json"
    cfg.write_text(json.dumps({"uroboros": {"state_dir": str(tmp_path / "state")}}), encoding="utf-8")
    payload = {"tool_name": "Bash", "session_id": "u", "hook_event_name": "PreToolUse",
               "tool_input": {"command": NODE_A + "'systemctl status example-app'"}}
    assert call(cfg, payload) is None
    text = call(cfg, payload)["hookSpecificOutput"]["additionalContext"]
    assert text.startswith("UROBOROS REQUIRED: the same ? chain")


def test_codex_shell_list_command_gets_the_same_hint(tmp_path):
    payload = {"tool_name": "shell", "session_id": "c1", "hook_event_name": "PreToolUse",
               "tool_input": {"command": ["bash", "-lc", STATUS]}}
    out = call(setup(tmp_path), payload, "--vendor", "codex")
    assert "node-a-app-status" in out["hookSpecificOutput"]["additionalContext"]
    assert "permissionDecision" not in json.dumps(out)
    assert metric_rows(tmp_path)[-1]["vendor"] == "codex"


def test_codex_exec_command_cmd_field(tmp_path):
    payload = {"tool_name": "exec_command", "session_id": "c2", "hook_event_name": "PreToolUse",
               "tool_input": {"cmd": STATUS}}
    out = call(setup(tmp_path), payload, "--vendor", "codex")
    assert "node-a-app-status" in out["hookSpecificOutput"]["additionalContext"]


def test_antigravity_gets_explicit_allow_only(tmp_path):
    # The ported hook keeps the current behaviour: Antigravity gets only {"decision": "allow"};
    # the advisory text is not delivered to it, but the call is still counted.
    payload = {"conversationId": "a1", "toolCall": {"name": "run_command", "args": {"CommandLine": STATUS}}}
    assert call(setup(tmp_path), payload, "--vendor", "antigravity") == {"decision": "allow"}
    assert metric_rows(tmp_path)[-1]["vendor"] == "antigravity"


def test_antigravity_other_tool_and_broken_input_get_explicit_allow(tmp_path):
    cfg = setup(tmp_path)
    assert call(cfg, {"toolCall": {"name": "view_file", "args": {}}}, "--vendor", "antigravity") == {"decision": "allow"}
    assert call(cfg, None, "--vendor", "antigravity", raw="{nope") == {"decision": "allow"}


def test_pin_guard_warns_on_write_to_pinned_file(tmp_path):
    text = run(tmp_path, NODE_B + f"'sudo -n sed -i s/a/b/ {PINNED}'", pins=True)
    assert text and text.startswith("PIN GUARD (node-b)") and PINNED in text
    assert "example-pin-check" in text and "example-sync-health" in text and "nothing is blocked" in text


def test_pin_guard_silent_on_read_of_pinned_file(tmp_path):
    # the basename itself contains "apply": a read must not count as a write
    text = run(tmp_path, NODE_B + f"'sudo -n sha256sum {PINNED}; grep -c accept {PINNED}'", pins=True)
    assert text is None or "PIN GUARD" not in text


def test_pin_guard_reads_local_script_fed_to_remote_shell(tmp_path):
    (tmp_path / "apply.sh").write_text(f"S={PINNED}\ncp -a \"$S\" \"$S.bak\"\n", encoding="utf-8")
    text = run(tmp_path, NODE_B + "'sudo bash -s' < apply.sh", pins=True, cwd=str(tmp_path))
    assert text and "PIN GUARD" in text and PINNED in text


def test_pin_guard_prefix_and_other_hosts(tmp_path):
    text = run(tmp_path, NODE_B + "'sudo -n install -m0644 x /etc/example-app/sync.json'", pins=True)
    assert text and "/etc/example-app/*" in text
    other = run(tmp_path, NODE_A + f"'sudo -n sed -i s/a/b/ {PINNED}'", pins=True)
    assert other is None or "PIN GUARD" not in other


def test_malformed_input_never_breaks_the_tool_call(tmp_path):
    assert call(setup(tmp_path), None, raw="{not json") is None


def test_replay_counts_repeats(tmp_path, capsys):
    cfg = setup(tmp_path)
    calls = tmp_path / "calls.json"
    calls.write_text(json.dumps([{"session": "r", "ts": i, "cmd": STATUS} for i in range(3)]
                                + [{"session": "r", "ts": 9, "cmd": "git status"}]), encoding="utf-8")
    p = subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "uroboros-repeat-hook", "replay", str(calls)],
                       capture_output=True, text=True, env=env_for(cfg), timeout=30)
    stats = json.loads(p.stdout)
    assert (stats["calls"], stats["remote"], stats["advice"], stats["route"]) == (4, 3, 1, 1)
    assert stats["by_route"] == {"node-a-app-status": 1}


def test_route_share_from_hook_metrics(tmp_path):
    cfg = setup(tmp_path)
    run(tmp_path, STATUS)
    run(tmp_path, "bash scripts/uroboros-run.sh node-a-app-status")
    day = time.strftime("%Y-%m-%d")  # the hook names its metric file by local date
    p = subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "uroboros-share", "hook", day],
                       capture_output=True, text=True, env=env_for(cfg), timeout=30)
    rows = {r["day"]: r for r in map(json.loads, p.stdout.splitlines())}
    assert rows[day]["prod_calls"] == 2 and rows[day]["via_route"] == 1 and rows[day]["share_pct"] == 50.0
    assert rows[f"{day} claude"]["top_unrouted_hosts"] == [["node-a", 1]]


def test_route_share_from_transcripts(tmp_path):
    projects = tmp_path / "projects" / "p"
    projects.mkdir(parents=True)
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    lines = [{"type": "assistant", "timestamp": now, "message": {"content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": c}}]}}
        for c in (STATUS, "integrity-guards uroboros run node-a-app-status", "ssh elsewhere uptime", "git status")]
    (projects / "t.jsonl").write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    cfg = setup(tmp_path)
    data = json.loads(cfg.read_text(encoding="utf-8"))
    data["uroboros"]["transcripts_dir"] = str(tmp_path / "projects")
    cfg.write_text(json.dumps(data), encoding="utf-8")
    p = subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "uroboros-share", "transcripts", "1"],
                       capture_output=True, text=True, env=env_for(cfg), timeout=30)
    (row,) = [json.loads(x) for x in p.stdout.splitlines()]
    assert (row["prod_calls"], row["via_route"]) == (2, 1)
