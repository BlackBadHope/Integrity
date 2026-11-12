"""Stand tests for the lock guard with the invented host table under examples/.

Nothing connects anywhere: commands are only parsed and classified.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import integrity_guards
from integrity_guards import lock_guard as lg

COMPONENT = Path(__file__).resolve().parents[1]
HOSTS_FILE = COMPONENT / "examples" / "hosts.example.json"
HOSTS = lg.load_hosts(HOSTS_FILE)
SRC = str(Path(integrity_guards.__file__).resolve().parents[1])
NOW = dt.datetime(2030, 1, 1, 12, 0, tzinfo=dt.timezone.utc)
LATER = "2030-01-01T13:00:00+00:00"
EARLIER = "2030-01-01T11:00:00+00:00"

WRITE = 'ssh node-a "systemctl restart example-app"'
READ = 'ssh node-a "systemctl status example-app"'


def lock(session, hosts, expires=LATER, **extra):
    return {"lock_id": f"L-{session}", "owner_session_id": session, "target_hosts": hosts,
            "status": "active", "expires_utc": expires, **extra}


def decide(command, state=None, mode="enforce", tool="Bash", session="s1"):
    return lg.decide(tool, {"command": command}, session, state, HOSTS, mode, now=NOW)


class TestHostTable:
    def test_aliases_ips_and_vmids(self):
        assert HOSTS["192.0.2.10"] == "node-a"
        assert HOSTS["node-b.example.invalid"] == "node-b"
        assert HOSTS["vmid:101"] == "node-b"
        assert not any(k.startswith("vmid:_") for k in HOSTS)

    def test_unconfigured_table_raises(self, monkeypatch):
        monkeypatch.setattr(lg, "DEFAULT_HOSTS", None)
        with pytest.raises(FileNotFoundError):
            lg.load_hosts()


class TestDecide:
    def test_reads_and_local_allowed(self):
        assert decide(READ)["decision"] == "allow"
        assert decide("rm -rf build")["decision"] == "allow"
        assert decide("cat /etc/hosts", tool="Read")["reason"] == "not-a-shell-action"
        assert decide('ssh localhost "rm -rf /tmp/x"')["decision"] == "allow"

    def test_write_without_state_denied_in_enforce(self):
        result = decide(WRITE)
        assert result["decision"] == "deny" and result["hosts"] == ["node-a"]
        assert result["reason"].startswith("lock-state-unknown")

    def test_write_by_ip_maps_to_canonical(self):
        assert decide('ssh 192.0.2.10 "rm -f /opt/example-app/x"')["hosts"] == ["node-a"]

    def test_own_lock_allows(self):
        state = {"locks": [lock("s1", ["node-a"])]}
        assert decide(WRITE, state)["reason"] == "own-lock-covers-targets"

    def test_expired_own_lock_does_not_cover(self):
        state = {"locks": [lock("s1", ["node-a"], expires=EARLIER)]}
        assert decide(WRITE, state)["reason"].startswith("no-own-lock")

    def test_released_lock_ignored(self):
        state = {"locks": [lock("s2", ["node-a"], status="released")]}
        assert decide(WRITE, state)["reason"].startswith("no-own-lock")

    def test_foreign_lock_denies_even_with_own(self):
        state = {"locks": [lock("s1", ["node-a"]), lock("s2", ["node-a"], owner_actor="agent-b", reason="upgrade")]}
        result = decide(WRITE, state)
        assert result["decision"] == "deny" and result["reason"].startswith("host-locked: node-a")
        assert "agent-b" in result["reason"]

    def test_foreign_lock_on_other_host_irrelevant(self):
        state = {"locks": [lock("s1", ["node-a"]), lock("s2", ["node-b"])]}
        assert decide(WRITE, state)["decision"] == "allow"

    def test_unknown_host(self):
        result = decide('ssh unlisted-box "reboot"')
        assert result["decision"] == "deny" and result["reason"].startswith("unknown-host")

    def test_opaque_transport(self):
        result = decide('GIT_SSH_COMMAND="sh -c x" git fetch')
        assert result["decision"] == "deny"
        assert result["reason"].startswith("opaque-ssh-transport")

    def test_proxy_command_counts_as_change_on_target(self):
        result = decide('ssh -o ProxyCommand="sh -c x" node-a uptime', {"locks": []})
        assert result["decision"] == "deny" and result["hosts"] == ["node-a"]

    def test_shadow_silent_without_server_locks(self, monkeypatch):
        monkeypatch.setattr(lg, "SERVER_LOCK_KIND", False)
        assert decide(WRITE, mode="shadow")["reason"] == "own-lock-unavailable-shadow"
        state = {"locks": [lock("s2", ["node-a"])]}
        assert decide(WRITE, state, mode="shadow")["decision"] == "warn"

    def test_shadow_warns_once_server_accepts_locks(self, monkeypatch):
        monkeypatch.setattr(lg, "SERVER_LOCK_KIND", True)
        assert decide(WRITE, mode="shadow")["decision"] == "warn"

    def test_interactive_session_only_warns(self):
        assert decide("ssh node-a")["decision"] in ("warn", "allow")


class TestRecord:
    def test_admission_snapshot_and_own_receipt(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lg, "STATE_DIR", tmp_path)
        snapshot = {"active_locks": [lock("s2", ["node-b"])]}
        lg.record({"tool_name": "mcp__integrity__integrity_context_admission", "session_id": "s1",
                   "tool_response": json.dumps(snapshot)})
        lg.record({"tool_name": "mcp__integrity__integrity_append_event", "session_id": "s1",
                   "tool_input": {"details": {"lock_action": "acquire", "lock_id": "own-1",
                                              "target_hosts": ["node-a"], "ttl_minutes": 30}}})
        state = lg.load_state("s1")
        owners = sorted(x["owner_session_id"] for x in state["locks"])
        assert owners == ["s1", "s2"]
        assert lg.decide("Bash", {"command": WRITE}, "s1", state, HOSTS, "enforce")["decision"] == "allow"
        lg.record({"tool_name": "mcp__integrity__integrity_append_event", "session_id": "s1",
                   "tool_input": {"details": {"lock_action": "release", "lock_id": "own-1"}}})
        assert [x["owner_session_id"] for x in lg.load_state("s1")["locks"]] == ["s2"]

    def test_non_integrity_tool_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(lg, "STATE_DIR", tmp_path)
        lg.record({"tool_name": "Bash", "session_id": "s1", "tool_response": "{}"})
        assert lg.load_state("s1") is None


def run_main(payload, *args, **env):
    full = dict(os.environ)
    full["PYTHONPATH"] = SRC + os.pathsep + full.get("PYTHONPATH", "")
    full.update(env)
    return subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "lock-guard", *args],
                          input=json.dumps(payload), capture_output=True, text=True, env=full, timeout=30)


class TestMain:
    def test_enforce_exit_code_and_hook_json(self, tmp_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": WRITE}, "session_id": "s1"}
        p = run_main(payload, "--enforce", "--exit-code", INTEGRITY_LOCK_GUARD_HOSTS=str(HOSTS_FILE),
                     INTEGRITY_LOCK_GUARD_STATE=str(tmp_path), INTEGRITY_GUARDS_CONFIG=str(tmp_path / "none.json"))
        assert p.returncode == 2
        out = json.loads(p.stdout)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "lock-state-unknown" in p.stderr

    def test_without_host_table_every_remote_host_is_unknown(self, tmp_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": WRITE}, "session_id": "s1"}
        p = run_main(payload, "--enforce", INTEGRITY_GUARDS_CONFIG=str(tmp_path / "none.json"),
                     INTEGRITY_LOCK_GUARD_STATE=str(tmp_path))
        env_hosts = os.environ.get("INTEGRITY_LOCK_GUARD_HOSTS")
        if env_hosts:
            pytest.skip("INTEGRITY_LOCK_GUARD_HOSTS is set in the test environment")
        assert p.returncode == 0
        assert "unknown-host" in json.loads(p.stdout)["hookSpecificOutput"]["permissionDecisionReason"]

    def test_read_prints_empty_object(self, tmp_path):
        payload = {"tool_name": "Bash", "tool_input": {"command": READ}, "session_id": "s1"}
        p = run_main(payload, "--enforce", INTEGRITY_LOCK_GUARD_HOSTS=str(HOSTS_FILE),
                     INTEGRITY_LOCK_GUARD_STATE=str(tmp_path))
        assert (p.returncode, json.loads(p.stdout)) == (0, {})
