"""Stand tests for the rule guard, its Antigravity adapter, the installer, rule libraries and drift check.

No network. The device registry is the invented example under examples/; every
machine-specific value comes from a temporary guards configuration.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import integrity_guards
from integrity_guards import install, rule_guard as g, rule_libs as r, rules_drift_check

COMPONENT = Path(__file__).resolve().parents[1]
REGISTRY_FILE = COMPONENT / "examples" / "device-registry.example.json"
REG = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
SRC = str(Path(integrity_guards.__file__).resolve().parents[1])

CONFIG = {
    "rule_guard": {
        "device_registry": str(REGISTRY_FILE),
        "device_tool_patterns": ["switch-runner(?:\\.py)?"],
        "device_address_patterns": ["198\\.51\\.100\\.\\d{1,3}"],
        "exempt_command_patterns": ["\\bwave-runner\\.py\\b[^\\n;|&]*\\b(apply|rollback|save)\\b"],
        "protected_secret_paths": ["vault[\\\\/][^\\s\"'|;&]*\\.md\\b", "vault[\\\\/][^\\s\"'|;&]*\\.bak\\b"],
        "secret_tool": "vault_get.py",
        "sql_write_targets": ["\\bbilling-db\\b"],
        "sql_write_marker": "db-write-go:",
        "browser_js_warning": "no JavaScript on admin.example.invalid",
    }
}


@pytest.fixture(autouse=True)
def guards_config(tmp_path, monkeypatch):
    path = tmp_path / "guards.json"
    path.write_text(json.dumps(CONFIG), encoding="utf-8")
    monkeypatch.setenv("INTEGRITY_GUARDS_CONFIG", str(path))
    monkeypatch.delenv(g.ENV_MODE, raising=False)
    monkeypatch.delenv(g.ENV_REGISTRY, raising=False)
    return path


def child_env(**extra: str) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.update(extra)
    return env


def run_hook(cmd, mode="warn", tool="Bash", *args, **env):
    p = subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "rule-guard", "hook", *args],
                       input=json.dumps({"tool_name": tool, "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, env=child_env(INTEGRITY_RULE_GUARD_MODE=mode, **env),
                       timeout=30)
    return p.returncode, (json.loads(p.stdout) if p.stdout.strip() else None)


WRITE_TO_DEVICE = "plink -ssh 198.51.100.11 \"config ports 2 state disable\""


class TestRegistry:
    def test_profile_requires_its_exact_syntax(self):
        assert g.validate_lines(REG, "vendor-a-access", ["config ports 5 state disable"])
        assert g.validate_lines(REG, "vendor-a-access", ["config ports 5 medium_type copper state disable"]) == []

    def test_port_above_max_refused(self):
        p = g.validate_lines(REG, "vendor-a-access", ["config ports 26 medium_type copper state disable"])
        assert any("max_port" in x for x in p)

    def test_read_only_profile_refuses_write(self):
        assert g.validate_lines(REG, "vendor-d-readonly", ["config ports 1 state disable"])

    def test_unknown_profile(self):
        assert g.validate_lines(REG, "vendor-x", ["show ports 1"])

    def test_unverified_wave_command_flagged(self):
        reg = copy.deepcopy(REG)
        reg["wave"]["vendor-b-core"]["tc_set"]["status"] = "unverified"
        line = reg["wave"]["vendor-b-core"]["tc_set"]["cmd"].replace("{port}", "7").replace("{bc}", "500")
        p = g.validate_lines(reg, "vendor-b-core", [line])
        assert any("not live-verified" in x for x in p), p

    def test_max_port_not_applied_to_wave_keys(self):
        tpl = REG["wave"]["vendor-b-core"]["tc_read"]["cmd"]
        p = g.validate_lines(REG, "vendor-b-core", [tpl.replace("{ports}", "24")])
        assert not any("max_port" in x for x in p), p

    def test_untested_profile_write_unverified(self):
        p = g.validate_lines(REG, "vendor-c-untested", ["interface ethernet 5"])
        assert any("not live-verified" in x for x in p), p

    def test_validate_cli(self, capsys):
        assert g.main(["rule-guard", "validate", "--profile", "vendor-a-access",
                       "--line", "config ports 5 medium_type copper state disable"]) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True


class TestSwitchHook:
    def test_no_profile_declared_warns(self):
        rc, out = run_hook(WRITE_TO_DEVICE)
        assert rc == 0
        assert "R-SWITCH" in out["systemMessage"]
        assert "permissionDecision" not in out["hookSpecificOutput"]

    def test_enforce_denies(self):
        _, out = run_hook(WRITE_TO_DEVICE, mode="enforce")
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_registry_command_passes(self):
        cmd = ("python switch-runner.py 198.51.100.13 # registry-profile: vendor-a-access\n"
               "'config ports 5 medium_type copper state disable'")
        assert run_hook(cmd, mode="enforce")[1] is None

    def test_ignores_non_device_and_reads(self):
        assert run_hook("git config --list", mode="enforce")[1] is None
        assert run_hook("ssh ops-node 'show ports 5'", mode="enforce")[1] is None
        assert run_hook("dir", tool="Read", mode="enforce")[1] is None

    def test_exempt_runner_is_registry_path_but_only_its_segment(self):
        assert g.check_switch("ssh ops-node 'cd ~/w && python3 -B wave-runner.py r plan.json 3 apply'") == []
        assert g.check_switch("python3 wave-runner.py r p 1 apply; plink 198.51.100.11 'config ports 2 state disable'")

    def test_configured_tool_and_address_are_device_evidence(self):
        assert g.check_switch("switch-runner 'config ports 6 state disable'")
        assert g.check_switch("python3 x.py 198.51.100.40 'config ports 6 state disable'")
        assert g.check_switch("python3 x.py 'config ports 6 state disable'") == []

    def test_warn_only_flag_never_denies(self):
        _, out = run_hook(WRITE_TO_DEVICE, "enforce", "Bash", "--warn-only")
        assert "permissionDecision" not in out["hookSpecificOutput"]
        assert "R-SWITCH" in out["systemMessage"]

    def test_missing_registry_fails_open_silently(self, tmp_path):
        cmd = "plink 198.51.100.11 'config ports 2 state disable' # registry-profile: vendor-a-access"
        rc, out = run_hook(cmd, mode="enforce", INTEGRITY_RULE_GUARD_REGISTRY=str(tmp_path / "missing.json"))
        assert (rc, out) == (0, None)

    def test_linux_shutdown_not_flagged(self):
        assert g.check_switch('ssh ops-node "shutdown -r now"') == []

    def test_off_mode(self):
        assert run_hook(WRITE_TO_DEVICE, mode="off")[1] is None

    def test_mode_from_configuration(self, tmp_path, monkeypatch):
        cfg = dict(CONFIG, rule_guard=dict(CONFIG["rule_guard"], mode="enforce"))
        path = tmp_path / "enforce.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        monkeypatch.setenv("INTEGRITY_GUARDS_CONFIG", str(path))
        assert g.mode() == "enforce"


class TestLineEndings:
    def test_crlf_upload_flagged_lf_passes(self, tmp_path):
        bad, ok = tmp_path / "x.pl", tmp_path / "y.pl"
        bad.write_bytes(b"#!/usr/bin/perl\r\nprint 1;\r\n")
        ok.write_bytes(b"#!/usr/bin/perl\nprint 1;\n")
        assert g.check_lf(f"scp {bad.as_posix()} host:/var/www/x.pl")
        assert g.check_lf(f"scp {ok.as_posix()} host:/var/www/y.pl") == []
        _, out = run_hook(f"pscp {bad.as_posix()} root@vm:/tmp/x.pl", mode="enforce")
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "R-LF" in out["hookSpecificOutput"]["permissionDecisionReason"]

    def test_native_path_crlf_flagged(self, tmp_path):
        bad = tmp_path / "x.pl"
        bad.write_bytes(b"a\r\nb\r\n")
        assert g.check_lf(f"scp {bad} host:/tmp/x.pl")
        assert g.check_lf(f'pscp "{bad}" root@vm:/tmp/x.pl')

    def test_bad_stdin_never_breaks(self):
        p = subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "rule-guard", "hook"],
                           input="not json", capture_output=True, text=True, env=child_env(), timeout=30)
        assert (p.returncode, p.stdout) == (0, "")


class TestSecretSqlBrowser:
    def test_secret_read_flagged_tool_ok(self):
        assert g.evaluate({"tool_name": "Bash", "tool_input": {"command": r"cat C:\work\vault\switches.md"}})
        assert g.evaluate({"tool_name": "Read", "tool_input": {"file_path": r"C:\work\vault\old.bak"}})
        assert g.evaluate({"tool_name": "Bash", "tool_input": {"command": r"python C:\work\tools\vault_get.py sw"}}) == []
        assert g.evaluate({"tool_name": "Read", "tool_input": {"file_path": r"C:\work\docs\README.md"}}) == []

    def test_secret_rule_inactive_without_configuration(self, tmp_path, monkeypatch):
        monkeypatch.setenv("INTEGRITY_GUARDS_CONFIG", str(tmp_path / "absent.json"))
        assert g.evaluate({"tool_name": "Read", "tool_input": {"file_path": r"C:\work\vault\old.bak"}}) == []
        assert g.check_sql("ssh billing-db \"mysql -e 'DELETE FROM t'\"") == []
        assert g.check_browser("mcp__browser__javascript_tool", {}) == []

    def test_sql_rollback_and_marker(self):
        dry = "ssh billing-db \"mysql -e 'BEGIN; DELETE FROM users WHERE id=1; ROLLBACK;'\""
        assert "ROLLBACK" in g.evaluate({"tool_name": "Bash", "tool_input": {"command": dry}})[0]
        nomark = "ssh billing-db \"mysql -e 'UPDATE users SET plan=1 WHERE id=2'\""
        assert g.evaluate({"tool_name": "Bash", "tool_input": {"command": nomark}})
        assert g.evaluate({"tool_name": "Bash", "tool_input": {"command": nomark + " # db-write-go: REF-1"}}) == []
        read = "ssh billing-db \"mysql -e 'SELECT COUNT(*) FROM users'\""
        assert g.evaluate({"tool_name": "Bash", "tool_input": {"command": read}}) == []
        other = "ssh other-db \"mysql -e 'DELETE FROM users'\""
        assert g.evaluate({"tool_name": "Bash", "tool_input": {"command": other}}) == []

    def test_browser_js_warns(self):
        assert g.evaluate({"tool_name": "mcp__browser__javascript_tool", "tool_input": {"text": "1"}})
        assert g.evaluate({"tool_name": "mcp__browser__navigate", "tool_input": {"url": "x"}}) == []


class TestAntigravityAdapter:
    def run(self, payload_text):
        p = subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "rule-guard-antigravity"],
                           input=payload_text, capture_output=True, text=True, env=child_env(), timeout=30)
        return json.loads(p.stdout)

    def test_always_allows(self):
        ok = self.run(json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}}}))
        assert ok == {"decision": "allow"}
        cmd = "plink 198.51.100.13 'config ports 6 state disable'"
        warn = self.run(json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}}))
        assert warn["decision"] == "allow"
        assert "R-SWITCH" in warn["reason"]
        assert self.run("garbage") == {"decision": "allow"}


class TestRuleLibs:
    def test_billing_and_unbind(self):
        normal = {"prepaid_tariffs": [100], "parked_ip_prefixes": ["203.0.113."]}
        assert not r.billing_card_is_anomaly({"paket": 100, "balance": 50}, **normal)
        assert not r.billing_card_is_anomaly({"paket": 5, "ip": "203.0.113.3"}, **normal)
        assert r.billing_card_is_anomaly({"paket": 5, "ip": "192.0.2.3"}, **normal)
        assert r.billing_card_is_anomaly({"paket": 100, "balance": 50})  # nothing declared normal
        assert not r.gpon_unbind_allowed({}, None)[0]
        protected = [("192.0.2.101", "21")]
        assert not r.gpon_unbind_allowed({"switch_ip": "192.0.2.101", "port": "21"}, 3,
                                         protected_ports=protected)[0]
        assert r.gpon_unbind_allowed({}, 2)[0]

    def test_monitor_freshness(self):
        assert r.monitor_freshness(0, 60, now=200)["stale"]
        assert not r.monitor_freshness(150, 60, now=200)["stale"]


class TestInstaller:
    def test_install_and_rollback_touch_only_own_entry(self, tmp_path):
        settings = tmp_path / "settings.json"
        other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-hook"}]}
        settings.write_text(json.dumps({"hooks": {"PreToolUse": [other]}, "model": "x"}), encoding="utf-8")
        result = install.install(settings, python="/usr/bin/python3")
        assert result["installed"] and Path(result["backup"]).exists()
        data = json.loads(settings.read_text(encoding="utf-8"))
        commands = [c["command"] for h in data["hooks"]["PreToolUse"] for c in h["hooks"]]
        assert commands[0] == "other-hook" and install.MARK in commands[1] and "--warn-only" in commands[1]
        install.install(settings, python="/usr/bin/python3")  # idempotent: still one entry
        assert json.dumps(json.loads(settings.read_text(encoding="utf-8"))).count(install.MARK) == 1
        assert install.rollback(settings)["remaining_guard_entries"] == 0
        data = json.loads(settings.read_text(encoding="utf-8"))
        assert data["model"] == "x" and data["hooks"]["PreToolUse"] == [other]

    def test_install_creates_missing_settings(self, tmp_path):
        settings = tmp_path / "new" / "settings.json"
        assert install.install(settings)["backup"] is None
        assert install.MARK in settings.read_text(encoding="utf-8")


class TestRulesDrift:
    def test_new_and_changed_rules(self, tmp_path, capsys):
        mem = tmp_path / "memory"
        mem.mkdir()
        (mem / "MEMORY.md").write_text("index", encoding="utf-8")
        (mem / "kept.md").write_text("same", encoding="utf-8")
        (mem / "changed.md").write_text("new text", encoding="utf-8")
        (mem / "fresh.md").write_text("x", encoding="utf-8")
        import hashlib
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"owner_rules": [
            {"rule_id": "kept", "source": {"sha256": hashlib.sha256(b"same").hexdigest()}},
            {"rule_id": "changed", "source": {"sha256": "0" * 64}},
        ]}), encoding="utf-8")
        lines = rules_drift_check.drift(export, mem)
        assert any(x.startswith("RULE_DRIFT: changed") for x in lines)
        assert any(x.startswith("RULE_NEW: fresh") for x in lines)
        assert not any("kept" in x or "MEMORY" in x for x in lines)
        assert rules_drift_check.drift() == []  # nothing configured -> nothing reported
        assert rules_drift_check.main(["--memory-dir", str(mem), "--hook"]) == 0
        assert capsys.readouterr().out == ""  # no export configured for the hook form
