"""Tests for integrity_killswitch. Never touches a live state file, log or bus host.

Every test points INTEGRITY_KILLSWITCH_STATE/LOG at a temporary directory and
replaces caller detection with a fake, so no real process is inspected or stopped.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from integrity_killswitch import killswitch as ks


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.state = self.dir / "killswitch.json"
        keys = (ks.ENV_STATE, ks.ENV_LOG, ks.ENV_CONFIG, "LLM_VENDOR")
        self._env = {k: os.environ.get(k) for k in keys}
        os.environ[ks.ENV_STATE] = str(self.state)
        os.environ[ks.ENV_LOG] = str(self.dir / "killswitch.log")
        os.environ.pop(ks.ENV_CONFIG, None)
        os.environ.pop("LLM_VENDOR", None)
        ks.configure({})
        self._detect, self._web = ks.detect_vendor, ks.web_actor
        self._ancestors = ks.get_process_ancestor_names
        self._linux = ks.read_linux_ancestry
        ks.get_process_ancestor_names = lambda *a, **k: ["python.exe", "fake-parent.exe"]
        ks.read_linux_ancestry = lambda *a, **k: None

    def tearDown(self) -> None:
        ks.detect_vendor, ks.web_actor = self._detect, self._web
        ks.get_process_ancestor_names = self._ancestors
        ks.read_linux_ancestry = self._linux
        ks.configure({})
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def as_actor(self, actor: str) -> None:
        ks.detect_vendor = lambda *a, **k: actor

    def read_state(self) -> dict:
        return json.loads(self.state.read_text(encoding="utf-8"))


class DetectVendor(Base):
    CASES = [
        (["python.exe", "bash.exe", "ssh.exe", "bash.exe", "claude.exe", "explorer.exe"], {}, "claude"),
        (["python.exe", "language_server_windows_x64.exe", "antigravity.exe"], {}, "antigravity"),
        (["python.exe", "cmd.exe", "codex.exe"], {"LLM_VENDOR": "grok"}, "codex"),
        (["python.exe", "bash.exe"], {}, "unknown_llm"),
        (["python.exe"], {}, "unknown_llm"),
        ([], {}, "unknown_llm"),
        (["python.exe", "node.exe", "explorer.exe"], {}, "unknown_llm"),
        (["python.exe", "node.exe"], {"LLM_VENDOR": "owner"}, "unknown_llm"),
        (["python.exe", "cmd.exe", "ssh.exe", "pwsh.exe", "windowsterminal.exe", "explorer.exe"], {}, "owner"),
        (["python.exe", "pwsh.exe", "windowsterminal.exe", "svchost.exe", "services.exe", "wininit.exe"], {}, "owner"),
        (["python.exe", "pwsh.exe"], {}, "owner"),
        (["python.exe", "powershell.exe", "svchost.exe", "services.exe", "wininit.exe"], {}, "service"),
        (["python.exe", "bash.exe", "ssh.exe", "pythonw.exe"], {}, "service"),
        (["python.exe", "bash.exe", "ssh.exe", "pythonw.exe"], {"LLM_VENDOR": "grok"}, "grok"),
    ]

    def test_cases(self) -> None:
        for names, env, want in self.CASES:
            with self.subTest(names=names, env=env):
                self.assertEqual(ks.detect_vendor(names, env=env), want)

    def test_configured_vendor(self) -> None:
        ks.configure({"vendors": {"example-agent": {"title": "Example", "markers": ["example-agent"]}}})
        self.assertEqual(ks.detect_vendor(["python.exe", "example-agent.exe", "explorer.exe"], env={}),
                         "example-agent")
        self.assertEqual(ks.detect_vendor(["python.exe", "pythonw.exe"], env={"LLM_VENDOR": "example-agent"}),
                         "example-agent")
        self.assertIn("example-agent", ks.init_state()["vendors"])
        with self.assertRaises(ValueError):
            ks.configure({"vendors": {"owner": {}}})

    def test_msys_table(self) -> None:
        # STIME is not parsed; it is left as "-" in this fixture.
        out = (
            "      PID    PPID    PGID     WINPID   TTY         UID    STIME COMMAND\n"
            "   242585  242584  242581      46052  ?         197609 - /c/Python312/python\n"
            "S  242581       1  242581      35500  ?         197609 - /usr/bin/bash\n"
            "   242584  242581  242581      12868  ?         197609 - /usr/bin/ssh\n"
            "garbage line\n"
        )
        self.assertEqual(ks._parse_msys_ps(out), {46052: 12868, 12868: 35500})


def _symlinks_work() -> bool:
    with tempfile.TemporaryDirectory() as folder:
        try:
            os.symlink("/invented/target", os.path.join(folder, "link"))
            return True
        except (OSError, NotImplementedError):
            return False


@unittest.skipUnless(_symlinks_work(), "a fake /proc needs symbolic links")
class LinuxAncestry(Base):
    """read_linux_ancestry and classify_linux on an invented /proc tree."""

    def setUp(self) -> None:
        super().setUp()
        ks.read_linux_ancestry = self._linux
        self.proc = self.dir / "proc"

    def add(self, pid: int, ppid: int, start: int, exe: str | None, comm: str | None,
            argv: list[str] | None) -> None:
        folder = self.proc / str(pid)
        folder.mkdir(parents=True)
        name = comm or "x"
        # The comm field may hold spaces and ')': the parser cuts at the last ')'.
        (folder / "stat").write_text(f"{pid} ({name} )x) S {ppid} 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 "
                                     f"{start} 1 1\n", encoding="utf-8")
        if exe is not None:
            os.symlink(exe, folder / "exe")
        if comm is not None:
            (folder / "comm").write_text(comm + "\n", encoding="utf-8")
        if argv is not None:
            (folder / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")

    def chain(self, *rows) -> None:
        """rows from the caller upwards: (exe, comm, argv); pids 105..101, start times rising downwards."""
        pids = list(range(100 + len(rows), 100, -1))
        pids[-1] = 1
        for index, (exe, comm, argv) in enumerate(rows):
            ppid = pids[index + 1] if index + 1 < len(pids) else 0
            self.add(pids[index], ppid, 1000 - index * 10, exe, comm, argv)
        self.start = pids[0]

    def walk(self):
        return ks.read_linux_ancestry(self.start, proc_root=str(self.proc))

    def judge(self, env=None) -> str:
        return ks.classify_linux(self.walk(), env or {})

    SELF = ("/usr/bin/python3.12", "integrity-killsw", ["/venv/bin/python", "/venv/bin/integrity-killswitch", "on", "x"])
    SSH = [("/usr/bin/bash", "bash", ["-bash"]), (None, "sshd-session", ["sshd-session: user@pts/0"]),
           (None, "sshd", ["sshd: /usr/sbin/sshd -D"]), (None, "systemd", ["/sbin/init"])]
    CONSOLE = [("/usr/bin/bash", "bash", ["-bash"]), (None, "login", ["/bin/login", "-p", "--"]),
               (None, "systemd", ["/sbin/init"])]

    def test_console_login_shell_is_the_owner(self) -> None:
        self.chain(self.SELF, *self.CONSOLE)
        self.assertEqual([name for name, _ in self.walk()], ["python", "bash", "login", "systemd"])
        self.assertEqual(self.judge(), "owner")
        self.assertEqual(self.judge({"LLM_VENDOR": "grok"}), "grok")
        self.assertEqual(self.judge({"LLM_VENDOR": "owner"}), "owner")

    def test_desktop_terminal_with_sudo_is_the_owner(self) -> None:
        self.chain(self.SELF, (None, "sudo", ["sudo", "integrity-killswitch", "on", "x"]),
                   ("/usr/bin/zsh", "zsh", ["zsh"]),
                   ("/usr/libexec/gnome-terminal-server", "gnome-terminal-", ["/usr/libexec/gnome-terminal-server"]),
                   ("/usr/lib/systemd/systemd", "systemd", ["/usr/lib/systemd/systemd", "--user"]),
                   (None, "systemd", ["/sbin/init"]))
        self.assertEqual(self.judge(), "owner")

    def test_ssh_and_tmux_shells_are_not_the_owner(self) -> None:
        self.chain(self.SELF, *self.SSH)
        self.assertEqual([name for name, _ in self.walk()], ["python", "bash", "sshd-session", "sshd", "systemd"])
        self.assertEqual(self.judge(), "unknown_llm")
        self.chain_reset()
        self.chain(self.SELF, ("/usr/bin/bash", "bash", ["-bash"]), ("/usr/bin/tmux", "tmux: server", ["tmux"]),
                   ("/usr/lib/systemd/systemd", "systemd", ["/usr/lib/systemd/systemd", "--user"]),
                   (None, "systemd", ["/sbin/init"]))
        self.assertEqual(self.judge(), "unknown_llm")

    def test_node_agent_script_is_a_marker(self) -> None:
        agent = ("/usr/bin/node", "node", ["node", "--no-warnings", "/usr/lib/node_modules/@vendor/claude-code/cli.js"])
        self.chain(self.SELF, ("/usr/bin/bash", "bash", ["bash", "-c", "x"]), agent, *self.CONSOLE)
        self.assertEqual(self.judge(), "claude")

    def test_interpreter_path_alone_is_not_a_marker(self) -> None:
        tool = ("/opt/claude-tools/bin/python3", "python3", ["python3", "/opt/tool/run.py"])
        self.chain(self.SELF, tool, *self.CONSOLE)
        self.assertEqual(self.judge(), "unknown_llm")  # an interpreter above the caller runs some program
        self.chain_reset()
        node = ("/opt/codex/bin/node", "node", ["node", "-e", "1"])
        self.chain(self.SELF, node, *self.CONSOLE)
        self.assertEqual(self.judge(), "unknown_llm")

    def chain_reset(self) -> None:
        import shutil

        shutil.rmtree(self.proc)

    def test_native_agent_binary_is_a_marker(self) -> None:
        self.chain(self.SELF, ("/opt/agents/bin/codex", "codex", ["codex"]), *self.CONSOLE)
        self.assertEqual(self.judge(), "codex")

    def test_unreadable_exe_uses_comm_and_cmdline(self) -> None:
        self.chain(self.SELF, (None, "grok", ["grok", "chat"]), *self.CONSOLE)
        self.assertEqual(self.judge(), "grok")

    def test_unreadable_exe_comm_and_cmdline_refuse(self) -> None:
        for row in ((None, None, ["bash"]), (None, "bash", None), (None, None, None)):
            with self.subTest(row=row):
                self.chain_reset() if self.proc.exists() else None
                self.chain(self.SELF, row, *self.CONSOLE)
                self.assertIsNone(self.walk())
                self.assertEqual(self.judge(), "unknown_llm")
                self.assertEqual(self.judge({"LLM_VENDOR": "codex"}), "codex")

    def test_interpreter_without_command_line_refuses(self) -> None:
        self.chain(self.SELF, ("/usr/bin/node", "node", None), *self.CONSOLE)
        self.assertIsNone(self.walk())

    def test_parent_exited_during_the_walk_refuses(self) -> None:
        self.chain(self.SELF, *self.SSH)
        real = ks._linux_stat
        calls = {"n": 0}

        def flaky(proc, pid):
            calls["n"] += 1
            if pid == 104 and calls["n"] > 5:  # the second pass finds the shell gone
                return None
            return real(proc, pid)

        ks._linux_stat = flaky
        try:
            self.assertIsNone(self.walk())
        finally:
            ks._linux_stat = real

    def test_parent_replaced_during_the_walk_refuses(self) -> None:
        self.chain(self.SELF, *self.SSH)
        real = ks._linux_stat
        seen: set[int] = set()

        def reparented(proc, pid):
            first = pid not in seen
            seen.add(pid)
            ppid, start = real(proc, pid)
            return (ppid, start) if first or pid != 105 else (1, start)

        ks._linux_stat = reparented
        try:
            self.assertIsNone(self.walk())
        finally:
            ks._linux_stat = real

    def test_reused_parent_pid_refuses(self) -> None:
        self.chain(self.SELF, *self.SSH)
        stat = self.proc / "104" / "stat"
        stat.write_text(stat.read_text(encoding="utf-8").replace(" 990 ", " 5000 "), encoding="utf-8")
        self.assertIsNone(self.walk())

    def test_detached_shell_and_services(self) -> None:
        self.chain(self.SELF, ("/usr/bin/bash", "bash", ["bash", "-c", "x"]),
                   ("/usr/lib/systemd/systemd", "systemd", ["/usr/lib/systemd/systemd", "--user"]),
                   (None, "systemd", ["/sbin/init"]))
        self.assertEqual(self.judge(), "unknown_llm")
        self.chain_reset()
        self.chain(self.SELF, (None, "systemd", ["/sbin/init"]))
        self.assertEqual(self.judge(), "service")
        self.chain_reset()
        self.chain(self.SELF, (None, "cron", ["/usr/sbin/cron", "-f"]), (None, "systemd", ["/sbin/init"]))
        self.assertEqual(self.judge(), "unknown_llm")

    def test_walk_must_reach_pid_one(self) -> None:
        self.add(105, 7, 1000, "/usr/bin/python3", "python3", ["python3", "-c", "1"])
        self.start = 105
        self.assertIsNone(self.walk())

    def test_python_command_lines(self) -> None:
        cases = [
            (["python3", "-I", "-B", "/x/claude/a.py", "arg"], "/x/claude/a.py"),
            (["python3", "-W", "ignore", "-m", "pkg.mod"], "pkg.mod"),
            (["python3", "-mpkg"], "pkg"),
            (["python3", "-c", "print(1)"], ""),
            (["python3"], ""),
            (["python3", "-m"], None),
        ]
        for argv, want in cases:
            with self.subTest(argv=argv):
                self.assertEqual(ks._linux_script("python", argv), want)
        self.assertEqual(ks._linux_script("node", ["node", "-r", "x", "s.js"]), "s.js")
        self.assertEqual(ks._linux_script("deno", ["deno", "run", "-A", "m.ts"]), "m.ts")


@unittest.skipUnless(ks.LINUX_ANCESTRY, "Linux only: reads the real /proc")
class LinuxRealProcesses(Base):
    """read_linux_ancestry on real processes started by this test."""

    def setUp(self) -> None:
        super().setUp()
        # Base stands in for both readers; these tests read the real process tree.
        ks.read_linux_ancestry = self._linux
        ks.get_process_ancestor_names = self._ancestors

    def run_child(self, parent_script: Path) -> dict:
        code = ("import json, os; from integrity_killswitch import killswitch as ks; "
                "print(json.dumps({'names': [n for n, _ in ks.read_linux_ancestry() or []], "
                "'vendor': ks.detect_vendor(env={})}))")
        parent_script.parent.mkdir(parents=True, exist_ok=True)
        parent_script.write_text("import subprocess, sys\n"
                                 f"sys.exit(subprocess.run([sys.executable, '-c', {code!r}]).returncode)\n",
                                 encoding="utf-8")
        out = subprocess.run([sys.executable, str(parent_script)], capture_output=True, text=True, timeout=60,
                             env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_this_process_tree_reaches_pid_one(self) -> None:
        entries = ks.read_linux_ancestry()
        self.assertIsNotNone(entries)
        self.assertEqual(entries[0][0], "python")
        self.assertEqual(ks.get_process_ancestor_names(), [name for name, _ in entries])

    def test_agent_script_in_the_parent_is_detected(self) -> None:
        result = self.run_child(self.dir / "claude-agent" / "agent.py")
        self.assertEqual(result["names"][:2], ["python", "python"])
        self.assertEqual(result["vendor"], "claude")

    def test_unknown_parent_script_is_not_the_owner(self) -> None:
        result = self.run_child(self.dir / "plain-tool" / "tool.py")
        self.assertEqual(result["names"][:2], ["python", "python"])
        # unknown_llm in CI; under an agent its own marker wins. Never the owner.
        self.assertNotIn(result["vendor"], ("owner", "service"))


class Configuration(Base):
    def test_config_file_and_env(self) -> None:
        cfg = self.dir / "cfg.json"
        cfg.write_text(json.dumps({"state_file": str(self.dir / "from-config.json")}), encoding="utf-8")
        self.assertEqual(ks.load_config(str(cfg))["state_file"], str(self.dir / "from-config.json"))
        os.environ[ks.ENV_CONFIG] = str(cfg)
        self.assertIn("state_file", ks.load_config())
        ks.configure(ks.load_config())
        self.assertEqual(ks.state_path(), self.state)  # the environment wins over the file
        os.environ.pop(ks.ENV_STATE)
        self.assertEqual(ks.state_path(), self.dir / "from-config.json")

    def test_default_state_dir_is_per_user(self) -> None:
        os.environ.pop(ks.ENV_STATE)
        self.assertEqual(ks.state_path().parent.name, "integrity-killswitch")

    def test_bus_sync_needs_configuration(self) -> None:
        with self.assertRaises(RuntimeError):
            ks.bus_sync_settings()
        ks.configure({"bus_sync": {"ssh_command": ["ssh", "bus.example.invalid"]}})
        with self.assertRaises(RuntimeError):
            ks.bus_sync_settings()
        ks.configure({"bus_sync": {"ssh_command": ["ssh", "bus.example.invalid"],
                                   "principals_path": "/opt/x/principals.json; rm -rf /"}})
        with self.assertRaises(RuntimeError):
            ks.bus_sync_settings()
        ks.configure({"bus_sync": {"ssh_command": ["ssh", "bus.example.invalid"],
                                   "principals_path": "/opt/x/principals.json"}})
        self.assertEqual(ks.bus_sync_settings()["remote_command"], list(ks.DEFAULT_REMOTE_COMMAND))

    def test_unconfigured_sync_is_a_notice(self) -> None:
        self.assertEqual(ks.cmd_sync_bus(argparse.Namespace(state=None, apply=False)), 1)


class IsAllowed(Base):
    def test_matrix(self) -> None:
        ok = lambda vendor, action="direct_ssh": ks.is_allowed(vendor=vendor, action=action, state_file=self.state)[0]
        self.assertTrue(ok("claude"))
        self.assertTrue(ok("service"))
        self.assertFalse(ok("unknown_llm"))
        self.assertFalse(ok("made-up-vendor"))

        state = ks.load_state(self.state)
        state["vendors"]["claude"]["enabled"] = False
        ks.save_state(self.state, state, "test")
        self.assertFalse(ok("claude"))
        self.assertTrue(ok("codex"))

        state["vendors"]["claude"]["enabled"] = True
        state["scopes"]["secret_get"] = False
        ks.save_state(self.state, state, "test")
        self.assertFalse(ok("claude", "secret_get"))
        self.assertTrue(ok("claude", "direct_ssh"))

        state["master_panic"] = True
        ks.save_state(self.state, state, "test")
        self.assertFalse(ok("codex"))
        self.assertFalse(ok("service"))
        self.assertTrue(ok("owner"))

    def test_corrupt_state_fails_closed(self) -> None:
        self.state.write_text("{not json", encoding="utf-8")
        self.assertFalse(ks.is_allowed(vendor="claude", state_file=self.state)[0])
        self.assertTrue(ks.is_allowed(vendor="owner", state_file=self.state)[0])


class AdminCommands(Base):
    def ns(self, **kw) -> argparse.Namespace:
        return argparse.Namespace(state=None, reason=None, sync=False, **kw)

    def test_llm_can_tighten_but_not_restore(self) -> None:
        self.as_actor("claude")
        self.assertEqual(ks.cmd_set_vendor(self.ns(vendor="grok"), False), 0)
        self.assertFalse(self.read_state()["vendors"]["grok"]["enabled"])
        self.assertEqual(self.read_state()["updated_by"], "claude-cli")
        self.assertEqual(ks.cmd_set_vendor(self.ns(vendor="grok"), True), ks.EXIT_REFUSED)
        self.assertFalse(self.read_state()["vendors"]["grok"]["enabled"])
        self.assertEqual(ks.cmd_panic(self.ns()), 0)
        self.assertEqual(ks.cmd_resume(self.ns()), ks.EXIT_REFUSED)
        self.assertTrue(self.read_state()["master_panic"])

    def test_owner_can_restore(self) -> None:
        self.as_actor("claude")
        ks.cmd_set_vendor(self.ns(vendor="grok"), False)
        ks.cmd_panic(self.ns())
        self.as_actor("owner")
        self.assertEqual(ks.cmd_resume(self.ns()), 0)
        self.assertEqual(ks.cmd_set_vendor(self.ns(vendor="grok"), True), 0)
        state = self.read_state()
        self.assertFalse(state["master_panic"])
        self.assertTrue(state["vendors"]["grok"]["enabled"])

    def test_vendor_name_is_validated(self) -> None:
        self.as_actor("owner")
        self.assertEqual(ks.cmd_set_vendor(self.ns(vendor="x; rm -rf /"), False), 2)
        self.assertEqual(ks.bus_sync_args("plan", False, {"grok", "a b", "$(x)"}, "/opt/x/p.json")[3], "grok")

    def test_check_cannot_claim_owner(self) -> None:
        self.as_actor("claude")
        ks.cmd_panic(self.ns())
        args = argparse.Namespace(state=None, vendor="owner", action="direct_ssh", target="x",
                                  match_blocked=False, verbose=False)
        self.assertEqual(ks.cmd_check(args), ks.EXIT_REFUSED)

    def test_main_status_runs(self) -> None:
        self.as_actor("owner")
        self.assertEqual(ks.main(["status"]), 0)


class DoctorAndUninstall(Base):
    def report(self, **kw) -> dict:
        return {item["check"]: item for item in ks.doctor_report(**kw)["checks"]}

    def test_doctor_is_read_only_on_a_clean_machine(self) -> None:
        self.as_actor("owner")
        self.assertEqual(ks.main(["doctor"]), 0)
        self.assertEqual(ks.main(["doctor", "--json"]), 0)
        self.assertEqual(list(self.dir.iterdir()), [])  # no state file, no log line
        checks = self.report()
        self.assertIn("not created yet", checks["state"]["detail"])
        self.assertEqual(checks["caller"]["result"], "ok" if ks.ANCESTRY_SUPPORTED else "warn")
        self.assertIn("not configured", checks["bus sync"]["detail"])

    def test_doctor_names_what_is_blocked(self) -> None:
        self.as_actor("claude")
        ks.cmd_set_vendor(argparse.Namespace(state=None, reason=None, sync=False, vendor="grok"), False)
        detail = self.report()["state"]["detail"]
        self.assertIn("vendor grok", detail)
        self.assertNotIn("master panic", detail)

    def test_doctor_fails_on_unreadable_state_and_bad_configuration(self) -> None:
        self.as_actor("owner")
        self.state.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.report()["state"]["result"], "fail")
        self.assertEqual(ks.main(["doctor"]), 1)
        self.state.unlink()
        self.assertEqual(ks.main(["--config", str(self.dir / "missing.json"), "doctor"]), 1)
        self.assertEqual(ks.main(["--config", str(self.dir / "missing.json"), "status"]), 2)

    def test_uninstall_lists_first_and_removes_with_yes(self) -> None:
        self.as_actor("claude")
        self.assertEqual(ks.main(["status"]), 0)
        ks.log_audit_event("test", {})
        log = self.dir / "killswitch.log"
        self.assertEqual(ks.main(["uninstall"]), 0)
        self.assertTrue(self.state.exists() and log.exists())
        self.assertEqual(ks.main(["uninstall", "--yes"]), 0)  # nothing is blocked, so any caller may remove it
        self.assertEqual(list(self.dir.iterdir()), [])
        self.assertEqual(ks.main(["uninstall", "--yes"]), 0)

    def test_uninstall_cannot_lift_a_block(self) -> None:
        self.as_actor("claude")
        ks.cmd_panic(argparse.Namespace(state=None, reason=None, sync=False))
        self.assertEqual(ks.main(["uninstall", "--yes"]), ks.EXIT_REFUSED)
        self.assertTrue(self.read_state()["master_panic"])
        self.state.write_text("{not json", encoding="utf-8")
        self.assertEqual(ks.main(["uninstall", "--yes"]), ks.EXIT_REFUSED)
        self.assertTrue(self.state.exists())
        self.as_actor("owner")
        self.assertEqual(ks.main(["uninstall", "--yes"]), 0)
        self.assertFalse(self.state.exists())


class BusSyncScript(Base):
    def run_sync(self, mode: str, panic: str, disabled: str) -> dict:
        res = subprocess.run([sys.executable, "-", mode, str(self.principals), panic, disabled],
                             input=ks.BUS_SYNC_SCRIPT.encode("utf-8"), capture_output=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr.decode("utf-8", "replace"))
        return json.loads(res.stdout.decode("utf-8").strip().splitlines()[-1])

    def revoked(self) -> dict:
        data = json.loads(self.principals.read_text(encoding="utf-8"))
        return {n: bool(i.get("revoked", False)) for n, i in data["principals"].items()}

    def test_only_own_revocations_are_undone(self) -> None:
        self.principals = self.dir / "principals.json"
        self.principals.write_text(json.dumps({"principals": {
            "owner-console": {"vendor": ""},
            "hub": {"vendor": "owner"},
            "room-grok": {"vendor": "grok"},
            "room-claude": {"vendor": "claude"},
            "room-codex": {"vendor": "codex", "revoked": True},
        }}), encoding="utf-8")
        before = self.principals.read_text(encoding="utf-8")

        plan = self.run_sync("plan", "0", "grok")
        self.assertEqual([c["name"] for c in plan["changes"]], ["room-grok"])
        self.assertEqual(plan["foreign_revoked"], ["room-codex"])
        self.assertEqual(self.principals.read_text(encoding="utf-8"), before)

        done = self.run_sync("apply", "0", "grok")
        self.assertEqual(done["applied"], 1)
        self.assertTrue(Path(done["backup"]).exists())
        self.assertEqual(self.revoked(), {"owner-console": False, "hub": False, "room-grok": True,
                                          "room-claude": False, "room-codex": True})

        self.run_sync("apply", "0", "-")
        self.assertEqual(self.revoked()["room-grok"], False)
        self.assertEqual(self.revoked()["room-codex"], True)

        self.run_sync("apply", "1", "-")
        self.assertEqual(self.revoked(), {"owner-console": False, "hub": False, "room-grok": True,
                                          "room-claude": True, "room-codex": True})
        self.run_sync("apply", "0", "-")
        self.assertEqual(self.revoked(), {"owner-console": False, "hub": False, "room-grok": False,
                                          "room-claude": False, "room-codex": True})

    def test_ssh_argv_uses_configuration(self) -> None:
        ks.configure({"bus_sync": {"ssh_command": [sys.executable, "-c", "import sys; sys.exit(7)"],
                                   "principals_path": "/opt/x/principals.json"}})
        with self.assertRaises(RuntimeError) as caught:
            ks._run_bus_sync("plan", False, set())
        self.assertIn("code 7", str(caught.exception))


class Dashboard(Base):
    def setUp(self) -> None:
        super().setUp()
        self.server = ks.ThreadingHTTPServer(("127.0.0.1", 0), ks.KillswitchHTTPHandler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def post(self, path: str, payload: dict, origin: str | None = None) -> int:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(payload).encode(),
                                     method="POST", headers={"Content-Type": "application/json"})
        if origin:
            req.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_restore_is_owner_only(self) -> None:
        ks.web_actor = lambda names: "claude"
        self.assertEqual(self.post("/api/toggle", {"vendor": "grok", "enabled": False}), 200)
        self.assertEqual(self.post("/api/panic", {}), 200)
        self.assertEqual(self.post("/api/toggle", {"vendor": "grok", "enabled": True}), 403)
        self.assertEqual(self.post("/api/resume", {}), 403)
        state = self.read_state()
        self.assertTrue(state["master_panic"])
        self.assertFalse(state["vendors"]["grok"]["enabled"])

        ks.web_actor = lambda names: "owner"
        self.assertEqual(self.post("/api/resume", {}), 200)
        self.assertEqual(self.post("/api/toggle", {"vendor": "grok", "enabled": True}), 200)
        self.assertEqual(self.post("/api/toggle", {"vendor": "grok", "enabled": True},
                                   origin=f"http://127.0.0.1:{self.port}"), 200)
        state = self.read_state()
        self.assertFalse(state["master_panic"])
        self.assertTrue(state["vendors"]["grok"]["enabled"])

    def test_cross_origin_is_refused(self) -> None:
        ks.web_actor = lambda names: "owner"
        self.assertEqual(self.post("/api/panic", {}, origin="http://evil.example"), 403)
        self.assertFalse(ks.load_state(self.state)["master_panic"])

    def test_dashboard_escapes_state_text(self) -> None:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=10) as resp:
            page = resp.read().decode("utf-8")
        self.assertIn("function esc(", page)
        self.assertIn("${esc(v.reason || '')}", page)

    def test_web_actor(self) -> None:
        ks.web_actor = self._web
        self.assertEqual(ks.web_actor(["chrome.exe", "chrome.exe", "explorer.exe"]), "owner")
        self.assertEqual(ks.web_actor(["msedge.exe", "svchost.exe"]), "owner")
        self.assertEqual(ks.web_actor(["chrome.exe", "claude.exe"]), "claude")
        self.assertEqual(ks.web_actor(["curl.exe", "bash.exe"]), "unknown_llm")
        self.assertEqual(ks.web_actor([]), "unknown_llm")

    @unittest.skipUnless(os.name == "nt", "Windows only: reads the Windows TCP owner table")
    def test_peer_pid(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname()) as client:
                conn, _ = listener.accept()
                with conn:
                    pid = ks._tcp_peer_pid(client.getsockname()[1], listener.getsockname()[1])
        self.assertEqual(pid, os.getpid())


if __name__ == "__main__":
    unittest.main(verbosity=1)
