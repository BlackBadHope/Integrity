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
        ks.get_process_ancestor_names = lambda *a, **k: ["python.exe", "fake-parent.exe"]

    def tearDown(self) -> None:
        ks.detect_vendor, ks.web_actor = self._detect, self._web
        ks.get_process_ancestor_names = self._ancestors
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
