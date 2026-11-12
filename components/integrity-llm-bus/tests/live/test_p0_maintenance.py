"""P0-3: owned expiring maintenance/freeze records block launcher and relay."""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


def _state_value(module, state):
    """Point one resource module's configured state directory at a test folder."""
    original = module._integrity_value
    return patch.object(module, "_integrity_value",
                        lambda key: str(state) if key == "state_directory" else original(key))

import launcher
import maintenance as mt


class MaintenanceTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"; self.state.mkdir()

    def tearDown(self):
        self.td.cleanup()

    def test_owner_reason_expiry(self):
        rec = mt.acquire(self.state, "maintenance", "codexint", "G176 gate write", 10)
        self.assertEqual(mt.blocking(self.state)["owner"], "codexint")
        with self.assertRaises(ValueError):
            mt.acquire(self.state, "maintenance", "grok", "other", 10)
        with self.assertRaises(ValueError):
            mt.release(self.state, "maintenance", "grok")
        self.assertIsNone(mt.blocking(self.state, now=rec["expires"] + 1))
        self.assertTrue(mt.release(self.state, "maintenance", "codexint"))
        self.assertIsNone(mt.blocking(self.state))

    def test_expired_record_can_be_taken_over(self):
        mt.acquire(self.state, "freeze", "ilia", "freeze", 1, now=time.time() - 120)
        self.assertIsNone(mt.blocking(self.state))
        self.assertEqual(mt.acquire(self.state, "freeze", "grok", "next", 5)["owner"], "grok")

    def test_corrupt_record_is_fail_safe(self):
        (self.state / "FREEZE.json").write_text("not json", encoding="utf-8")
        self.assertTrue(mt.blocking(self.state)["invalid"])
        (self.state / "FREEZE.json").write_text("", encoding="utf-8")
        self.assertIsNotNone(mt.blocking(self.state))

    def test_validation(self):
        for owner, reason, ttl in (("", "r", 5), ("A B", "r", 5), ("ok", "", 5), ("ok", "r", 0), ("ok", "r", 99999)):
            with self.assertRaises(ValueError):
                mt.acquire(self.state, "maintenance", owner, reason, ttl)

    def test_launcher_refuses_during_maintenance(self):
        mt.acquire(self.state, "maintenance", "codexint", "install", 10)
        with _state_value(launcher, self.state), patch("launcher.subprocess.Popen") as popen:
            with self.assertRaises(RuntimeError):
                launcher.start("grok", environment={"GROKBOT_WEBHOOK_KEY": "dummy"})
            popen.assert_not_called()

    def test_cli_status_exit_code(self):
        self.assertEqual(mt.main(["--state-dir", str(self.state), "status"]), 0)
        mt.acquire(self.state, "maintenance", "codexint", "install", 10)
        self.assertEqual(mt.main(["--state-dir", str(self.state), "status"]), 3)

    def test_relay_once_refuses_during_maintenance(self):
        import relay
        mt.acquire(self.state, "maintenance", "codexint", "install", 10)
        argv = ["relay.py", "--once", "--targets", "grok"]
        with _state_value(relay, self.state), patch.object(sys, "argv", argv), \
             patch("relay.Relay") as R, patch("relay.agent_registry.codex_threads", return_value={}):
            self.assertEqual(relay.main(), 4)
            R.return_value.once.assert_not_called()


if __name__ == "__main__":
    unittest.main()
