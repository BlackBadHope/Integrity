"""P0-2: sender learns the recipient is unreachable; watchdog notice is emitted once."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import local_cli
import reachability as rc


class ReachabilityTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        self.store = local_cli.open_store(self.state)

    def tearDown(self):
        self.td.cleanup()

    def running(self, targets=None):
        (self.state / "relay.pid").write_text(str(os.getpid()), encoding="ascii")
        if targets is not None:
            (self.state / "relay-targets.json").write_text(json.dumps({"targets": targets}), encoding="utf-8")

    def test_reasons(self):
        self.assertEqual(rc.assess("nobody", self.state)["reason"], "unregistered")
        self.assertEqual(rc.assess("grok", self.state)["reason"], "relay_stopped")
        self.running(["grok"])
        self.assertTrue(rc.assess("grok", self.state)["deliverable"])
        self.assertEqual(rc.assess("codexfc", self.state, host_link=True)["reason"], "no_consumer")
        self.running(["grok", "codexfc"])
        self.assertEqual(rc.assess("codexfc", self.state, host_link=False)["reason"], "host_link_down")
        self.assertTrue(rc.assess("codexfc", self.state, host_link=True)["deliverable"])
        (self.state / "RELAY_STOP").write_text("")
        self.assertEqual(rc.assess("grok", self.state)["reason"], "relay_stopped")

    def test_pull_recipient_is_deliverable_without_relay(self):
        self.assertTrue(rc.assess("claude", self.state)["deliverable"])

    def test_dead_pid_is_stopped(self):
        (self.state / "relay.pid").write_text("999999", encoding="ascii")
        self.assertFalse(rc.relay_state(self.state)["running"])

    def test_cli_send_and_queue_report_deliverable(self):
        body = Path(self.td.name) / "b.txt"; body.write_text("hi", encoding="utf-8")
        out = []
        with patch("sys.stdout.write", side_effect=out.append):
            local_cli.main(["--state-dir", str(self.state), "send", "--from", "claude", "--to", "grok",
                            "--id", "m1", "--body-file", str(body), "--delivery", "steer"])
        result = json.loads("".join(out)); out.clear()
        self.assertEqual((result["deliverable"], result["reason"]), (False, "relay_stopped"))
        with patch("sys.stdout.write", side_effect=out.append):
            local_cli.main(["--state-dir", str(self.state), "queue", "--agent", "grok"])
        self.assertEqual(json.loads("".join(out))["reason"], "relay_stopped")

    def test_notify_stale_once(self):
        self.store.post({"id": "old", "from": "claude", "to": "grok", "body": "x", "reply_to": None})
        later = time.time() + 3600
        first = rc.notify_stale(self.state, self.store, 15, now=later)
        self.assertEqual((first["count"], first["by_recipient"]), (1, {"grok": 1}))
        self.assertIsNone(rc.notify_stale(self.state, self.store, 15, now=later + 120))
        lines = (self.state / "bus-events.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertNotIn("x", json.loads(lines[0]).get("by_recipient"))

    def test_notify_silent_when_relay_running_or_fresh(self):
        self.store.post({"id": "new", "from": "claude", "to": "grok", "body": "x", "reply_to": None})
        self.assertIsNone(rc.notify_stale(self.state, self.store, 15))
        self.running(["grok"])
        self.assertIsNone(rc.notify_stale(self.state, self.store, 15, now=time.time() + 3600))


if __name__ == "__main__":
    unittest.main()
