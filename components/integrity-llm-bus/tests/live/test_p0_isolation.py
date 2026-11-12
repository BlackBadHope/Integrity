"""P0-1: one failing target never stops or corrupts the others; not-sent is retried, sent-ambiguous is not."""
import tempfile
import unittest
import urllib.error
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import relay
from relay import NotSent, Relay

THREAD = "a0000003-b003-7003-8003-c00000000003"


def post(r, mid, to):
    r.store.post({"id": mid, "from": "claude", "to": to, "body": "x", "reply_to": None})


class IsolationTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"

    def tearDown(self):
        self.td.cleanup()

    def test_not_sent_is_deferred_then_retried(self):
        calls = []
        def down(m, rid, t):
            calls.append(rid); raise NotSent("host_link_down")
        r = Relay(self.state, senders={"codexfc": down})
        post(r, "a", "codexfc")
        out = r.once(["codexfc"], 0)
        self.assertEqual((out[0]["state"], out[0]["sent"], out[0]["error_code"]), ("deferred", False, "host_link_down"))
        r.senders["codexfc"] = lambda m, rid, t: calls.append(rid) or {"status": "inProgress"}
        out = r.once(["codexfc"], 0)
        self.assertEqual((out[0]["state"], out[0]["attempts"]), ("accepted", 2))
        self.assertEqual(calls[0], calls[1])  # same idempotent request id, nothing was sent the first time
        self.assertEqual(r.once(["codexfc"], 0), [])

    def test_deferred_does_not_burn_hourly_quota(self):
        r = Relay(self.state, senders={"codexfc": lambda *a: (_ for _ in ()).throw(NotSent("host_link_down"))})
        post(r, "a", "codexfc")
        for _ in range(3):
            r.once(["codexfc"], 0, max_calls=1)
        r.senders["codexfc"] = lambda *a: {"status": "inProgress"}
        self.assertEqual(r.once(["codexfc"], 0, max_calls=1)[0]["state"], "accepted")

    def test_sent_ambiguous_is_unknown_and_never_replayed(self):
        calls = []
        def lost(m, rid, t):
            calls.append(rid); raise TimeoutError("lost")
        r = Relay(self.state, senders={"grok": lost})
        post(r, "p", "grok")
        out = r.once(["grok"], 0)
        self.assertEqual((out[0]["state"], out[0]["sent"]), ("unknown", True))
        self.assertEqual(Relay(self.state, senders={"grok": lost}).once(["grok"], 0), [])
        self.assertEqual(len(calls), 1)

    def test_down_target_does_not_block_grok(self):
        r = Relay(self.state, senders={"codexfc": lambda *a: (_ for _ in ()).throw(NotSent("host_link_down")),
                                       "grok": lambda *a: {"status": "ok"}})
        post(r, "c", "codexfc"); post(r, "g", "grok")
        states = {o["target"]: o["state"] for o in r.once(["codexfc", "grok"], 0)}
        self.assertEqual(states, {"codexfc": "deferred", "grok": "accepted"})

    def test_target_fault_is_isolated(self):
        r = Relay(self.state, senders={"grok": lambda *a: {"status": "ok"}})
        post(r, "c", "codexfc"); post(r, "g", "grok")
        with patch("relay.codex_delivery", side_effect=RuntimeError("boom")):
            out = r.once(["codexfc", "grok"], 0)
        self.assertEqual([(o["target"], o["state"]) for o in out], [("codexfc", "target_fault"), ("grok", "accepted")])

    def test_unregistered_target_is_deferred_not_unknown(self):
        r = Relay(self.state, senders={})
        post(r, "z", "codexfc")
        r.senders = {}
        r.threads = {}
        with patch.object(Relay, "is_codex", return_value=False):
            out = r.once(["codexfc"], 0)
        self.assertEqual((out[0]["state"], out[0]["error_code"]), ("deferred", "unregistered"))

    def test_peer_refused_before_send_is_not_sent(self):
        configured = {k: relay._integrity_value(k) for k in ("native_peer_host_id", "native_peer_port_49481")}
        with patch.object(relay, "_integrity_value", configured.__getitem__), \
             patch.object(relay.Path, "read_text", return_value="dummy-not-a-key"), \
             patch("relay.socket.create_connection", side_effect=ConnectionRefusedError()):
            with self.assertRaises(NotSent) as ctx:
                relay.peer_call("codex_send_prompt", {}, str(uuid.uuid4()))
        self.assertEqual(ctx.exception.code, "host_link_down")

    def test_wake_propagates_not_sent(self):
        with patch("relay.verify_desktop_peer_route"), patch("relay.owner_turn_hint", return_value=None), \
             patch("relay.peer_call", side_effect=NotSent("host_link_down")):
            with self.assertRaises(NotSent):
                relay.wake_codex(["p"], str(uuid.uuid4()), THREAD)
        with patch("relay.verify_desktop_peer_route"), patch("relay.owner_turn_hint", return_value=None), \
             patch("relay.peer_call", side_effect=TimeoutError()):
            with self.assertRaises(OSError) as ctx:
                relay.wake_codex(["p"], str(uuid.uuid4()), THREAD)
            self.assertNotIsInstance(ctx.exception, NotSent)

    def test_grok_connect_refused_is_not_sent(self):
        env = {"GROKBOT_WEBHOOK_URL": "https://webhook.example.invalid/hook/dummy", "GROKBOT_WEBHOOK_KEY": "dummy"}
        msg = {"id": "g", "from": "claude", "to": "grok", "body": "x", "reply_to": None}
        with patch.dict("os.environ", env), \
             patch("relay.urllib.request.urlopen", side_effect=urllib.error.URLError(ConnectionRefusedError())):
            with self.assertRaises(NotSent):
                relay.send_grok([msg], str(uuid.uuid4()), None)
        with patch.dict("os.environ", env), \
             patch("relay.urllib.request.urlopen", side_effect=urllib.error.URLError(TimeoutError())):
            with self.assertRaises(urllib.error.URLError):
                relay.send_grok([msg], str(uuid.uuid4()), None)

    def test_effective_targets_exclude_and_grok_only(self):
        fake = SimpleNamespace(refresh_registry=lambda: ["codex-grok-a0000005"])
        self.assertEqual(relay.effective_targets(fake, ["grok"]), ["grok", "codex-grok-a0000005"])
        self.assertEqual(relay.effective_targets(fake, ["grok"], {"codex-grok-a0000005"}), ["grok"])
        self.assertEqual(relay.effective_targets(fake, ["grok"], auto=False), ["grok"])


if __name__ == "__main__":
    unittest.main()
