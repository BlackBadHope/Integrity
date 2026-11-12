"""Webhook size guard: budget on the exact final request bytes; oversize singletons are visible, final, never sent."""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bus
import relay
from relay import OVERSIZE, SIZING_REQUEST_ID, PayloadTooLarge, Relay, grok_payload


def post(r, mid, body="x", to="grok"):
    r.store.post({"id": mid, "from": "claude", "to": to, "body": body, "reply_to": None})


class SizeGuardTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        self.calls = []

    def tearDown(self):
        self.td.cleanup()

    def sender(self, messages, request_id, _thread):
        self.calls.append([m["id"] for m in messages])
        return {"status": "ok"}

    def relay(self):
        return Relay(self.state, senders={"grok": self.sender})

    def rows(self, r):
        return {m["id"]: m for m in r.store.inbox("grok", "pending", 50)}

    def size_of(self, r, ids):
        rows = self.rows(r)
        return len(grok_payload([rows[i] for i in ids], SIZING_REQUEST_ID))

    def test_batch_at_cap_is_one_request(self):
        r = self.relay()
        post(r, "a"); post(r, "b")
        cap = self.size_of(r, ["a", "b"])
        with patch.object(relay, "WEBHOOK_MAX_BYTES", cap):
            out = r.once(["grok"], 0)
        self.assertEqual(self.calls, [["a", "b"]])
        self.assertEqual(out[0]["state"], "accepted")

    def test_one_byte_over_cap_splits_batch(self):
        r = self.relay()
        post(r, "a"); post(r, "b")
        cap = self.size_of(r, ["a", "b"]) - 1
        with patch.object(relay, "WEBHOOK_MAX_BYTES", cap):
            r.once(["grok"], 0)
            r.once(["grok"], 0)
        self.assertEqual(self.calls, [["a"], ["b"]])

    def test_oversize_singleton_is_final_visible_and_unsent(self):
        r = self.relay()
        post(r, "big", "x" * 5000)
        with patch.object(relay, "WEBHOOK_MAX_BYTES", 4000):
            out = r.once(["grok"], 0)
            self.assertEqual(r.once(["grok"], 0), [])  # not retried
        self.assertEqual(self.calls, [])
        self.assertEqual((out[0]["state"], out[0]["sent"]), (OVERSIZE, False))
        self.assertGreater(out[0]["payload_bytes"], 4000)
        self.assertIn("big", self.rows(r))  # row still pending, nothing dropped
        view = {m["id"]: m for m in bus.queue_view(r.store, "grok")}
        self.assertEqual(view["big"]["relay_state"], OVERSIZE)
        reopened = Relay(self.state, senders={"grok": self.sender})
        with patch.object(relay, "WEBHOOK_MAX_BYTES", 4000):
            self.assertEqual(reopened.once(["grok"], 0), [])  # final across restarts

    def test_mixed_keeps_order_and_isolates_oversize(self):
        r = self.relay()
        post(r, "s1"); post(r, "big", "x" * 5000); post(r, "s2")
        with patch.object(relay, "WEBHOOK_MAX_BYTES", 4000):
            states = [o["state"] for _ in range(3) for o in r.once(["grok"], 0)]
        self.assertEqual(self.calls, [["s1"], ["s2"]])
        self.assertEqual(states, ["accepted", OVERSIZE, "accepted"])

    def test_oversize_burns_neither_gap_nor_quota(self):
        r = self.relay()
        post(r, "big", "x" * 5000); post(r, "s1")
        with patch.object(relay, "WEBHOOK_MAX_BYTES", 4000):
            r.once(["grok"], min_gap=60, max_calls=1)
            out = r.once(["grok"], min_gap=60, max_calls=1)
        self.assertEqual((self.calls, out[0]["state"]), ([["s1"]], "accepted"))

    def test_multibyte_and_escaping_counted_after_serialization(self):
        r = self.relay()
        body = 'я"\\\n' * 300  # 2-byte letters, quote and backslash escapes, newlines
        post(r, "m", body)
        exact = self.size_of(r, ["m"])
        self.assertGreater(exact, len(body.encode("utf-8")))
        with patch.object(relay, "WEBHOOK_MAX_BYTES", exact - 1):
            self.assertEqual(r.once(["grok"], 0)[0]["state"], OVERSIZE)
        self.assertEqual(self.calls, [])


class SendGrokBytesTest(unittest.TestCase):
    URL = "https://webhook.example.invalid/hook/test-route"
    MSG = {"id": "m1", "from": "claude", "to": "grok", "reply_to": None, "body": "тест \"q\"", "delivery": None}

    def setUp(self):
        self.env = patch.dict(os.environ, {"GROKBOT_WEBHOOK_URL": self.URL, "GROKBOT_WEBHOOK_KEY": "test-key"})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_sends_exactly_the_measured_bytes(self):
        sent = []

        def fake_urlopen(request, timeout):
            sent.append(request.data)
            response = unittest.mock.MagicMock()
            response.__enter__.return_value = response
            response.status = 200
            response.read.return_value = b'{"success":true}'
            return response

        rid = "11111111-2222-3333-4444-555555555555"
        with patch("urllib.request.urlopen", fake_urlopen):
            relay.send_grok([self.MSG], rid, None)
        self.assertEqual(sent, [grok_payload([self.MSG], rid)])
        self.assertEqual(len(sent[0]), len(grok_payload([self.MSG], SIZING_REQUEST_ID)))

    def test_over_cap_raises_before_any_connection(self):
        with patch("urllib.request.urlopen") as opened, patch.object(relay, "WEBHOOK_MAX_BYTES", 100):
            with self.assertRaises(PayloadTooLarge) as caught:
                relay.send_grok([self.MSG], SIZING_REQUEST_ID, None)
        opened.assert_not_called()
        self.assertGreater(caught.exception.size, 100)

    def test_send_time_oversize_is_journaled_not_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            r = Relay(Path(td) / "state")
            post(r, "m", "x" * 300)
            # batching sees 1 byte, the real send sees 200: the send-time guard must still hold
            with patch("urllib.request.urlopen") as opened, patch.object(relay, "WEBHOOK_MAX_BYTES", 100), \
                    patch.object(relay, "grok_payload", side_effect=[b"x", b"x" * 200]):
                out = r.once(["grok"], 0)
            opened.assert_not_called()
            self.assertEqual((out[0]["state"], out[0]["sent"]), (OVERSIZE, False))


if __name__ == "__main__":
    unittest.main()
