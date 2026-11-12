import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import bus
import local_cli


class QueuePagingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name) / "state"
        self.store = local_cli.open_store(self.state)

    def tearDown(self):
        self.temp.cleanup()

    def post(self, mid, target="grok"):
        self.store.post({"id": mid, "from": "codex", "to": target,
                         "body": "test metadata", "reply_to": None})

    def test_tail_is_visible_and_pages_do_not_overlap(self):
        for index in range(61):
            self.post(f"message-{index}")
        self.post("other-recipient", "claude")
        first = bus.queue_page(self.store, "grok")
        self.assertEqual(len(first["queue"]), 50)
        self.assertTrue(first["has_more"])
        second = bus.queue_page(self.store, "grok", after_seq=first["next_seq"])
        self.assertEqual([r["id"] for r in second["queue"]], [f"message-{i}" for i in range(50, 61)])
        self.assertFalse(second["has_more"])
        self.assertIsNone(second["next_seq"])
        self.assertEqual(len({r["id"] for r in first["queue"] + second["queue"]}), 61)

    def test_ack_and_expiry_between_pages_cannot_skip_tail(self):
        for index in range(6):
            self.post(f"message-{index}")
        first = bus.queue_page(self.store, "grok", limit=3)
        for row in first["queue"]:
            self.store.ack(row["id"], "grok")
        with self.store._connection() as db:
            db.execute("UPDATE messages SET expires_at=1 WHERE id='message-3'")
        second = bus.queue_page(self.store, "grok", limit=3, after_seq=first["next_seq"])
        self.assertEqual([r["id"] for r in second["queue"]], ["message-4", "message-5"])

    def test_empty_and_exact_limit_have_no_next_page(self):
        self.assertEqual(bus.queue_page(self.store, "grok"),
                         {"agent": "grok", "queue": [], "has_more": False, "next_seq": None})
        for index in range(3):
            self.post(f"message-{index}")
        page = bus.queue_page(self.store, "grok", limit=3)
        self.assertFalse(page["has_more"])
        self.assertIsNone(page["next_seq"])

    def test_queue_distinguishes_http_rejection_from_unverified_acceptance(self):
        self.post("rejected")
        self.post("accepted")
        journal = {"version": 1, "batches": {
            "bad": {"ids": ["rejected"], "state": "rejected", "error_type": "HTTPError", "http_status": 400},
            "good": {"ids": ["accepted"], "state": "accepted",
                     "receipt": {"http_status": 200, "execution_complete": False}}}}
        (self.state / "relay-journal.json").write_text(json.dumps(journal), encoding="utf-8")
        rows = bus.queue_page(self.store, "grok")["queue"]
        self.assertEqual((rows[0]["relay_state"], rows[0]["relay_http_status"], rows[0]["relay_error_type"]),
                         ("rejected", 400, "HTTPError"))
        self.assertEqual(rows[1]["relay_http_status"], 200)
        self.assertIs(rows[1]["execution_complete"], False)
        self.assertIsNone(rows[1]["application_verified"])

    def test_invalid_cursor_and_limit_are_rejected(self):
        for cursor in (-1, 2**63, True, "0"):
            with self.subTest(cursor=cursor), self.assertRaises(ValueError):
                bus.queue_page(self.store, "grok", after_seq=cursor)
        for limit in (0, 51, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                bus.queue_page(self.store, "grok", limit=limit)

    def test_cli_can_follow_cursor_and_does_not_ack_or_write_messages(self):
        for index in range(4):
            self.post(f"message-{index}")
        args = ["--state-dir", str(self.state), "queue", "--agent", "grok", "--limit", "2"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(local_cli.main(args), 0)
        first = json.loads(output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(local_cli.main(args + ["--after-seq", str(first["next_seq"])]), 0)
        self.assertEqual([r["id"] for r in json.loads(output.getvalue())["queue"]], ["message-2", "message-3"])
        self.assertEqual(len(self.store.inbox("grok", "pending", 50)), 4)


if __name__ == "__main__":
    unittest.main()
