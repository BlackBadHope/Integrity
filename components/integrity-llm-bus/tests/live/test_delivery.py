import uuid
import json, sqlite3, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

import bus, local_cli, relay
from relay import Relay

THREAD = "a0000003-b003-7003-8003-c00000000003"


def msg(mid, delivery=None, to="codexfc", body="Subject line\nmore"):
    m = {"id": mid, "from": "grok", "to": to, "body": body, "reply_to": None}
    if delivery is not None:
        m["delivery"] = delivery
    return m


class DeliveryTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); self.state = Path(self.td.name) / "state"
        self.store = local_cli.open_store(self.state)

    def tearDown(self):
        self.td.cleanup()

    def test_validation_and_legacy_shape(self):
        self.assertNotIn("delivery", bus._validate_message(msg("a"), "grok"))
        self.assertEqual(bus._validate_message(msg("a", "steer"), "grok")["delivery"], "steer")
        with self.assertRaises(ValueError):
            bus._validate_message(msg("a", "now"), "grok")
        with self.assertRaises(ValueError):
            bus._validate_message({**msg("a"), "x": 1}, "grok")

    def test_migration_adds_nullable_column_and_keeps_rows(self):
        path = Path(self.td.name) / "old.sqlite3"
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, sender TEXT NOT NULL, recipient TEXT NOT NULL, body TEXT NOT NULL, reply_to TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, acked_at INTEGER, replied_at INTEGER)")
        db.execute("INSERT INTO messages (id,sender,recipient,body,created_at,expires_at) VALUES ('old','grok','codex','b',1,99999999999)")
        db.commit(); db.close()
        store = bus.MessageStore(path, 3600)
        bus.MessageStore(path, 3600)  # idempotent
        self.assertIsNone(store.inbox("codex", "pending", 5)[0]["delivery"])

    def test_store_roundtrip_and_conflict_on_changed_delivery(self):
        self.store.post(bus._validate_message(msg("s", "steer"), "grok"))
        self.assertEqual(self.store.inbox("codexfc", "pending", 5)[0]["delivery"], "steer")
        with self.assertRaises(FileExistsError):
            self.store.post(bus._validate_message(msg("s", "queue"), "grok"))

    def test_cli_send_and_queue_view(self):
        body = Path(self.td.name) / "b.txt"; body.write_text("PING one\nrest", encoding="utf-8")
        base = ["--state-dir", str(self.state)]
        self.assertEqual(local_cli.main(base + ["send", "--from", "grok", "--to", "codexfc", "--id", "q1", "--body-file", str(body), "--delivery", "steer"]), 0)
        self.assertEqual(local_cli.main(base + ["send", "--from", "grok", "--to", "codexfc", "--id", "q2", "--body-file", str(body)]), 0)
        q = bus.queue_view(self.store, "codexfc")
        self.assertEqual([(e["id"], e["delivery"], e["delivery_explicit"], e["subject"], e["relay_state"]) for e in q],
                         [("q1", "steer", True, "PING one", "not_notified"), ("q2", "steer", False, "PING one", "not_notified")])
        self.assertEqual(local_cli.main(base + ["queue", "--agent", "codexfc"]), 0)

    def test_relay_combines_implicit_and_explicit_steer(self):
        for m in (msg("a1", "steer"), msg("a2"), msg("a3", "steer")):
            self.store.post(bus._validate_message(m, "grok"))
        seen = []
        r = Relay(self.state, senders={"codexfc": lambda m, *_: seen.append([x["id"] for x in m]) or {"status": "queued"}})
        out = r.once(["codexfc"], min_gap=0)
        self.assertEqual(seen, [["a1", "a2", "a3"]]); self.assertEqual(out[0]["delivery"], "steer")
        self.assertEqual(r.once(["codexfc"], min_gap=0), [])
        self.assertEqual(r.journal["batches"][out[0]["request_id"]]["delivery"], "steer")
        self.assertEqual(bus.queue_view(self.store, "codexfc")[0]["relay_state"], "queued")

    def test_grok_target_preserves_requested_delivery(self):
        self.store.post(bus._validate_message(dict(msg("g1", "steer", to="grok"), **{"from": "codex"}), "codex"))
        r = Relay(self.state, senders={"grok": lambda *_: {"status": "ok"}})
        out = r.once(["grok"], min_gap=0)
        self.assertEqual(out[0]["delivery"], "steer"); self.assertNotIn("delivery_ignored", out[0])

    def test_send_codex_honors_mode(self):
        with patch("relay.wake_codex", return_value={"status": "inProgress"}) as w, \
             patch("relay.queue_codex", return_value={"status": "queued"}) as q:
            self.assertEqual(relay.send_codex([dict(msg("x"), delivery=None)], str(uuid.uuid4()), THREAD, "codexfc")["requested_delivery"], "steer")
            q.assert_not_called(); w.assert_called_once()
            self.assertEqual(relay.send_codex([msg("fresh", "queue")], str(uuid.uuid4()), THREAD, "codexfc")["requested_delivery"], "queue")
            q.assert_called_once()
            rec = relay.send_codex([dict(msg("y"), delivery="steer")], str(uuid.uuid4()), THREAD, "codexfc")
            self.assertEqual((rec["status"], rec["requested_delivery"]), ("inProgress", "steer"))
    def test_queue_boundary_preserves_message_order(self):
        for m in (msg("first"), msg("fresh", "queue"), msg("last", "steer")):
            self.store.post(bus._validate_message(m, "grok"))
        seen = []
        r = Relay(self.state, senders={"codexfc": lambda m, *_: seen.append([x["id"] for x in m]) or {"status": "ok"}})
        for expected in ("steer", "queue", "steer"):
            self.assertEqual(r.once(["codexfc"], min_gap=0)[0]["delivery"], expected)
        self.assertEqual(seen, [["first"], ["fresh"], ["last"]])

    def test_default_delivery_wakes_owner_and_mixed_batch_is_rejected(self):
        with patch("relay.wake_codex", return_value={"status": "inProgress"}) as w, patch("relay.queue_codex") as q:
            self.assertEqual(relay.send_codex([msg("unknown")], str(uuid.uuid4()), THREAD)["requested_delivery"], "steer")
            w.assert_called_once(); q.assert_not_called()
            with self.assertRaises(ValueError):
                relay.send_codex([msg("a"), msg("b", "queue")], str(uuid.uuid4()), THREAD)
    def test_prompt_hint_mentions_queue_and_delivery_without_body(self):
        p = relay.codex_prompts([dict(msg("h", body="SECRET body"), delivery="steer")], "codexfc")[0]
        self.assertIn("queue --agent <recipient>", p); self.assertIn("--delivery steer|queue", p)
        self.assertIn("do not duplicate", p); self.assertNotIn("SECRET", p); self.assertIn('"delivery": "steer"', p)


if __name__ == "__main__":
    unittest.main()
