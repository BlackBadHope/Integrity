"""Archived Codex recipients: no send, sender notified, registry/status marked."""
import json, os, tempfile, unittest
from pathlib import Path

import archived_detect
from relay import Relay

TID = "a0000004-b004-7004-b004-c00000000004"


class ArchivedDetectTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        self.home = root / "codex"
        os.environ["AGENTBUS_CODEX_HOME"] = str(self.home)
        self.state = root / "state"
        self.calls = []

    def tearDown(self):
        os.environ.pop("AGENTBUS_CODEX_HOME", None)
        self.td.cleanup()

    def rollout(self, sub):
        d = self.home / sub / "2026" / "10" / "21"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"rollout-2026-10-21T00-00-00-{TID}.jsonl").write_text("{}\n")

    def up(self, messages, rid, _t):
        self.calls.append([m["id"] for m in messages])
        return {"status": "inProgress"}

    def relay(self):
        r = Relay(self.state, senders={"codexfc": self.up})
        r.threads["codexfc"] = TID
        return r

    def post(self, r, mid):
        r.store.post({"id": mid, "from": "grok", "to": "codexfc", "body": "x", "reply_to": None})

    def test_detect(self):
        self.assertFalse(archived_detect.thread_archived(TID))
        self.rollout("archived_sessions")
        self.assertTrue(archived_detect.thread_archived(TID))
        self.rollout("sessions")
        self.assertFalse(archived_detect.thread_archived(TID))
        self.assertFalse(archived_detect.thread_archived(None))

    def test_archived_not_sent_and_sender_notified(self):
        self.rollout("archived_sessions")
        r = self.relay(); self.post(r, "m1")
        out = r.once(["codexfc"], 0)
        self.assertEqual(out[0]["state"], "recipient_archived")
        self.assertFalse(out[0]["sent"])
        self.assertEqual(self.calls, [])
        inbox = r.store.inbox("grok", "pending", 50)
        notice = [m for m in inbox if m["id"] == "relay-archived-m1"][0]
        body = json.loads(notice["body"])
        self.assertEqual(body["data"]["delivery_status"], "recipient_archived")
        self.assertIsNone(notice["reply_to"])
        self.assertEqual(notice["from"], archived_detect.SYSTEM_SENDER)
        self.assertEqual(notice["from"], "bus-relay")
        self.assertEqual((body["k"], body["data"]["re"]), ("fyi", "m1"))
        orig = [m for m in r.store.inbox("codexfc", "all", 50) if m["id"] == "m1"][0]
        self.assertEqual(orig["status"], "pending")  # original untouched, not marked replied
        st = archived_detect.load_status(self.state)
        self.assertEqual(st["archived"]["codexfc"]["thread"], TID)

    def test_no_retry_loop_and_idempotent(self):
        self.rollout("archived_sessions")
        r = self.relay(); self.post(r, "m1")
        r.once(["codexfc"], 0); self.assertEqual(r.once(["codexfc"], 0), [])
        self.assertEqual(len([m for m in r.store.inbox("grok", "pending", 50) if m["id"].startswith("relay-archived-")]), 1)

    def test_live_thread_delivers_and_unmarks(self):
        self.rollout("archived_sessions")
        r = self.relay(); self.post(r, "m1"); r.once(["codexfc"], 0)
        self.rollout("sessions")  # unarchived
        self.post(r, "m2")
        out = r.once(["codexfc"], 0)
        self.assertEqual(out[0]["state"], "accepted")
        self.assertEqual(self.calls, [["m2"]])
        self.assertNotIn("codexfc", archived_detect.load_status(self.state)["archived"])

    def test_non_codex_untouched(self):
        self.rollout("archived_sessions")
        r = Relay(self.state, senders={"grok": self.up})
        r.store.post({"id": "g1", "from": "claude", "to": "grok", "body": "x", "reply_to": None})
        self.assertEqual(r.once(["grok"], 0)[0]["state"], "accepted")

    def test_notice_is_valid_agent_bus_1(self):
        import agentbus_validate as v
        self.rollout("archived_sessions")
        r = self.relay(); self.post(r, "m1"); r.once(["codexfc"], 0)
        notice = [m for m in r.store.inbox("grok", "pending", 50) if m["id"] == "relay-archived-m1"][0]
        errors = v.validate(notice["body"])
        self.assertFalse(errors)

    def test_bus_relay_reserved_and_not_addressable(self):
        import agent_registry as ar
        with self.assertRaises(ValueError):
            ar.register("bus-relay", TID, "codex", "", self.state)
        self.assertNotIn("bus-relay", ar.all_agents(self.state))


if __name__ == "__main__":
    unittest.main()
