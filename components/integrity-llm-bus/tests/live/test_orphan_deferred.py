"""A deferred batch whose id set grows is retired, never orphaned; nothing is sent twice."""
import tempfile
import unittest
from pathlib import Path

import bus
from relay import NotSent, Relay


def post(r, mid, to="codexfc"):
    r.store.post({"id": mid, "from": "claude", "to": to, "body": "x", "reply_to": None})


def down(*_):
    raise NotSent("host_link_down")


class OrphanDeferredTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        self.calls = []

    def tearDown(self):
        self.td.cleanup()

    def up(self, messages, rid, _thread):
        self.calls.append([m["id"] for m in messages])
        return {"status": "inProgress"}

    def by_state(self, r, state):
        return [k for k, v in r.journal["batches"].items() if v.get("target") == "codexfc" and v.get("state") == state]

    def test_grown_set_supersedes_old_deferred(self):
        r = Relay(self.state, senders={"codexfc": down})
        post(r, "a")
        first = r.once(["codexfc"], 0)[0]["request_id"]
        post(r, "b")
        second = r.once(["codexfc"], 0)[0]["request_id"]
        self.assertNotEqual(first, second)
        self.assertEqual(self.by_state(r, "deferred"), [second])
        self.assertEqual(self.by_state(r, "superseded"), [first])
        self.assertEqual(r.journal["batches"][first]["superseded_by"], second)

    def test_delivery_after_supersede_sends_each_id_once(self):
        r = Relay(self.state, senders={"codexfc": down})
        post(r, "a"); r.once(["codexfc"], 0)
        post(r, "b"); r.once(["codexfc"], 0)
        r.senders["codexfc"] = self.up
        out = r.once(["codexfc"], 0)
        self.assertEqual(out[0]["state"], "accepted")
        self.assertEqual(self.calls, [["a", "b"]])
        self.assertEqual(r.once(["codexfc"], 0), [])
        self.assertEqual(self.by_state(r, "deferred"), [])

    def test_superseded_ids_stay_eligible_after_reopen(self):
        r = Relay(self.state, senders={"codexfc": down})
        post(r, "a"); r.once(["codexfc"], 0)
        post(r, "b"); r.once(["codexfc"], 0)
        reopened = Relay(self.state, senders={"codexfc": self.up})
        reopened.once(["codexfc"], 0)
        self.assertEqual(self.calls, [["a", "b"]])

    def test_superseded_does_not_burn_hourly_quota(self):
        r = Relay(self.state, senders={"codexfc": down})
        post(r, "a"); r.once(["codexfc"], 0, max_calls=1)
        post(r, "b"); r.once(["codexfc"], 0, max_calls=1)
        r.senders["codexfc"] = self.up
        self.assertEqual(r.once(["codexfc"], 0, max_calls=1)[0]["state"], "accepted")

    def test_other_targets_untouched(self):
        r = Relay(self.state, senders={"codexfc": down, "grok": down})
        post(r, "g", "grok"); r.once(["grok"], 0)
        post(r, "a"); r.once(["codexfc"], 0)
        post(r, "b"); r.once(["codexfc"], 0)
        grok = [v["state"] for v in r.journal["batches"].values() if v.get("target") == "grok"]
        self.assertEqual(grok, ["deferred"])

    def test_subset_attempt_keeps_uncovered_batch_live(self):
        r = Relay(self.state, senders={"codexfc": down})
        post(r, "a"); post(r, "b")
        both = r.once(["codexfc"], 0)[0]["request_id"]
        only_a = r.once(["codexfc"], 0, only_ids={"a"})[0]["request_id"]
        self.assertEqual(sorted(self.by_state(r, "deferred")), sorted([both, only_a]))
        view = {m["id"]: m for m in bus.queue_view(r.store, "codexfc")}
        self.assertEqual((view["b"]["relay_batch"], view["b"]["relay_state"]), (both, "deferred"))
        post(r, "c")
        grown = r.once(["codexfc"], 0)[0]["request_id"]
        self.assertEqual(self.by_state(r, "deferred"), [grown])

    def test_queue_view_shows_live_batch(self):
        r = Relay(self.state, senders={"codexfc": down})
        post(r, "a"); r.once(["codexfc"], 0)
        post(r, "b"); live = r.once(["codexfc"], 0)[0]["request_id"]
        view = {m["id"]: m for m in bus.queue_view(r.store, "codexfc")}
        self.assertEqual(view["a"]["relay_batch"], live)
        self.assertEqual(view["a"]["relay_state"], "deferred")


if __name__ == "__main__":
    unittest.main()
