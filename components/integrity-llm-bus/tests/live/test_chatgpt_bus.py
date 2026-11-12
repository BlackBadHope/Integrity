"""Tests for ChatGPT Web adapter on LLM Bus."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import agent_registry as ar
import chatgpt_bus as cb
import reachability
from bus import create_server
from local_cli import open_store

T_CHATGPT = "00000000-0000-4000-8000-0000000000c1"  # chatgpt_thread_id in the test configuration
T_ARGON = "a0000008-b009-4009-8009-c00000000009"
T_CODEX = "a0000009-b00a-700a-a00a-c0000000000a"


class TestChatGPTBus(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        self.state.mkdir(parents=True)
        (self.state / "relay-threads.json").write_text(json.dumps({"codex": T_CODEX}), encoding="utf-8")
        self.store = open_store(self.state)

    def tearDown(self):
        try:
            self.td.cleanup()
        except Exception:
            pass

    def test_registration_and_reachability(self):
        entry, again = cb.ensure_registered(state_dir=self.state)
        self.assertFalse(again)
        self.assertEqual(entry["thread"], T_CHATGPT)
        self.assertEqual(entry["harness"], "chatgpt")

        # Second call is idempotent
        entry2, again2 = cb.ensure_registered(state_dir=self.state)
        self.assertTrue(again2)

        # Reachability assessment: chatgpt-web has route=pull and deliverable=True
        acc = reachability.assess("chatgpt-web", self.state)
        self.assertTrue(acc["deliverable"])
        self.assertEqual(acc["route"], "pull")

        # All agents includes chatgpt-web
        agents = ar.all_agents(self.state)
        self.assertIn("chatgpt-web", agents)

    def test_send_inbox_reply_ack_cycle(self):
        # Register chatgpt-web and argon
        cb.ensure_registered(state_dir=self.state)
        ar.register("argon-a96225a77a734cde", T_ARGON, harness="gemini", state_dir=self.state)

        # 1. Send message from argon to chatgpt-web
        body_to_web = json.dumps({
            "v": 1,
            "k": "task",
            "th": "integrity-seats-review",
            "need": "review",
            "data": {"question": "Hello ChatGPT Web, please review Integrity Seats design."},
        })
        m1 = self.store.post({
            "id": "argon-to-chatgpt-01",
            "from": "argon-a96225a77a734cde",
            "to": "chatgpt-web",
            "body": body_to_web,
            "reply_to": None,
            "delivery": "steer",
        })[0]

        # 2. Check inbox of chatgpt-web
        pending = cb.inbox(agent="chatgpt-web", status="pending", state_dir=self.state)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["id"], "argon-to-chatgpt-01")
        self.assertEqual(pending[0]["from"], "argon-a96225a77a734cde")

        # 3. Get full message
        full = cb.get_message("argon-to-chatgpt-01", agent="chatgpt-web", state_dir=self.state)
        self.assertIsNotNone(full)
        self.assertIn("Hello ChatGPT Web", full["body"])

        # 4. ACK original message
        acked = cb.ack("argon-to-chatgpt-01", agent="chatgpt-web", state_dir=self.state)
        self.assertIsNotNone(acked)
        self.assertEqual(acked["status"], "acked")

        # 5. Reply to the message
        reply_body = {
            "v": 1,
            "k": "verdict",
            "th": "integrity-seats-review",
            "need": "none",
            "data": {"verdict": "PASS", "note": "Integrity Seats design approved by ChatGPT Web."},
        }
        rep = cb.reply(
            to_msg_id="argon-to-chatgpt-01",
            body=reply_body,
            msg_id="chatgpt-reply-01",
            from_agent="chatgpt-web",
            state_dir=self.state,
        )
        self.assertEqual(rep["id"], "chatgpt-reply-01")
        self.assertEqual(rep["to"], "argon-a96225a77a734cde")
        self.assertEqual(rep["reply_to"], "argon-to-chatgpt-01")

        # 6. Check status of argon-to-chatgpt-01 (now replied)
        st = cb.message_status("argon-to-chatgpt-01", state_dir=self.state)
        self.assertEqual(st["message"]["status"], "replied")
        self.assertEqual(len(st["replies"]), 1)
        self.assertEqual(st["replies"][0]["id"], "chatgpt-reply-01")

        # 7. Check inbox pending is now empty
        pending_after = cb.inbox(agent="chatgpt-web", status="pending", state_dir=self.state)
        self.assertEqual(len(pending_after), 0)

        # 8. Check inbox all has 1 message
        all_msgs = cb.inbox(agent="chatgpt-web", status="all", state_dir=self.state)
        self.assertEqual(len(all_msgs), 1)

    def test_grok_wakeup_routing(self):
        cb.ensure_registered(state_dir=self.state)

        # 1. Default delivery to grok is steer
        body1 = {"v": 1, "k": "fyi", "th": "wake-test", "need": "none", "data": {"text": "hello grok default"}}
        res1 = cb.send(to="grok", body=body1, msg_id="chatgpt-grok-01", state_dir=self.state)
        self.assertEqual(res1["delivery"], "steer")

        # 2. Explicit queue to grok is automatically routed to steer (wakeup routing)
        body2 = {"v": 1, "k": "fyi", "th": "wake-test", "need": "none", "data": {"text": "hello grok queue"}}
        res2 = cb.send(to="grok", body=body2, delivery="queue", msg_id="chatgpt-grok-02", state_dir=self.state)
        self.assertEqual(res2["delivery"], "steer")

        # 3. Followup alias to grok is automatically routed to steer
        body3 = {"v": 1, "k": "fyi", "th": "wake-test", "need": "none", "data": {"text": "hello grok followup"}}
        res3 = cb.send(to="grok", body=body3, delivery="followup", msg_id="chatgpt-grok-03", state_dir=self.state)
        self.assertEqual(res3["delivery"], "steer")

        # 4. Replying to a message from grok with queue routes to steer
        # Post incoming message from grok to chatgpt-web
        grok_msg = {
            "id": "grok-to-chatgpt-01",
            "from": "grok",
            "to": "chatgpt-web",
            "body": json.dumps({"v": 1, "k": "question", "th": "wake-test", "need": "answer", "data": {"q": "ping"}}),
            "reply_to": None,
            "delivery": "steer",
        }
        self.store.post(grok_msg)

        reply_res = cb.reply(
            to_msg_id="grok-to-chatgpt-01",
            body={"v": 1, "k": "verdict", "th": "wake-test", "need": "none", "data": {"ans": "pong"}},
            delivery="queue",
            msg_id="chatgpt-grok-reply-01",
            state_dir=self.state,
        )
        self.assertEqual(reply_res["delivery"], "steer")
        self.assertEqual(reply_res["to"], "grok")

        # 5. Non-grok recipient (argon) still preserves queue delivery
        ar.register("argon-a96225a77a734cde", T_ARGON, harness="gemini", state_dir=self.state)
        argon_res = cb.send(
            to="argon-a96225a77a734cde",
            body={"v": 1, "k": "fyi", "th": "queue-test", "need": "none", "data": {"text": "queue for argon"}},
            delivery="queue",
            msg_id="chatgpt-argon-01",
            state_dir=self.state,
        )
        self.assertEqual(argon_res["delivery"], "queue")

        # 6. CLI send to grok with --delivery queue routes to steer
        sd = ["--state-dir", str(self.state)]
        cli_args = sd + [
            "send",
            "--to", "grok",
            "--id", "chatgpt-grok-cli-01",
            "--delivery", "queue",
            "--body", json.dumps({"v": 1, "k": "fyi", "th": "cli-test", "need": "none", "data": {"t": "cli"}}),
        ]
        self.assertEqual(cb.main(cli_args), 0)
        cli_msg = cb.get_message("chatgpt-grok-cli-01", state_dir=self.state)
        self.assertEqual(cli_msg["delivery"], "steer")

    def test_cli_interface(self):
        sd = ["--state-dir", str(self.state)]

        # CLI register
        self.assertEqual(cb.main(sd + ["register"]), 0)

        # Register peer
        ar.register("argon-a96225a77a734cde", T_ARGON, harness="gemini", state_dir=self.state)

        # CLI send
        send_args = sd + [
            "send",
            "--to", "argon-a96225a77a734cde",
            "--id", "chatgpt-cli-01",
            "--body", json.dumps({"v": 1, "k": "fyi", "th": "test", "need": "none", "data": {"text": "ping"}}),
        ]
        self.assertEqual(cb.main(send_args), 0)

        # CLI status
        self.assertEqual(cb.main(sd + ["status", "chatgpt-cli-01"]), 0)

        # CLI agents
        self.assertEqual(cb.main(sd + ["agents"]), 0)


if __name__ == "__main__":
    unittest.main()
