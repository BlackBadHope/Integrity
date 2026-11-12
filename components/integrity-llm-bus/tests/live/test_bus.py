"""Bounded loopback HTTP tests; no external network or LLM calls."""

from __future__ import annotations

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path

from bus import MAX_BODY_BYTES, MessageStore, create_server


TOKENS = {
    "codex": "codex-local-test-token-00000001",
    "claude": "claude-local-test-token-00000002",
    "grok": "grok-local-test-token-00000003",
}


class BusHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp.name) / "state"
        self.server = create_server(self.state_dir, TOKENS, port=0, ttl_hours=1)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def request(self, method: str, path: str, agent: str | None = None, payload: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {}
        if agent:
            headers["Authorization"] = f"Bearer {TOKENS[agent]}"
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read())
        code = response.status
        connection.close()
        return code, data

    @staticmethod
    def envelope(mid: str, sender: str = "codex", recipient: str = "claude", body: str = "hello", reply_to: str | None = None):
        return {"id": mid, "from": sender, "to": recipient, "body": body, "reply_to": reply_to}

    def test_auth_inbox_ack_and_persistence(self) -> None:
        message = self.envelope("m-1")
        self.assertEqual(self.request("POST", "/v1/messages", payload=message)[0], 401)
        code, created = self.request("POST", "/v1/messages", "codex", message)
        self.assertEqual(code, 201)
        self.assertEqual(created["message"]["status"], "pending")
        self.assertEqual(self.request("GET", "/v1/inbox", "codex")[1]["messages"], [])
        self.assertEqual(self.request("GET", "/v1/inbox", "claude")[1]["messages"][0]["id"], "m-1")
        # Reading again is not an ACK.
        self.assertEqual(self.request("GET", "/v1/inbox", "claude")[1]["messages"][0]["status"], "pending")
        self.assertEqual(self.request("POST", "/v1/messages/m-1/ack", "codex")[0], 404)
        self.assertEqual(self.request("POST", "/v1/messages/m-1/ack", "claude")[1]["message"]["status"], "acked")
        self.assertEqual(self.request("POST", "/v1/messages/m-1/ack", "claude")[1]["message"]["status"], "acked")
        repeated_code, repeated = self.request("POST", "/v1/messages", "codex", message)
        self.assertEqual((repeated_code, repeated["duplicate"], repeated["message"]["status"]), (200, True, "acked"))
        self.assertEqual(self.request("GET", "/v1/inbox", "claude")[1]["messages"], [])
        reopened = MessageStore(self.state_dir / "bus.sqlite3", 3600)
        self.assertEqual(reopened.inbox("claude", "acked", 10)[0]["id"], "m-1")

    def test_idempotency_and_conflict(self) -> None:
        message = self.envelope("same-id")
        self.assertEqual(self.request("POST", "/v1/messages", "codex", message)[0], 201)
        code, duplicate = self.request("POST", "/v1/messages", "codex", message)
        self.assertEqual((code, duplicate["duplicate"]), (200, True))
        self.assertEqual(self.request("POST", "/v1/messages", "codex", self.envelope("same-id", body="changed"))[0], 409)
        self.assertEqual(len(self.request("GET", "/v1/inbox", "claude")[1]["messages"]), 1)

    def test_reply_marks_parent_and_rejects_wrong_parent(self) -> None:
        self.request("POST", "/v1/messages", "codex", self.envelope("parent"))
        bad = self.envelope("bad", sender="grok", recipient="codex", reply_to="parent")
        self.assertEqual(self.request("POST", "/v1/messages", "grok", bad)[0], 400)
        reply = self.envelope("reply", sender="claude", recipient="codex", body="answer", reply_to="parent")
        self.assertEqual(self.request("POST", "/v1/messages", "claude", reply)[0], 201)
        self.assertEqual(self.request("GET", "/v1/inbox", "claude")[1]["messages"], [])
        self.assertEqual(self.request("GET", "/v1/inbox?status=replied", "claude")[1]["messages"][0]["id"], "parent")
        self.assertEqual(self.request("GET", "/v1/inbox", "codex")[1]["messages"][0]["id"], "reply")

    def test_limits_and_expiry(self) -> None:
        self.assertEqual(self.request("POST", "/v1/messages", "codex", self.envelope("too-large", body="x" * (MAX_BODY_BYTES + 1)))[0], 400)
        self.assertEqual(self.request("POST", "/v1/messages", "claude", self.envelope("spoofed"))[0], 400)
        self.assertEqual(self.request("GET", "/v1/inbox?limit=51", "claude")[0], 400)
        self.request("POST", "/v1/messages", "codex", self.envelope("expire"))
        with closing(sqlite3.connect(self.state_dir / "bus.sqlite3")) as db:
            with db:
                db.execute("UPDATE messages SET expires_at = 0 WHERE id = 'expire'")
        self.assertEqual(self.request("GET", "/v1/inbox", "claude")[1]["messages"], [])


if __name__ == "__main__":
    unittest.main()
