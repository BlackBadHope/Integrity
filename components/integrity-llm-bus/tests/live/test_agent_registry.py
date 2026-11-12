import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import agent_registry as ar
from local_cli import main as cli
from relay import Relay

T1 = "a0000001-b001-7001-8001-c00000000001"
T2 = "a0000002-b002-7002-8002-c00000000002"
FC = "a0000003-b003-7003-8003-c00000000003"


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        self.state.mkdir()
        (self.state / "relay-threads.json").write_text(json.dumps({"codexfc": FC}), encoding="utf-8")
        # relay checks ~/.codex/archived_sessions for codex targets; point it at the tempdir
        env = patch.dict(os.environ, {"AGENTBUS_CODEX_HOME": str(Path(self.td.name) / "codex-home")})
        env.start()
        self.addCleanup(env.stop)

    def tearDown(self):
        self.td.cleanup()

    def test_register_idempotent_and_conflicts(self):
        e, again = ar.register("codexops", T1, topic="ops audit", state_dir=self.state)
        self.assertFalse(again); self.assertEqual(e["topic"], "ops audit"); self.assertIn("registered_at", e)
        e2, again = ar.register("codexops", T1, state_dir=self.state)
        self.assertTrue(again); self.assertEqual(e2["registered_at"], e["registered_at"])
        for addr, thr in (("codexops", T2), ("other", T1), ("codexfc", T2), ("x2", FC), ("A", T2), ("a_b", T2), ("a" * 33, T2)):
            with self.assertRaises(ValueError):
                ar.register(addr, thr, state_dir=self.state)
        with self.assertRaises(ValueError):
            ar.register("ok-name", "not-a-uuid", state_dir=self.state)
        self.assertEqual(ar.all_agents(self.state), ar.BUILTIN + (ar.OWNER, "codexops"))

    def test_builtins_unchanged_without_registry(self):
        self.assertEqual(ar.all_agents(self.state), ("codex", "claude", "grok", "codexfc", "owner"))

    def test_antigravity_model_addresses_are_separate_passive_mailboxes(self):
        argon, _ = ar.register("gemini-argon", T1, harness="gemini", state_dir=self.state)
        claude, _ = ar.register("claude-antigravity", T2, harness="antigravity", state_dir=self.state)
        self.assertEqual(argon["thread"], T1)
        self.assertEqual(claude["thread"], T2)
        self.assertNotIn("gemini-argon", ar.codex_threads(self.state))
        self.assertNotIn("claude-antigravity", ar.codex_threads(self.state))
        self.assertEqual(Relay(self.state, senders={"grok": lambda *_: {}}).refresh_registry(), [])

    def test_cli_register_agents_send(self):
        sd = ["--state-dir", str(self.state)]
        self.assertEqual(cli(sd + ["register", "--address", "codexqos", "--thread", T1, "--topic", "QoS"]), 0)
        self.assertEqual(cli(sd + ["register", "--address", "codexqos", "--thread", T1]), 0)
        self.assertEqual(cli(sd + ["register", "--address", "codexqos2", "--thread", T1]), 2)
        self.assertEqual(cli(sd + ["agents"]), 0)
        body = Path(self.td.name) / "b.txt"; body.write_text("PING", encoding="utf-8")
        self.assertEqual(cli(sd + ["send", "--from", "grok", "--to", "codexqos", "--id", "p1", "--body-file", str(body)]), 0)
        self.assertEqual(cli(sd + ["send", "--from", "codexqos", "--to", "grok", "--id", "p2", "--body-file", str(body)]), 0)
        with self.assertRaises(SystemExit):
            cli(sd + ["send", "--from", "grok", "--to", "nobody", "--id", "p3", "--body-file", str(body)])

    def test_relay_delivers_to_registered_thread_by_uuid(self):
        ar.register("codexops", T1, state_dir=self.state)
        relay = Relay(self.state, senders={"grok": lambda *_: {}})
        calls = []
        import relay as relay_mod
        orig = relay_mod.send_codex
        relay_mod.send_codex = lambda m, r, thread, agent="codex": calls.append((thread, agent, [x["id"] for x in m])) or {"status": "queued"}
        try:
            self.assertEqual(relay.refresh_registry(), ["codexops"])
            relay.store.post({"id": "m1", "from": "grok", "to": "codexops", "body": "PING", "reply_to": None})
            out = relay.once(["codexops"], 0)
        finally:
            relay_mod.send_codex = orig
        self.assertEqual(out[0]["state"], "accepted"); self.assertEqual(out[0]["delivery"], "steer")
        self.assertEqual(calls, [(T1, "codexops", ["m1"])])
        self.assertEqual(relay.threads["codexfc"], FC)

    def test_http_register_and_agents(self):
        import threading, urllib.request, urllib.error
        from bus import create_server
        st = Path(self.td.name) / "http-state"
        s = create_server(st, {"codex": "c" * 30, "claude": "l" * 30, "grok": "g" * 30}, 0)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        def call(method, path, body=None):
            req = urllib.request.Request(f"http://127.0.0.1:{s.server_port}{path}", method=method,
                                         data=json.dumps(body).encode() if body else None,
                                         headers={"Authorization": "Bearer " + "g" * 30, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req) as r: return r.status
            except urllib.error.HTTPError as e: return e.code
        try:
            self.assertEqual(call("POST", "/v1/register", {"address": "codexh", "thread": T1}), 201)
            self.assertEqual(call("POST", "/v1/register", {"address": "codexh", "thread": T1}), 200)
            self.assertEqual(call("POST", "/v1/register", {"address": "codexh2", "thread": T1}), 409)
            self.assertEqual(call("POST", "/v1/register", {"address": "Bad!", "thread": T2}), 400)
            self.assertEqual(call("GET", "/v1/agents"), 200)
            self.assertEqual(call("POST", "/v1/messages", {"id": "h1", "from": "grok", "to": "codexh", "body": "PING", "reply_to": None}), 201)
        finally:
            s.shutdown(); s.server_close()


if __name__ == "__main__":
    unittest.main()
