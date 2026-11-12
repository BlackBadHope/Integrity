import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from grok_cache import read_envelopes


class LocalAdaptersTest(unittest.TestCase):
    def test_cli_real_persistence_reply_and_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            state = base / "state"
            body = base / "body.txt"
            body.write_text("Проверка", encoding="utf-8")
            def run(*args, expected=0):
                result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[2] / "src" / "integrity_llm_bus" / "resources" / "local_cli.py"),
                                         "--state-dir", str(state), *args], capture_output=True, encoding="utf-8")
                self.assertEqual(result.returncode, expected, result.stderr)
                return json.loads(result.stdout) if expected == 0 else None
            run("send", "--from", "codex", "--to", "claude", "--id", "ping", "--body-file", str(body))
            self.assertEqual(run("inbox", "--agent", "claude")["messages"][0]["body"], "Проверка")
            self.assertTrue(run("send", "--from", "codex", "--to", "claude", "--id", "ping", "--body-file", str(body))["duplicate"])
            body.write_text("PONG", encoding="utf-8")
            run("send", "--from", "codex", "--to", "claude", "--id", "ping", "--body-file", str(body), expected=2)
            run("send", "--from", "claude", "--to", "codex", "--id", "pong", "--reply-to", "ping", "--body-file", str(body))
            result = run("status", "--id", "ping")
            self.assertEqual(result["message"]["status"], "replied")
            self.assertEqual(result["replies"][0]["id"], "pong")
            self.assertNotIn("body", result["message"])

    def test_cache_filters_sender_marker_and_cursor(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cache.blob"
            envelope = {"id": "grok-pong", "from": "grok", "to": "codex", "body": "PONG", "reply_to": "ping"}
            entries = [{"id": "a", "seq": 1, "kind": "message", "message": {"type": "text", "content": "private user text"}},
                       {"id": "b", "seq": 2, "kind": "send-message", "message": {"type": "text", "content": "LLM_BUS_BEGIN\n" + json.dumps(envelope) + "\nLLM_BUS_END"}}]
            p.write_text(json.dumps({"schemaVersion": 1, "value": {"entries": entries}}), encoding="utf-8")
            values, seq, seen = read_envelopes(p, 1, set())
            self.assertEqual(values, [envelope])
            self.assertEqual(read_envelopes(p, seq, seen)[0], [])
            envelope["from"] = "claude"
            entries[1]["message"]["content"] = "LLM_BUS_BEGIN" + json.dumps(envelope) + "LLM_BUS_END"
            p.write_text(json.dumps({"schemaVersion": 1, "value": {"entries": entries}}), encoding="utf-8")
            self.assertEqual(read_envelopes(p, 1, set())[0], [])


if __name__ == "__main__":
    unittest.main()
