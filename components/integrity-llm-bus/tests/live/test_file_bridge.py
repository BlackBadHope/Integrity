import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import file_bridge
from local_cli import open_store


class MirrorTest(unittest.TestCase):
    def test_two_way_reply_and_repeated_pass_has_no_echo(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            files = root / "files"
            (files / "messages").mkdir(parents=True)
            mirror_state = root / "mirror"
            mirror_state.mkdir()
            store = open_store(root / "sqlite")
            with patch.multiple(file_bridge, FILE_ROOT=files, BSTATE=mirror_state,
                                STATE_F=mirror_state / "bridge.json", LOG_F=mirror_state / "bridge.log"):
                store.post({"id": "out", "from": "codex", "to": "claude", "body": "PING", "reply_to": None})
                self.assertEqual(file_bridge.one_pass(store), (0, 1))
                incoming = {"id": "return", "ts": "2026-10-09T01:00:00Z", "from": "claude", "to": "codex",
                            "body": "PONG", "reply_to": "s.out"}
                (files / "messages" / "reply.json").write_text(json.dumps(incoming), encoding="utf-8")
                self.assertEqual(file_bridge.one_pass(store), (1, 0))
                reply = store.inbox("codex", "pending", 10)[0]
                self.assertEqual(reply["reply_to"], "out")
                self.assertEqual(file_bridge.one_pass(store), (0, 0))
                self.assertEqual(file_bridge.one_pass(store), (0, 0))
                self.assertEqual(len(list((files / "messages").glob("*.json"))), 2)
                self.assertEqual(len(store.inbox("codex", "all", 10)), 1)
                self.assertEqual(store.inbox("claude", "all", 10)[0]["status"], "replied")


if __name__ == "__main__":
    unittest.main()
