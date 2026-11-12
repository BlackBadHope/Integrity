"""local_cli send --strict: agent-bus/1 bodies pass, invalid ones exit 2 before any DB write, default stays legacy."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import local_cli
from agentbus_validate import MAX_BODY_BYTES


class StrictSendTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.state = self.root / "state"
        self.n = 0

    def tearDown(self):
        self.td.cleanup()

    def send(self, text, strict=True):
        self.n += 1
        path = self.root / f"body{self.n}.txt"
        path.write_text(text, encoding="utf-8")
        args = ["--state-dir", str(self.state), "send", "--from", "claude", "--to", "grok",
                "--id", f"m{self.n}", "--body-file", str(path)] + (["--strict"] if strict else [])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = local_cli.main(args)
        return code, out.getvalue(), err.getvalue()

    def stored(self):
        return [m["id"] for m in local_cli.open_store(self.state).inbox("grok", "all", 50)]

    def test_strict_valid_is_stored(self):
        code, out, _ = self.send('{"v":1,"k":"ack"}')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["message"]["id"], "m1")
        self.assertEqual(self.stored(), ["m1"])

    def test_strict_invalid_exits_2_without_write(self):
        code, out, err = self.send('{"v":1,"k":"reply","st":"OK"}')
        self.assertEqual((code, out), (2, ""))
        report = json.loads(err)
        self.assertEqual((report["error"], report["protocol"]), ("SchemaError", "agent-bus/1"))
        self.assertTrue(any(e.startswith("$.k") for e in report["errors"]))
        self.assertTrue(any(e.startswith("$.st") for e in report["errors"]))
        self.assertEqual(self.stored(), [])

    def test_strict_rejects_prose(self):
        code, _, err = self.send("ACK id=x status=received")
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)
        self.assertEqual(self.stored(), [])

    def test_default_is_legacy_passthrough(self):
        code, _, _ = self.send("ACK id=x status=received; prose stays allowed without --strict", strict=False)
        self.assertEqual(code, 0)
        self.assertEqual(self.stored(), ["m1"])

    def test_utf8_byte_edge(self):
        base = '{"v":1,"k":"fyi","data":{"p":""}}'
        fits = base.replace('""', '"' + "я" * ((MAX_BODY_BYTES - len(base.encode("utf-8"))) // 2) + '"')
        pad = MAX_BODY_BYTES - len(fits.encode("utf-8"))
        fits = fits.replace('"}}', "x" * pad + '"}}')
        self.assertEqual(len(fits.encode("utf-8")), MAX_BODY_BYTES)
        self.assertEqual(self.send(fits)[0], 0)
        over = fits.replace('"}}', 'x"}}')
        code, _, err = self.send(over)
        self.assertEqual(code, 2)
        self.assertIn("send ptr", err)
        self.assertEqual(self.stored(), ["m1"])

    def test_probe_inputs_exit_2_without_write(self):
        for text in ('{"v":1,"k":["ack"]}', '{"v":true,"k":"ack"}', '{"v":1,"k":"ack","k":"task"}',
                     '{"v":1,"k":"fyi","data":{"x":NaN}}'):
            with self.subTest(text=text):
                code, out, err = self.send(text)
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(json.loads(err)["error"], "SchemaError")
        self.assertEqual(self.stored(), [])

    def test_validator_crash_still_rejects(self):
        import agentbus_validate
        original = agentbus_validate.validate
        agentbus_validate.validate = lambda text: 1 / 0
        try:
            code, _, err = self.send('{"v":1,"k":"ack"}')
        finally:
            agentbus_validate.validate = original
        self.assertEqual(code, 2)
        self.assertIn("validator error ZeroDivisionError", err)
        self.assertEqual(self.stored(), [])

    def test_bom_is_ignored(self):
        path = self.root / "bom.txt"
        path.write_bytes(b"\xef\xbb\xbf" + b'{"v":1,"k":"ack"}')
        args = ["--state-dir", str(self.state), "send", "--from", "claude", "--to", "grok",
                "--id", "bom", "--body-file", str(path), "--strict"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(local_cli.main(args), 0)


if __name__ == "__main__":
    unittest.main()
