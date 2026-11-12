"""agent-bus/1 validator: valid body per kind, every rejection path, 4 KB limit, Cyrillic rules, CLI exit codes."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentbus_validate import MAX_BODY_BYTES, validate

HERE = Path(__file__).resolve().parents[2] / "src" / "integrity_llm_bus" / "resources"
SHA = "6fd0212772e29effede48a4f591987401418f75adcfcf32172e0190f96800827"


def body(**fields):
    return json.dumps({"v": 1, **fields}, ensure_ascii=False, separators=(",", ":"))


class ValidTest(unittest.TestCase):
    def test_minimal_ack(self):
        self.assertEqual(validate(body(k="ack")), [])

    def test_every_kind(self):
        for kind in ("task", "report", "verdict", "ack", "question", "decision", "cancel", "fyi"):
            with self.subTest(kind=kind):
                self.assertEqual(validate(body(k=kind)), [])

    def test_full_verdict(self):
        text = body(k="verdict", th="AGENTBUS-P0", need="none", st="PARTIAL", sup="old-id-1",
                    by="2026-01-02T12:00+03:00",
                    dec={"id": "dec-20260102-01", "src": "example-chat", "by": "operator", "ts": "2026-01-02T07:08+03:00",
                         "text": "Сравни два формата сообщений"},
                    chk={"zip": "PASS", "cfg": "UNKNOWN:writer not found", "deploy": "BLOCKED:needs GO"},
                    ev=[{"p": "D:/x/MANIFEST.sha256", "sha256": SHA}], note="Кириллица в note разрешена",
                    data={"tokens": {"o200k": 424}, "свободно": "любое"})
        self.assertEqual(validate(text), [])

    def test_ptr_for_large_content(self):
        self.assertEqual(validate(body(k="report", ptr={"p": "D:/x/big.json", "sha256": SHA})), [])

    def test_exactly_limit(self):
        base = body(k="fyi", data={"pad": ""})
        pad = MAX_BODY_BYTES - len(base.encode("utf-8"))
        self.assertEqual(validate(body(k="fyi", data={"pad": "x" * pad})), [])


class InvalidTest(unittest.TestCase):
    def assertRejects(self, text, fragment):
        errors = validate(text)
        self.assertTrue(errors, "expected rejection")
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_not_json(self):
        self.assertRejects("k=ack", "not valid JSON")

    def test_not_object(self):
        self.assertRejects("[1]", "must be a JSON object")

    def test_over_limit_points_to_ptr(self):
        self.assertRejects(body(k="fyi", data={"pad": "x" * MAX_BODY_BYTES}), "send ptr")

    def test_cyrillic_counts_bytes_not_chars(self):
        self.assertRejects(body(k="fyi", data={"pad": "я" * (MAX_BODY_BYTES // 2)}), "bytes >")

    def test_missing_version(self):
        self.assertRejects(json.dumps({"k": "ack"}), "$.v")

    def test_unknown_kind(self):
        self.assertRejects(body(k="reply"), "$.k")

    def test_unknown_top_key(self):
        self.assertRejects(body(k="report", crit=["x"]), "put kind-specific fields under data")

    def test_db_columns_not_allowed(self):
        self.assertRejects(body(k="ack", re="some-id"), "unknown keys")

    def test_bad_need_and_status(self):
        self.assertRejects(body(k="task", need="act"), "$.need")
        self.assertRejects(body(k="report", st="OK"), "$.st")

    def test_truncated_hash(self):
        self.assertRejects(body(k="report", ev=[{"p": "D:/x", "sha256": SHA[:8]}]), "full lowercase 64-hex")

    def test_uppercase_hash(self):
        self.assertRejects(body(k="report", ev=[{"p": "D:/x", "sha256": SHA.upper()}]), "64-hex")

    def test_too_many_evidence(self):
        self.assertRejects(body(k="report", ev=[{"p": "D:/x", "sha256": SHA}] * 9), "prefer one manifest")

    def test_check_value_format(self):
        self.assertRejects(body(k="verdict", chk={"zip": "ok"}), "STATUS or STATUS:detail")
        self.assertRejects(body(k="verdict", chk={"zip": "PASS:совпало"}), "STATUS or STATUS:detail")

    def test_note_too_long(self):
        self.assertRejects(body(k="fyi", note="x" * 201), "$.note")

    def test_decision_needs_source(self):
        self.assertRejects(body(k="decision", dec={"text": "GO"}), "$.dec.src")

    def test_decision_source_ascii(self):
        self.assertRejects(body(k="decision", dec={"src": "чат Grok"}), "non-ASCII")

    def test_bad_thread_and_deadline(self):
        self.assertRejects(body(k="task", th="has space"), "$.th")
        self.assertRejects(body(k="task", by="tomorrow"), "$.by")

    def test_data_must_be_object(self):
        self.assertRejects(body(k="fyi", data=[1]), "$.data")


class EdgeProbeTest(unittest.TestCase):
    """Inputs found by codex-grok-a0000005 validator-probe: must be rejected, never raise or pass."""

    def assertRejects(self, text, fragment):
        errors = validate(text)
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_kind_need_status_as_array_or_object(self):
        for key in ("k", "need", "st"):
            for value in (["ack"], {"a": 1}, 1, None):
                with self.subTest(key=key, value=value):
                    fields = {"k": "ack", key: value}
                    self.assertRejects(json.dumps({"v": 1, **fields}), f"$.{key}")

    def test_version_bool_or_float(self):
        self.assertRejects('{"v":true,"k":"ack"}', "$.v")
        self.assertRejects('{"v":1.0,"k":"ack"}', "$.v")
        self.assertRejects('{"v":"1","k":"ack"}', "$.v")

    def test_duplicate_keys_top_and_nested(self):
        self.assertRejects('{"v":1,"k":"ack","k":"task"}', "duplicate key 'k'")
        self.assertRejects('{"v":1,"k":"fyi","data":{"a":1,"a":2}}', "duplicate key 'a'")

    def test_non_standard_constants(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                self.assertRejects('{"v":1,"k":"fyi","data":{"x":%s}}' % constant, "non-standard JSON constant")

    def test_overflowing_number(self):
        self.assertRejects('{"v":1,"k":"fyi","data":{"x":1e999}}', "not finite")
        self.assertEqual(validate('{"v":1,"k":"fyi","data":{"x":1.5e10}}'), [])

    def test_lone_surrogate_in_value_and_key(self):
        self.assertRejects('{"v":1,"k":"fyi","note":"\\ud800"}', "$.note: unpaired")
        self.assertRejects('{"v":1,"k":"fyi","data":{"\\udfff":1}}', "unpaired")
        self.assertEqual(validate('{"v":1,"k":"fyi","note":"\\ud83d\\ude42"}'), [])  # valid pair

    def test_impossible_deadline(self):
        self.assertRejects(body(k="task", by="2026-99-99T25:99+99:99"), "$.by")
        self.assertRejects(body(k="task", by="2026-02-30T10:00Z"), "$.by")
        self.assertEqual(validate(body(k="task", by="2026-02-28T23:59:59+03:00")), [])

    def test_decision_by_and_ts_types(self):
        self.assertRejects(body(k="decision", dec={"src": "example-chat", "ts": []}), "$.dec.ts")
        self.assertRejects(body(k="decision", dec={"src": "example-chat", "by": False}), "$.dec.by")

    def test_note_counts_code_points(self):
        self.assertEqual(validate(body(k="fyi", note="🙂" * 200)), [])
        self.assertRejects(body(k="fyi", note="🙂" * 201), "$.note")

    def test_deep_nesting_is_rejected_not_crashed(self):
        from agentbus_validate import MAX_DEPTH

        def nested(levels, as_list):
            value = 1
            for _ in range(levels):
                value = [value] if as_list else {"a": value}
            return value

        for as_list in (True, False):
            with self.subTest(as_list=as_list):
                # these levels still fit in 4096 bytes: the explicit limit, not the size cap, must reject them
                levels = 2000 if as_list else 600
                text = json.dumps({"v": 1, "k": "fyi", "data": {"x": nested(levels, as_list)}}, separators=(",", ":"))
                self.assertLessEqual(len(text.encode()), MAX_BODY_BYTES)
                self.assertRejects(text, "nesting deeper than")
                # body object = level 1, data = level 2: data may hold MAX_DEPTH-2 more containers
                ok = body(k="fyi", data={"x": nested(MAX_DEPTH - 2, as_list)})
                self.assertEqual(validate(ok), [])
                self.assertRejects(body(k="fyi", data={"x": nested(MAX_DEPTH - 1, as_list)}), "nesting deeper than")


class CliTest(unittest.TestCase):
    def run_cli(self, text):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "b.json"
            path.write_text(text, encoding="utf-8")
            return subprocess.run([sys.executable, "-B", str(HERE / "agentbus_validate.py"), str(path)],
                                  capture_output=True, text=True, encoding="utf-8")

    def test_valid_exit_zero(self):
        result = self.run_cli(body(k="ack"))
        self.assertEqual((result.returncode, result.stdout), (0, ""))

    def test_invalid_exit_two_with_paths(self):
        result = self.run_cli(body(k="nope", st="OK"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("$.k", result.stdout)
        self.assertIn("$.st", result.stdout)


class SchemaParityTest(unittest.TestCase):
    def test_schema_enums_match_validator(self):
        schema = json.loads((HERE / "agent-bus-1.schema.json").read_text(encoding="utf-8"))
        from agentbus_validate import KINDS, NEEDS, STATUSES, TOP_KEYS
        self.assertEqual(set(schema["properties"]["k"]["enum"]), KINDS)
        self.assertEqual(set(schema["properties"]["need"]["enum"]), NEEDS)
        self.assertEqual(tuple(schema["$defs"]["status"]["enum"]), STATUSES)
        self.assertEqual(set(schema["properties"]), TOP_KEYS)
        self.assertEqual(schema["required"], ["v", "k"])


if __name__ == "__main__":
    unittest.main()
