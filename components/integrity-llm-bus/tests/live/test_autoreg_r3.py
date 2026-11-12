"""autoreg r3: reproductions of codex-ra's interleavings + Claude review notes N1/N2."""
import importlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_registry as ar
import autoreg
import local_cli
import registry_db as rdb

A = "11111111-1111-4111-8111-111111111111"
B = "22222222-2222-4222-8222-222222222222"
C = "33333333-3333-4333-8333-333333333333"
S = "a0000006-b007-4007-8007-c00000000007"


def names(state):
    return sorted(json.loads((state / "agents-registry.json").read_text(encoding="utf-8"))["agents"])


class R3Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        self.store = local_cli.open_store(self.state)

    def tearDown(self):
        self.td.cleanup()


class StaleExportTest(R3Base):
    def setUp(self):
        super().setUp()
        rdb.migrate(self.state, backup=False)
        ar.register("fixture-a", A, "codex", "a", self.state)

    def test_codex_ra_interleaving_no_stale_overwrite(self):
        """codex-ra P1#1: A snapshots, B commits+publishes, A publishes. r2 lost fixture-b in JSON."""
        original = rdb.os.replace
        workers, errors = [], []

        def writer():
            try:
                ar.register("fixture-b", B, "codex", "b", self.state)
            except BaseException as exc:  # reported via assertion
                errors.append(repr(exc))

        def publish(src, dst):
            if not workers:
                t = threading.Thread(target=writer); workers.append(t); t.start()
            return original(src, dst)

        # A: a committed mutation whose export has not run yet (as in ensure()/upsert_doc()).
        con = rdb.connect(self.state); con.execute("BEGIN IMMEDIATE"); rdb.bump_generation(con); con.execute("COMMIT"); con.close()
        with patch.object(rdb.os, "replace", publish):
            self.assertTrue(rdb.export_json(self.state)["published"])
        self.assertEqual(len(workers), 1)
        for t in workers:
            t.join(5)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(rdb.load_doc(self.state)["agents"]), ["fixture-a", "fixture-b"])
        self.assertEqual(names(self.state), ["fixture-a", "fixture-b"])

    def test_late_export_is_noop_and_generation_monotonic(self):
        con = rdb.connect(self.state, readonly=True); g1 = rdb.generation(con); con.close()
        ar.register("fixture-b", B, "codex", "b", self.state)
        autoreg.ensure("codex", C, source="test", state_dir=self.state)
        con = rdb.connect(self.state, readonly=True); g2 = rdb.generation(con); con.close()
        self.assertGreater(g2, g1)
        before = (self.state / "agents-registry.json").read_bytes()
        r = rdb.export_json(self.state)  # a late/duplicate publisher
        self.assertEqual((r["published"], r["reason"]), (False, "up-to-date"))
        self.assertEqual((self.state / "agents-registry.json").read_bytes(), before)
        self.assertEqual(names(self.state), ["codex-33333333", "fixture-a", "fixture-b"])

    def test_missing_json_is_republished(self):
        (self.state / "agents-registry.json").unlink()
        self.assertTrue(rdb.export_json(self.state)["published"])
        self.assertEqual(names(self.state), ["fixture-a"])


class UnmigrateConcurrentTest(R3Base):
    def test_codex_ra_interleaving_commit_before_drop_survives(self):
        """codex-ra P1#2: writer commits, pauses before its export, rollback drops tables. r2 lost fixture-c."""
        rdb.migrate(self.state, backup=False)
        ar.register("fixture-a", A, "codex", "a", self.state)
        original_export = rdb.export_json
        committed, release = threading.Event(), threading.Event()
        errors, late = [], []

        def export(sd, *a, **k):
            if threading.current_thread().name == "fixture-writer":
                committed.set()
                release.wait(5)
                late.append(original_export(sd, *a, **k))
                return late[-1]
            return original_export(sd, *a, **k)

        def writer():
            try:
                ar.register("fixture-c", C, "codex", "c", self.state)
            except Exception as exc:
                errors.append(repr(exc))

        with patch.object(rdb, "export_json", export):
            w = threading.Thread(target=writer, name="fixture-writer"); w.start()
            self.assertTrue(committed.wait(5))
            r = rdb.unmigrate(self.state)
            release.set(); w.join(5)
        self.assertTrue(r["unmigrated"])
        self.assertFalse(rdb.migrated(self.state))
        self.assertEqual(errors, [])
        self.assertEqual(late, [{"published": False, "reason": "not-migrated"}])
        self.assertEqual(names(self.state), ["fixture-a", "fixture-c"])
        self.assertIn("fixture-c", ar.load(self.state))  # JSON-backed registry again

    def test_writer_queued_behind_rollback_fails_loudly(self):
        rdb.migrate(self.state, backup=False)
        holder = rdb.connect(self.state, timeout_ms=1000)
        holder.execute("BEGIN IMMEDIATE")
        res = {}
        t = threading.Thread(target=lambda: res.update(r=rdb.unmigrate(self.state, timeout_ms=5000))); t.start()
        holder.execute("COMMIT"); holder.close(); t.join(5)
        self.assertTrue(res["r"]["unmigrated"])
        # A writer that still believes the DB is authoritative cannot silently commit into dropped tables.
        con = rdb.connect(self.state)
        with self.assertRaises(Exception):
            con.execute("BEGIN IMMEDIATE"); rdb.bump_generation(con)
        con.close()

    def test_failed_publish_rolls_back(self):
        rdb.migrate(self.state, backup=False)
        ar.register("fixture-a", A, "codex", "a", self.state)
        with patch.object(rdb, "_publish", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                rdb.unmigrate(self.state)
        self.assertTrue(rdb.migrated(self.state))
        self.assertIn("fixture-a", rdb.load_doc(self.state)["agents"])


class ReviewNotesTest(R3Base):
    def test_n2_non_dict_first_line(self):
        for first in ("[]", "\"x\"", "5", "null", "[{\"type\":\"session_meta\"}]"):
            p = Path(self.td.name) / "rollout-x.jsonl"
            p.write_text(first + "\n", encoding="utf-8")
            self.assertIsNone(autoreg.interactive_codex_meta(p))

    def test_n2_discover_survives_non_dict_rollout(self):
        rdb.migrate(self.state, backup=False)
        root = Path(self.td.name) / "sessions"; d = root / "2026" / "10" / "22"; d.mkdir(parents=True)
        (d / "rollout-bad.jsonl").write_text("[1,2]\n", encoding="utf-8")
        self.assertEqual(autoreg.discover_codex(self.state, root), [])

    def test_n1_claude_hook_delivers_without_autoreg(self):
        ar.register("claude-lead", S, "claude", "", self.state)
        self.store.post({"id": "m-r3-1", "from": "grok", "to": "claude-lead", "body": "{}", "reply_to": None})
        sys.modules.pop("bus_claude_hook", None)
        with patch.dict(sys.modules, {"autoreg": None}):  # import autoreg -> ImportError
            hook = importlib.import_module("bus_claude_hook")
            self.assertIsNone(hook.autoreg)
            r = hook.collect({"session_id": S}, self.state)
        sys.modules.pop("bus_claude_hook", None)
        self.assertEqual([p["id"] for p in r["pointers"]], ["m-r3-1"])


if __name__ == "__main__":
    unittest.main()
