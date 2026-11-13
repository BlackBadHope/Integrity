"""Auto-registration: unit, collision/concurrency, hook timeout/fail-open, discovery, routing."""
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_registry as ar
import autoreg
import autoreg_hook
import local_cli
import registry_db as rdb

HERE = Path(__file__).resolve().parents[2] / "src" / "integrity_llm_bus" / "resources"
A = "a0000005-b005-7005-8005-c00000000005"
B = "a0000005-b006-7006-8006-c00000000006"
C = "a0000006-b007-4007-8007-c00000000007"


class AutoregTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        self.store = local_cli.open_store(self.state)
        self.reg = self.state / "agents-registry.json"
        rdb.migrate(self.state, backup=False)

    def tearDown(self):
        self.td.cleanup()

    def test_ensure_creates_auto_entry_and_is_idempotent(self):
        r = autoreg.ensure("codex", A, source="test", state_dir=self.state)
        self.assertEqual((r["address"], r["created"], r["route"]), ("codex-a0000005", True, "pull"))
        e = ar.load(self.state)["codex-a0000005"]
        self.assertEqual((e["auto"], e["wake"], e["vendor"]), (True, False, "openai"))
        before = self.reg.read_bytes()
        again = autoreg.ensure("codex", A, source="test", state_dir=self.state)
        self.assertEqual((again["address"], again["fast"]), ("codex-a0000005", True))
        self.assertEqual(self.reg.read_bytes(), before)  # fast path wrote nothing

    def test_antigravity_dynamic_model_switch_keeps_seat_stable(self):
        tid = "a0000007-b008-4008-9008-c00000000008"
        # Turn 1: Gemini
        r1 = autoreg.ensure("antigravity", tid, source="hook:PreInvocation", model="gemini-3.8-flash-high", state_dir=self.state)
        self.assertEqual(r1["address"], "ag-a0000007")
        e1 = ar.load(self.state)["ag-a0000007"]
        self.assertEqual(e1["harness"], "antigravity")
        self.assertEqual(e1["vendor"], "google")
        self.assertEqual(e1["model"], "gemini-3.8-flash-high")

        # Turn 2: Switch model to Claude Opus 5.5 High inside the same thread
        r2 = autoreg.ensure("antigravity", tid, source="hook:PreInvocation", model="claude-opus-5-5-high", state_dir=self.state)
        self.assertEqual(r2["address"], "ag-a0000007")  # Seat is stable!
        self.assertFalse(r2.get("fast", False))          # Model change must not take fast path!
        e2 = ar.load(self.state)["ag-a0000007"]
        self.assertEqual(e2["harness"], "antigravity")   # Harness is preserved!
        self.assertEqual(e2["vendor"], "anthropic")      # Vendor dynamically updated!
        self.assertEqual(e2["model"], "claude-opus-5-5-high")

        # Turn 3: Switch back to Gemini 3.8 Flash High
        r3 = autoreg.ensure("antigravity", tid, source="hook:PreInvocation", model="gemini-3.8-flash-high", state_dir=self.state)
        self.assertEqual(r3["address"], "ag-a0000007")  # Seat is stable!
        self.assertFalse(r3.get("fast", False))
        e3 = ar.load(self.state)["ag-a0000007"]
        self.assertEqual(e3["harness"], "antigravity")
        self.assertEqual(e3["vendor"], "google")
        self.assertEqual(e3["model"], "gemini-3.8-flash-high")

        # Turn 4: Same model within heartbeat interval -> fast path
        r4 = autoreg.ensure("antigravity", tid, source="hook:PreInvocation", model="gemini-3.8-flash-high", state_dir=self.state)
        self.assertTrue(r4.get("fast"))

        # Missing data = unknown / None, no self-spoofing
        tid2 = "00000000-1111-2222-3333-444444444444"
        r_unk = autoreg.ensure("antigravity", tid2, source="discovery", model=None, state_dir=self.state)
        e_unk = ar.load(self.state)[r_unk["address"]]
        self.assertIsNone(e_unk.get("model"))
        self.assertIsNone(e_unk.get("vendor"))

    def test_heartbeat_never_changes_address_or_wake(self):
        ar.register("codex-grok-x", A, "codex", "explicit", self.state)
        r = autoreg.ensure("codex", A, source="t", state_dir=self.state, now=time.time())
        self.assertEqual((r["address"], r["created"], r["route"]), ("codex-grok-x", False, "wake"))
        e = ar.load(self.state)["codex-grok-x"]
        self.assertNotIn("wake", e); self.assertNotIn("auto", e); self.assertIn("last_seen", e)
        t0 = e["last_seen"]
        autoreg.ensure("codex", A, source="t", state_dir=self.state, now=t0 + 60)
        self.assertEqual(ar.load(self.state)["codex-grok-x"]["last_seen"], t0)  # < 10 min: no write
        autoreg.ensure("codex", A, source="t", state_dir=self.state, now=t0 + 700)
        self.assertEqual(ar.load(self.state)["codex-grok-x"]["last_seen"], int(t0 + 700))
        self.assertTrue((self.state / "agents-registry.json.prev").exists())

    def test_collision_extends_to_12_and_is_stored(self):
        a = autoreg.ensure("codex", A, source="t", state_dir=self.state)["address"]
        b = autoreg.ensure("codex", B, source="t", state_dir=self.state)["address"]
        self.assertEqual((a, b), ("codex-a0000005", "codex-a0000005b006"))
        self.assertEqual(autoreg.ensure("codex", B, source="t", state_dir=self.state, now=time.time() + 900)["address"], b)

    def test_concurrent_processes_one_entry_each(self):
        cmd = [sys.executable, "-B", str(HERE / "autoreg.py"), "--state-dir", str(self.state), "ensure", "--harness", "codex"]
        identities = (A, B, A, B)
        for _ in range(3):
            procs = [subprocess.Popen(cmd + ["--identity", i], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in identities]
            outs = [p.communicate(timeout=30) for p in procs]
            self.assertTrue(any(p.returncode == 0 for p in procs), outs)
            for identity, proc, (_, err) in zip(identities, procs, outs):
                if proc.returncode == 0:
                    continue
                # ensure waits LOCK_WAIT_MS for the registry lock and then gives up by design: a hook
                # must not hold a turn. A process that lost the wait exits with 2 and says so; nothing
                # else may fail. Its caller repeats it until the identity has its entry.
                self.assertEqual((proc.returncode, json.loads(err)), (2, {"error": "registry busy"}), outs)
                for _attempt in range(5):
                    again = subprocess.run(cmd + ["--identity", identity], capture_output=True, timeout=30, check=False)
                    if again.returncode == 0:
                        break
                    self.assertEqual(json.loads(again.stderr), {"error": "registry busy"})
                self.assertEqual(again.returncode, 0, again.stderr)
        agents = ar.load(self.state)
        self.assertEqual(sorted(e["thread"] for e in agents.values()), sorted([A, B]))

    def test_ensure_command_reports_a_held_registry_as_busy(self):
        cmd = [sys.executable, "-B", str(HERE / "autoreg.py"), "--state-dir", str(self.state), "ensure",
               "--harness", "codex", "--identity", A]
        con = rdb.connect(self.state, timeout_ms=2000)
        con.execute("BEGIN IMMEDIATE")
        try:
            held = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
        finally:
            con.execute("ROLLBACK")
            con.close()
        self.assertEqual((held.returncode, json.loads(held.stderr)), (2, {"error": "registry busy"}))
        self.assertEqual(ar.load(self.state), {})
        free = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
        self.assertEqual(free.returncode, 0, free.stderr)

    def test_hook_timeout_is_bounded_and_fail_open(self):
        with patch("autoreg.ensure", side_effect=lambda *a, **k: time.sleep(2)):
            t = time.monotonic()
            self.assertIsNone(autoreg.ensure_bounded("codex", A, state_dir=self.state, source="t"))
            self.assertLess(time.monotonic() - t, 0.6)
        with patch("autoreg.ensure", side_effect=RuntimeError("x")):
            self.assertIsNone(autoreg.ensure_bounded("codex", A, state_dir=self.state, source="t"))
        events = [json.loads(l)["event"] for l in (self.state / "autoreg.log").read_text().splitlines()]
        self.assertEqual(events, ["ensure-timeout", "ensure-failed"])

    def test_hook_main_never_fails(self):
        for raw in (b"", b"not json", b"[]", json.dumps({"session_id": "zzz"}).encode()):
            # Default state is this package's state/; keep even a failed ensure() log out of it.
            with patch.object(ar, "DEFAULT_STATE", self.state), patch("sys.stdin", io.TextIOWrapper(io.BytesIO(raw))):
                self.assertEqual(autoreg_hook.main(["--harness", "codex"]), 0)
        with patch.object(ar, "DEFAULT_STATE", self.state), \
             patch("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps({"session_id": C, "cwd": "D:\\x\\proj", "prompt": "SECRET-PROMPT"}).encode()))):
            self.assertEqual(autoreg_hook.main(["--harness", "claude"]), 0)
        self.assertIn("claude-a0000006", ar.load(self.state))
        self.assertNotIn("SECRET-PROMPT", self.reg.read_text(encoding="utf-8"))

    def test_fast_path_p95(self):
        autoreg.ensure("codex", A, source="t", state_dir=self.state)
        times = []
        for _ in range(100):
            t = time.perf_counter(); autoreg.ensure("codex", A, source="t", state_dir=self.state); times.append(time.perf_counter() - t)
        p95 = sorted(times)[94]
        print(f"\nfast-path p95 {p95*1000:.2f} ms", file=sys.stderr)
        self.assertLess(p95, 0.05)

    def test_discovery_interactive_only_first_line(self):
        root = Path(self.td.name) / "sessions" / "2026" / "10" / "22"; root.mkdir(parents=True)
        def roll(name, payload, extra=""):
            line = json.dumps({"type": "session_meta", "payload": payload})
            (root / f"rollout-{name}.jsonl").write_text(line + "\n" + extra, encoding="utf-8")
        roll("i", {"id": A, "originator": "Codex Desktop", "source": "vscode",
                   "cwd": "D:\\work\\project" if os.name == "nt" else "/work/project"}, '{"prompt":"SECRET-PROMPT"}\n')
        roll("e", {"id": B, "originator": "codex_exec", "source": "exec"})
        roll("s", {"id": "11111111-1111-4111-8111-111111111111", "originator": "Codex Desktop",
                   "source": {"subagent": {"thread_spawn": {"parent_thread_id": A}}}})
        roll("x", {"id": "22222222-2222-4222-8222-222222222222", "originator": "Codex Desktop", "source": "exec"})
        roll("old", {"id": "33333333-3333-4333-8333-333333333333", "originator": "Codex Desktop", "source": "vscode"})
        os.utime(root / "rollout-old.jsonl", (time.time() - 30 * 86400,) * 2)
        (root / "rollout-big.jsonl").write_text("x" * 70000, encoding="utf-8")
        out = autoreg.discover_codex(self.state, Path(self.td.name) / "sessions")
        self.assertEqual([o["address"] for o in out], ["codex-a0000005"])
        e = ar.load(self.state)["codex-a0000005"]
        self.assertEqual((e["wake"], e["source"], e["topic"]), (False, "discovery", "project codex"))
        self.assertNotIn("SECRET-PROMPT", self.reg.read_text(encoding="utf-8"))

    def test_routes_wake_owner_only_and_lease(self):
        now = time.time()
        autoreg.ensure("codex", A, source="t", state_dir=self.state, now=now)
        self.assertEqual(autoreg.route("grok", self.state)["route"], "webhook")
        self.assertEqual(autoreg.route("codex-a0000005", self.state, now)["route"], "pull")
        self.assertIn("codex-a0000005", autoreg.relay_excluded(self.state, now))
        autoreg.set_wake("codex-a0000005", True, self.state)
        self.assertEqual(autoreg.route("codex-a0000005", self.state, now)["route"], "wake")
        self.assertNotIn("codex-a0000005", autoreg.relay_excluded(self.state, now))
        autoreg.ensure("codex", A, source="t", state_dir=self.state, now=now + 900)
        self.assertTrue(ar.load(self.state)["codex-a0000005"]["wake"])  # ensure keeps wake
        later = now + 8 * 86400
        self.assertEqual(autoreg.route("codex-a0000005", self.state, later)["route"], "dormant")
        self.assertIn("codex-a0000005", autoreg.relay_excluded(self.state, later))
        autoreg.ensure("codex", A, source="t", state_dir=self.state, now=later)  # revives
        self.assertEqual(autoreg.route("codex-a0000005", self.state, later)["route"], "wake")

    def test_topic_and_identity_validation(self):
        moj = "сборка и инструкции".encode("utf-8").decode("cp1251")
        for bad in (moj, "x\ufffdy", "a" * 201):
            with self.assertRaises(ValueError):
                autoreg.ensure("codex", A, source="t", topic=bad, state_dir=self.state)
        with self.assertRaises(ValueError):
            autoreg.ensure("codex", "not-a-uuid", source="t", state_dir=self.state)
        self.assertEqual(autoreg.ensure("codex", A, source="t", topic="шина агентов", state_dir=self.state)["created"], True)

    def test_claude_hook_autoregisters_then_delivers(self):
        import bus_claude_hook
        self.store.post({"id": "early", "from": "grok", "to": "claude", "body": "x", "reply_to": None})
        r = bus_claude_hook.collect({"session_id": C}, self.state)
        self.assertEqual(r.get("addresses"), ["claude-a0000006"])
        self.store.post({"id": "m1", "from": "grok", "to": "claude-a0000006", "body": "x", "reply_to": None})
        r = bus_claude_hook.collect({"session_id": C}, self.state)
        self.assertEqual([p["id"] for p in r["pointers"]], ["m1"])

    def test_codex_hook_pull_pointer_once(self):
        import codex_steer_hook
        autoreg.ensure("codex", A, source="t", state_dir=self.state)
        self.store.post({"id": "p1", "from": "grok", "to": "codex-a0000005", "body": "BODY-SECRET", "reply_to": None})
        payload = json.dumps({"hook_event_name": "PostToolUse", "session_id": A})
        outs = []
        for _ in range(2):
            out = io.StringIO()
            with patch.object(ar, "DEFAULT_STATE", self.state), patch("codex_steer_hook.take_for_hook", return_value=[]), \
                 patch("sys.stdin", io.StringIO(payload)), patch("sys.stdout", out):
                self.assertEqual(codex_steer_hook.main(), 0)
            outs.append(out.getvalue())
        self.assertIn("p1", outs[0]); self.assertNotIn("BODY-SECRET", outs[0]); self.assertEqual(outs[1], "")

    def test_reachability_and_relay_respect_routes(self):
        import reachability, relay
        autoreg.ensure("codex", A, source="t", state_dir=self.state)
        self.assertEqual(reachability.assess("codex-a0000005", self.state),
                         {"deliverable": True, "reason": None, "route": "pull"})
        self.assertNotIn("codex-a0000005", relay.load_threads(self.state))
        ar.register("codex-explicit", B, "codex", "", self.state)
        self.assertIn("codex-explicit", relay.load_threads(self.state))
        with patch("autoreg.time.time", return_value=time.time() + 9 * 86400):
            pass
        con = rdb.connect(self.state); con.execute("UPDATE agents SET last_seen=1 WHERE address='codex-a0000005'"); con.close()
        self.assertEqual(reachability.assess("codex-a0000005", self.state)["reason"], "dormant")


class RegistryDbTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.state = Path(self.td.name) / "state"
        local_cli.open_store(self.state)

    def tearDown(self):
        self.td.cleanup()

    def seed_json(self):
        ar.register("codexcw", A, "codex", "explicit topic", self.state)
        ar.register("claude-lead", C, "claude", "", self.state)
        ar.set_claude_alias("claude-lead", None, self.state)
        return json.loads((self.state / "agents-registry.json").read_text(encoding="utf-8"))

    def test_migration_idempotent_preserves_everything(self):
        before = self.seed_json()
        r = rdb.migrate(self.state)
        self.assertTrue(r["first"]); self.assertEqual(r["imported"], 2); self.assertTrue(Path(r["db_backup"]).exists())
        self.assertEqual(rdb.load_doc(self.state)["agents"], before["agents"])
        self.assertEqual(rdb.load_doc(self.state)["aliases"], {"claude": "claude-lead"})
        self.assertEqual(rdb.migrate(self.state)["imported"], 0)
        self.assertEqual(ar.load(self.state), before["agents"])
        self.assertEqual(ar.claude_mailboxes(C, self.state), ("claude-lead", "claude"))
        self.assertEqual(autoreg.route("codexcw", self.state)["route"], "wake")  # explicit wake unchanged

    def test_explicit_register_after_migration_lands_in_db_and_export(self):
        rdb.migrate(self.state, backup=False)
        autoreg.ensure("codex", A, source="t", state_dir=self.state)
        ar.register("codex-new", B, "codex", "x", self.state)
        con = rdb.connect(self.state, readonly=True)
        rows = {r["address"]: r["last_seen"] for r in con.execute("SELECT address,last_seen FROM agents")}; con.close()
        self.assertEqual(set(rows), {"codex-a0000005", "codex-new"})
        self.assertIsNotNone(rows["codex-a0000005"])  # agent_registry upsert did not wipe autoreg columns
        exported = json.loads((self.state / "agents-registry.json").read_text(encoding="utf-8"))
        self.assertEqual(set(exported["agents"]), {"codex-a0000005", "codex-new"})
        self.assertFalse(exported["agents"]["codex-a0000005"]["wake"])

    def test_not_migrated_is_fail_open(self):
        self.assertIsNone(autoreg.ensure_bounded("codex", A, state_dir=self.state, source="t"))
        self.assertFalse(rdb.migrated(self.state))

    def test_busy_db_fails_open_within_300ms(self):
        rdb.migrate(self.state, backup=False)
        holder = rdb.connect(self.state, timeout_ms=1000); holder.execute("BEGIN IMMEDIATE")
        try:
            t = time.monotonic()
            self.assertIsNone(autoreg.ensure_bounded("codex", A, state_dir=self.state, source="t"))
            self.assertLess(time.monotonic() - t, 0.6)
        finally:
            holder.execute("ROLLBACK"); holder.close()
            time.sleep(0.5)  # let the abandoned fail-open worker release the DB before tempdir cleanup
        self.assertEqual(autoreg.ensure("codex", A, source="t", state_dir=self.state)["address"], "codex-a0000005")

    def test_unmigrate_rollback_keeps_registrations(self):
        self.seed_json(); rdb.migrate(self.state, backup=False)
        autoreg.ensure("codex", B, source="t", state_dir=self.state)
        self.assertTrue(rdb.unmigrate(self.state)["unmigrated"])
        self.assertFalse(rdb.migrated(self.state))
        self.assertEqual(set(ar.load(self.state)), {"codexcw", "claude-lead", "codex-a0000005"})
        ar.register("codex-after", "12345678-1234-4234-8234-123456789abc", "codex", "", self.state)  # JSON path works again

    def test_periodic_scan_interval_and_failure(self):
        rdb.migrate(self.state, backup=False)
        root = Path(self.td.name) / "sessions"; d = root / "2026" / "10" / "22"; d.mkdir(parents=True)
        (d / "rollout-i.jsonl").write_text(json.dumps({"type": "session_meta", "payload":
            {"id": A, "originator": "Codex Desktop", "source": "vscode"}}) + "\n", encoding="utf-8")
        with patch("autoreg.discover_antigravity", return_value=[]):
            last, ev = autoreg.periodic_scan(self.state, 0.0, now=1000.0 + time.time(), root=root)
            self.assertEqual((ev["event"], ev["created"]), ("discovery", 1))
            self.assertEqual(autoreg.periodic_scan(self.state, last, now=last + 10, root=root), (last, None))
            with patch("autoreg.discover_codex", side_effect=RuntimeError("x")):
                self.assertEqual(autoreg.periodic_scan(self.state, 0.0)[1]["event"], "discovery-failed")
        e = ar.load(self.state)["codex-a0000005"]
        self.assertLessEqual(e["last_seen"], int((d / "rollout-i.jsonl").stat().st_mtime) + 1)  # lease = real activity


if __name__ == "__main__":
    unittest.main()
