import json, tempfile, unittest
from pathlib import Path
import agent_registry as ar
import fix_registry_topics as fx
import local_cli

T = "a000000f-b010-4010-8010-c00000000010"
GOOD = "Example, сборка и инструкции"
BAD = GOOD.encode("utf-8").decode("cp1251")


class TopicFixTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); self.state = Path(self.td.name) / "state"
        local_cli.open_store(self.state)
        ar.register("codexcw", T, "codex", "", self.state)
        ar.register("other", "a000000f-b010-4010-8010-c00000000011", "codex", "plain ascii", self.state)
        ar.register("ru", "a000000f-b010-4010-8010-c00000000012", "codex", "нормальная тема", self.state)
        p = self.state / "agents-registry.json"; d = json.loads(p.read_text(encoding="utf-8"))
        d["agents"]["codexcw"]["topic"] = BAD; p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def test_dry_run_changes_nothing(self):
        before = (self.state / "agents-registry.json").read_bytes()
        self.assertEqual(fx.plan(self.state), {"codexcw": {"from": BAD, "to": GOOD}})
        self.assertEqual((self.state / "agents-registry.json").read_bytes(), before)

    def test_apply_json_only_topic_changes(self):
        before = ar.load(self.state)
        r = fx.apply(self.state)
        self.assertEqual((r["store"], list(r["changed"])), ("json", ["codexcw"]))
        self.assertTrue(Path(r["backup"]).exists())
        after = ar.load(self.state)
        self.assertEqual(after["codexcw"]["topic"], GOOD)
        before["codexcw"]["topic"] = GOOD
        self.assertEqual(after, before)
        self.assertEqual(fx.apply(self.state)["changed"], {})  # idempotent

    def test_apply_after_db_migration(self):
        try:
            import registry_db
        except ImportError:
            self.skipTest("registry_db not installed")
        registry_db.migrate(self.state, backup=False)
        r = fx.apply(self.state)
        self.assertEqual(r["store"], "sqlite")
        self.assertEqual(registry_db.load_doc(self.state)["agents"]["codexcw"]["topic"], GOOD)
        self.assertEqual(json.loads((self.state / "agents-registry.json").read_text(encoding="utf-8"))["agents"]["codexcw"]["topic"], GOOD)

    def test_r3_fresh_backup_matches_live_at_install(self):
        import hashlib
        live = hashlib.sha256((self.state / "agents-registry.json").read_bytes()).hexdigest()
        r = fx.apply(self.state)
        self.assertEqual(r["backup_sha256"], live)
        self.assertEqual(hashlib.sha256(Path(r["backup"]).read_bytes()).hexdigest(), live)

    def test_r3_plan_recomputed_under_lock(self):
        # Registry changed after an earlier dry run: apply must not use the stale plan.
        old = fx.plan(self.state)
        self.assertIn("codexcw", old)
        p = self.state / "agents-registry.json"; d = json.loads(p.read_text(encoding="utf-8"))
        d["agents"]["codexcw"]["topic"] = "renamed by owner"; p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
        r = fx.apply(self.state)
        self.assertEqual(r["changed"], {})
        self.assertEqual(ar.load(self.state)["codexcw"]["topic"], "renamed by owner")

    def test_r3_db_concurrent_topic_change_wins(self):
        try:
            import registry_db
        except ImportError:
            self.skipTest("registry_db not installed")
        registry_db.migrate(self.state, backup=False)
        real = fx._plan_from
        def stale_then_change(agents):
            out = real(agents)
            con = registry_db.connect(self.state); con.execute("BEGIN IMMEDIATE")
            core = json.loads(con.execute("SELECT core_json FROM agents WHERE address='codexcw'").fetchone()[0])
            core["topic"] = "owner topic"
            con.execute("UPDATE agents SET core_json=? WHERE address='codexcw'", (json.dumps(core, ensure_ascii=False),))
            con.execute("COMMIT"); con.close()
            return out
        fx._plan_from = stale_then_change
        try:
            r = fx.apply(self.state)
        except RuntimeError:
            r = None
        finally:
            fx._plan_from = real
        self.assertEqual(registry_db.load_doc(self.state)["agents"]["codexcw"]["topic"], "owner topic")


if __name__ == "__main__":
    unittest.main()
