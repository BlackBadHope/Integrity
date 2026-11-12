"""Stand tests for the compiled-route runner and the route list (invented example routes, fake runner)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import integrity_guards
from integrity_guards import uroboros_exec as ux

COMPONENT = Path(__file__).resolve().parents[1]
ROUTES = COMPONENT / "examples" / "compiled-routes"
SRC = str(Path(integrity_guards.__file__).resolve().parents[1])


def route(name):
    return ux.load_route(str(ROUTES / f"{name}.json"))


class FakeRunner:
    """Answers like the real commands would, without starting anything."""

    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        code = argv[-1]
        if self.fail and self.fail in code:
            return 1, "", "simulated failure"
        if code.startswith("print('") and code.endswith("')"):
            return 0, code[len("print('"):-2] + "\n", ""
        return 0, "", ""


class TestRunner:
    def test_example_routes_validate(self):
        assert route("echo-route")["safety"] == "read"
        assert route("echo-write-route")["safety"] == "write"

    def test_read_route_runs_and_extracts(self):
        fake = FakeRunner()
        result = ux.run_compiled_route(route("echo-route"), {"name": "node-a"}, runner=fake, environ={})
        assert result["ok"] and result["outputs"] == {"greeting": "hello node-a"}
        assert [s["phase"] for s in result["steps"]] == ["precondition", "step"]
        assert result["production_authority"] is False

    def test_param_schema_and_unknown_params(self):
        fake = FakeRunner()
        bad = ux.run_compiled_route(route("echo-route"), {"name": "Bad Name"}, runner=fake, environ={})
        assert not bad["ok"] and "does not match" in bad["error"] and fake.calls == []
        extra = ux.run_compiled_route(route("echo-route"), {"name": "a1", "x": "1"}, runner=fake, environ={})
        assert "unknown parameters: x" in extra["error"]

    def test_precondition_failure_falls_back_to_agent(self):
        result = ux.run_compiled_route(route("echo-route"), {"name": "a1"}, runner=FakeRunner(fail="ok"), environ={})
        assert not result["ok"] and result["fallback"] == "agent"

    def test_write_route_dry_run_by_default(self):
        fake = FakeRunner()
        result = ux.run_compiled_route(route("echo-write-route"), {"value": "7"}, runner=fake, environ={})
        assert result["dry_run"] and fake.calls == []
        assert any("<backup_id>" in line for line in result["planned"])

    def test_write_route_needs_go_for_this_route(self):
        fake = FakeRunner()
        env = {ux.ENV_WRITE_GO: "some-other-route"}
        result = ux.run_compiled_route(route("echo-write-route"), {"value": "7"}, apply=True, runner=fake, environ=env)
        assert "needs an operator GO" in result["error"] and fake.calls == []

    def test_write_route_backup_then_write(self):
        fake = FakeRunner()
        env = {ux.ENV_WRITE_GO: "echo-write-route"}
        result = ux.run_compiled_route(route("echo-write-route"), {"value": "7"}, apply=True, runner=fake, environ=env)
        assert result["ok"] and result["outputs"]["backup_id"] == "42"
        assert fake.calls[-1][-1] == "print('wrote 7 after 42')"

    def test_failed_backup_writes_nothing(self):
        fake = FakeRunner(fail="backup-id")
        env = {ux.ENV_WRITE_GO: "echo-write-route"}
        result = ux.run_compiled_route(route("echo-write-route"), {"value": "7"}, apply=True, runner=fake, environ=env)
        assert "nothing written" in result["error"] and len(fake.calls) == 1

    def test_route_id_requires_directory(self, monkeypatch):
        monkeypatch.delenv(ux.ENV_ROUTES_DIR, raising=False)
        with pytest.raises(ux.CompiledRouteError):
            ux.load_route("echo-route")
        assert ux.load_route("echo-route", routes_dir=str(ROUTES))["route_id"] == "echo-route"


def local_routes(tmp_path):
    """The example routes with `python` replaced by this interpreter, so the CLI test runs real processes."""
    out = tmp_path / "routes"
    out.mkdir()
    for path in ROUTES.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        for phase in ("preconditions", "backup", "steps"):
            for step in data.get(phase, []):
                step["argv"] = [sys.executable if a == "python" else a for a in step["argv"]]
        (out / path.name).write_text(json.dumps(data), encoding="utf-8")
    return out


def cli(*args, **env):
    full = {k: v for k, v in os.environ.items() if not k.startswith("INTEGRITY_")}
    full["PYTHONPATH"] = SRC + os.pathsep + full.get("PYTHONPATH", "")
    full.update(env)
    return subprocess.run([sys.executable, "-B", "-m", "integrity_guards", "uroboros", *args],
                          capture_output=True, text=True, env=full, timeout=60)


class TestCli:
    def test_run_by_id_from_configuration(self, tmp_path):
        routes = local_routes(tmp_path)
        cfg = tmp_path / "guards.json"
        cfg.write_text(json.dumps({"uroboros": {"compiled_routes": str(routes)}}), encoding="utf-8")
        p = cli("run", "echo-route", "name=node-a", INTEGRITY_GUARDS_CONFIG=str(cfg))
        assert p.returncode == 0, p.stderr
        assert json.loads(p.stdout)["outputs"]["greeting"] == "hello node-a"

    def test_write_route_cli_dry_run_exit_1(self, tmp_path):
        routes = local_routes(tmp_path)
        p = cli("run", "echo-write-route", "value=3", INTEGRITY_COMPILED_ROUTES=str(routes))
        assert p.returncode == 1 and json.loads(p.stdout)["dry_run"] is True

    def test_missing_route_names_closest(self, tmp_path):
        p = cli("run", "echo-rout", INTEGRITY_COMPILED_ROUTES=str(ROUTES))
        out = json.loads(p.stdout)
        assert p.returncode == 2 and "not a compiled one-call route" in out["error"]
        assert "echo-route" in out["closest_compiled"]

    def test_list_filters_by_words(self):
        p = cli("list", "write", INTEGRITY_COMPILED_ROUTES=str(ROUTES))
        assert p.returncode == 0
        assert "echo-write-route" in p.stdout and "-- 1 of 2 compiled routes" in p.stdout

    def test_list_without_directory_is_empty(self, tmp_path):
        p = cli("list", INTEGRITY_GUARDS_CONFIG=str(tmp_path / "none.json"))
        assert p.returncode == 0 and "-- 0 of 0 compiled routes" in p.stdout

    def test_validate(self):
        p = cli("validate", str(ROUTES / "echo-route.json"))
        assert (p.returncode, p.stdout.strip()) == (0, "ok: echo-route (read)")
