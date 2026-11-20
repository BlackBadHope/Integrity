"""The project's own compiled routes (.integrity/routes): Integrity packages its changes with Uroboros.

These routes run the project's development steps (manifest, catalog, the public-surface CI
checks, the review package) as fixed argv lists. None of them pushes, opens a pull request
or merges, none names a host, and every path in them is relative to the repository.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from integrity_guards import runbooks
from integrity_guards import uroboros_exec as ux

ROOT = Path(__file__).resolve().parents[1]
ROUTES_DIR = ROOT / ".integrity" / "routes"
RUNBOOKS = ROOT / ".integrity" / "runbooks.json"
ROUTE_TOOLS = ROOT / ".github" / "scripts" / "route_tools.py"

EXPECTED = {
    "integrity-dev.manifest-refresh": "write",
    "integrity-dev.manifest-add": "write",
    "integrity-dev.catalog-write": "write",
    "integrity-dev.ci-checks": "read",
    "integrity-dev.ci-build": "read",
    "integrity-dev.ci-tests": "read",
    "integrity-dev.package-diff": "read",
}
GOOD_VALUES = {"base": "main", "out": "../package.diff", "work": "../ci-work", "kind": "add",
               "path": "tests/test_example.py"}
BAD_VALUES = ["../../outside.diff", "/absolute", "C:/absolute", "-option", "--output=x", "a/../b", "..",
              "x y", "x;y", "$(x)", "~/x", "https://example.invalid/x", ".git/config", ".GIT/config", ".git"]
NOT_IN_A_ROUTE = re.compile(r"\b(push|merge|rebase|reset|checkout|clean|stash|remote|fetch|pull|gh|curl|wget|ssh|scp)\b",
                            re.IGNORECASE)
GIT_SUBCOMMANDS = {"rev-parse", "ls-files", "hash-object", "diff", "status"}
REPO_FILE = re.compile(r"\A(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.(?:py|json)\Z")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def all_steps(route: dict) -> list[dict]:
    return [*route.get("preconditions", []), *route.get("backup", []), *route["steps"]]


def local_python(argv: list[str]) -> list[str]:
    return [sys.executable, *argv[1:]] if argv[:1] == ["python"] else list(argv)


def runner_in(cwd: Path, calls: list[list[str]] | None = None):
    """The executor's runner, without a shell, with the working directory set to ``cwd``."""

    def run(argv: list[str], timeout: float) -> tuple[int, str, str]:
        if calls is not None:
            calls.append(list(argv))
        done = subprocess.run(local_python(argv), cwd=cwd, capture_output=True, text=True,
                              timeout=timeout, check=False, encoding="utf-8", errors="replace")
        return done.returncode, done.stdout, done.stderr

    return run


def git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", "-c", "user.name=route-test", "-c", "user.email=route-test@example.invalid",
                           "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
                          cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout


ROUTE_FILES = sorted(ROUTES_DIR.glob("*.json"))


def test_the_project_routes_are_the_expected_set() -> None:
    routes = {load(path)["route_id"]: load(path)["safety"] for path in ROUTE_FILES}
    assert routes == EXPECTED


@pytest.mark.parametrize("path", ROUTE_FILES, ids=lambda p: p.stem)
def test_every_route_is_valid_and_named_by_its_id(path: Path) -> None:
    route = ux.validate_compiled_route(load(path))
    assert path.name == f"{route['route_id']}.json"
    assert ux.load_route(route["route_id"], routes_dir=str(ROUTES_DIR))["route_id"] == route["route_id"]


@pytest.mark.parametrize("path", ROUTE_FILES, ids=lambda p: p.stem)
def test_routes_never_publish_and_stay_inside_the_repository(path: Path) -> None:
    route = load(path)
    for step in all_steps(route):
        argv = step["argv"]
        assert argv[0] in {"git", "python"}, step["name"]
        if argv[0] == "git":
            assert argv[1] in GIT_SUBCOMMANDS, step["name"]
        for word in argv:
            assert not NOT_IN_A_ROUTE.search(word), (step["name"], word)
            assert "://" not in word and "~" not in word, (step["name"], word)
            assert not word.startswith(("/", "\\")) and not re.match(r"[A-Za-z]:[\\/]", word), (step["name"], word)
            if REPO_FILE.fullmatch(word):
                assert (ROOT / word).is_file(), (step["name"], word)


@pytest.mark.parametrize("path", ROUTE_FILES, ids=lambda p: p.stem)
def test_pytest_steps_keep_the_summary_line_they_extract(path: Path) -> None:
    # pyproject.toml already adds -q; a second -q hides the "N passed" line the step extracts.
    for step in all_steps(load(path)):
        if "pytest" in step["argv"] and any("passed" in p for p in (step.get("extract") or {}).values()):
            assert "-q" not in step["argv"] and "-qq" not in step["argv"], step["name"]


@pytest.mark.parametrize("path", ROUTE_FILES, ids=lambda p: p.stem)
def test_parameters_refuse_escapes_options_and_absolute_paths(path: Path) -> None:
    for name, pattern in load(path)["params"].items():
        assert re.fullmatch(pattern, GOOD_VALUES[name]), name
        for bad in BAD_VALUES:
            assert not re.fullmatch(pattern, bad), (name, bad)


@pytest.mark.parametrize("route_id", sorted(r for r, s in EXPECTED.items() if s == "write"))
def test_write_routes_keep_a_backup_and_only_plan_without_apply(route_id: str) -> None:
    route = ux.load_route(route_id, routes_dir=str(ROUTES_DIR))
    assert route["backup"], route_id
    params = {name: GOOD_VALUES[name] for name in route["params"]}
    if route_id == "integrity-dev.manifest-add":
        params = {"kind": "add-generated", "path": ".github/scripts/route_tools.py"}
    calls: list[list[str]] = []
    result = ux.run_compiled_route(route, params, apply=False, runner=runner_in(ROOT, calls), environ={})
    assert result["dry_run"] is True and not result["ok"], result
    assert len(result["planned"]) == len(route["backup"]) + len(route["steps"])
    # Only the read-only preconditions ran; nothing that writes.
    assert len(calls) == len(route.get("preconditions", []))
    assert not any("--write" in call or "update_manifest.py" in " ".join(call) for call in calls)


def test_project_runbooks_see_every_route_and_stay_off() -> None:
    routes = runbooks.load_routes(ROUTES_DIR)
    assert set(routes) == set(EXPECTED)
    config = runbooks.validate_config(load(RUNBOOKS), routes)
    assert config["enabled"] is False
    assert {t["route_id"] for t in config["triggers"]} == set(EXPECTED)
    assert runbooks.routes_dir(load(RUNBOOKS)) == Path(".integrity/routes")


@pytest.mark.parametrize(("trigger_id", "line", "decision"), [
    ("integrity-dev.package-request", "package base=main out=../package.diff", "turn"),
    ("integrity-dev.ci-tests-request", "ci tests work=../ci-work", "turn"),
    ("integrity-dev.manifest-add-request", "manifest add tests/test_example.py", "proposal"),
    ("integrity-dev.catalog-write-request", "catalog write", "proposal"),
])
def test_runbooks_explain_turns_reads_and_proposes_writes(trigger_id: str, line: str, decision: str) -> None:
    routes = runbooks.load_routes(ROUTES_DIR)
    config = runbooks.validate_config(load(RUNBOOKS), routes)
    trigger = next(t for t in config["triggers"] if t["trigger_id"] == trigger_id)
    route = routes[trigger["route_id"]]
    values, problem = runbooks.extract_params(trigger, route, re.search(trigger["match"], line))
    assert values is not None, problem
    assert ("turn" if route["safety"] == "read" else "proposal") == decision
    assert runbooks.route_command(route["route_id"], values).startswith(
        f"integrity-guards uroboros run {route['route_id']}")


def test_runbooks_refuse_a_line_that_escapes_the_repository() -> None:
    routes = runbooks.load_routes(ROUTES_DIR)
    config = runbooks.validate_config(load(RUNBOOKS), routes)
    trigger = next(t for t in config["triggers"] if t["trigger_id"] == "integrity-dev.package-request")
    line = "package base=main out=../a..b.diff"
    match = re.search(trigger["match"], line)
    values, _problem = runbooks.extract_params(trigger, routes[trigger["route_id"]], match)
    assert values is None


def test_runbooks_refuse_a_manifest_line_into_git() -> None:
    routes = runbooks.load_routes(ROUTES_DIR)
    config = runbooks.validate_config(load(RUNBOOKS), routes)
    trigger = next(t for t in config["triggers"] if t["trigger_id"] == "integrity-dev.manifest-add-request")
    for path in (".git/config", ".GIT/config", ".git"):
        assert re.search(trigger["match"], f"manifest add {path}") is None, path
    assert re.search(trigger["match"], "manifest add .github/scripts/route_tools.py")


def test_manifest_add_refuses_an_ignored_path() -> None:
    # build/ is in .gitignore: build output must not be named in the public manifest.
    route = ux.load_route("integrity-dev.manifest-add", routes_dir=str(ROUTES_DIR))
    names = [step["name"] for step in route["preconditions"]]
    assert names.index("not-ignored") < names.index("file-exists")
    calls: list[list[str]] = []
    result = ux.run_compiled_route(route, {"kind": "add", "path": "build/x.py"}, apply=False,
                                   runner=runner_in(ROOT, calls), environ={})
    assert not result["ok"] and "not-ignored" in json.dumps(result), result
    assert not any("update_manifest.py" in " ".join(call) for call in calls)


def test_route_tools_not_ignored() -> None:
    def not_ignored(path: str) -> tuple[int, str]:
        done = subprocess.run([sys.executable, "-B", str(ROUTE_TOOLS), "not-ignored", path], cwd=ROOT,
                              capture_output=True, text=True, check=False)
        return done.returncode, done.stdout.strip()

    assert not_ignored("tests/test_example.py") == (0, "not-ignored")
    assert not_ignored("build/x.py") == (1, "ignored: build/x.py")
    assert not_ignored("x.egg-info/PKG-INFO") == (1, "ignored: x.egg-info/PKG-INFO")
    assert not_ignored(".GIT/config") == (1, "in .git: .GIT/config")


def test_route_tools_absent_and_empty_glob() -> None:
    absent = subprocess.run([sys.executable, "-B", str(ROUTE_TOOLS), "absent", str(ROOT / "README.md")],
                            capture_output=True, text=True, check=False)
    assert absent.returncode == 1 and absent.stdout.startswith("present")
    empty = subprocess.run([sys.executable, "-B", str(ROUTE_TOOLS), "py-run", "--glob", "no-such-dir-*/x",
                            "--", "-c", "pass"], capture_output=True, text=True, check=False, cwd=ROOT)
    assert empty.returncode == 2


def test_venv_routes_refuse_a_pythonpath(tmp_path: Path) -> None:
    # With PYTHONPATH on a source tree, the build's *.egg-info makes pip skip those wheels,
    # and the steps then test the source instead of the installed package.
    for route_id in ("integrity-dev.ci-build", "integrity-dev.ci-tests"):
        names = [step["name"] for step in ux.load_route(route_id, routes_dir=str(ROUTES_DIR))["preconditions"]]
        assert "no-pythonpath" in names, route_id
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    clean = subprocess.run([sys.executable, "-B", str(ROUTE_TOOLS), "unset", "PYTHONPATH"], env=env,
                           capture_output=True, text=True, check=False)
    assert (clean.returncode, clean.stdout.strip()) == (0, "unset")
    env["PYTHONPATH"] = str(tmp_path)
    dirty = subprocess.run([sys.executable, "-B", str(ROUTE_TOOLS), "unset", "PYTHONPATH"], env=env,
                           capture_output=True, text=True, check=False)
    assert (dirty.returncode, dirty.stdout.strip()) == (1, "set: PYTHONPATH")


def test_ci_checks_refuse_build_leftovers() -> None:
    # The public-surface check counts every file on disk; ignored build output (*.egg-info,
    # build/) left by an earlier build or install fails it with a membership mismatch.
    route = ux.load_route("integrity-dev.ci-checks", routes_dir=str(ROUTES_DIR))
    step = next(s for s in route["preconditions"] if s["name"] == "no-build-leftovers")
    assert step["argv"] == ["git", "status", "--porcelain", "--ignored", "--untracked-files=all"]
    assert re.search(step["expect"], "") and not re.search(step["expect"], "!! components/x/build/\n")


def test_package_route_runs_on_a_clean_clone(tmp_path: Path) -> None:
    """Route d on a fresh clone: a plain diff outside the tree, its sha256, and it applies to base."""
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "--quiet", "--no-hardlinks", str(ROOT), str(clone))
    git(clone, "branch", "route-test-base", "HEAD")
    git(clone, "checkout", "--quiet", "-B", "route-test-change")
    # The clone holds the committed tree; bring the route helper as the change under review.
    helper = clone / ".github" / "scripts" / "route_tools.py"
    helper.write_bytes(ROUTE_TOOLS.read_bytes())
    (clone / "route-test-note.txt").write_text("a change under review\n", encoding="utf-8")
    git(clone, "add", "--all")
    git(clone, "commit", "--quiet", "--allow-empty", "-m", "route test change")
    route = ux.load_route("integrity-dev.package-diff", routes_dir=str(ROUTES_DIR))

    result = ux.run_compiled_route(route, {"base": "route-test-base", "out": "../package.diff"}, apply=False,
                                   runner=runner_in(clone), environ={})

    assert result["ok"], json.dumps(result)
    package = tmp_path / "package.diff"
    data = package.read_bytes()
    assert data == subprocess.run(["git", "diff", "--binary", "route-test-base..HEAD"], cwd=clone,
                                  capture_output=True, check=True).stdout
    assert result["outputs"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert int(result["outputs"]["bytes"]) == len(data)
    assert int(result["outputs"]["files"]) == data.count(b"\ndiff --git ") + data.startswith(b"diff --git ")
    assert result["outputs"]["head"] == git(clone, "rev-parse", "HEAD").strip()
    assert git(clone, "status", "--porcelain", "--untracked-files=all") == ""

    again = ux.run_compiled_route(route, {"base": "route-test-base", "out": "../package.diff"}, apply=False,
                                  runner=runner_in(clone), environ={})
    assert not again["ok"] and "out-is-new" in again["error"]
