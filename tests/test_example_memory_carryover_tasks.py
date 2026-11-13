"""The example two-session tasks: reference solutions pass, stubs fail, metadata matches."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "examples" / "memory-carryover-tasks"
TASKS = ["T1", "T2", "T3", "T4", "T5", "T6"]


def run_tests(task: str, solution: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    work = tmp_path / task
    work.mkdir()
    shutil.copyfile(solution, work / "solution.py")
    shutil.copyfile(ROOT / task / "hidden_tests" / "test_solution.py", work / "test_solution.py")
    return subprocess.run([sys.executable, "-B", "-X", "utf8", "-m", "unittest", "test_solution"],
                          cwd=work, capture_output=True, timeout=120)


def test_the_set_has_exactly_six_tasks():
    assert sorted(p.name for p in ROOT.iterdir() if p.is_dir()) == TASKS


@pytest.mark.parametrize("task", TASKS)
def test_reference_solution_passes(task, tmp_path):
    done = run_tests(task, ROOT / task / "_private" / "oracle.py", tmp_path)
    assert done.returncode == 0, done.stderr.decode(errors="replace")[-2000:]


@pytest.mark.parametrize("task", TASKS)
def test_stub_fails(task, tmp_path):
    done = run_tests(task, ROOT / task / "solution.py", tmp_path)
    assert done.returncode != 0


@pytest.mark.parametrize("task", TASKS)
def test_metadata_matches_the_folder(task):
    folder = ROOT / task
    meta = json.loads((folder / "_private" / "assessment.json").read_text(encoding="utf-8"))
    assert meta["task"] == task
    assert meta["copy_exclusions"] == ["hidden_tests", "_private"]
    assert isinstance(meta["s1_only_facts"], list)
    assert bool(meta["s1_only_facts"]) == (task != "T6")
    for name in ("README.md", "_private/S1.txt", "_private/S2.txt"):
        assert (folder / name).read_text(encoding="utf-8").strip()
    stub = (folder / "solution.py").read_text(encoding="utf-8")
    assert "NotImplementedError" in stub
    for symbol in meta["s1_symbols_for_rework"]:
        assert f"def {symbol}(" in stub
