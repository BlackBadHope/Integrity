# SPDX-License-Identifier: BUSL-1.1
"""Claude hook patch series (hook-series/claude-windows): strict build, sha chain, refusals.

Offline and read-only on the repository: every build goes to tmp_path, every mutation is made on a
copy under tmp_path. The built hook is only compiled, never imported or executed.
"""
from __future__ import annotations

import json
import shutil
import types
from pathlib import Path

import pytest

SERIES_DIR = Path(__file__).resolve().parents[1] / "hook-series" / "claude-windows"
PARTS = ("admission", "turn_guard")


def load_builder(folder: Path) -> types.ModuleType:
    """Load build_hook.py from ``folder`` without writing bytecode next to it."""
    path = folder / "build_hook.py"
    module = types.ModuleType(f"claude_hook_series_builder_{abs(hash(str(folder)))}")
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def series(folder: Path = SERIES_DIR) -> dict:
    return json.loads((folder / "SERIES.json").read_text(encoding="utf-8"))


@pytest.fixture()
def copy(tmp_path: Path) -> Path:
    target = tmp_path / "claude-windows"
    shutil.copytree(SERIES_DIR, target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def test_full_build_reproduces_every_recorded_step_and_equals_built(tmp_path: Path):
    builder = load_builder(SERIES_DIR)
    doc = series()
    for key in PARTS:
        part = doc[key]
        steps: dict[str, bytes] = {}
        final = builder.build(part, keep_steps=steps)
        assert len(steps) == len(part["steps"])
        previous = part["base_sha256"]
        for step in part["steps"]:
            tag = step["patch"].split("-", 1)[0]
            assert step["pre_sha256"] == previous
            assert builder.sha(steps[tag]) == step["post_sha256"]
            assert (b"\r\n" in steps[tag]) == step["crlf"]
            previous = step["post_sha256"]
        assert final == (SERIES_DIR / "built" / part["file"]).read_bytes()
    out = tmp_path / "out"
    assert builder.main(["--out", str(out)]) == 0
    for key in PARTS:
        name = doc[key]["file"]
        assert (out / name).read_bytes() == (SERIES_DIR / "built" / name).read_bytes()


def test_series_counts_match_the_patches():
    doc = series()
    assert len(doc["admission"]["steps"]) == 20 and len(doc["turn_guard"]["steps"]) == 3
    for key in PARTS:
        for step in doc[key]["steps"]:
            assert "evidence_file" not in step
            lines = (SERIES_DIR / "patches" / step["patch"]).read_text(encoding="utf-8").splitlines()
            assert step["added"] == sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
            assert step["removed"] == sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
    listed = {s["patch"] for key in PARTS for s in doc[key]["steps"]}
    assert listed == {p.name for p in (SERIES_DIR / "patches").glob("*.diff")}


def _flip_first(path: Path, prefix: str) -> None:
    lines = path.read_bytes().split(b"\n")
    for index, line in enumerate(lines):
        if line.startswith(prefix.encode()) and not line.startswith((b"+++", b"---")) and len(line) > 4:
            last = line[-1:]
            lines[index] = line[:-1] + (b"#" if last != b"#" else b"!")
            break
    else:  # pragma: no cover - the fixture series always has such a line
        raise AssertionError("no line to change")
    path.write_bytes(b"\n".join(lines))


def test_a_changed_added_line_is_refused_by_the_step_sha(copy: Path):
    _flip_first(copy / "patches" / "A10-ISS-017.diff", "+")
    builder = load_builder(copy)
    with pytest.raises(SystemExit, match=r"A10-ISS-017\.diff: result .* != recorded"):
        builder.build(series(copy)["admission"])


def test_a_changed_context_line_is_refused_by_the_strict_applier(copy: Path):
    _flip_first(copy / "patches" / "T02-tg-ISS-011-to-ISS-018.diff", " ")
    builder = load_builder(copy)
    with pytest.raises(SystemExit, match=r"T02-tg-ISS-011-to-ISS-018\.diff: context mismatch"):
        builder.build(series(copy)["turn_guard"])


def test_a_changed_base_byte_is_refused(copy: Path):
    path = copy / "base" / "integrity_turn_guard.py"
    data = bytearray(path.read_bytes())
    data[-2] = ord("#") if data[-2] != ord("#") else ord("!")
    path.write_bytes(bytes(data))
    builder = load_builder(copy)
    with pytest.raises(SystemExit, match="base sha"):
        builder.build(series(copy)["turn_guard"])


def test_upto_never_writes_into_the_full_build_folder(copy: Path, tmp_path: Path):
    builder = load_builder(copy)
    built = copy / "built"
    before = {p.name: p.read_bytes() for p in built.iterdir()}
    with pytest.raises(SystemExit, match="must not be built/"):
        builder.main(["--upto", "A08", "--out", str(built)])
    live = tmp_path / "live"
    live.mkdir()
    with pytest.raises(SystemExit, match="must not be built/"):
        builder.main(["--upto", "A08", "--out", str(live), "--live", str(live)])
    assert list(live.iterdir()) == []
    with pytest.raises(SystemExit):
        builder.main(["--upto", "A08"])  # no default output folder
    partial = tmp_path / "partial"
    assert builder.main(["--upto", "A08", "--out", str(partial)]) == 0
    names = sorted(p.name for p in partial.iterdir())
    assert names == ["integrity-client-admission.py.upto-A08", "integrity_turn_guard.py.upto-A08"]
    a08 = next(s for s in series(copy)["admission"]["steps"] if s["patch"].startswith("A08"))
    assert builder.sha((partial / names[0]).read_bytes()) == a08["post_sha256"]
    assert {p.name: p.read_bytes() for p in built.iterdir()} == before


def test_compare_live_needs_an_explicit_folder(copy: Path, tmp_path: Path):
    builder = load_builder(copy)
    with pytest.raises(SystemExit):
        builder.main(["--out", str(tmp_path / "x"), "--compare-live"])
    live = tmp_path / "live"
    shutil.copytree(copy / "built", live)
    assert builder.main(["--out", str(tmp_path / "y"), "--compare-live", "--live", str(live)]) == 0
    (live / "integrity_turn_guard.py").write_bytes(b"# different\n")
    assert builder.main(["--out", str(tmp_path / "z"), "--compare-live", "--live", str(live)]) == 1


@pytest.mark.parametrize("name", ["integrity-client-admission.py", "integrity_turn_guard.py"])
def test_built_files_are_valid_python(name: str):
    source = (SERIES_DIR / "built" / name).read_bytes()
    compile(source, name, "exec")  # compile only; the hook is never executed here
