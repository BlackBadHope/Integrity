"""Race test for the single-verifier lock of the Seed verification memo.

The holder removes the lock file before it releases the lock. A process that was
waiting on that removed file must not run next to a newcomer that created a fresh
lock file at the same path. The test starts real processes with a real ``flock``
and checks that their critical sections never overlap.

POSIX only: the lock needs ``fcntl``. Elsewhere the lock is a no-op by design.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

import pytest

from integrity_guardian import seed_catalog

fcntl = pytest.importorskip("fcntl", reason="the single-verifier lock needs fcntl")

KEY = "a" * 64

# Processes compare time.monotonic() values with each other. On Linux that clock is
# shared by all processes; the test is not meaningful where it is per process.
pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="needs a system-wide monotonic clock"
)

_WORKER = r"""
import json, sys, time
from pathlib import Path
from integrity_guardian import seed_catalog

root, log, name = sys.argv[1], sys.argv[2], sys.argv[3]
start_at, hold, fail = float(sys.argv[4]), float(sys.argv[5]), sys.argv[6] == "1"
seed_catalog._verification_memo_root = Path(root)


def note(event):
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"n": name, "e": event, "t": time.monotonic()}) + "\n")


while time.monotonic() < start_at:
    time.sleep(0.002)
try:
    with seed_catalog._single_verifier(sys.argv[7]):
        note("in")
        time.sleep(hold)
        note("out")
        if fail:
            raise RuntimeError("body failure")
except RuntimeError:
    pass
"""


def _run(tmp_path: Path, plan: list[tuple[str, float, float, bool]]):
    """Start one process per plan row (name, delay, hold, fail) and collect intervals."""

    root = tmp_path / "memo"
    root.mkdir(mode=0o700)
    log = tmp_path / "log.jsonl"
    # Leave time for every interpreter to start and import the package.
    start = time.monotonic() + 3.0
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _WORKER,
                str(root),
                str(log),
                name,
                repr(start + delay),
                repr(hold),
                "1" if fail else "0",
                KEY,
            ]
        )
        for name, delay, hold, fail in plan
    ]
    for process in processes:
        assert process.wait(timeout=60) == 0
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    entered = {event["n"]: event["t"] for event in events if event["e"] == "in"}
    left = {event["n"]: event["t"] for event in events if event["e"] == "out"}
    intervals = sorted((entered[name], left[name], name) for name in entered if name in left)
    overlaps = [
        (first[2], second[2])
        for index, first in enumerate(intervals)
        for second in intervals[index + 1 :]
        if second[0] < first[1]
    ]
    lock_files = sorted(path.name for path in root.iterdir() if path.name.endswith(".lock"))
    return len(intervals), overlaps, lock_files


def test_waiters_on_a_removed_lock_file_do_not_run_beside_a_newcomer(tmp_path: Path) -> None:
    # A holds the lock; B and C wait on A's file; D arrives right after A releases.
    ran, overlaps, lock_files = _run(
        tmp_path,
        [
            ("A", 0.0, 1.0, False),
            ("B", 0.2, 0.6, False),
            ("C", 0.3, 0.6, False),
            ("D", 1.08, 0.6, False),
        ],
    )
    assert ran == 4
    assert overlaps == []
    assert lock_files == []


def test_a_failing_body_releases_the_lock(tmp_path: Path) -> None:
    ran, overlaps, lock_files = _run(tmp_path, [("A", 0.0, 0.4, True), ("B", 0.1, 0.3, False)])
    assert ran == 2
    assert overlaps == []
    assert lock_files == []


def test_twelve_processes_never_verify_in_parallel(tmp_path: Path) -> None:
    rnd = random.Random(7)
    plan = [
        (f"P{index}", rnd.uniform(0, 1.5), rnd.uniform(0.05, 0.25), False) for index in range(12)
    ]
    ran, overlaps, lock_files = _run(tmp_path, plan)
    assert ran == 12
    assert overlaps == []
    assert lock_files == []


def test_an_unusable_memo_directory_fails_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(seed_catalog, "_verification_memo_root", tmp_path / "missing" / "memo")
    ran = False
    with seed_catalog._single_verifier(KEY):
        ran = True
    assert ran


def test_exhausted_lock_attempts_fail_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "memo"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(seed_catalog, "_verification_memo_root", root)
    monkeypatch.setattr(seed_catalog, "SINGLE_VERIFIER_LOCK_ATTEMPTS", 0)
    ran = False
    with seed_catalog._single_verifier(KEY):
        ran = True
    assert ran
    assert not os.listdir(root)
