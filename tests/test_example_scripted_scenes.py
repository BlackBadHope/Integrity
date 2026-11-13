# SPDX-License-Identifier: BUSL-1.1
"""The scripted example: the four scenes hold."""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples" / "scripted-scenes" / "run.py"


@pytest.fixture(scope="module")
def example():
    spec = importlib.util.spec_from_file_location("integrity_scripted_scenes", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scenes(example):
    return example.run_scenes()


def lines_of(scene: dict) -> list[str]:
    return [text for _, text in scene["lines"]]


def test_scene_one_closes_the_turn_with_a_signed_receipt(scenes) -> None:
    text = "\n".join(lines_of(scenes[0]))
    assert "event 1 stored, catalog verified" in text
    assert re.search(r"close receipt sha256:[0-9a-f]{12}\.\.\.  signature ed25519: valid", text)


def test_scene_two_recalls_the_decision_with_its_origin(scenes, example) -> None:
    text = "\n".join(lines_of(scenes[1]))
    assert "event 1  by agent-a  at " + example.DECISION["ts_utc"] in text
    assert example.DECISION["summary"] in text
    assert "production_authority=false" in text


def test_scene_three_refuses_memory_allows_one_grant_refuses_replay(scenes) -> None:
    verdicts = [text.split()[1] for style, text in scenes[2]["lines"] if style in ("ok", "deny")]
    assert verdicts == ["REFUSED", "ALLOWED", "REFUSED"]
    assert "already consumed" in lines_of(scenes[2])[-1]


def test_scene_four_shows_the_missing_close_in_the_doctor(scenes) -> None:
    text = "\n".join(lines_of(scenes[3]))
    assert re.search(r"coverage gap sha256:[0-9a-f]{12}\.\.\.  signature ed25519: valid", text)
    assert "coverage: 1/2 registered turns closed (events 1, no-event 0, unresolved 1)" in text


def test_the_script_does_not_present_itself_as_agents(scenes) -> None:
    titles = " ".join(scene["title"] for scene in scenes)
    assert "vendor" not in titles
    assert "played by this script" in SCRIPT.read_text(encoding="utf-8")


def test_the_command_of_the_readme_runs() -> None:
    done = subprocess.run([sys.executable, "-B", str(SCRIPT)], capture_output=True, text=True,
                          encoding="utf-8", timeout=300, check=False)
    assert done.returncode == 0, done.stderr[-400:]
    assert done.stdout.count("== scene ") == 4
