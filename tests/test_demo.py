# SPDX-License-Identifier: BUSL-1.1
"""The README demo: the four scenes hold, and the committed pictures are this run."""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"


@pytest.fixture(scope="module")
def demo():
    spec = importlib.util.spec_from_file_location("integrity_demo_run", ROOT / "demo" / "run.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scenes(demo):
    return demo.run_scenes()


def lines_of(scene: dict) -> list[str]:
    return [text for _, text in scene["lines"]]


def test_scene_one_closes_the_turn_with_a_signed_receipt(scenes) -> None:
    text = "\n".join(lines_of(scenes[0]))
    assert "event 1 stored, catalog verified" in text
    assert re.search(r"close receipt sha256:[0-9a-f]{12}\.\.\.  signature ed25519: valid", text)


def test_scene_two_recalls_the_decision_with_its_origin(scenes, demo) -> None:
    text = "\n".join(lines_of(scenes[1]))
    assert "event 1  by agent-a  at " + demo.DECISION["ts_utc"] in text
    assert demo.DECISION["summary"] in text
    assert "production_authority=false" in text


def test_scene_three_refuses_memory_allows_one_grant_refuses_replay(scenes) -> None:
    verdicts = [text.split()[1] for style, text in scenes[2]["lines"] if style in ("ok", "deny")]
    assert verdicts == ["REFUSED", "ALLOWED", "REFUSED"]
    assert "already consumed" in lines_of(scenes[2])[-1]


def test_scene_four_shows_the_missing_close_in_the_doctor(scenes) -> None:
    text = "\n".join(lines_of(scenes[3]))
    assert re.search(r"coverage gap sha256:[0-9a-f]{12}\.\.\.  signature ed25519: valid", text)
    assert "coverage: 1/2 registered turns closed (events 1, no-event 0, unresolved 1)" in text


def test_committed_pictures_are_this_run(scenes, demo) -> None:
    for name, data in demo.pictures(scenes).items():
        assert (ASSETS / name).read_bytes() == data, name + " is out of date: python demo/run.py --svg docs/assets"


def test_pictures_have_no_script_and_fit_the_width(scenes, demo) -> None:
    for data in demo.pictures(scenes).values():
        text = data.decode("utf-8")
        assert "<script" not in text and "href" not in text
        assert text.count("<animate ") == sum(len(s["lines"]) + 1 for s in scenes) + len(demo.STEPS)
