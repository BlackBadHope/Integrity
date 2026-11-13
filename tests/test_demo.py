# SPDX-License-Identifier: BUSL-1.1
"""The README demo: the records of a real run hold, this code gives the same answers, the pictures are the records."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from integrity_guardian import local_memory as lm

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
STABLE = ("recalled", "event_id", "summary", "author", "author_note", "claim_kinds", "claim_resources",
          "claim_fence", "release_names_event", "turn_status", "listed", "gap_recorded")


@pytest.fixture(scope="module")
def demo():
    spec = importlib.util.spec_from_file_location("integrity_demo_run", ROOT / "demo" / "run.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def records(demo) -> dict:
    return {name: demo.load_record(path) for name, path in demo.RECORDS.items()}


def test_records_use_only_tools_the_server_offers(records) -> None:
    offered = {tool["name"] for tool in lm.TOOLS}
    for record in records.values():
        for agent in record["agents"]:
            assert {call["tool"] for call in agent["calls"]} <= offered
            assert not any(call.get("is_error") for call in agent["calls"])


def test_the_published_prompts_are_the_ones_that_were_run(records, demo) -> None:
    for record in records.values():
        for agent in record["agents"]:
            assert demo.prompt_digest(ROOT / agent["prompt"]) == agent["prompt_sha256"], agent["prompt"]


def test_c_read_what_b_wrote_claimed_and_how_b_closed(records, demo) -> None:
    known = demo.facts(records["closed"])
    assert known["recalled"] == [("agent-a", "Result: 2"), ("agent-b", "Result: X")]
    assert known["summary"] == "Result: X" and known["author"] == ("agent-b", "codex", "local-machine")
    assert "not verified" in known["author_note"]
    assert known["claim_kinds"] == ["claim-acquired", "claim-released"] and known["release_names_event"]
    assert known["turn_status"] == "closed" and known["listed"] and not known["gap_recorded"]


def test_the_records_are_a_run_of_two_clients(records, demo) -> None:
    for record in records.values():
        clients = [demo.client_of(record, agent) for agent in record["agents"]]
        assert [name.split(" ")[0] for name in clients] == ["Claude", "Codex", "Claude"]
        declared = [agent["calls"][0]["arguments"]["declared_client"] for agent in record["agents"][:2]]
        assert declared == ["claude-code", "codex"]


def test_c_saw_that_b_broke_off(records, demo) -> None:
    known = demo.facts(records["broken-off"])
    assert known["summary"] == "Result: X" and known["author"][0] == "agent-b"
    assert known["claim_kinds"] == ["claim-acquired"] and not known["release_names_event"]
    assert known["turn_status"] == "open" and not known["listed"] and not known["gap_recorded"]


def replay(record: dict, home: Path) -> dict:
    """Send the recorded calls to a new instance; ids of the record are replaced by the new ones."""
    renamed: dict[str, str] = {}

    def fresh(value):
        if isinstance(value, str):
            return renamed.get(value, value)
        if isinstance(value, dict):
            return {key: fresh(item) for key, item in value.items()}
        return value

    replayed = copy.deepcopy(record)
    memory = lm.LocalMemory.create(home)
    try:
        for agent in replayed["agents"]:
            for call in agent["calls"]:
                reply = lm.dispatch(memory, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": call["tool"], "arguments": fresh(call["arguments"])}})
                assert reply["result"]["isError"] is False, call["tool"]
                result = json.loads(reply["result"]["content"][0]["text"])
                for key in ("registration_id", "claim_id", "event_uid"):
                    if isinstance(call["result"].get(key), str) and isinstance(result.get(key), str):
                        renamed[call["result"][key]] = result[key]
                call["result"] = result
    finally:
        memory.close()
    return replayed


@pytest.mark.parametrize("name", ["closed", "broken-off"])
def test_this_code_gives_the_recorded_answers(records, demo, tmp_path, name) -> None:
    recorded, now = demo.facts(records[name]), demo.facts(replay(records[name], tmp_path / "home"))
    assert {key: recorded[key] for key in STABLE} == {key: now[key] for key in STABLE}


def test_committed_pictures_are_the_records(demo) -> None:
    for name, data in demo.pictures(demo.load_scenes()).items():
        assert (ASSETS / name).read_bytes() == data, name + " is out of date: python demo/run.py --svg docs/assets"


def test_pictures_have_no_script_and_fit_the_width(demo) -> None:
    scenes = demo.load_scenes()
    for data in demo.pictures(scenes).values():
        text = data.decode("utf-8")
        assert "<script" not in text and "href" not in text
        assert text.count("<animate ") == sum(len(s["lines"]) + 1 for s in scenes) + len(demo.STEPS)
