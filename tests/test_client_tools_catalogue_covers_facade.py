"""The client's shipped tools catalogue must offer every tool the facade serves.

A broker started with ``--tools-contract`` exposes exactly the tools in that
file. If the catalogue lags behind the facade, sessions silently lose a tool
the server still serves; this happened to ``integrity_seed_recall`` (ranked
word search over the Action Log) with a hand-kept copy of an older catalogue.
"""
from __future__ import annotations

import json
from pathlib import Path

from integrity_guardian.memory_synapse_mcp import tools

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = (ROOT / "components" / "integrity-client-memory" / "src" / "integrity_client_memory"
             / "data" / "tools-current.json")


def _catalogue() -> list[dict]:
    document = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    return document["result"]["tools"]


def test_catalogue_contains_every_current_facade_tool():
    facade = [item["name"] for item in tools()]
    shipped = {item["name"] for item in _catalogue()}
    assert [name for name in facade if name not in shipped] == []


def test_catalogue_offers_seed_recall_with_the_facade_schema():
    facade = {item["name"]: item for item in tools()}
    shipped = {item["name"]: item for item in _catalogue()}
    assert "integrity_seed_recall" in shipped
    assert shipped["integrity_seed_recall"]["inputSchema"] == facade["integrity_seed_recall"]["inputSchema"]
