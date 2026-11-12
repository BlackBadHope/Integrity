"""owner-rule/v1 selector: index building, trigger scoring, byte budget, and the opt-in live path."""
from __future__ import annotations

import json

import pytest

from integrity_guardian import owner_rules


def _rule(rule_id: str, **extra):
    base = {
        "rule_id": rule_id,
        "version": 1,
        "event_id": 100,
        "rule_en": f"rule {rule_id}",
        "how": "do the thing",
        "triggers": {},
    }
    base.update(extra)
    return base


def test_index_keeps_latest_version_and_drops_superseded():
    records = [
        _rule("a", version=1),
        _rule("a", version=2),
        _rule("b", version=1),
        _rule("c", version=1, supersedes={"rule_id": "b", "version": 1}),
        _rule("d", state="superseded"),
        _rule("e", rule_kind="note"),
    ]
    index = owner_rules.build_rule_index(records)
    assert [(r["rule_id"], r["version"]) for r in index] == [("a", 2), ("c", 1)]


def test_selection_scores_hosts_tools_and_keywords():
    index = owner_rules.build_rule_index([
        _rule("host-rule", triggers={"hosts": ["192.0.2.*"]}),
        _rule("tool-rule", triggers={"tools": ["deploy"]}),
        _rule("keyword-rule", triggers={"keywords_en": ["backup window"]}),
        _rule("unrelated", triggers={"keywords_en": ["quarterly invoice"]}),
    ])
    picked, receipt = owner_rules.select_owner_rules(
        index, "check the backup window on 192.0.2.10 before the deploy")
    ids = [item["rule_id"] for item in picked]
    assert set(ids) == {"host-rule", "tool-rule", "keyword-rule"}
    assert ids.index("keyword-rule") == 2  # weight 1 ranks below hosts/tools (weight 3)
    assert all(item["why"].startswith("match:") for item in picked)
    assert receipt["protocol"] == owner_rules.PROTOCOL
    assert receipt["rules_considered"] == 4 and receipt["rules_selected"] == 3


def test_always_rules_fill_only_leftover_slots():
    index = owner_rules.build_rule_index([
        _rule("standing", always=True),
        _rule("matched", triggers={"tools": ["deploy"]}),
    ])
    picked, _ = owner_rules.select_owner_rules(index, "deploy now", max_rules=1)
    assert [item["rule_id"] for item in picked] == ["matched"]
    picked, _ = owner_rules.select_owner_rules(index, "deploy now", max_rules=2)
    assert [(item["rule_id"], item["why"]) for item in picked] == [("matched", "match:3"), ("standing", "always")]


def test_byte_budget_truncates_and_reports():
    index = owner_rules.build_rule_index([_rule(f"r{i}", always=True, how="x" * 200) for i in range(4)])
    picked, receipt = owner_rules.select_owner_rules(index, "", max_bytes=400)
    assert 0 < len(picked) < 4
    assert receipt["rules_truncated"] == 4 - len(picked)
    assert receipt["bytes"] <= 400


def test_language_follows_the_query():
    index = owner_rules.build_rule_index([
        _rule("r", always=True, rule_ru="правило", rule_en="rule"),
    ])
    picked, receipt = owner_rules.select_owner_rules(index, "проверь резервную копию")
    assert receipt["lang"] == "ru" and picked[0]["rule"] == "правило"
    picked, receipt = owner_rules.select_owner_rules(index, "check the backup")
    assert receipt["lang"] == "en" and picked[0]["rule"] == "rule"


def test_live_path_is_off_by_default(monkeypatch):
    monkeypatch.delenv("INTEGRITY_OWNER_RULES", raising=False)
    assert owner_rules.live_rules_request({"recall": {"terms": ["deploy"]}}) is None


@pytest.mark.parametrize("content", [None, b"not json"])
def test_live_path_fails_closed_on_a_bad_index(monkeypatch, tmp_path, content):
    path = tmp_path / "index.json"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setenv("INTEGRITY_OWNER_RULES", "on")
    monkeypatch.setenv("INTEGRITY_OWNER_RULES_INDEX", str(path))
    assert owner_rules.live_rules_request({"recall": {"terms": ["deploy"]}}) is None


def test_live_path_builds_a_request_from_recall_terms(monkeypatch, tmp_path):
    path = tmp_path / "index.json"
    path.write_text(json.dumps({"owner_rules": [_rule("matched", triggers={"tools": ["deploy"]})]}), encoding="utf-8")
    monkeypatch.setenv("INTEGRITY_OWNER_RULES", "on")
    monkeypatch.setenv("INTEGRITY_OWNER_RULES_INDEX", str(path))
    monkeypatch.setenv("INTEGRITY_OWNER_RULES_MAX", "3")
    owner_rules._INDEX_CACHE.clear()
    request = owner_rules.live_rules_request({"auxiliary_recall": {"terms": ["deploy", 7]}})
    assert request["enabled"] is True and request["query"] == "deploy 7" and request["max_rules"] == 3
    assert [r["rule_id"] for r in request["index"]] == ["matched"]
