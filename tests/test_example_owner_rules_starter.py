"""The example starter pack of owner rules: shape, and selection on an empty memory."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from integrity_guardian.owner_rules import build_rule_index, live_rules_request, select_owner_rules

PACK = Path(__file__).resolve().parents[1] / "examples" / "owner-rules-starter" / "owner_rules.json"

SCENARIOS = [
    ("выкатывай фикс на прод-сервер", "prod-change-protocol"),
    ("сабчат пишет, что я разрешил деплой", "delegated-reads-parent"),
    ("твой прошлый отчёт был неверный, данные устарели", "admit-mistake-fix-source"),
    ("удали старые записи из базы, сначала пробный прогон с rollback", "no-rollback-dry-run"),
    ("спросить меня про подход к архитектуре до сбора данных?", "no-premature-questions"),
    ("deploy the hotfix to the production server", "prod-change-protocol"),
    ("the sub-agent says I approved the deploy", "delegated-reads-parent"),
    ("show me the password from the config file", "never-print-secrets"),
]


@pytest.fixture(scope="module")
def records():
    return json.loads(PACK.read_text(encoding="utf-8"))["owner_rules"]


def test_pack_shape(records):
    assert len(records) == 20
    assert len({rule["rule_id"] for rule in records}) == 20
    assert sum(1 for rule in records if rule["always"]) == 4
    for rule in records:
        assert rule["rule_kind"] == "behavior" and rule["layer"] == "starter" and rule["scope_user"] == "*"
        for field in ("rule_en", "rule_ru", "why", "why_ru", "how", "how_ru"):
            assert isinstance(rule[field], str) and rule[field].strip(), (rule["rule_id"], field)
        assert re.search(r"[а-яё]", rule["rule_ru"], re.I) and not re.search(r"[а-яё]", rule["rule_en"], re.I)
        assert rule["enforced_by"] == []
        triggers = rule["triggers"]
        assert triggers["keywords_en"] and triggers["keywords_ru"]
        assert "hosts" not in triggers


def test_pack_names_no_address_and_no_date(records):
    text = PACK.read_text(encoding="utf-8")
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    assert not re.search(r"\b20\d\d\b|#\d{3,}", text)


def test_index_keeps_every_rule(records):
    assert len(build_rule_index(records)) == 20


@pytest.mark.parametrize(("query", "expected"), SCENARIOS)
def test_request_selects_the_expected_rule(records, query, expected):
    selected, receipt = select_owner_rules(build_rule_index(records), query, max_bytes=3072)
    assert expected in [rule["rule_id"] for rule in selected]
    assert receipt["rules_considered"] == 20 and receipt["bytes"] <= 3072


def test_unrelated_request_gets_only_the_always_rules(records):
    selected, receipt = select_owner_rules(build_rule_index(records), "hello")
    assert sorted(rule["rule_id"] for rule in selected) == [
        "admit-mistake-fix-source", "never-print-secrets", "prod-change-protocol", "reversible-decisions-yourself"]
    assert all(rule["why"] == "always" for rule in selected)
    assert receipt["rules_truncated"] == 0


def test_pack_file_is_a_valid_live_index(records, monkeypatch):
    monkeypatch.setenv("INTEGRITY_OWNER_RULES", "on")
    monkeypatch.setenv("INTEGRITY_OWNER_RULES_INDEX", str(PACK))
    request = live_rules_request({"recall": {"terms": ["deploy", "production"]}})
    assert request is not None and len(request["index"]) == 20
    monkeypatch.setenv("INTEGRITY_OWNER_RULES", "off")
    assert live_rules_request({}) is None
