"""Opt-in keywords-line advisory in the Claude standalone hook (claude/admission.py).

The check is off unless the owner configuration sets
values.event_summary_keywords_line. It never refuses an append: it only warns
and counts results in keywords-line-health.json.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

RESOURCES = Path(__file__).resolve().parents[1] / "src" / "integrity_client_memory" / "resources"
HOOK = RESOURCES / "claude" / "admission.py"

RUSSIAN = {"label": "Ключевые слова:", "min_items": 5, "max_items": 8, "script": "cyrillic",
           "min_script_share": 0.5}
OK_LINE = "Ключевые слова: индекс правил; ключевые слова; ядро памяти; установка; откат"


@pytest.fixture()
def hook(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEGRITY_CLIENT_STATE_ROOT", str(tmp_path / "integrity-memory" / "state"))
    sys.modules.pop("integrity_client_turn_envelope", None)
    sys.path.insert(0, str(RESOURCES / "common"))
    try:
        spec = importlib.util.spec_from_file_location("integrity_keywords_line_hook", HOOK)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def policy(hook, **value):
    return hook.keyword_line_policy({"event_summary_keywords_line": value})


def test_off_without_configuration(hook, monkeypatch):
    monkeypatch.delenv("INTEGRITY_CLIENT_MEMORY_CONFIG", raising=False)
    assert hook.keyword_line_policy() is None
    assert hook.keyword_line_policy({}) is None
    assert hook.keyword_line_policy({"event_summary_keywords_line": None}) is None


@pytest.mark.parametrize("value", [
    {"label": ""}, {"label": "a\nb"}, {"label": "x" * 65}, {"label": 5},
    {"label": "K:", "min_items": 0}, {"label": "K:", "min_items": 6, "max_items": 5},
    {"label": "K:", "max_items": 33}, {"label": "K:", "min_items": True},
    {"label": "K:", "script": "greek"}, {"label": "K:", "min_script_share": 1.5},
    {"label": "K:", "min_script_share": True},
])
def test_invalid_policy_is_off(hook, value):
    assert policy(hook, **value) is None


def test_defaults(hook):
    assert policy(hook, label=" Keywords: ") == {"label": "Keywords:", "min_items": 5, "max_items": 8,
                                                   "script": None, "min_script_share": 0.5}


@pytest.mark.parametrize("summary,expect", [
    ("Fixed `foo()` in x.py:12\n```\nfor i in range(3):\n    print(i)\n```\n" + OK_LINE, None),
    ("Installed release; verify-release rc=0; acceptance PASS.\n" + OK_LINE, None),
    ("Text\r\n" + OK_LINE + "\r\n\r\n  \n", None),
    ("x\nКлючевые слова: а; б; в; г; д", None),
    ("x\nКлючевые слова: а, б, в, г, д, е, ж, з", None),
    ("x\nКлючевые слова: сервер HTTP-2; порт; кольцо; отказ; таймаут", None),
    ("x\n" + OK_LINE + "\nP.S. one more sentence", "does not start"),
    ("Just a summary without the line.", "does not start"),
    ("Done. " + OK_LINE, "does not start"),
    ("x\nКлючевые слова: а; б; в; г", "4 items"),
    ("x\nКлючевые слова: а; б; в; г; д; е; ж; з; и", "9 items"),
    ("x\nКлючевые слова: индекс; bgp; ядро; откат; установка", None),
    ("x\nКлючевые слова: API, CPU, учётки, бэкап, проверка восстановления", None),
    ("x\nКлючевые слова: API; CPU; HTTP-2; бэкап; ядро; откат", None),
    ("x\nКлючевые слова: API; CPU; HTTP-2; бэкап; ядро", "cyrillic"),
    ("x\nКлючевые слова: index; rules; core; install; rollback", "cyrillic"),
    ("x\nКлючевые слова:", "0 items"),
    (None, "not text"),
    ("   \n ", "empty"),
])
def test_russian_owner_policy(hook, summary, expect):
    got = hook.keyword_line_problem(summary, policy(hook, **RUSSIAN))
    assert got is None if expect is None else (got is not None and expect in got)


def test_other_label_and_no_script(hook):
    english = policy(hook, label="Keywords:", min_items=3, max_items=4)
    assert hook.keyword_line_problem("x\nKeywords: memory, hook, advisory", english) is None
    assert "5 items" in hook.keyword_line_problem("x\nKeywords: a, b, c, d, e", english)
    assert hook.keyword_line_problem("x\nКлючевые слова: а; б; в", english) is not None


def test_ukrainian_letters_count_as_cyrillic(hook):
    got = hook.keyword_line_problem("x\nКлючові слова: їжак; ґанок; євро; інше; abc",
                                    policy(hook, **{**RUSSIAN, "label": "Ключові слова:"}))
    assert got is None


def test_counters_live_in_their_own_file(hook, tmp_path):
    root = tmp_path / "integrity-memory"
    health = root / "hook-health.json"
    health.parent.mkdir(parents=True, exist_ok=True)
    health.write_text(json.dumps({"consecutive_failures": 3}))
    before = health.read_bytes()
    hook.record_keyword_line("missing")
    hook.record_keyword_line(None)
    hook.record_keyword_line(None)
    record = json.loads((root / "keywords-line-health.json").read_text(encoding="utf-8"))
    assert record["keywords_line_missing"] == 1 and record["keywords_line_ok"] == 2
    assert record["protocol"] == "integrity-memory/keywords-line-health/v1"
    assert health.read_bytes() == before
    assert not [p for p in root.iterdir() if p.name.startswith(".")]


def test_advice_warns_and_never_denies(hook, monkeypatch, capsys):
    monkeypatch.setattr(hook, "keyword_line_policy", lambda values=None: hook.__dict__["_policy"])
    hook._policy = None
    hook.keyword_line_advice("no line")
    assert capsys.readouterr().out == ""
    hook._policy = {"label": "Ключевые слова:", "min_items": 5, "max_items": 8, "script": "cyrillic",
                    "min_script_share": 0.5}
    hook.keyword_line_advice("x\n" + OK_LINE)
    assert capsys.readouterr().out == ""
    hook.keyword_line_advice("no line")
    out = json.loads(capsys.readouterr().out)
    text = json.dumps(out, ensure_ascii=False)
    assert "NOT refused" in text and "Do not retry this append" in text
    assert "deny" not in text and "block" not in text


def test_call_site_is_after_the_append_state_is_saved():
    source = HOOK.read_text(encoding="utf-8")
    branch = source[source.index("    if APPEND_TOOL_RE.search(name):"):source.index("# Cadence tracks local progress")]
    assert branch.index("save_state(identity, state)") < branch.index("keyword_line_advice(")
    assert branch.rstrip().endswith('keyword_line_advice(tool_input(payload).get("summary"))\n        return'.rstrip())
