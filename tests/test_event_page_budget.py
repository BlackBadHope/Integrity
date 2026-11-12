"""Seed event pages are byte-budgeted server-side; an oversized event is presented summary-only."""
from __future__ import annotations

from integrity_guardian import memory_synapse_mcp as mcp


def _event(event_id: int, size: int) -> dict:
    return {"id": event_id, "kind": "task", "summary": "s" * size, "tags": ["a", "b"], "details": {"k": "v" * size}}


def test_page_within_budget_is_returned_whole():
    events = [_event(i, 100) for i in range(1, 6)]
    fitted, info = mcp._fit_event_page(events)
    assert fitted == events
    assert info["trimmed"] is False and info["returned_count"] == 5 and info["summary_only_event_ids"] == []
    assert info["page_bytes"] <= info["byte_budget"] == mcp.EVENT_PAGE_BYTE_BUDGET


def test_page_is_cut_at_the_budget_and_keeps_order():
    events = [_event(i, 2_000) for i in range(1, 40)]
    fitted, info = mcp._fit_event_page(events, budget=16_384)
    assert 0 < len(fitted) < len(events)
    assert fitted == events[: len(fitted)]
    assert info["trimmed"] is True and info["source_count"] == 39
    assert info["page_bytes"] <= 16_384


def test_single_oversized_event_is_summary_only():
    big = _event(7, 40_000)
    fitted, info = mcp._fit_event_page([big, _event(8, 10)], budget=8_192)
    assert len(fitted) == 1 and info["summary_only_event_ids"] == [7] and info["trimmed"] is True
    shown = fitted[0]
    assert shown["id"] == 7 and shown["kind"] == "task" and shown["tags"] == ["a", "b"]
    assert len(shown["summary"]) == mcp.EVENT_SUMMARY_TEXT_LIMIT
    assert "details" not in shown
    assert shown["presentation"]["mode"] == "summary-only"
    assert shown["presentation"]["full_bytes"] == mcp._event_page_bytes(big)


def test_oversized_event_after_a_fitting_one_starts_the_next_page():
    fitted, info = mcp._fit_event_page([_event(1, 10), _event(2, 40_000)], budget=8_192)
    assert [e["id"] for e in fitted] == [1]
    assert info["summary_only_event_ids"] == [] and info["trimmed"] is True
