"""Uroboros known-route retrieval: selection, versions, noise and authority."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from integrity_guardian.mind_retrieval import derive_retrieval_terms
from integrity_guardian.uroboros_routes import (
    MAX_HINT_CHARS,
    PROTOCOL,
    ROUTE_FORMAT,
    build_known_routes,
    route_from_event,
    routes_from_event,
    route_hint,
)

NOW = dt.datetime(2026, 11, 6, tzinfo=dt.UTC)


def _explicit(event_id, route_id, *, version=1, status="verified", title, triggers=(), ts="2026-11-01T00:00:00Z"):
    return {
        "id": event_id,
        "ts_utc": ts,
        "action": "medor_concept_create",
        "summary": title,
        "tags": ["concept"],
        "details": {
            "uroboros_route": {
                "format": ROUTE_FORMAT,
                "route_id": route_id,
                "version": version,
                "status": status,
                "title": title,
                "triggers": list(triggers),
                "steps": ["read current VLAN", "check PON", "check uplink"],
                "rollback": "no writes; nothing to roll back",
                "verified_at": ts,
            }
        },
    }


def _observed(event_id, summary, *, task_id, verified=True, ts="2026-10-20T00:00:00Z"):
    return {
        "id": event_id,
        "ts_utc": ts,
        "action": "agent_change_complete",
        "summary": summary,
        "tags": ["agent-log"],
        "details": {
            "task_id": task_id,
            "kind": "task-complete",
            "result": "done",
            "truth_status": "verified" if verified else "reported",
            "commands": ["virsh domstate vm", "virsh undefine --remove-all-storage vm"],
            "verification": "pre: shut off; post: domain absent",
            "rollback": "restore from backup image",
        },
    }


EVENTS = [
    _explicit(10, "gpon-migration-vlan", version=2, title="Переход абонента на GPON: текущий VLAN → PON → uplink",
              triggers=["gpon", "абонент", "vlan", "onu"]),
    _explicit(5, "gpon-migration-vlan", version=1, title="Старый маршрут перехода абонента на GPON",
              triggers=["gpon", "абонент"]),
    _explicit(11, "stp-storm-break", status="superseded", title="Anti storm: break the ring loop",
              triggers=["stp", "storm", "ring"]),
    _explicit(12, "stp-storm-break-v2", status="stale", title="Anti storm: break the ring loop, current version",
              triggers=["stp", "storm", "ring"]),
    _observed(20, "Deleted test VM integrity-cleanvm with guarded virsh undefine", task_id="vm-delete-cleanvm"),
    _observed(21, "Unverified VM delete attempt", task_id="vm-delete-other", verified=False),
    {"id": 30, "ts_utc": "2026-11-01T00:00:00Z", "action": "note", "summary": "Random GPON chatter about абонент",
     "tags": [], "details": {}},
]


def _routes(prompt):
    return build_known_routes(derive_retrieval_terms(prompt), EVENTS, now=NOW)


def test_explicit_route_is_found_and_latest_version_wins():
    result = _routes("Переведи абонента 1234 на GPON, проверь VLAN")
    assert result["protocol"] == PROTOCOL
    assert result["routes"][0]["event_id"] == 10
    assert result["routes"][0]["version"] == 2
    assert all(route["event_id"] != 5 for route in result["routes"])


def test_superseded_is_hidden_and_stale_is_labelled():
    result = _routes("STP storm on the ring again")
    ids = [route["event_id"] for route in result["routes"]]
    assert 11 not in ids and 12 in ids
    stale = next(route for route in result["routes"] if route["event_id"] == 12)
    assert "verify first" in stale["hint"]


def test_verified_completion_becomes_observed_route():
    result = _routes("delete the test VM with virsh undefine")
    ids = [route["event_id"] for route in result["routes"]]
    assert ids[0] == 20
    assert 21 not in ids  # not verified → not a route
    assert result["routes"][0]["source"] == "observed"
    assert result["routes"][0]["has_rollback"] is True


def test_unrelated_prompt_yields_nothing():
    assert _routes("напиши стихотворение про осень")["routes"] == []
    assert _routes("")["status"] == "empty-terms"


def test_plain_notes_are_not_routes():
    assert route_from_event(EVENTS[-1]) is None


def test_harness_noise_does_not_drive_retrieval():
    noise = (
        "<system-reminder>Linked sessions now: gpon-migration = local_x (idle); "
        "vlan202 abonent GPON ONU VLAN</system-reminder>\nнапиши стихотворение про осень"
    )
    assert _routes(noise)["routes"] == []


def test_hint_is_bounded_and_never_authority():
    long_title = "x" * 1000
    hint = route_hint({"event_id": 1, "status": "verified", "source": "explicit", "route_id": "r1",
                       "version": 3, "title": long_title, "verified_at": "2026-11-01T00:00:00Z"})
    assert len(hint) <= MAX_HINT_CHARS
    assert "not authority" in hint
    result = _routes("Переведи абонента на GPON")
    assert result["authority"] == "none" and result["production_authority"] is False
    assert all(len(route["hint"]) <= MAX_HINT_CHARS for route in result["routes"])


def test_deterministic_for_same_snapshot():
    assert _routes("Переведи абонента на GPON") == _routes("Переведи абонента на GPON")


def test_component_copy_matches_canonical_source():
    root = Path(__file__).resolve().parents[1]
    canonical = (root / "src/integrity_guardian/uroboros_routes.py").read_text(encoding="utf-8")
    component = (root / "components/integrity-action-log/src/integrity_action_log/resources/"
                 "uroboros_routes.py").read_text(encoding="utf-8")
    assert component == "# SPDX-License-Identifier: Apache-2.0\n" + canonical


def test_bundle_registers_several_routes_in_one_event():
    bundle = {
        "id": 40, "ts_utc": "2026-11-05T00:00:00Z", "action": "medor_concept_create",
        "summary": "Route catalogue import", "tags": ["uroboros-route"],
        "details": {"uroboros_routes": [
            _explicit(0, "power-outage-analysis", title="Mass switch outage analysis by power queue",
                      triggers=["outage", "switches", "power"])["details"]["uroboros_route"],
            _explicit(0, "vm-guarded-delete", title="Delete a test VM with guarded virsh undefine",
                      triggers=["virsh", "delete", "vm"])["details"]["uroboros_route"],
            {"format": "uroboros-route/v1", "route_id": "!bad"},
        ]},
    }
    assert [r["route_id"] for r in routes_from_event(bundle)] == ["power-outage-analysis", "vm-guarded-delete"]
    result = build_known_routes(derive_retrieval_terms("mass outage of switches, check power queue"), [bundle], now=NOW)
    assert [r["route_id"] for r in result["routes"]] == ["power-outage-analysis"]
    assert result["routes"][0]["event_id"] == 40


def test_capsule_text_never_cuts_inside_the_route_hints():
    """Live 06.11: the 8 KiB budget cut the second ROUTE line mid-word."""
    from integrity_guardian.context_budget import build_context_capsule, resolve_context_budget

    hints = [route_hint({"event_id": n, "status": "verified", "source": "explicit", "route_id": f"route-{n}",
                         "version": 1, "title": "т" * 300, "verified_at": "2026-11-01"}) for n in (1, 2, 3)]
    capsule = {"protocol": "integrity-guardian/mind-capsule/v1", "door": "admitted", "links_status": "isolated",
               "budget": "complete", "projection": "current",
               "here": {"task_id": "", "status": "", "agent_id": "claude:x", "agent_product": "claude"},
               "links": [], "moves": [{"kind": "wait-or-resume-after", "provenance": "declared",
                                       "reason": "Read-only admission. Do not resume writes."}],
               "learned_hints": hints, "omitted_link_count": 0, "production_authority": False}

    def records(count):
        return [{"id": n + 1, "summary": "ж" * 1500, "next_action": "ж" * 400} for n in range(count)]

    source = {
        "capsule": capsule, "context_text": "x" * 20_000, "recall": {"hits": records(8)},
        "invariants": ["ж" * 300] * 7, "epistemic": {"contradictions": records(4)},
        "plan": {"items": records(5)}, "attention": {"items": records(5)}, "logical_chains": records(4),
        "snapshot": {"event_count": 1, "event_cursor": 1},
    }
    admission = {"intent_fingerprint": "f", "projection_digest": "sha256:" + "0" * 64}
    policy = resolve_context_budget("route", budget={"max_context_bytes": 8192, "max_candidates": 5})
    built, _receipt = build_context_capsule(source, admission, policy)
    text = built["working_set"]["context_text"]
    assert all(hint in text for hint in hints)


def test_draft_validates_and_round_trips_through_retrieval():
    from integrity_guardian.uroboros_routes import draft_route_record

    record = draft_route_record(route_id="onu-reboot", title="Reboot one ONU safely",
                                triggers=["onu", "reboot"], steps=["check ONU is idle"], rollback="none",
                                status="verified")
    event = {"id": 50, "ts_utc": "2026-11-05T00:00:00Z", "action": "x", "summary": "s", "tags": [],
             "details": {"uroboros_route": record}}
    result = build_known_routes(derive_retrieval_terms("reboot the ONU please"), [event], now=NOW)
    assert [route["route_id"] for route in result["routes"]] == ["onu-reboot"]


def test_validation_rejects_bad_records_without_echoing_content():
    import pytest

    from integrity_guardian.uroboros_routes import RouteRecordError, validate_route_record

    base = {"format": ROUTE_FORMAT, "route_id": "ok-route", "title": "t", "triggers": ["a", "b"]}
    assert validate_route_record(base)["status"] == "candidate"
    bad = [
        {**base, "format": "other"},
        {**base, "route_id": "!"},
        {**base, "status": "done"},
        {**base, "triggers": ["only-one"]},
        {**base, "surprise": 1},
        {**base, "provenance_event_ids": [0]},
    ]
    for record in bad:
        with pytest.raises(RouteRecordError):
            validate_route_record(record)
    secret = "hunter2-very-secret"
    with pytest.raises(RouteRecordError) as caught:
        validate_route_record({**base, "steps": [f"password={secret}"]})
    assert secret not in str(caught.value)


def test_secret_like_routes_are_never_offered():
    event = _explicit(60, "leaky-route", title="GPON route with token=abcdef123456 inside",
                      triggers=["gpon", "onu", "абонент"])
    result = build_known_routes(derive_retrieval_terms("Переведи абонента на GPON"), [event], now=NOW)
    assert result["routes"] == [] and result["rejected_secret_like"] == 1


def test_cli_draft_and_validate(tmp_path, capsys):
    import json as _json

    from integrity_guardian.uroboros_routes import main

    assert main(["draft", "--route-id", "cli-route", "--title", "CLI route",
                 "--trigger", "cli", "--trigger", "route"]) == 0
    details = _json.loads(capsys.readouterr().out)
    path = tmp_path / "route.json"
    path.write_text(_json.dumps(details), encoding="utf-8")
    assert main(["validate", str(path)]) == 0
    path.write_text(_json.dumps({"uroboros_routes": [details["uroboros_route"], {"format": "x"}]}),
                    encoding="utf-8")
    assert main(["validate", str(path)]) == 2


def _check(event_id, route_id, result, *, version=None, checked_at="2026-11-06T00:00:00Z"):
    record = {"format": "uroboros-route-check/v1", "route_id": route_id, "result": result,
              "checked_at": checked_at}
    if version is not None:
        record["version"] = version
    return {"id": event_id, "ts_utc": checked_at, "action": "x", "summary": "check", "tags": [],
            "details": {"uroboros_route_check": record}}


def test_failed_check_marks_route_stale_and_asks_for_repair():
    events = EVENTS + [_check(70, "gpon-migration-vlan", "fail", version=2)]
    route = _routes_for(events, "Переведи абонента на GPON")[0]
    assert route["status"] == "stale" and route["check_failed_at"].startswith("2026-11-06")
    assert "repair" in route["hint"]


def test_passing_check_promotes_candidate_and_dates_it():
    events = [_explicit(5, "onu-reset", status="candidate", title="Reset an ONU after a profile change",
                        triggers=["onu", "reset", "profile"]),
              _check(6, "onu-reset", "pass", checked_at="2026-11-06T03:00:00Z")]
    route = _routes_for(events, "reset the ONU profile")[0]
    assert route["status"] == "verified" and route["verified_at"].startswith("2026-11-06T03")


def test_repair_version_after_failed_check_wins():
    events = EVENTS + [_check(70, "gpon-migration-vlan", "fail", version=2),
                       _explicit(80, "gpon-migration-vlan", version=3, title="Переход абонента на GPON, исправлено",
                                 triggers=["gpon", "абонент", "vlan"])]
    route = _routes_for(events, "Переведи абонента на GPON")[0]
    assert (route["event_id"], route["version"], route["status"]) == (80, 3, "verified")
    assert route["check_failed_at"] == ""


def test_check_for_another_version_is_ignored():
    events = EVENTS + [_check(70, "gpon-migration-vlan", "fail", version=1)]
    assert _routes_for(events, "Переведи абонента на GPON")[0]["status"] == "verified"


def test_cli_check(capsys):
    import json as _json

    from integrity_guardian.uroboros_routes import main

    assert main(["check", "--route-id", "gpon-migration-vlan", "--result", "fail", "--version", "3",
                 "--note", "uplink no longer carries the VLAN"]) == 0
    record = _json.loads(capsys.readouterr().out)["uroboros_route_check"]
    assert record["result"] == "fail" and record["checked_at"]
    assert main(["check", "--route-id", "x-route", "--result", "fail", "--note", "token=abcdef123456"]) == 2


def _routes_for(events, prompt):
    return build_known_routes(derive_retrieval_terms(prompt), events, now=NOW)["routes"]


def test_example_catalogue_is_valid_and_retrievable():
    import json as _json

    from integrity_guardian.uroboros_routes import MAX_BUNDLE_ROUTES, validate_route_record

    path = Path(__file__).resolve().parents[1] / "examples/uroboros-routes/routes.json"
    details = _json.loads(path.read_text(encoding="utf-8"))
    records = details["uroboros_routes"]
    assert 0 < len(records) <= MAX_BUNDLE_ROUTES
    for record in records:
        validate_route_record(record)
    event = {"id": 1, "ts_utc": "2026-11-06T00:00:00Z", "action": "x", "summary": "catalogue",
             "tags": [], "details": details}
    hits = build_known_routes(derive_retrieval_terms("our TLS certificate expiry is close, renew it"),
                              [event], now=NOW)["routes"]
    assert hits[0]["route_id"] == "example.tls-certificate-renewal"


def test_peer_message_noise_does_not_pull_observed_routes():
    """Live 06.11: an Arbiter peer message pulled three unrelated observed routes."""
    history = [
        _observed(6610, "Cross-session chain recovery protocol accepted: CENTRAL_PULL_READ restores PON",
                  task_id="cross-session-recovery"),
        _observed(4693, "Orbit Arbiter arbitrary-N fleet is live; HTTP login loop fixed and verified",
                  task_id="orbit-arbiter-fleet"),
    ]
    prompt = ('<cross-session-message from="local_752e" from-name="[100%] [ARBITER] Arbiter">\n'
              "Arbiter question: did you restart codex-action-log this morning? One line: who and why.\n"
              "</cross-session-message>")
    assert build_known_routes(derive_retrieval_terms(prompt), history, now=NOW)["routes"] == []


def test_peer_message_text_stays_searchable():
    terms = derive_retrieval_terms('<cross-session-message from="x" from-name="y">check SIP phone 220</cross-session-message>')
    assert "SIP" in terms and "phone" in terms
    assert not any("cross-session" in term or "from-name" in term for term in terms)


def test_hint_points_to_one_call_that_returns_the_steps():
    route = _routes("Переведи абонента на GPON")["routes"][0]
    assert "steps: read_events after_id=9" in route["hint"]
    assert route["run_steps"] == ["read current VLAN", "check PON", "check uplink"]


def test_routes_block_lists_runnable_steps():
    from integrity_guardian.uroboros_routes import render_routes_block

    block = render_routes_block(build_known_routes(derive_retrieval_terms("Переведи абонента на GPON"), EVENTS, now=NOW))
    assert block.startswith("KNOWN ROUTES")
    assert "1) read current VLAN" in block and len(block) <= 1500
    assert render_routes_block({"routes": []}) == ""
