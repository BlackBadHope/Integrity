"""Known Uroboros routes reach every client through the Mind capsule."""
import importlib.util
import json
from pathlib import Path
import sys
import threading


def _load(tmp_path, monkeypatch):
    component = Path(__file__).resolve().parents[1]
    source = component / "src/integrity_action_log/resources"
    template = json.loads((component / "configuration.example.json").read_text())
    template.update(configured=True)
    template["values"] = {key: str(tmp_path / key) for key in template["values"]}
    config = tmp_path / "config.json"
    config.write_text(json.dumps(template))
    monkeypatch.setenv("INTEGRITY_ACTION_LOG_CONFIG", str(config))
    monkeypatch.setenv("CODEX_LOG_DB", str(tmp_path / "routes.sqlite3"))
    monkeypatch.setenv("CODEX_LOG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CODEX_LOG_TOKEN", "public-synthetic-test-token-" * 3)
    monkeypatch.syspath_prepend(str(source))
    spec = importlib.util.spec_from_file_location("public_action_log_routes_test", source / "codex_action_log.py")
    log = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, log)
    spec.loader.exec_module(log)
    log.ensure_db()
    return log


ROUTE = {
    "format": "uroboros-route/v1",
    "route_id": "synthetic-onu-migration",
    "version": 1,
    "status": "verified",
    "title": "Move a subscriber ONU to the GPON VLAN: current VLAN, PON, uplink, profile",
    "triggers": ["gpon", "onu", "vlan", "subscriber"],
    "steps": ["read current VLAN", "verify VLAN on PON", "verify uplink tagging"],
    "rollback": "read-only route; no writes",
    "verified_at": "2026-11-01T00:00:00Z",
}


def test_route_reaches_capsule_and_guardian_admits_it(tmp_path, monkeypatch):
    log = _load(tmp_path, monkeypatch)
    log.insert_event({"actor": "unit-test", "action": "note", "summary": "Unrelated synthetic note",
                      "details": {}, "tags": ["test"], "event_uid": "client:routes-noise"})
    event = log.insert_event({"actor": "unit-test", "action": "medor_concept_create",
                              "summary": "Synthetic GPON migration route",
                              "details": {"uroboros_route": ROUTE}, "tags": ["uroboros-route"],
                              "event_uid": "client:routes-gpon"})
    cursor = event["id"]
    # Closed door: the route is projected but never spoken into the capsule.
    closed = log.build_mind({"q": ["Move subscriber ONU to GPON VLAN"], "snapshot_event_id": [str(cursor)]})
    assert closed["capsule"]["door"] != "admitted"
    assert closed["known_routes"]["routes"]
    assert not any(h.startswith("ROUTE #") for h in closed["capsule"]["learned_hints"])
    # Admitted door (session mechanics are tested elsewhere): hints are delivered.
    original = log.build_synaptic_capsule

    def admitted_capsule(**kwargs):
        return {**original(**kwargs), "door": "admitted"}

    monkeypatch.setattr(log, "build_synaptic_capsule", admitted_capsule)
    prompt = "<system-reminder>Linked sessions now: x (idle)</system-reminder>\nMove subscriber ONU to GPON VLAN"
    response = log.build_mind({"q": [prompt], "snapshot_event_id": [str(cursor)]})
    routes = response["known_routes"]
    assert routes["authority"] == "none" and routes["production_authority"] is False
    assert [route["event_id"] for route in routes["routes"]] == [cursor]
    assert any(hint.startswith(f"ROUTE #{cursor} verified") for hint in response["capsule"]["learned_hints"])
    assert "HINTS (learned, not authority):" in response["context_text"]
    assert "KNOWN ROUTES" in response["context_text"]
    assert "1) read current VLAN" in response["context_text"]

    from integrity_guardian.mind_admission import verify_mind_companion
    assert verify_mind_companion(response, snapshot_event_id=cursor, snapshot_event_count=2)["ok"] is True

    unrelated = log.build_mind({"q": ["write a poem about autumn"], "snapshot_event_id": [str(cursor)]})
    assert unrelated["known_routes"]["routes"] == []
    assert not any(h.startswith("ROUTE #") for h in unrelated["capsule"]["learned_hints"])

    server = log.BoundedThreadingHTTPServer(("127.0.0.1", 0), log.Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        from integrity_guardian.memory_synapse_mcp import ActionLogClient
        client = ActionLogClient("http://127.0.0.1:" + str(server.server_address[1]),
                                 auth_token="public-synthetic-test-token-" * 3, timeout=2)
        client.bind_snapshot(cursor, 2)
        admitted = client.mind({"intent": "Move subscriber ONU to GPON VLAN", "limit": 5})
        assert admitted["mind"]["known_routes"]["routes"][0]["event_id"] == cursor
        assert any(h.startswith("ROUTE #") for h in admitted["mind"]["capsule"]["learned_hints"])
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
