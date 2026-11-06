"""Facade identity negotiation between release lines that pin different labels.

Installed clients compare the facade label exactly. The public line advertises
2.11.0, a private deployment profile may keep its installed clients on 2.10.0;
both labels describe the same contract and the same capability shape.
"""
from __future__ import annotations

import json

import pytest

from integrity_guardian import deployment_profile as dp
from integrity_guardian import memory_synapse_lts as lts
from integrity_guardian import memory_synapse_mcp as m


def _init(name: str = "integrity-client-turn-broker", version: str = "1.4.1", accepted=None) -> dict:
    params: dict = {"clientInfo": {"name": name, "version": version}, "capabilities": {}}
    if accepted is not None:
        params["capabilities"]["experimental"] = {m.FACADE_IDENTITY_CAPABILITY: {
            "protocol": m.FACADE_IDENTITY_PROTOCOL, "accepted_server_versions": accepted}}
    return params


def test_public_deployment_keeps_the_public_label():
    assert m._facade_identity(_init()) == ("2.11.0", None)
    assert m._facade_identity(_init(version="1.6.0")) == ("2.11.0", None)


def test_legacy_default_serves_installed_clients_their_label():
    assert m._facade_identity(_init(version="1.4.1"), default="2.10.0") == ("2.10.0", None)
    assert m._facade_identity(_init(name="g7-probe", version="9.9.9"), default="2.10.0") == ("2.10.0", None)
    assert m._facade_identity({"capabilities": {}}, default="2.10.0") == ("2.10.0", None)


def test_public_generation_broker_keeps_public_label_on_legacy_deployment():
    assert m._facade_identity(_init(version="1.6.0"), default="2.10.0") == ("2.11.0", None)
    assert m._facade_identity(_init(version="1.10.2"), default="2.10.0") == ("2.11.0", None)
    assert m._facade_identity(_init(version="1.5.9"), default="2.10.0") == ("2.10.0", None)
    assert m._facade_identity(_init(version="not-a-version"), default="2.10.0") == ("2.10.0", None)


def test_explicit_declaration_wins_and_is_acknowledged():
    version, ack = m._facade_identity(_init(version="1.6.0", accepted=["2.10.0"]), default="2.10.0")
    assert version == "2.10.0"
    assert ack == {"protocol": m.FACADE_IDENTITY_PROTOCOL, "server_version": "2.10.0"}
    version, ack = m._facade_identity(_init(accepted=["2.10.0", "2.11.0"]))
    assert version == "2.11.0" and ack["server_version"] == "2.11.0"
    # Nothing acceptable declared: fall back to the deployment rules.
    assert m._facade_identity(_init(accepted=["9.0.0"]), default="2.10.0") == ("2.10.0", None)


def test_selected_label_reaches_capabilities_and_server_info(tmp_path):
    service = lts.MemorySynapseLtsService(tmp_path / "absent.sqlite3")
    try:
        lts.select_facade_server_version("2.10.0")
        legacy = service.capabilities()
        assert legacy["facade"]["server_version"] == "2.10.0"
        assert lts.facade_server_version() == "2.10.0"
        lts.select_facade_server_version("2.11.0")
        public = service.capabilities()
        assert public["facade"]["server_version"] == "2.11.0"
        strip = lambda c: {k: v for k, v in c.items() if k != "capabilities_digest"}
        legacy_core, public_core = strip(legacy), strip(public)
        legacy_core["facade"] = {**legacy_core["facade"], "server_version": "x"}
        public_core["facade"] = {**public_core["facade"], "server_version": "x"}
        assert legacy_core == public_core  # the label is the only difference
        with pytest.raises(ValueError):
            lts.select_facade_server_version("2.12.0")
    finally:
        lts.select_facade_server_version(lts.FACADE_SERVER_VERSION)


def _profile(extra: dict) -> bytes:
    document = {"protocol": dp.PROTOCOL, "profile_id": "deployment:test-facade", **extra}
    return json.dumps(document, sort_keys=True).encode("utf-8")


def test_profile_accepts_only_known_facade_defaults():
    import hashlib
    raw = _profile({"facade_identity": {"default_server_version": "2.10.0"}})
    profile = dp.parse_profile(raw, "sha256:" + hashlib.sha256(raw).hexdigest())
    assert profile.facade_default_server_version == "2.10.0"
    raw = _profile({})
    assert dp.parse_profile(raw, "sha256:" + hashlib.sha256(raw).hexdigest()).facade_default_server_version is None
    for bad in ({"default_server_version": "2.12.0"}, {"other": "2.10.0"}, "2.10.0"):
        raw = _profile({"facade_identity": bad})
        with pytest.raises(dp.DeploymentProfileError):
            dp.parse_profile(raw, "sha256:" + hashlib.sha256(raw).hexdigest())
