"""Deployment-bound archive tool surface (rolling upgrade of archive-bound brokers).

A broker installed against a deployment that hard-bound one archive declares
``manifest_event_uid``/``source_sha256`` as ``const`` and compares upstream
inputSchema byte-structurally. A server whose deployment profile supplies the
same archive must acknowledge and serve exactly that bound surface; a server
without the archive, or with another one, must not.
"""
from __future__ import annotations

from types import SimpleNamespace

from integrity_guardian import memory_synapse_mcp as m
from integrity_guardian.historical_archive import ArchivePolicy, archive_tools

POLICY = ArchivePolicy(
    source_sha256="ab" * 32,
    manifest_event_uid="client:example-archive-0123456789abcdef-manifest-v1",
    message_count=10,
    part_count=2,
)
OTHER = ArchivePolicy(
    source_sha256="cd" * 32,
    manifest_event_uid="client:other-archive-0123456789abcdef-manifest-v1",
    message_count=10,
    part_count=2,
)


def _init(surface: str) -> dict:
    return {
        "clientInfo": {"name": "integrity-client-turn-broker", "version": "1.10.0"},
        "capabilities": {"experimental": {"integrityClientToolSurface": {
            "protocol": m.BROKER_TOOL_SURFACE_PROTOCOL,
            "tools_surface_sha256": surface,
        }}},
    }


def test_bound_schema_pins_the_configured_archive():
    for tool in archive_tools(POLICY):
        props = tool["inputSchema"]["properties"]
        assert props["manifest_event_uid"] == {"type": "string", "const": POLICY.manifest_event_uid}
        assert props["source_sha256"] == {"type": "string", "const": POLICY.source_sha256}
    unbound = archive_tools()
    assert all("pattern" in t["inputSchema"]["properties"]["source_sha256"] for t in unbound)
    # Only the two archive-identity fields change; everything else is identical.
    for bound, plain in zip(archive_tools(POLICY), unbound, strict=True):
        assert bound["annotations"] == plain["annotations"]
        assert bound["inputSchema"]["required"] == plain["inputSchema"]["required"]


def test_default_surfaces_are_unchanged_by_the_binding_parameter():
    for profile in ("turn-curator-v1", m.ARCHIVE_TOOL_CONTRACT_PROFILE, m.CURRENT_TOOL_CONTRACT_PROFILE):
        assert m.tools(profile=profile) == m.tools(profile=profile, archive_policy=None)
    assert m.tools() == m.tools(archive_policy=POLICY)


def test_bound_surface_is_acknowledged_and_selects_its_profile():
    for profile in ("turn-curator-v1", m.ARCHIVE_TOOL_CONTRACT_PROFILE):
        surface = m._tool_surface_sha256(m.tools(profile=profile, archive_policy=POLICY))
        assert surface != m._tool_surface_sha256(m.tools(profile=profile))
        params = _init(surface)
        assert m._tool_contract_profile(params, archive_policy=POLICY) == profile
        ack = m._broker_tool_surface_ack(params, archive_policy=POLICY)
        assert ack is not None and ack["accepted_tools_surface_sha256"] == surface
        # Without the archive, or with a different one, the bound surface is unknown.
        assert m._broker_tool_surface_ack(params) is None
        assert m._broker_tool_surface_ack(params, archive_policy=OTHER) is None
        assert m._tool_contract_profile(params) == m.PRE_V4_TOOL_CONTRACT_PROFILE


def test_unbound_surfaces_still_negotiate_on_an_archive_bound_server():
    surface = m._tool_surface_sha256(m.tools(profile="turn-curator-v1"))
    params = _init(surface)
    assert m._tool_contract_profile(params, archive_policy=POLICY) == "turn-curator-v1"
    assert m._broker_tool_surface_ack(params, archive_policy=POLICY) is not None
    assert m._archive_bound_tool_surface(params, POLICY) is None


def test_tools_list_serves_the_negotiated_bound_schema():
    server = SimpleNamespace(
        _tool_contract_profile="turn-curator-v1", _tool_contract_archive_policy=POLICY
    )
    reply = m.dispatch(server, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    served = reply["result"]["tools"]
    assert served == m.tools(profile="turn-curator-v1", archive_policy=POLICY)
    server._tool_contract_archive_policy = None
    reply = m.dispatch(server, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert reply["result"]["tools"] == m.tools(profile="turn-curator-v1")
