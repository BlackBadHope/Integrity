"""Hub copy of the bridge: Codex Desktop tool pipe discovery accepts both pipe families, app-tools first.

The hub copy learns the pipe path only from the environment and from Codex processes. It accepted only
the older codex-browser-use-* family, so a current Codex Desktop (codex-app-tools-*) gave no writer.
"""
import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1] / "src/integrity_bridges/resources/hub"
APP = r"\\.\pipe\codex-app-tools-123"
BROWSER = r"\\.\pipe\codex-browser-use-456"
CAPS = [{"namespace": "codex_app", "name": name} for name in ("read_thread", "send_message_to_thread")]


@pytest.fixture()
def m(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    config.write_text(
        '{"schema":"integrity/component-config/v1","component":"integrity-bridges",'
        '"configured":true,"guardian_version":"6.1.0","memory_api_version":"2.11.0",'
        '"values":{"upstream_mcp_command":"python -m example",'
        '"delegation_source_thread_id":"thread-source-example","delegation_target_thread_id":"thread-target-example",'
        '"pin_9e26652d89d8":"' + "0" * 64 + '","pin_d03d5e208f04":"' + "1" * 64 + '"}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("INTEGRITY_BRIDGES_CONFIG", str(config))
    monkeypatch.syspath_prepend(str(ROOT))
    spec = importlib.util.spec_from_file_location("public_hub_pipe_discovery_test", ROOT / "unified_mcp.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_codex_process_ids", lambda: [])
    monkeypatch.setattr(module, "safe_log", lambda *a, **k: None)
    monkeypatch.setenv("CODEX_APP_TOOLS_PIPE_PATH", "")
    monkeypatch.setenv("INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH", "")
    return module


def test_app_tools_pipe_from_the_environment_is_accepted(m, monkeypatch):
    monkeypatch.setenv("CODEX_APP_TOOLS_PIPE_PATH", APP)
    assert m.discover_codex_app_tool_pipes() == [APP]


def test_process_pipes_both_families_app_tools_first_and_bad_names_dropped(m, monkeypatch):
    found = {1: BROWSER, 2: APP, 3: r"\\.\pipe\codex-mcp-789", 4: r"\\server\pipe\codex-app-tools-123",
             5: r"\\.\pipe\codex-app-tools-../bad", 6: APP}
    monkeypatch.setattr(m, "_codex_process_ids", lambda: sorted(found))
    monkeypatch.setattr(m, "_read_process_environment_value", lambda pid, key: found[pid])
    assert m.discover_codex_app_tool_pipes() == [APP, BROWSER]


def select(m, catalogs):
    calls = []

    class FakeRpc:
        def __init__(self, path):
            self.pipe_path = path

        def list_tools(self):
            calls.append(self.pipe_path)
            return catalogs[self.pipe_path]

    with patch.object(m, "discover_codex_app_tool_pipes", return_value=[APP, BROWSER]), \
            patch.object(m, "NativeAppHostRpc", FakeRpc):
        host = m.Backends().get_codex_host()
    return host, calls


def test_app_tools_pipe_with_both_capabilities_is_chosen_first(m):
    host, calls = select(m, {APP: CAPS, BROWSER: []})
    assert host.pipe_path == APP and calls == [APP]


def test_older_family_still_needs_both_capabilities(m):
    host, calls = select(m, {APP: CAPS[:1], BROWSER: CAPS})
    assert host.pipe_path == BROWSER and calls == [APP, BROWSER]


def test_no_pipe_with_both_capabilities_means_no_writer(m):
    with pytest.raises(m.RpcError, match="codex_app_host_unavailable"):
        select(m, {APP: CAPS[:1], BROWSER: []})
