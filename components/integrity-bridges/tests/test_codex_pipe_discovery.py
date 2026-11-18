"""Codex Desktop tool pipe discovery: both pipe families, app-tools first, capabilities still required.

Codex Desktop names its tool pipe codex-app-tools-*; older builds used codex-browser-use-*, which may
expose only browser calls. Discovery that knew only the old family found no writer, so the bridge
could read threads but not send to them.
"""
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1] / "src/integrity_bridges/resources/private-memory"
APP = r"\\.\pipe\codex-app-tools-123"
BROWSER = r"\\.\pipe\codex-browser-use-456"
CAPS = [{"namespace": "codex_app", "name": name} for name in ("read_thread", "send_message_to_thread")]


@pytest.fixture()
def m(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    config.write_text(
        '{"schema":"integrity/component-config/v1","component":"integrity-bridges",'
        '"configured":true,"guardian_version":"6.1.0","memory_api_version":"2.11.0",'
        '"values":{"upstream_mcp_command":"python -m example"}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("INTEGRITY_BRIDGES_CONFIG", str(config))
    spec = importlib.util.spec_from_file_location("public_pipe_discovery_test", ROOT / "unified_mcp.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_codex_process_ids", lambda: [])
    monkeypatch.setattr(module, "safe_log", lambda *a, **k: None)
    monkeypatch.setenv("CODEX_APP_TOOLS_PIPE_PATH", "")
    monkeypatch.setenv("INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH", "")
    return module


windows_only = pytest.mark.skipif(os.name != "nt", reason="the pipe namespace is listed only on Windows")


@windows_only
def test_both_families_listed_app_tools_first_and_bad_names_dropped(m):
    names = ["codex-browser-use-456", "codex-app-tools-123", "codex-mcp-789", "codex-app-tools-../bad", "unrelated"]
    with patch.object(m.os, "listdir", return_value=names):
        assert m._enumerate_codex_app_tool_pipes() == [APP, BROWSER]


@windows_only
def test_app_tools_kept_before_the_128_pipe_limit(m):
    names = ["codex-browser-use-%d" % i for i in range(140)] + ["codex-app-tools-123"]
    with patch.object(m.os, "listdir", return_value=names):
        paths = m._enumerate_codex_app_tool_pipes()
    assert len(paths) == 128 and paths[0] == APP


def test_explicit_path_deduplicated_and_app_tools_first(m, monkeypatch):
    monkeypatch.setenv("CODEX_APP_TOOLS_PIPE_PATH", APP)
    monkeypatch.setenv("INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH", APP)
    with patch.object(m, "_enumerate_codex_app_tool_pipes", return_value=[BROWSER, APP]):
        assert m.discover_codex_app_tool_pipes() == [APP, BROWSER]


def test_explicit_path_outside_the_local_pipe_namespace_is_rejected(m, monkeypatch):
    monkeypatch.setenv("CODEX_APP_TOOLS_PIPE_PATH", r"\\server\pipe\codex-app-tools-123")
    with patch.object(m, "_enumerate_codex_app_tool_pipes", return_value=[]):
        assert m.discover_codex_app_tool_pipes() == []


def select(m, catalogs):
    calls = []

    class FakeRpc:
        def __init__(self, path):
            self.pipe_path = path

        def list_tools(self):
            calls.append(self.pipe_path)
            return catalogs[self.pipe_path]

    with patch.object(m, "_enumerate_codex_app_tool_pipes", return_value=[APP, BROWSER]), \
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
