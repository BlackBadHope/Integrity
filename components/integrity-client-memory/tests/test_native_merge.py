"""integrity-native-merge: user-scope merge of a generated Native profile.

Fixture profiles only; every settings file lives under tmp_path. No vendor
binary, model or upstream server is started.
"""
import json
import os
import sqlite3
import sys
import tomllib
from pathlib import Path

import pytest
from integrity_client_memory import native_install as install
from integrity_client_memory import native_merge as merge

UPSTREAM = {"command": sys.executable, "args": ["-c", "raise RuntimeError('UPSTREAM MUST NOT START')"]}
UNRELATED = {"type": "command", "command": "/usr/local/bin/my-formatter --check", "timeout": 5}


# Same fixture bindings as test_native_install (importlib mode has no sibling imports).
def _bindings(tmp_path, vendor):
    result = {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
              "architecture_checkpoint_id": "checkpoint:fixture-architecture", "codex_executable": sys.executable,
              "claude_executable": sys.executable}
    if vendor == "claude":
        session = "11111111-1111-4111-8111-111111111111"
        for name in (session + ".jsonl", "host_node.py", "claude_owner.py", "fixture-claude.exe", "owner-mcp.json"):
            (tmp_path / name).write_text("{}\n", encoding="utf-8")
        install.write_json(tmp_path / "owner.json", {"schema": "integrity-claude-owner/v1",
            "binary": str(tmp_path / "fixture-claude.exe"), "binary_sha256": install.digest((tmp_path / "fixture-claude.exe").read_bytes()),
            "workspace": str(tmp_path), "state_dir": str(tmp_path), "mcp_config": str(tmp_path / "owner-mcp.json"),
            "mcp_sha256": install.digest((tmp_path / "owner-mcp.json").read_bytes()), "permission_profile": "full_access"})
        with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
            db.execute("CREATE TABLE tasks(id TEXT PRIMARY KEY,session_id TEXT)")
            db.execute("INSERT INTO tasks VALUES (?,?)", (session, session))
        result.update(claude_session_id=session, claude_owner_file=str(tmp_path / "owner.json"),
                      claude_ledger=str(tmp_path / "ledger.sqlite3"), claude_transcript=str(tmp_path / (session + ".jsonl")),
                      claude_publisher_script=str(tmp_path / "host_node.py"), claude_publisher_python=sys.executable,
                      claude_project_root=str(tmp_path))
    return result


@pytest.fixture(params=merge.VENDORS)
def profile(request, tmp_path):
    root = tmp_path / ("generated-" + request.param)
    install.build(request.param, UPSTREAM, _bindings(tmp_path, request.param), root)
    return root / "profile.json"


def _hooks_path(home, vendor):
    return merge.targets(vendor, home, None)["hooks"]


def _run(profile, home, *extra):
    return merge.main(["--profile", str(profile), "--home", str(home), *extra])


def _native_count(document):
    return sum(1 for groups in document.get("hooks", {}).values() for group in groups
               for handler in group.get("hooks", []) if merge.is_native_hook(handler))


def test_dry_run_writes_nothing(profile, tmp_path, capsys):
    home = tmp_path / "home"
    assert _run(profile, home) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["applied"] is False and report["changes"]["hooks"]["changed"]
    assert not home.exists()


def test_apply_merges_and_preserves_unrelated_entries(profile, tmp_path, capsys):
    vendor = install.read_json(profile)["vendor"]
    home = tmp_path / "home"
    hooks = _hooks_path(home, vendor)
    hooks.parent.mkdir(parents=True)
    hooks.write_text(json.dumps({"model": "keep-me", "hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [UNRELATED]}],
        "Notification": [{"hooks": [UNRELATED]}]}}), encoding="utf-8")
    os.chmod(hooks, 0o640)
    mcp = merge.targets(vendor, home, None)["mcp"]
    if vendor == "claude":
        mcp.write_text(json.dumps({"numStartups": 7, "mcpServers": {"other": {"command": "x"}}}), encoding="utf-8")
    else:
        mcp.write_text('model = "keep"\n\n[mcp_servers.other]\ncommand = "x"\n', encoding="utf-8")

    assert _run(profile, home, "--apply") == 0
    report = json.loads(capsys.readouterr().out)
    merged = json.loads(hooks.read_text(encoding="utf-8"))
    assert merged["model"] == "keep-me"
    assert merged["hooks"]["PreToolUse"][0] == {"matcher": "Bash", "hooks": [UNRELATED]}
    assert merged["hooks"]["Notification"] == [{"hooks": [UNRELATED]}]
    generated = install.read_json(profile.parent / install.LAUNCH_FILES[vendor][1])["hooks"]
    assert _native_count(merged) == len(generated)
    if os.name == "posix":  # Windows has no POSIX permission bits to keep
        assert os.stat(hooks).st_mode & 0o777 == 0o640
    backup = Path(report["changes"]["hooks"]["backup"])
    assert json.loads(backup.read_text(encoding="utf-8"))["model"] == "keep-me"
    if vendor == "claude":
        document = json.loads(mcp.read_text(encoding="utf-8"))
        assert document["numStartups"] == 7 and set(document["mcpServers"]) == {"other", "integrity_native"}
    else:
        document = tomllib.loads(mcp.read_text(encoding="utf-8"))
        assert document["model"] == "keep" and set(document["mcp_servers"]) == {"other", "integrity_native"}


def test_second_profile_replaces_instead_of_doubling(profile, tmp_path, capsys):
    vendor = install.read_json(profile)["vendor"]
    home = tmp_path / "home"
    assert _run(profile, home, "--apply") == 0
    newer = tmp_path / "generated-newer"
    (tmp_path / "newer-bindings").mkdir()
    install.build(vendor, UPSTREAM, _bindings(tmp_path / "newer-bindings", vendor), newer)
    capsys.readouterr()
    assert _run(newer / "profile.json", home, "--apply") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["changes"]["hooks"]["replaced"] and not report["changes"]["hooks"]["added"]
    assert report["changes"]["mcp"]["action"] == "replaced"
    merged = json.loads(_hooks_path(home, vendor).read_text(encoding="utf-8"))
    generated = install.read_json(newer / install.LAUNCH_FILES[vendor][1])["hooks"]
    assert _native_count(merged) == len(generated)
    assert all(str(newer) in h["command"] for groups in merged["hooks"].values()
               for g in groups for h in g["hooks"])
    if vendor == "codex":
        text = merge.targets(vendor, home, None)["mcp"].read_text(encoding="utf-8")
        assert text.count("[mcp_servers.integrity_native]") == 1


def test_reapply_is_a_no_op(profile, tmp_path, capsys):
    home = tmp_path / "home"
    assert _run(profile, home, "--apply") == 0
    capsys.readouterr()
    assert _run(profile, home, "--apply") == 0
    report = json.loads(capsys.readouterr().out)
    assert not report["changes"]["hooks"]["changed"] and not report["changes"]["mcp"]["changed"]
    assert report["changes"]["hooks"]["backup"] is None


def test_remove_restores_unrelated_settings(profile, tmp_path):
    vendor = install.read_json(profile)["vendor"]
    home = tmp_path / "home"
    hooks = _hooks_path(home, vendor)
    hooks.parent.mkdir(parents=True)
    original = {"hooks": {"Stop": [{"hooks": [UNRELATED]}]}}
    hooks.write_text(json.dumps(original), encoding="utf-8")
    assert _run(profile, home, "--apply") == 0
    assert _run(profile, home, "--apply", "--remove") == 0
    assert json.loads(hooks.read_text(encoding="utf-8")) == original
    mcp = merge.targets(vendor, home, None)["mcp"]
    if vendor == "claude":
        assert json.loads(mcp.read_text(encoding="utf-8")) == {"mcpServers": {}}
    else:
        assert "integrity_native" not in tomllib.loads(mcp.read_text(encoding="utf-8")).get("mcp_servers", {})


def test_invalid_settings_are_refused_not_overwritten(profile, tmp_path, capsys):
    vendor = install.read_json(profile)["vendor"]
    home = tmp_path / "home"
    hooks = _hooks_path(home, vendor)
    hooks.parent.mkdir(parents=True)
    hooks.write_text("{ not json", encoding="utf-8")
    assert _run(profile, home, "--apply") == 2
    assert "not valid JSON" in capsys.readouterr().err
    assert hooks.read_text(encoding="utf-8") == "{ not json"
    assert list(hooks.parent.glob("*.integrity-backup-*")) == []


def test_drifted_profile_is_refused(profile, tmp_path, capsys):
    vendor = install.read_json(profile)["vendor"]
    generated = profile.parent / install.LAUNCH_FILES[vendor][1]
    generated.write_text(generated.read_text(encoding="utf-8").replace('"timeout": 60', '"timeout": 61'),
                         encoding="utf-8")
    home = tmp_path / "home"
    assert _run(profile, home, "--apply") == 2
    assert "Native merge refused" in capsys.readouterr().err
    assert not home.exists()


def test_antigravity_profile_needs_no_merge(tmp_path, capsys):
    root = tmp_path / "generated-ag"
    install.build("antigravity", UPSTREAM, _bindings(tmp_path, "antigravity"), root)
    assert _run(root / "profile.json", tmp_path / "home") == 2
    assert "already user scope" in capsys.readouterr().err


def test_other_integrity_hooks_are_kept_and_reported():
    plugin = {"type": "command", "command": "python /opt/integrity-claude-code/hook.py Stop"}
    document = {"hooks": {"Stop": [{"hooks": [plugin]}]}}
    merged, summary = merge.merge_hooks(document, {"Stop": [{"hooks": [
        {"type": "command", "command": "py -m integrity_client_memory.native_runtime --profile p hook Stop"}]}]})
    assert merged["hooks"]["Stop"][0] == {"hooks": [plugin]} and len(merged["hooks"]["Stop"]) == 2
    assert summary["kept_other_integrity"] == {"Stop": 1}


def test_toml_subtables_are_replaced_and_inline_tables_refused():
    text = ('[mcp_servers.integrity_native]\ncommand = "old"\n\n[mcp_servers.integrity_native.env]\n'
            'A = "1"\n\n[mcp_servers.keep]\ncommand = "k"\n')
    merged, action = merge.merge_toml_server(text, "integrity_native", '[mcp_servers.integrity_native]\ncommand = "new"\n')
    parsed = tomllib.loads(merged)["mcp_servers"]
    assert action == "replaced" and parsed["integrity_native"] == {"command": "new"} and parsed["keep"]
    with pytest.raises(ValueError, match="does not edit"):
        merge.merge_toml_server('mcp_servers = { integrity_native = { command = "x" } }\n', "integrity_native", "")
