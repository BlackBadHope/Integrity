"""Configuration contract, address helpers and launcher (no process is started)."""
import json
import subprocess
import sys

import pytest

from integrity_humanx import configuration as C
from integrity_humanx import launcher


def test_addresses_follow_room_acl_prefixes(hx):
    assert C.operator_id() == hx.OPERATOR
    assert C.operator_address() == "human-" + hx.OPERATOR
    assert C.room_prefix() == "room-%s-" % hx.OPERATOR
    assert C.room_address("codex") == "room-%s-codex" % hx.OPERATOR


@pytest.mark.parametrize("bad", ["", "Operator", "op_1", "op%", "-op", "a" * 33])
def test_operator_id_is_validated(tmp_path, monkeypatch, hx, bad):
    doc = json.loads(open(C.os.environ[C.ENVIRONMENT], encoding="utf-8").read())
    doc["values"]["operator_id"] = bad
    p = tmp_path / "c.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setenv(C.ENVIRONMENT, str(p))
    with pytest.raises(C.ConfigurationError):
        C.operator_id()


def test_missing_value_has_no_default(tmp_path, monkeypatch):
    doc = json.loads(open(C.os.environ[C.ENVIRONMENT], encoding="utf-8").read())
    doc["values"].pop("bus_replica")
    p = tmp_path / "c.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setenv(C.ENVIRONMENT, str(p))
    with pytest.raises(C.ConfigurationError, match="bus_replica"):
        C.value("bus_replica")


def test_unconfigured_example_is_refused(monkeypatch):
    example = C.Path(__file__).resolve().parents[1] / "configuration.example.json"
    monkeypatch.setenv(C.ENVIRONMENT, str(example))
    with pytest.raises(C.ConfigurationError):
        C.read_config()


def test_example_lists_every_documented_value():
    root = C.Path(__file__).resolve().parents[1]
    example = json.loads((root / "configuration.example.json").read_text(encoding="utf-8"))
    documented = json.loads((root / "CONFIGURATION-VALUES.json").read_text(encoding="utf-8"))
    assert set(example["values"]) == set(documented)
    assert all(v is None for v in example["values"].values())


def test_launcher_list_and_preflight(capsys):
    assert launcher.main(["--list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["entrypoints"] == ["humanx-ro-gateway", "humanx-ro-snapshot", "humanx-web"]
    assert launcher.main(["--preflight"]) == 0
    pre = json.loads(capsys.readouterr().out)
    assert pre["process_started"] is False and pre["network_used"] is False
    assert launcher.main(["no-such-entry"]) == 2


def test_catalog_paths_exist():
    for entry in launcher.resource_catalog().values():
        assert (launcher.HERE / entry["path"]).is_file()


def test_package_import_is_inert():
    code = ("import sys, integrity_humanx, integrity_humanx.configuration, integrity_humanx.launcher;"
            "print(sorted(m for m in sys.modules if m.startswith('integrity_humanx')))")
    env = dict(C.os.environ)
    env.pop(C.ENVIRONMENT, None)
    out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "resources" not in out.stdout
