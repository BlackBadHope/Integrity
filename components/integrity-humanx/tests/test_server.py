"""integrity-humanx-server without root: argument checks, written configuration, record handling.

The install itself, doctor on real accounts and uninstall --yes run in the CI job
`humanx server (ubuntu, real accounts)` (.github/scripts/humanx_server_check.py).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from integrity_humanx import server

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def install_args(**changes):
    values = {"etc": "/etc/example-humanx", "state": "/var/lib/example-humanx", "runtime": "/run/example-humanx",
              "web_user": "example-web", "gateway_user": "example-ro", "socket_group": "example-ro-sock",
              "bus_group": "example-bus-sock", "bus_gateway_user": "example-bus-gw",
              "bus_socket": "/run/example-bus/core.sock", "web_key": "/nonexistent/web.key",
              "operator_id": "operator", "vendor": ["claude"], "bind": "127.0.0.1", "port": 8890,
              "allow": ["127.0.0.1"]}
    values.update(changes)
    return argparse.Namespace(**values)


def record(tmp_path):
    args = install_args(etc=str(tmp_path / "etc"), state=str(tmp_path / "state"), runtime=str(tmp_path / "run"))
    return {"protocol": server.RECORD_PROTOCOL, "web_user": args.web_user, "gateway_user": args.gateway_user,
            "socket_group": args.socket_group, "bus_group": args.bus_group, "bus_gateway_user": args.bus_gateway_user,
            "bus_socket": args.bus_socket, "operator_id": args.operator_id, "vendors": args.vendor, "bind": args.bind,
            "port": args.port, "allow": args.allow, "etc": args.etc, "state": args.state, "runtime": args.runtime,
            "python": "/opt/example/bin/python"}


def test_valid_arguments_have_no_problems():
    assert server.check_install_args(install_args()) == []


@pytest.mark.parametrize("changes, text", [
    ({"web_user": "Web"}, "web user"),
    ({"gateway_user": "example-web"}, "three different names"),
    ({"socket_group": "example-bus-sock"}, "differ from the bus group"),
    ({"state": "relative/state"}, "--state"),
    ({"bus_socket": "core.sock"}, "--bus-socket"),
    ({"operator_id": "Operator_1"}, "operator id"),
    ({"bind": "localhost"}, "--bind"),
    ({"port": 0}, "--port"),
    ({"allow": None}, "--allow"),
    ({"allow": ["not-an-address"]}, "--allow"),
    ({"vendor": None}, "--vendor"),
    ({"vendor": ["Claude!"]}, "--vendor"),
])
def test_bad_arguments_are_named(changes, text):
    problems = server.check_install_args(install_args(**changes))
    assert problems and any(text in p for p in problems), problems


def test_written_web_and_gateway_configuration_have_the_keys_the_resources_read(tmp_path):
    rec = record(tmp_path)
    for built, example in ((server.web_configuration(rec), "web-config.example.json"),
                           (server.gateway_configuration(rec), "ro-gateway-config.example.json")):
        expected = set(json.loads((EXAMPLES / example).read_text(encoding="utf-8"))) - {"_comment"}
        assert set(built) >= expected - {"mysql"}, sorted(expected - set(built))
    gateway = server.gateway_configuration(rec)
    assert gateway["switch_nets"] == [] and gateway["web_rings_ips"] == [] and gateway["storm_host"] == ""
    assert gateway["gateway_user"] == rec["bus_gateway_user"]
    assert set(server.GATEWAY_OWNED) <= set(gateway)


def test_component_configuration_passes_the_configuration_contract(tmp_path, monkeypatch):
    from integrity_humanx import configuration
    path = tmp_path / "configuration.json"
    path.write_text(json.dumps(server.component_configuration(record(tmp_path))), encoding="utf-8")
    monkeypatch.setenv(configuration.ENVIRONMENT, str(path))
    assert configuration.operator_id() == "operator"
    assert configuration.value("web_config").endswith("web.json")
    assert configuration.value("ro_gateway_socket").endswith("gw.sock")


def test_start_commands_use_the_launcher_as_each_account(tmp_path):
    commands = server.start_commands(record(tmp_path))
    assert commands["web"]["user"] == "example-web" and commands["web"]["argv"][-1] == "humanx-web"
    assert commands["gateway"]["user"] == "example-ro" and commands["gateway"]["argv"][-1] == "humanx-ro-gateway"
    assert commands["web"]["argv"][1:5] == ["-I", "-B", "-m", "integrity_humanx"]


def test_web_key_file_is_checked_and_never_echoed(tmp_path):
    key = tmp_path / "web.key"
    key.write_text("synthetic-key-value\n", encoding="utf-8")
    assert server.read_web_key(str(key)) == "synthetic-key-value"
    key.write_text("two words\n", encoding="utf-8")
    with pytest.raises(server.ServerError) as refused:
        server.read_web_key(str(key))
    assert "two words" not in str(refused.value)
    with pytest.raises(server.ServerError):
        server.read_web_key(str(tmp_path / "missing.key"))


def test_install_refuses_off_linux_and_without_root(monkeypatch):
    monkeypatch.setattr(server.sys, "platform", "win32")
    with pytest.raises(server.ServerError, match="Linux only"):
        server.install(install_args())
    monkeypatch.setattr(server.sys, "platform", "linux")
    monkeypatch.setattr(server.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(server.ServerError, match="needs root"):
        server.install(install_args())


def test_doctor_and_uninstall_without_an_install(tmp_path, capsys):
    etc = tmp_path / "etc"
    assert server.main(["doctor", "--etc", str(etc)]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "not-installed"
    assert server.main(["uninstall", "--etc", str(etc), "--yes"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "not-installed"
    etc.mkdir()
    assert server.main(["doctor", "--etc", str(etc)]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "broken"


def test_uninstall_without_yes_only_lists(tmp_path, capsys):
    rec = record(tmp_path)
    etc = Path(rec["etc"])
    etc.mkdir()
    (etc / server.RECORD).write_text(json.dumps(rec), encoding="utf-8")
    assert server.main(["uninstall", "--etc", str(etc)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "dry-run"
    assert rec["state"] in report["would_remove"] and any(rec["bus_gateway_user"] in t for t in report["would_remove"])
    assert etc.exists()


def test_a_foreign_record_is_refused(tmp_path, capsys):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / server.RECORD).write_text(json.dumps({"protocol": "something-else"}), encoding="utf-8")
    assert server.main(["doctor", "--etc", str(etc)]) == 2
    assert "not a HumanX server install record" in json.loads(capsys.readouterr().out)["error"]
