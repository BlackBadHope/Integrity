"""integrity-humanx-server without root: argument checks, written configuration, record handling.

The install itself, doctor on real accounts and uninstall --yes run in the CI job
`humanx server (ubuntu, real accounts)` (.github/scripts/humanx_server_check.py).
"""
from __future__ import annotations

import argparse
import json
import os
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
            "python": "/opt/example/bin/python", "complete": True,
            "existed": {"bus_group": args.bus_group, "bus_gateway_user": args.bus_gateway_user,
                        "bus_gateway_groups": [args.bus_gateway_user, args.bus_group]},
            "created": [{"kind": "dir", "name": args.etc, "state": "created"},
                        {"kind": "group", "name": args.socket_group, "state": "created"},
                        {"kind": "user", "name": args.web_user, "user_group": True, "state": "created"},
                        {"kind": "user", "name": args.gateway_user, "user_group": True, "state": "created"},
                        {"kind": "membership", "name": args.bus_gateway_user, "group": args.socket_group,
                         "state": "created"},
                        {"kind": "dir", "name": args.state, "state": "created"},
                        {"kind": "dir", "name": args.runtime, "state": "created"}]}


posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes and symbolic links")


class FakeAccounts:
    """pwd and grp for the uninstall tests: accounts and groups that exist, and who is in which group."""

    def __init__(self, users, groups):
        self.users, self.groups = set(users), {name: set(members) for name, members in groups.items()}

    def getpwnam(self, name):
        if name not in self.users:
            raise KeyError(name)
        return argparse.Namespace(pw_name=name, pw_uid=1000 + len(name), pw_gid=1000 + len(name))

    def getgrnam(self, name):
        if name not in self.groups:
            raise KeyError(name)
        return argparse.Namespace(gr_name=name, gr_mem=sorted(self.groups[name]))


def fake_system(monkeypatch, users, groups):
    """Root without a real system: commands change FakeAccounts and are recorded in order."""
    accounts = FakeAccounts(users, groups)
    ran = []

    def run(argv):
        ran.append(argv)
        tool, rest = argv[0], argv[1:]
        if tool == "userdel":
            accounts.users.discard(rest[0])
            accounts.groups.pop(rest[0], None)
        elif tool == "groupdel":
            accounts.groups.pop(rest[0])
        elif tool == "gpasswd":
            accounts.groups[rest[2]].discard(rest[1])

    monkeypatch.setattr(server, "_accounts", lambda: (accounts, accounts))
    monkeypatch.setattr(server, "_run", run)
    monkeypatch.setattr(server, "_tool", lambda name: name)
    monkeypatch.setattr(server, "_processes_of", lambda uid: [])
    monkeypatch.setattr(server.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(server, "_save", lambda record: None)
    return accounts, ran


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
    ({"bind": "0.0.0.0"}, "--allow-any-address"),
    ({"bind": "::"}, "--allow-any-address"),
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


def test_bind_defaults_to_loopback_and_every_address_needs_the_flag():
    base = ["install", "--etc", "/e", "--state", "/s", "--runtime", "/r", "--web-user", "w", "--gateway-user", "g",
            "--socket-group", "s", "--bus-group", "b", "--bus-gateway-user", "bg", "--bus-socket", "/b.sock",
            "--web-key", "/k", "--operator-id", "operator", "--port", "8890"]
    args = server.build_parser().parse_args(base)
    assert args.bind == "127.0.0.1" and args.allow_any_address is False
    args = server.build_parser().parse_args([*base, "--bind", "0.0.0.0", "--allow-any-address"])
    assert not [p for p in server.check_install_args(install_args(bind=args.bind, allow_any_address=True))
                if "--bind" in p]


@posix_only
def test_web_key_file_is_checked_and_never_echoed(tmp_path):
    key = tmp_path / "web.key"
    key.write_text("synthetic-key-value\n", encoding="utf-8")
    os.chmod(key, 0o600)
    assert server.read_web_key(str(key), server.key_owners()) == "synthetic-key-value"
    key.write_text("two words\n", encoding="utf-8")
    with pytest.raises(server.ServerError) as refused:
        server.read_web_key(str(key))
    assert "two words" not in str(refused.value)
    with pytest.raises(server.ServerError):
        server.read_web_key(str(tmp_path / "missing.key"))


@posix_only
def test_web_key_source_must_be_a_private_regular_file_of_root_or_the_caller(tmp_path):
    key = tmp_path / "web.key"
    key.write_text("synthetic-key-value\n", encoding="utf-8")
    os.chmod(key, 0o600)
    link = tmp_path / "link.key"
    link.symlink_to(key)
    with pytest.raises(server.ServerError, match="symbolic link"):
        server.read_web_key(str(link))
    for mode in (0o644, 0o640, 0o604, 0o620):
        os.chmod(key, mode)
        with pytest.raises(server.ServerError, match="group or others") as refused:
            server.read_web_key(str(key))
        assert "synthetic-key-value" not in str(refused.value)
    os.chmod(key, 0o400)
    with pytest.raises(server.ServerError, match="owned by uid"):
        server.read_web_key(str(key), owners={os.stat(key).st_uid + 1})
    with pytest.raises(server.ServerError, match="regular file"):
        server.read_web_key(str(tmp_path))


@posix_only
def test_written_files_get_their_mode_before_any_byte_and_leave_no_temporary(tmp_path):
    path = tmp_path / server.WEB_KEY
    server._write(path, "synthetic-key-value\n", 0o400, os.getuid(), os.getgid())
    assert oct(os.stat(path).st_mode & 0o777) == oct(0o400)
    assert sorted(p.name for p in tmp_path.iterdir()) == [server.WEB_KEY]


def test_uninstall_removes_only_what_the_record_lists_as_created(tmp_path, monkeypatch, capsys):
    rec = record(tmp_path)
    for folder in (rec["etc"], rec["state"], rec["runtime"]):
        Path(folder).mkdir()
    (Path(rec["etc"]) / server.RECORD).write_text(json.dumps(rec), encoding="utf-8")
    groups = {"example-ro-sock": {"example-bus-gw"}, "example-web": set(), "example-ro": set(),
              "example-bus-sock": {"example-web"}, "example-bus-gw": set(), "unrelated": {"example-bus-gw"}}
    accounts, ran = fake_system(monkeypatch, {"example-web", "example-ro", "example-bus-gw", "unrelated-user"}, groups)
    assert server.main(["uninstall", "--etc", rec["etc"], "--yes"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "removed" and report["kept"] == ["example-bus-gw", "example-bus-sock"]
    assert [argv[0] for argv in ran] == ["gpasswd", "userdel", "userdel", "groupdel"]
    assert ran[0] == ["gpasswd", "--delete", "example-bus-gw", "example-ro-sock"]
    assert ran[-1] == ["groupdel", "example-ro-sock"]
    assert accounts.users == {"example-bus-gw", "unrelated-user"}
    assert sorted(accounts.groups) == ["example-bus-gw", "example-bus-sock", "unrelated"]
    assert accounts.groups["unrelated"] == {"example-bus-gw"}
    assert not any(os.path.exists(rec[k]) for k in ("etc", "state", "runtime"))


def test_a_partial_install_is_named_by_doctor_and_removed_by_its_record(tmp_path, monkeypatch, capsys):
    rec = record(tmp_path)
    rec["complete"] = False
    rec["created"] = rec["created"][:4] + [{**rec["created"][4], "state": "planned"}]
    Path(rec["etc"]).mkdir()
    (Path(rec["etc"]) / server.RECORD).write_text(json.dumps(rec), encoding="utf-8")
    (Path(rec["etc"]) / ".web.key.tmp").write_text("", encoding="utf-8")
    assert server.main(["doctor", "--etc", rec["etc"]]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "partial" and "membership example-bus-gw in example-ro-sock" in report["checks"][0]["detail"]
    groups = {"example-ro-sock": set(), "example-web": set(), "example-ro": set(), "example-bus-sock": {"example-web"}}
    accounts, ran = fake_system(monkeypatch, {"example-web", "example-ro", "example-bus-gw"}, groups)
    assert server.main(["uninstall", "--etc", rec["etc"], "--yes"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "removed"
    assert [argv[0] for argv in ran] == ["userdel", "userdel", "groupdel"]   # the planned membership was not made
    assert accounts.users == {"example-bus-gw"} and sorted(accounts.groups) == ["example-bus-sock"]
    assert not os.path.exists(rec["etc"])


def test_uninstall_without_a_record_removes_nothing(tmp_path, capsys):
    etc = tmp_path / "etc"
    etc.mkdir()
    assert server.main(["uninstall", "--etc", str(etc), "--yes"]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "refused" and etc.exists()


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
    assert f"dir {rec['state']}" in report["would_remove"] and report["would_remove"][-1] == f"dir {rec['etc']}"
    assert f"membership {rec['bus_gateway_user']} in {rec['socket_group']}" in report["would_remove"]
    assert not any(t.endswith(f" {rec['bus_group']}") for t in report["would_remove"])
    assert etc.exists()


def test_a_foreign_record_is_refused(tmp_path, capsys):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / server.RECORD).write_text(json.dumps({"protocol": "something-else"}), encoding="utf-8")
    assert server.main(["doctor", "--etc", str(etc)]) == 2
    assert "not a HumanX server install record" in json.loads(capsys.readouterr().out)["error"]
