"""integrity-llm-bus-hub without accounts: the parts that need no root and no Linux.

The install with real accounts, the daemon over its socket and the removal run in the CI job
"bus hub (ubuntu, real accounts)" (.github/scripts/bus_hub_accounts_check.py).
"""
import importlib
import json
import sys

hub = importlib.import_module("integrity_llm_bus.hub")

KEY = "0" * 63 + "a"


def run(capsys, *argv):
    code = hub.main(list(argv))
    return json.loads(capsys.readouterr().out), code


def test_keys_are_accepted_only_as_sha256():
    good = {"principals": {"vendor-a": {"vendor": "claude", "account": "a", "addresses": ["claude"]},
                           "local-b": {"key_sha256": KEY, "vendor": "codex", "account": "b"}},
            "accounts": {"a": {"seats": 1}}}
    assert hub.check_principals(good) == []
    for entry, text in (({"key_sha256": KEY.upper()}, "64 lowercase hex"),
                        ({"key_sha256": "abc"}, "64 lowercase hex"),
                        ({"token": "x"}, "may hold a secret"),
                        ({"api_secret": "x"}, "may hold a secret"),
                        ({"private_key": "x"}, "may hold a secret")):
        problems = hub.check_principals({"principals": {"vendor-a": entry}})
        assert any(text in p for p in problems), (entry, problems)
    assert hub.check_principals({"principals": {"A b": {}}})
    assert hub.check_principals({"principals": {}, "other": 1})
    assert hub.check_principals([])


def test_a_key_without_a_vendor_the_daemon_accepts_is_refused_at_install():
    # A web key written with vendor "humanx" installed, and then the daemon refused each of its requests.
    for vendor in ("humanx", None, "Claude"):
        entry = {"key_sha256": KEY, "vendor": vendor, "account": "a"}
        problems = hub.check_principals({"principals": {"web-a": entry}})
        assert any("vendor must be one of" in p for p in problems), (vendor, problems)
    entry = {"key_sha256": KEY, "vendor": "human", "account": "a", "addresses": ["human-operator"]}
    assert hub.check_principals({"principals": {"web-a": entry}}) == []


def test_the_vendor_list_is_the_daemons():
    import ast
    import re
    from pathlib import Path
    source = (Path(hub.DAEMON)).read_text(encoding="utf-8")
    line = re.search(r"^VENDORS = (\{[^}]*\})", source, re.M).group(1)
    assert set(hub.VENDORS) == ast.literal_eval(line)


def test_the_published_example_keys_file_is_not_installable_as_it_is():
    from pathlib import Path
    example = Path(__file__).resolve().parents[1] / "examples" / "hub" / "principals.example.json"
    problems = hub.check_principals(json.loads(example.read_text(encoding="utf-8")))
    assert problems and all("key_sha256" in p for p in problems)


def test_doctor_and_uninstall_say_not_installed(tmp_path, capsys):
    missing = tmp_path / "etc"
    assert run(capsys, "doctor", "--etc", str(missing)) == ({"status": "not-installed", "checks": []}, 3)
    assert run(capsys, "uninstall", "--etc", str(missing), "--yes") == ({"status": "not-installed", "removed": []}, 0)
    missing.mkdir()
    report, code = run(capsys, "doctor", "--etc", str(missing))
    assert (report["status"], code) == ("broken", 1)


def test_a_foreign_record_is_refused(tmp_path, capsys):
    (tmp_path / "hub.json").write_text(json.dumps({"protocol": "something-else"}), encoding="utf-8")
    report, code = run(capsys, "doctor", "--etc", str(tmp_path))
    assert code == 2 and "not a hub install record" in report["error"]


def test_install_refuses_without_root_or_off_linux(tmp_path, capsys):
    report, code = run(capsys, "install", "--etc", str(tmp_path / "e"), "--state", str(tmp_path / "s"),
                       "--runtime", str(tmp_path / "r"), "--bus-user", "b", "--gateway-user", "g",
                       "--socket-group", "s", "--principals", str(tmp_path / "p.json"))
    assert code == 2
    if sys.platform != "linux":
        assert report["error"] == "the hub runs on Linux only"
    else:
        import os
        if os.geteuid() != 0:
            assert report["error"].startswith("install needs root")
    assert not (tmp_path / "e").exists()
