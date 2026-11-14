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


def _unix_socket():
    """A bound Unix socket in a short folder (a socket path holds about 100 bytes)."""
    import os
    import socket
    import tempfile
    path = os.path.join(tempfile.mkdtemp(), "core.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    return path, server


def _fake_daemon(answer):
    """A socket that answers one request with `answer` (bytes), or never answers when it is None."""
    import threading
    import time
    path, server = _unix_socket()
    server.listen(1)
    seen = []

    def serve():
        connection, _ = server.accept()
        with connection:
            seen.append(connection.makefile("rb").readline())
            if answer is None:
                time.sleep(2)
            else:
                connection.sendall(answer)
    threading.Thread(target=serve, daemon=True).start()
    return path, server, seen


def test_doctor_asks_the_daemon_one_request_without_a_key():
    import os
    import socket
    from pathlib import Path
    import pytest
    if not hasattr(socket, "AF_UNIX") or sys.platform == "win32":
        pytest.skip("the hub's socket is a Unix socket")
    path, server, seen = _fake_daemon(b'{"ok": false, "error": "no key"}\n')
    try:
        assert hub.daemon_problem(Path(path)) is None
        assert json.loads(seen[0]) == {"v": 1, "op": "status"}       # no key, no vendor: the bus is not read
    finally:
        server.close()
    for answer, text in ((b'{"ok": true, "result": {}}\n', "did not refuse"),
                         (b'{"ok": false, "error": "unknown vendor key"}\n', "did not refuse"),
                         (b"not json\n", "not JSON"),
                         (None, "does not answer within 0.5 s")):
        path, server, _ = _fake_daemon(answer)
        try:
            problem = hub.daemon_problem(Path(path), timeout=0.5)
            assert problem and text in problem, (answer, problem)
        finally:
            server.close()
    # a stopped daemon: its socket file left behind, nobody listening; and no socket at all
    path, server = _unix_socket()
    server.close()
    assert hub.daemon_problem(Path(path)) == "the daemon does not answer: ConnectionRefusedError"
    os.unlink(path)
    assert hub.daemon_problem(Path(path)) == f"the daemon does not run: {path} is missing"


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
