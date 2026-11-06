"""Release custody, forced-command behaviour and the session supervisor (Linux)."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("the core side is Linux-only", allow_module_level=True)

from integrity_remote import release as rel  # noqa: E402
from integrity_remote.cli import main  # noqa: E402

PROBE = ("import json,os,sys;print(json.dumps({'argv':sys.argv[1:],"
         "'env':{k:os.environ.get(k) for k in ('INTEGRITY_REMOTE_DEVICE_ID','SSH_ORIGINAL_COMMAND',"
         "'CLIENT_SUPPLIED','FIXED')},'stdin':sys.stdin.read()}),flush=True)")


def _core(tmp_path, argv=None, **kwargs):
    argv = argv or [sys.executable, "-c", PROBE, "{device_id}"]
    return rel.init_core(root=tmp_path / "core", argv=argv, env={"FIXED": "server-side"}, **kwargs)


def _run(forced, *args, stdin="", env=None):
    full_env = {"PATH": "/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": "cat /etc/passwd",
                "CLIENT_SUPPLIED": "x", **(env or {})}
    return subprocess.run([forced, *args], input=stdin, capture_output=True, text=True,
                          env=full_env, timeout=30)


def test_init_builds_a_verified_immutable_release(tmp_path):
    result = _core(tmp_path)
    release = Path(result["release"])
    assert release.name == result["digest"] and rel.DIGEST.match(result["digest"])
    assert oct(release.stat().st_mode & 0o777) == "0o555"
    assert sorted(p.name for p in release.iterdir()) == sorted(rel.ALL_FILES)
    assert rel.verify(release)["ok"]
    again = _core(tmp_path)
    assert again["digest"] == result["digest"] and again["created"] is False


def test_forced_command_ignores_client_command_and_environment(tmp_path):
    forced = _core(tmp_path)["forced_command"]
    out = _run(forced, "--device", "laptop-b", stdin="hello")
    assert out.returncode == 0, out.stderr
    seen = json.loads(out.stdout)
    assert seen["argv"] == ["laptop-b"] and seen["stdin"] == "hello"
    assert seen["env"] == {"INTEGRITY_REMOTE_DEVICE_ID": "laptop-b", "SSH_ORIGINAL_COMMAND": None,
                           "CLIENT_SUPPLIED": None, "FIXED": "server-side"}


@pytest.mark.parametrize("args,code", [((), 64), (("--device",), 64), (("--device", "Bad Id"), 64),
                                       (("--other", "x"), 64), (("--device", "a", "x"), 64)])
def test_forced_command_rejects_malformed_bindings(tmp_path, args, code):
    out = _run(_core(tmp_path)["forced_command"], *args)
    assert out.returncode == code and out.stdout == ""


def test_anonymous_release_accepts_no_device(tmp_path):
    out = _run(_core(tmp_path, device_required=False)["forced_command"])
    assert out.returncode == 0 and json.loads(out.stdout)["env"]["INTEGRITY_REMOTE_DEVICE_ID"] == ""


def _writable(path):
    os.chmod(path.parent, 0o755)
    os.chmod(path, 0o644)


@pytest.mark.parametrize("tamper", ["edit-server", "add-file", "writable", "symlink", "rename",
                                    "edit-sums", "hardlink"])
def test_tampered_release_never_starts_the_server(tmp_path, tamper):
    result = _core(tmp_path)
    release = Path(result["release"])
    forced = release / "run-mcp"
    marker = tmp_path / "server-ran"
    if tamper == "edit-server":
        _writable(release / "server.json")
        config = json.loads((release / "server.json").read_text())
        config["argv"] = ["/usr/bin/touch", str(marker)]
        (release / "server.json").write_text(json.dumps(config))
        os.chmod(release / "server.json", 0o444)
        os.chmod(release, 0o555)
    elif tamper == "add-file":
        os.chmod(release, 0o755)
        (release / "extra").write_text("x")
        os.chmod(release, 0o555)
    elif tamper == "writable":
        os.chmod(release / "supervisor.py", 0o666)
    elif tamper == "symlink":
        os.chmod(release, 0o755)
        (release / "server.json").unlink()
        (release / "server.json").symlink_to(tmp_path)
        os.chmod(release, 0o555)
    elif tamper == "rename":
        os.chmod(release, 0o755)
        moved = release.with_name("b" * 64)
        release.rename(moved)
        os.chmod(moved, 0o555)
        forced = moved / "run-mcp"
    elif tamper == "edit-sums":
        _writable(release / "SHA256SUMS")
        (release / "SHA256SUMS").write_text("")
        os.chmod(release / "SHA256SUMS", 0o444)
        os.chmod(release, 0o555)
    elif tamper == "hardlink":
        os.link(release / "server.json", tmp_path / "second-name")
    out = _run(str(forced), "--device", "b")
    assert out.returncode == 125 and out.stdout == "" and not marker.exists()


def test_group_writable_releases_directory_is_refused(tmp_path):
    release = Path(_core(tmp_path)["release"])
    os.chmod(release.parent, 0o775)
    assert _run(str(release / "run-mcp"), "--device", "b").returncode == 125


def test_session_cap_returns_tempfail_without_starting_a_second_server(tmp_path):
    hold = [sys.executable, "-c", "import sys,time;sys.stdout.write('up\\n');sys.stdout.flush();time.sleep(30)"]
    forced = _core(tmp_path, argv=hold, max_sessions=1, queue_wait_seconds=0.5)["forced_command"]
    env = {"PATH": "/usr/bin:/bin"}
    first = subprocess.Popen([forced, "--device", "a"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, text=True)
    try:
        assert first.stdout.readline() == "up\n"
        second = subprocess.run([forced, "--device", "b"], capture_output=True, text=True, env=env, timeout=20)
        assert second.returncode == 75 and "busy" in second.stderr and second.stdout == ""
    finally:
        first.terminate()
        first.wait(timeout=10)
    third = subprocess.Popen([forced, "--device", "c"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, text=True)
    try:  # the slot is free again once the first session ended
        assert third.stdout.readline() == "up\n"
    finally:
        third.terminate()
        third.wait(timeout=10)
        for proc in (first, third):
            proc.stdout.close()
            proc.stderr.close()


def test_session_end_kills_lingering_descendants(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    script = ("import subprocess,sys,os;"
              "p=subprocess.Popen(['/bin/sleep','60']);"
              f"open({str(pidfile)!r},'w').write(str(p.pid));"
              "sys.stdin.read()")
    forced = _core(tmp_path, argv=[sys.executable, "-c", script])["forced_command"]
    out = _run(forced, "--device", "b", stdin="")
    assert out.returncode == 0, out.stderr
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("descendant survived the session")


def test_detached_descendant_is_reaped_as_subreaper(tmp_path):
    pidfile = tmp_path / "detached.pid"
    script = ("import subprocess,sys;"
              "p=subprocess.Popen(['/bin/sleep','60'],start_new_session=True);"
              f"open({str(pidfile)!r},'w').write(str(p.pid))")
    forced = _core(tmp_path, argv=[sys.executable, "-c", script])["forced_command"]
    assert _run(forced, "--device", "b").returncode == 0
    pid = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("detached descendant survived the session")


@pytest.mark.parametrize("spec", [{"argv": []}, {"argv": ["relative"]}, {"argv": ["/nonexistent/x"]},
                                  {"argv": [sys.executable], "env": {"LD_PRELOAD": "/x.so"}},
                                  {"argv": [sys.executable], "env": {"SSH_ORIGINAL_COMMAND": "x"}},
                                  {"argv": [sys.executable], "extra": 1}])
def test_cli_init_refuses_unsafe_server_specs(tmp_path, spec, capsys):
    spec_file = tmp_path / "server.json"
    spec_file.write_text(json.dumps(spec))
    assert main(["core", "init", "--root", str(tmp_path / "core"), "--server-json", str(spec_file)]) == 2
    assert not (tmp_path / "core" / "releases").exists() or not any((tmp_path / "core" / "releases").iterdir())


def test_hardened_mode_requires_root(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    with pytest.raises(rel.ReleaseError, match="root"):
        _core(tmp_path, mode="hardened", service_user="nobody")


def test_cli_init_and_verify_round_trip(tmp_path, capsys):
    spec_file = tmp_path / "server.json"
    spec_file.write_text(json.dumps({"argv": [sys.executable, "-c", "pass"]}))
    assert main(["core", "init", "--root", str(tmp_path / "core"), "--server-json", str(spec_file)]) == 0
    created = json.loads(capsys.readouterr().out)
    assert main(["core", "verify", created["release"]]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
