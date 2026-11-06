"""authorized_keys rendering and the client transport; pure, runs on every OS."""
import base64
import json
import struct
import sys
import tomllib
from pathlib import Path

import pytest

from integrity_remote.authorize import AuthorizeError, authorized_line, parse_public_key
from integrity_remote.client import ClientError, render, ssh_args
from integrity_remote.cli import main

RELEASE = "/opt/integrity-core/releases/" + "a" * 64


def _key(key_type: str, payload: bytes = b"\x00" * 32) -> str:
    name = key_type.encode()
    blob = struct.pack(">I", len(name)) + name + struct.pack(">I", len(payload)) + payload
    return f"{key_type} {base64.b64encode(blob).decode()} someone@example.invalid\n"


def _rsa(bits: int) -> str:
    def mpint(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value
    name = b"ssh-rsa"
    modulus = b"\x00" + b"\xff" * (bits // 8)
    blob = struct.pack(">I", len(name)) + name + mpint(b"\x01\x00\x01") + mpint(modulus)
    return f"ssh-rsa {base64.b64encode(blob).decode()}\n"


def test_line_pins_release_device_and_restrictions():
    line = authorized_line(release=RELEASE, public_key=_key("ssh-ed25519"), device_id="laptop-b")
    options, key_type, _blob, comment = line.rsplit(" ", 3)
    assert options.startswith("restrict,no-user-rc,")
    assert f'command="{RELEASE}/run-mcp --device laptop-b"' in line
    assert key_type == "ssh-ed25519" and comment == "integrity-remote:laptop-b"
    assert "someone@" not in line


def test_from_patterns_are_rendered_and_validated():
    line = authorized_line(release=RELEASE, public_key=_key("ssh-ed25519"), device_id="b1",
                           from_patterns=("192.0.2.0/24", "!192.0.2.7"))
    assert 'from="192.0.2.0/24,!192.0.2.7"' in line
    with pytest.raises(AuthorizeError):
        authorized_line(release=RELEASE, public_key=_key("ssh-ed25519"), device_id="b1",
                        from_patterns=('x",command="/bin/sh',))


@pytest.mark.parametrize("device", ["", "Laptop", "a b", "a;rm", "-x", "a" * 64, 'a"b'])
def test_device_ids_are_strict(device):
    with pytest.raises(AuthorizeError):
        authorized_line(release=RELEASE, public_key=_key("ssh-ed25519"), device_id=device)


@pytest.mark.parametrize("release", ["relative/" + "a" * 64, "/opt/x y/" + "a" * 64,
                                     "/opt/core/releases/current", '/opt/"/' + "a" * 64,
                                     "/opt/../etc/" + "a" * 64])
def test_release_paths_are_strict(release):
    with pytest.raises(AuthorizeError):
        authorized_line(release=release, public_key=_key("ssh-ed25519"), device_id="b")


@pytest.mark.parametrize("text", [
    "", "ssh-ed25519\n", 'command="/bin/sh" ' + _key("ssh-ed25519"),
    _key("ssh-ed25519") + _key("ssh-ed25519"), "-----BEGIN OPENSSH " + "PRIV" + "ATE KEY-----\n",
    "ssh-ed25519 not-base64!!\n", _key("ssh-ed25519").replace("ssh-ed25519 ", "ssh-dss ", 1),
    _key("ecdsa-sha2-nistp256").replace("ecdsa-sha2-nistp256 ", "ssh-ed25519 ", 1),
])
def test_bad_public_keys_are_refused(text):
    with pytest.raises(AuthorizeError):
        parse_public_key(text)


def test_rsa_needs_opt_in_and_size():
    with pytest.raises(AuthorizeError):
        parse_public_key(_rsa(4096))
    with pytest.raises(AuthorizeError):
        parse_public_key(_rsa(2048), allow_rsa=True)
    assert parse_public_key(_rsa(4096), allow_rsa=True)[0] == "ssh-rsa"


def _files(tmp_path):
    identity = tmp_path / "device_ed25519"
    identity.write_text("placeholder", encoding="utf-8")
    identity.chmod(0o600)
    known = tmp_path / "known_hosts"
    known.write_text("[core-a.example.invalid]:2222 " + _key("ssh-ed25519"), encoding="utf-8")
    return identity, known


def test_ssh_args_are_hardened(tmp_path):
    identity, known = _files(tmp_path)
    args = ssh_args(host="core-a.example.invalid", user="integrity-core", identity=identity,
                    known_hosts=known, port=2222)
    options = {args[i + 1] for i, a in enumerate(args) if a == "-o"}
    for required in ("BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes",
                     "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                     "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes",
                     "RequestTTY=no", "PermitLocalCommand=no", "GlobalKnownHostsFile=none"):
        assert required in options
    assert f"UserKnownHostsFile={known}" in options or f'UserKnownHostsFile="{known}"' in options
    assert args[:3] == ["-T", "-F", "none"] and args[-1] == "core-a.example.invalid"
    assert args[args.index("-p") + 1] == "2222" and args[args.index("-l") + 1] == "integrity-core"
    assert not any(a.startswith("StrictHostKeyChecking=no") or a == "-A" for a in args)


def test_known_hosts_with_spaces_is_quoted(tmp_path):
    folder = tmp_path / "with space"
    folder.mkdir()
    identity, known = _files(folder)
    args = ssh_args(host="core-a.example.invalid", user="core", identity=identity, known_hosts=known)
    assert f'UserKnownHostsFile="{known}"' in args


@pytest.mark.parametrize("field,value", [("host", "-oProxyCommand=x"), ("host", "a b"),
                                         ("user", "Root"), ("user", "-l"), ("port", 0)])
def test_ssh_args_refuse_injection(tmp_path, field, value):
    identity, known = _files(tmp_path)
    values = {"host": "core-a.example.invalid", "user": "core", "port": 22} | {field: value}
    with pytest.raises(ClientError):
        ssh_args(identity=identity, known_hosts=known, **values)


def test_empty_or_missing_known_hosts_is_refused(tmp_path):
    identity, known = _files(tmp_path)
    known.write_text("\n", encoding="utf-8")
    with pytest.raises(ClientError, match="pin"):
        ssh_args(host="core-a.example.invalid", user="core", identity=identity, known_hosts=known)
    with pytest.raises(ClientError):
        ssh_args(host="core-a.example.invalid", user="core", identity=identity,
                 known_hosts=tmp_path / "absent")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_group_readable_identity_is_refused(tmp_path):
    identity, known = _files(tmp_path)
    identity.chmod(0o644)
    with pytest.raises(ClientError, match="chmod 600"):
        ssh_args(host="core-a.example.invalid", user="core", identity=identity, known_hosts=known)


def test_render_formats_round_trip(tmp_path):
    args = ["-T", "-o", "UserKnownHostsFile=/x y", "host"]
    upstream = json.loads(render("upstream-json", command="/usr/bin/ssh", args=args))
    assert upstream == {"command": "/usr/bin/ssh", "args": args, "env": {}}
    claude = json.loads(render("claude-mcp-json", command="/usr/bin/ssh", args=args, name="core"))
    assert claude["mcpServers"]["core"] == {"type": "stdio", "command": "/usr/bin/ssh", "args": args}
    codex = tomllib.loads(render("codex-toml", command="/usr/bin/ssh", args=args, name="core"))
    assert codex["mcp_servers"]["core"] == {"command": "/usr/bin/ssh", "args": args}
    with pytest.raises(ClientError):
        render("codex-toml", command="/usr/bin/ssh", args=args, name="bad name]")


def test_cli_client_upstream_writes_a_new_file_only(tmp_path, capsys):
    identity, known = _files(tmp_path)
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("", encoding="utf-8")
    output = tmp_path / "upstream.json"
    argv = ["client-upstream", "--host", "core-a.example.invalid", "--user", "core",
            "--identity", str(identity), "--known-hosts", str(known), "--ssh", str(fake_ssh),
            "--output", str(output)]
    assert main(argv) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["command"] == str(fake_ssh)
    assert main(argv) == 2  # never overwrites
    assert "exists" in capsys.readouterr().err.lower()


def test_cli_authorize_requires_existing_release(tmp_path, capsys):
    key = tmp_path / "device.pub"
    key.write_text(_key("ssh-ed25519"), encoding="utf-8")
    argv = ["authorize", "--release", RELEASE, "--device-id", "b", "--public-key", str(key)]
    assert main(argv) == 2
    assert main([*argv, "--no-check"]) == 0
    assert capsys.readouterr().out.startswith("restrict,no-user-rc,command=")


FAKE_SERVER = """import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {"serverInfo": {"name": "fake-core", "version": "0"}, "capabilities": {}}
    else:
        result = {"tools": [{"name": "b_tool"}, {"name": "a_tool"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""


def test_handshake_lists_tools_and_reports_failures(tmp_path):
    from integrity_remote.client import handshake
    server = tmp_path / "fake.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    good = handshake(sys.executable, [str(server)], timeout=30)
    assert good == {"ok": True, "server": {"name": "fake-core", "version": "0"},
                    "tools": ["a_tool", "b_tool"], "exit_code": 0}
    bad = handshake(sys.executable, ["-c", "import sys; sys.stderr.write('denied'); sys.exit(255)"], timeout=30)
    assert bad["ok"] is False and bad["exit_code"] == 255 and "denied" in bad["stderr_tail"]


def test_server_spec_accepts_both_shapes():
    from integrity_remote.cli import _server_spec
    assert _server_spec({"argv": ["/x", "a"]}) == (["/x", "a"], {})
    assert _server_spec({"command": "/x", "args": ["a"], "env": {"K": "v"}}) == (["/x", "a"], {"K": "v"})
    for bad in ({"argv": ["/x"], "command": "/y"}, {"cmd": "/x"}, [], {"command": "/x", "args": "a"}):
        with pytest.raises(ValueError):
            _server_spec(bad)
