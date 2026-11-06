"""Render the client-side transport: an ``ssh`` command with fixed, hardened options.

The output is an ordinary stdio command. Give it to any MCP client or to the
Native profile compiler as ``upstream.json``. Host keys are always checked
against a dedicated known_hosts file; the user's ssh config, agent forwarding,
port forwarding, TTYs and password prompts are all disabled.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat

HOST = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
IPV6 = re.compile(r"[0-9A-Fa-f:]{2,39}\Z")
USER = re.compile(r"[a-z_][a-z0-9_.-]{0,31}\Z")
NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
FORMATS = ("upstream-json", "claude-mcp-json", "codex-toml")


class ClientError(ValueError):
    pass


def ssh_args(*, host: str, user: str, identity: Path, known_hosts: Path, port: int = 22,
             jump: str | None = None, connect_timeout: int = 10) -> list[str]:
    if not (HOST.match(host) or IPV6.match(host)) or host.startswith("-"):
        raise ClientError("host must be a DNS name or IP address")
    if not USER.match(user):
        raise ClientError("user must be a POSIX account name")
    if not 1 <= port <= 65535:
        raise ClientError("port must be 1..65535")
    if not 1 <= connect_timeout <= 120:
        raise ClientError("connect timeout must be 1..120 seconds")
    for label, path in (("identity", identity), ("known_hosts", known_hosts)):
        if not path.is_absolute():
            raise ClientError(f"{label} must be an absolute path")
        if not path.is_file():
            raise ClientError(f"{label} file not found: {path}")
    if not known_hosts.read_text(encoding="utf-8", errors="replace").strip():
        raise ClientError("known_hosts is empty: pin the core's host key first")
    if os.name == "posix" and stat.S_IMODE(identity.stat().st_mode) & 0o077:
        raise ClientError("identity file must not be readable by group or others (chmod 600)")
    known = str(known_hosts)
    if '"' in known:
        raise ClientError("known_hosts path must not contain double quotes")
    if any(c.isspace() for c in known):
        known = f'"{known}"'  # ssh splits -o values on whitespace
    args = ["-T", "-F", "none",
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-i", str(identity),
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known}",
            "-o", "GlobalKnownHostsFile=none",
            "-o", "UpdateHostKeys=no",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PreferredAuthentications=publickey",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "RequestTTY=no",
            "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=4",
            "-o", "LogLevel=ERROR",
            "-p", str(port), "-l", user]
    if jump:
        if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,31}@[A-Za-z0-9.-]+(?::[0-9]{1,5})?", jump):
            raise ClientError("jump must be user@host[:port]")
        args += ["-J", jump]
    args.append(host)
    return args


def resolve_ssh(ssh: str | None = None) -> str:
    found = ssh or shutil.which("ssh")
    if not found:
        raise ClientError("OpenSSH client not found; pass --ssh /absolute/path/to/ssh")
    path = Path(found)
    if not path.is_absolute() or not path.is_file():
        raise ClientError("ssh must be an existing absolute path")
    return str(path)


def render(fmt: str, *, command: str, args: list[str], name: str = "integrity_remote") -> str:
    if fmt not in FORMATS:
        raise ClientError(f"format must be one of {', '.join(FORMATS)}")
    if not NAME.match(name):
        raise ClientError("server name must match [A-Za-z0-9_-]{1,64}")
    if fmt == "upstream-json":
        return json.dumps({"command": command, "args": args, "env": {}}, indent=2) + "\n"
    if fmt == "claude-mcp-json":
        return json.dumps({"mcpServers": {name: {"type": "stdio", "command": command,
                                                 "args": args}}}, indent=2) + "\n"
    quoted = ", ".join(json.dumps(a) for a in args)
    return f"[mcp_servers.{name}]\ncommand = {json.dumps(command)}\nargs = [{quoted}]\n"


def handshake(command: str, args: list[str], *, timeout: float = 60) -> dict:
    """Start the transport, run MCP ``initialize`` and ``tools/list``, then close stdin.

    Proves the whole path (ssh, host key, key, forced command, release check,
    supervisor, server) without calling any tool. Server stderr is not echoed.
    """
    import queue
    import subprocess
    import threading
    import time

    process = subprocess.Popen([command, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    lines: queue.Queue = queue.Queue()
    threading.Thread(target=lambda: [lines.put(x) for x in process.stdout] + [lines.put(None)],
                     daemon=True).start()
    errors: list[bytes] = []
    threading.Thread(target=lambda: errors.extend(process.stderr), daemon=True).start()
    deadline = time.monotonic() + timeout

    def call(identifier: int, method: str, params: dict) -> dict:
        message = {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}
        process.stdin.write(json.dumps(message).encode() + b"\n")
        process.stdin.flush()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no MCP response before the timeout")
            line = lines.get(timeout=remaining)
            if line is None:
                raise ConnectionError("transport closed before responding")
            response = json.loads(line)
            if response.get("id") == identifier:
                if "error" in response:
                    raise ConnectionError(f"MCP error: {response['error'].get('message', '')}")
                return response["result"]

    result: dict = {"ok": False}
    try:
        init = call(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                      "clientInfo": {"name": "integrity-remote-check", "version": "1"}})
        process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        process.stdin.flush()
        tools = call(2, "tools/list", {})
        result = {"ok": True, "server": init.get("serverInfo", {}),
                  "tools": sorted(t.get("name", "") for t in tools.get("tools", []))}
    except (OSError, ValueError, TimeoutError, ConnectionError, queue.Empty) as error:
        result = {"ok": False, "error": f"{type(error).__name__}: {error}"}
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    result["exit_code"] = process.returncode
    if not result["ok"]:
        result["stderr_tail"] = b"".join(errors).decode("utf-8", "replace")[-800:]
    return result
