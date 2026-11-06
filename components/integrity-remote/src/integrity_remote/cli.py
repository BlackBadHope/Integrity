"""integrity-remote: connect Integrity clients on machine B to a core on machine A over SSH.

  core init        (machine A) build an immutable forced-command release
  core verify      (machine A) re-run a release's custody and digest check
  authorize        (machine A) print one authorized_keys line for a device key
  client-upstream  (machine B) print the hardened ssh transport for an MCP client
  check            (machine B) start a transport, run MCP initialize + tools/list, print the result
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .authorize import AuthorizeError, authorized_line
from .client import FORMATS, ClientError, handshake, render, resolve_ssh, ssh_args


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="integrity-remote", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    core = sub.add_parser("core", help="machine A: build or verify a forced-command release")
    core_sub = core.add_subparsers(dest="core_command", required=True)
    init = core_sub.add_parser("init", help="build <root>/releases/<digest> for one server command")
    init.add_argument("--root", required=True, type=Path,
                      help="absolute directory for releases/ and run/ (created if missing)")
    init.add_argument("--server-json", required=True, type=Path,
                      help='JSON file {"argv": [...], "env": {...}}; argv[0] absolute; '
                           'the literal {device_id} is replaced by the key-bound device id')
    init.add_argument("--mode", choices=("user", "hardened"), default="user",
                      help="user: owned by the current account (no sudo); "
                           "hardened: root-owned release for a separate service account")
    init.add_argument("--service-user", help="hardened mode: the account named in authorized_keys")
    init.add_argument("--max-sessions", type=int, default=2)
    init.add_argument("--queue-wait-seconds", type=float, default=10)
    init.add_argument("--allow-anonymous-key", action="store_true",
                      help="accept keys whose line has no --device (not recommended)")
    init.add_argument("--python", help="absolute interpreter for the supervisor (default: this one)")
    verify = core_sub.add_parser("verify", help="run a release's verify-release")
    verify.add_argument("release", type=Path)

    auth = sub.add_parser("authorize", help="machine A: print an authorized_keys line")
    auth.add_argument("--release", required=True, help="absolute release directory from core init")
    auth.add_argument("--device-id", required=True, help="stable name of the client device, e.g. laptop-b")
    auth.add_argument("--public-key", required=True, type=Path, help="the device's .pub file")
    auth.add_argument("--from", dest="from_patterns", action="append", default=[],
                      help="optional OpenSSH from= pattern (repeatable), e.g. 192.0.2.0/24")
    auth.add_argument("--allow-rsa", action="store_true", help=f"accept ssh-rsa keys of 3072+ bits")
    auth.add_argument("--no-check", action="store_true",
                      help="do not require the release to exist on this machine")

    client = sub.add_parser("client-upstream", help="machine B: print the ssh transport")
    client.add_argument("--host", required=True)
    client.add_argument("--port", type=int, default=22)
    client.add_argument("--user", required=True, help="core service account")
    client.add_argument("--identity", required=True, type=Path, help="this device's private key file")
    client.add_argument("--known-hosts", required=True, type=Path,
                        help="dedicated known_hosts holding the core's pinned host key")
    client.add_argument("--jump", help="optional ProxyJump user@host[:port]")
    client.add_argument("--ssh", help="absolute path to the OpenSSH client (default: from PATH)")
    client.add_argument("--format", choices=FORMATS, default="upstream-json")
    client.add_argument("--name", default="integrity_remote", help="MCP server name in the output")
    client.add_argument("--output", type=Path, help="write to a new file instead of stdout")

    check = sub.add_parser("check", help="machine B: handshake through an upstream.json transport")
    check.add_argument("upstream", type=Path, help="file written by client-upstream --format upstream-json")
    check.add_argument("--timeout", type=float, default=60)
    return parser


def _server_spec(spec: object) -> tuple[list, dict]:
    """Accept {"argv": [...]} or the {"command": ..., "args": [...]} shape MCP configs use."""
    if isinstance(spec, dict) and "argv" in spec and not set(spec) - {"argv", "env"}:
        return spec["argv"], spec.get("env", {})
    if (isinstance(spec, dict) and "command" in spec and not set(spec) - {"command", "args", "env"}
            and isinstance(spec.get("args", []), list)):
        return [spec["command"], *spec.get("args", [])], spec.get("env", {})
    raise ValueError('server json must be {"argv": [...], "env": {...}} or {"command": ..., "args": [...]}')


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
        return
    with open(output, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "core":
            from . import release
            if args.core_command == "init":
                argv_spec, env_spec = _server_spec(json.loads(args.server_json.read_text(encoding="utf-8")))
                result = release.init_core(
                    root=args.root, argv=argv_spec, env=env_spec, mode=args.mode,
                    service_user=args.service_user, max_sessions=args.max_sessions,
                    queue_wait_seconds=args.queue_wait_seconds,
                    device_required=not args.allow_anonymous_key, python=args.python)
            else:
                result = release.verify(args.release.resolve())
            print(json.dumps(result, indent=2))
            return 0 if result.get("ok", True) else 1
        if args.command == "authorize":
            release_dir = args.release.rstrip("/")
            if not args.no_check and not Path(release_dir, "run-mcp").is_file():
                raise AuthorizeError("release not found here (use --no-check to skip)")
            line = authorized_line(release=release_dir,
                                   public_key=args.public_key.read_text(encoding="utf-8"),
                                   device_id=args.device_id, from_patterns=tuple(args.from_patterns),
                                   allow_rsa=args.allow_rsa)
            print(line)
            return 0
        if args.command == "check":
            spec = json.loads(args.upstream.read_text(encoding="utf-8"))
            result = handshake(spec["command"], spec["args"], timeout=args.timeout)
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
        ssh = resolve_ssh(args.ssh)
        transport = ssh_args(host=args.host, user=args.user, identity=args.identity.resolve(),
                             known_hosts=args.known_hosts.resolve(), port=args.port, jump=args.jump)
        _emit(render(args.format, command=ssh, args=transport, name=args.name), args.output)
        return 0
    except (AuthorizeError, ClientError, ValueError, OSError) as error:
        print(f"integrity-remote: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
