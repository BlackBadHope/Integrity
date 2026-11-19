"""One authoritative work-claim core, served over stdio.

``guardian-claims-core`` keeps one claim database in a private folder and
serves it one session per process on stdin/stdout. Many sessions may run at
once, from this machine or from others through an ``integrity-remote``
OpenSSH forced command; they all write to the same SQLite database, which
serializes every decision with ``BEGIN IMMEDIATE``. That single database is
what makes claims atomic, leases expire on one clock (the core's) and fencing
tokens strictly increase across every client.

The wire is one JSON object per line:

    -> {"id": 1, "method": "hello", "params": {}}
    <- {"id": 1, "result": {"protocol": ..., "core_id": ..., "identity_mode": ...}}
    -> {"id": 2, "method": "request", "params": <signed work-claim request>}
    <- {"id": 2, "result": {...}} | {"id": 2, "error": {"code": ..., "message": ...}}

Under a forced command the session's device id comes from
``INTEGRITY_REMOTE_DEVICE_ID``, which the ``authorized_keys`` line fixes; a key
enrolled for named devices is accepted only from them. Nothing a client sends
can change the core's folder, mode or keys: enrollment and revocation are
operator commands on the core.

The core needs no root and no listening port, and runs on any platform
Python and SQLite run on; the forced-command transport itself needs a Linux
core (see ``integrity-remote``).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from .canonical import canonical_bytes, parse_json_strict
from .work_claim_identity import ClaimRequestRejected, SignedClaimGate
from .work_claims import (
    IDENTITY_DECLARED,
    IDENTITY_MODES,
    IDENTITY_STRICT,
    StaleFenceError,
    WorkClaimError,
    WorkClaimRegistry,
)

PROTOCOL = "integrity-guardian/claims-core/v1"
MARKER = "claims-core.json"
DATABASE = "claims.sqlite"
MAX_LINE_BYTES = 65_536
DEVICE_ENV = "INTEGRITY_REMOTE_DEVICE_ID"


class ClaimsCoreError(RuntimeError):
    """Raised when a claims core folder is missing, foreign or inconsistent."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _private_folder(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(0o700)


def read_marker(home: Path) -> dict[str, Any]:
    try:
        marker = parse_json_strict((home / MARKER).read_bytes())
    except (OSError, ValueError) as exc:
        raise ClaimsCoreError(f"{home} is not a claims core (no readable {MARKER})") from exc
    if (
        not isinstance(marker, dict)
        or marker.get("protocol") != PROTOCOL
        or marker.get("identity_mode") not in IDENTITY_MODES
        or not isinstance(marker.get("core_id"), str)
    ):
        raise ClaimsCoreError(f"{home / MARKER} is not a claims core marker")
    return marker


def init(home: Path, *, identity_mode: str = IDENTITY_DECLARED) -> dict[str, Any]:
    """Create a claims core folder, or report the existing one unchanged."""

    if identity_mode not in IDENTITY_MODES:
        raise ClaimsCoreError("identity mode must be 'declared' or 'strict'")
    home = Path(home)
    if (home / MARKER).exists():
        marker = read_marker(home)
        if marker["identity_mode"] != identity_mode:
            raise ClaimsCoreError(
                f"this core already exists in {marker['identity_mode']} mode"
            )
        return {**marker, "home": str(home), "created": False}
    if home.exists() and any(home.iterdir()):
        raise ClaimsCoreError(f"{home} is not empty and is not a claims core")
    _private_folder(home)
    marker = {
        "protocol": PROTOCOL,
        "core_id": "claims-core:" + secrets.token_hex(16),
        "identity_mode": identity_mode,
        "created_at": _now(),
    }
    WorkClaimRegistry(home / DATABASE, identity_mode=identity_mode).close()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(home / MARKER, flags, 0o600), "wb") as handle:
        handle.write(canonical_bytes(marker))
    return {**marker, "home": str(home), "created": True}


@contextmanager
def open_core(home: Path) -> Iterator[SignedClaimGate]:
    home = Path(home)
    marker = read_marker(home)
    registry = WorkClaimRegistry(home / DATABASE, identity_mode=marker["identity_mode"])
    try:
        yield SignedClaimGate(registry, core_id=marker["core_id"])
    finally:
        registry.close()


def server_spec(home: Path) -> dict[str, Any]:
    """The ``server.json`` that ``integrity-remote core init`` turns into a release."""

    read_marker(Path(home))
    return {
        "argv": [sys.executable, "-I", "-m", "integrity_guardian.claims_core", "serve",
                 "--home", str(Path(home).resolve())],
    }


def _error(code: str, message: str) -> dict[str, Any]:
    return {"code": code, "message": message}


def handle(gate: SignedClaimGate, message: Any, *, device_id: str) -> dict[str, Any]:
    """Answer one wire message. Never raises for client input."""

    if not isinstance(message, dict) or set(message) - {"id", "method", "params"}:
        return {"id": None, "error": _error("malformed", "expected {id, method, params}")}
    ident = message.get("id")
    if ident is not None and (isinstance(ident, bool) or not isinstance(ident, (int, str))):
        return {"id": None, "error": _error("malformed", "id must be an integer or string")}
    method = message.get("method")
    if method == "hello":
        return {"id": ident, "result": {
            "protocol": PROTOCOL,
            "core_id": gate.core_id,
            "identity_mode": gate.identity_mode,
            "device_id": device_id or None,
        }}
    if method != "request":
        return {"id": ident, "error": _error("unknown-method", "methods: hello, request")}
    try:
        return {"id": ident, "result": gate.execute(message.get("params"), device_id=device_id)}
    except ClaimRequestRejected as exc:
        return {"id": ident, "error": _error(exc.code, str(exc))}
    except StaleFenceError as exc:
        return {"id": ident, "error": _error("stale-fence", str(exc))}
    except WorkClaimError as exc:
        return {"id": ident, "error": _error("refused", str(exc))}
    except sqlite3.Error as exc:
        # Nothing was committed: the transaction rolled back. The client may retry.
        return {"id": ident, "error": _error("core-unavailable", type(exc).__name__)}


def serve(home: Path, stdin: IO[bytes], stdout: IO[bytes], *, device_id: str = "") -> int:
    with open_core(home) as gate:
        while True:
            line = stdin.readline(MAX_LINE_BYTES + 1)
            if not line:
                return 0
            if len(line) > MAX_LINE_BYTES:
                response = {"id": None, "error": _error("too-large", "line exceeds the limit")}
                # Drop the rest of the oversized line.
                while line and not line.endswith(b"\n"):
                    line = stdin.readline(MAX_LINE_BYTES)
            elif not line.strip():
                continue
            else:
                try:
                    message = parse_json_strict(line)
                except ValueError:
                    response = {"id": None, "error": _error("malformed", "not strict JSON")}
                else:
                    response = handle(gate, message, device_id=device_id)
            stdout.write(canonical_bytes(response) + b"\n")
            stdout.flush()


def _print(document: Any) -> None:
    print(json.dumps(document, indent=2, sort_keys=True))


def _public_key_argument(value: str) -> str:
    path = Path(value)
    if path.is_file():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
        lines = [line for line in lines if line]
        if len(lines) != 1:
            raise ClaimsCoreError("a public key file holds exactly one line")
        return lines[0]
    return value.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardian-claims-core",
        description="One authoritative work-claim core, served over stdio.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def command(name: str, text: str) -> argparse.ArgumentParser:
        item = sub.add_parser(name, help=text)
        item.add_argument("--home", type=Path, required=True)
        return item

    created = command("init", "create a claims core folder")
    created.add_argument("--identity", choices=IDENTITY_MODES, default=IDENTITY_DECLARED,
                         help="strict refuses unsigned requests (default: declared)")
    enroll = command("enroll", "enroll an agent's public key")
    enroll.add_argument("--agent-id", required=True)
    enroll.add_argument("--public-key", required=True,
                        help="a .pub file written by 'guardian-claims keygen', or its value")
    enroll.add_argument("--device", action="append", default=[],
                        help="accept this key only from this integrity-remote device id")
    revoke = command("revoke", "revoke an enrolled key")
    revoke.add_argument("--key-id", required=True)
    command("keys", "list enrolled keys")
    command("verify", "recheck the event chain and every stored signed request")
    command("server-json", "print the server.json for integrity-remote core init")
    command("serve", "serve one session on stdin/stdout")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            _print(init(args.home, identity_mode=args.identity))
            return 0
        if args.command == "server-json":
            _print(server_spec(args.home))
            return 0
        if args.command == "serve":
            return serve(args.home, sys.stdin.buffer, sys.stdout.buffer,
                         device_id=os.environ.get(DEVICE_ENV, ""))
        with open_core(args.home) as gate:
            if args.command == "enroll":
                enrolled = gate.enroll(agent_id=args.agent_id,
                                       public_key=_public_key_argument(args.public_key),
                                       devices=args.device)
                _print(enrolled.public())
            elif args.command == "revoke":
                _print(gate.revoke(args.key_id).public())
            elif args.command == "keys":
                _print({"core_id": gate.core_id, "identity_mode": gate.identity_mode,
                        "keys": [item.public() for item in gate.enrolled_keys()]})
            elif args.command == "verify":
                _print({"ok": True, **gate.verify_log()})
        return 0
    except (ClaimsCoreError, WorkClaimError, OSError) as exc:
        print(f"guardian-claims-core: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "IDENTITY_DECLARED",
    "IDENTITY_STRICT",
    "PROTOCOL",
    "ClaimsCoreError",
    "handle",
    "init",
    "open_core",
    "read_marker",
    "serve",
    "server_spec",
]
