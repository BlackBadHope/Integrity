"""Client for a work-claim core: signs every request with the agent's key.

``ClaimsClient`` starts one session with any stdio command: the ``ssh``
command that ``integrity-remote client-upstream`` writes for a core on
another machine, or ``guardian-claims-core serve`` on this one. It asks the
core for its ``core_id`` once and binds every signed request to it.

``guardian-claims`` is the same client on the command line.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Self

from .canonical import canonical_bytes, parse_json_strict
from .work_claim_identity import REQUEST_PROTOCOL, AgentKey, sign_request


class ClaimsClientError(RuntimeError):
    """The core refused a request, or the session failed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def upstream_argv(path: Path) -> list[str]:
    """Read the ``upstream.json`` written by ``integrity-remote client-upstream``."""

    spec = parse_json_strict(Path(path).read_bytes())
    if (
        not isinstance(spec, dict)
        or not isinstance(spec.get("command"), str)
        or not isinstance(spec.get("args", []), list)
        or not all(isinstance(item, str) for item in spec.get("args", []))
    ):
        raise ClaimsClientError("bad-upstream", "upstream.json needs command and args")
    return [spec["command"], *spec.get("args", [])]


def local_core_argv(home: Path) -> list[str]:
    return [sys.executable, "-I", "-m", "integrity_guardian.claims_core", "serve",
            "--home", str(Path(home))]


class ClaimsClient:
    """One session with a claims core. Not thread-safe; open one per thread."""

    def __init__(
        self,
        argv: list[str],
        *,
        agent_id: str,
        key: AgentKey | None = None,
        timeout: float = 30.0,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.key = key
        self.timeout = timeout
        self._next = 0
        self._process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=None if env is None else dict(env),
        )
        self._lines: queue.Queue[bytes] = queue.Queue()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        try:
            hello = self._call("hello", {})
        except BaseException:
            self.close()
            raise
        self.core_id: str = hello["core_id"]
        self.identity_mode: str = hello["identity_mode"]
        self.device_id: str | None = hello.get("device_id")

    def _read(self) -> None:
        stream = self._process.stdout
        assert stream is not None
        for line in iter(stream.readline, b""):
            self._lines.put(line)
        self._lines.put(b"")

    def _call(self, method: str, params: Any) -> dict[str, Any]:
        self._next += 1
        message = {"id": self._next, "method": method, "params": params}
        stdin = self._process.stdin
        assert stdin is not None
        try:
            stdin.write(canonical_bytes(message) + b"\n")
            stdin.flush()
        except OSError as exc:
            raise ClaimsClientError("session-closed", self._stderr()) from exc
        try:
            line = self._lines.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise ClaimsClientError("timeout", "no answer from the claims core") from exc
        if not line:
            raise ClaimsClientError("session-closed", self._stderr())
        response = parse_json_strict(line)
        if response.get("id") != self._next:
            raise ClaimsClientError("protocol", "the core answered another request")
        if "error" in response:
            error = response["error"]
            raise ClaimsClientError(str(error.get("code")), str(error.get("message")))
        return response["result"]

    def _stderr(self) -> str:
        if self._process.poll() is None:
            return "the claims core session closed"
        stderr = self._process.stderr
        text = b"" if stderr is None else stderr.read()
        return text.decode(errors="replace")[-500:] or "the claims core session closed"

    def sign(self, operation: str, arguments: Mapping[str, Any], **options: Any) -> dict:
        if self.key is None:
            raise ClaimsClientError("no-key", "this client has no agent key")
        return sign_request(self.key, core_id=self.core_id, agent_id=self.agent_id,
                            operation=operation, arguments=arguments, **options)

    def send(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Send one prepared request exactly as given (tests use it for replays)."""

        return self._call("request", dict(request))

    def call(self, operation: str, **arguments: Any) -> dict[str, Any]:
        if self.key is None:
            request = {"protocol": REQUEST_PROTOCOL, "agent_id": self.agent_id,
                       "operation": operation, "arguments": arguments}
        else:
            request = self.sign(operation, arguments)
        return self.send(request)

    # -- operations --------------------------------------------------------

    def claim(self, resources: Iterable[str], *, ttl_seconds: int = 300,
              reference: Mapping[str, str] | None = None) -> dict[str, Any]:
        arguments: dict[str, Any] = {"resources": list(resources), "ttl_seconds": ttl_seconds}
        if reference is not None:
            arguments["reference"] = dict(reference)
        return self.call("claim", **arguments)

    def poll(self, claim_id: str) -> dict[str, Any]:
        return self.call("poll", claim_id=claim_id)

    def renew(self, claim_id: str, fence_token: int, *, ttl_seconds: int | None = None):
        arguments: dict[str, Any] = {"claim_id": claim_id, "fence_token": fence_token}
        if ttl_seconds is not None:
            arguments["ttl_seconds"] = ttl_seconds
        return self.call("renew", **arguments)

    def release(self, claim_id: str, fence_token: int, outcome: str) -> dict[str, Any]:
        return self.call("release", claim_id=claim_id, fence_token=fence_token, outcome=outcome)

    def record(self, claim_id: str, fence_token: int, result: str) -> dict[str, Any]:
        return self.call("record", claim_id=claim_id, fence_token=fence_token, result=result)

    def handoff(self, claim_id: str, fence_token: int, successor_id: str,
                note: str = "") -> dict[str, Any]:
        return self.call("handoff", claim_id=claim_id, fence_token=fence_token,
                         successor_id=successor_id, note=note)

    def cancel(self, claim_id: str) -> dict[str, Any]:
        return self.call("cancel", claim_id=claim_id)

    def assert_fence(self, claim_id: str, fence_token: int) -> dict[str, Any]:
        return self.call("assert_fence", claim_id=claim_id, fence_token=fence_token)

    def status(self, claim_id: str) -> dict[str, Any]:
        return self.call("status", claim_id=claim_id)

    def events(self, *, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        return self.call("events", after=after, limit=limit)["events"]

    def close(self) -> None:
        if self._process.stdin is not None and not self._process.stdin.closed:
            try:
                self._process.stdin.close()
            except OSError:
                pass
        try:
            self._process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=10)
        for stream in (self._process.stdout, self._process.stderr):
            if stream is not None:
                stream.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _print(document: Any) -> None:
    print(json.dumps(document, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardian-claims",
        description="Claim work at a claims core with a signed agent identity.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="write a new agent key and its .pub file")
    keygen.add_argument("--out", type=Path, required=True)
    pubkey = sub.add_parser("pubkey", help="print an agent key's public value and key id")
    pubkey.add_argument("--key", type=Path, required=True)

    def operation(name: str, text: str) -> argparse.ArgumentParser:
        item = sub.add_parser(name, help=text)
        target = item.add_mutually_exclusive_group(required=True)
        target.add_argument("--upstream", type=Path,
                            help="upstream.json from integrity-remote client-upstream")
        target.add_argument("--core-home", type=Path, help="a claims core on this machine")
        item.add_argument("--agent-id", required=True)
        item.add_argument("--key", type=Path,
                          help="agent key; without it the request is unsigned (declared)")
        return item

    operation("hello", "show the core id and identity mode")
    claim = operation("claim", "claim resources")
    claim.add_argument("--resource", action="append", required=True)
    claim.add_argument("--ttl", type=int, default=300)
    for name in ("poll", "status", "cancel"):
        operation(name, f"{name} a claim").add_argument("claim_id")
    renew = operation("renew", "extend a held claim")
    renew.add_argument("claim_id")
    renew.add_argument("--fence", type=int, required=True)
    renew.add_argument("--ttl", type=int)
    for name, field in (("release", "outcome"), ("record", "result")):
        item = operation(name, f"{name} under a held fence")
        item.add_argument("claim_id")
        item.add_argument("--fence", type=int, required=True)
        item.add_argument(f"--{field}", required=True)
    handoff = operation("handoff", "hand a held claim to another enrolled agent")
    handoff.add_argument("claim_id")
    handoff.add_argument("--fence", type=int, required=True)
    handoff.add_argument("--to", required=True)
    handoff.add_argument("--note", default="")
    events = operation("events", "read the claim log")
    events.add_argument("--after", type=int, default=0)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        key = AgentKey.generate()
        try:
            key.save(args.out)
            public = Path(str(args.out) + ".pub")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            with os.fdopen(os.open(public, flags, 0o644), "w", encoding="utf-8") as handle:
                handle.write(key.public_value + "\n")
        except OSError as exc:
            print(f"guardian-claims: {exc}", file=sys.stderr)
            return 1
        _print({"key": str(args.out), "public_key_file": str(public),
                "public_key": key.public_value, "key_id": key.key_id})
        return 0
    if args.command == "pubkey":
        key = AgentKey.load(args.key)
        _print({"public_key": key.public_value, "key_id": key.key_id})
        return 0

    target = upstream_argv(args.upstream) if args.upstream else local_core_argv(args.core_home)
    key = AgentKey.load(args.key) if args.key else None
    try:
        with ClaimsClient(target, agent_id=args.agent_id, key=key) as client:
            if args.command == "hello":
                result: Any = {"core_id": client.core_id, "identity_mode": client.identity_mode,
                               "device_id": client.device_id}
            elif args.command == "claim":
                result = client.claim(args.resource, ttl_seconds=args.ttl)
            elif args.command in {"poll", "status", "cancel"}:
                result = getattr(client, args.command)(args.claim_id)
            elif args.command == "renew":
                result = client.renew(args.claim_id, args.fence, ttl_seconds=args.ttl)
            elif args.command == "release":
                result = client.release(args.claim_id, args.fence, args.outcome)
            elif args.command == "record":
                result = client.record(args.claim_id, args.fence, args.result)
            elif args.command == "handoff":
                result = client.handoff(args.claim_id, args.fence, args.to, args.note)
            else:
                result = client.events(after=args.after)
    except ClaimsClientError as exc:
        _print({"ok": False, "code": exc.code, "message": exc.message})
        return 1
    _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
