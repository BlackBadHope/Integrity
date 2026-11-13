# SPDX-License-Identifier: BUSL-1.1
"""Four scenes of Integrity on one machine, with synthetic data.

No network, no account and no model call. Every file is written to a temporary
directory that is removed at the end. The agents are played by this script;
the memory, the receipts and the checks are the code of this repository.

    python demo/run.py               run the scenes and print the transcript
    python demo/run.py --svg DIR     also write demo-light.svg and demo-dark.svg to DIR
    python demo/run.py --check DIR   fail if the pictures in DIR differ from this run
"""
from __future__ import annotations

import argparse
import hashlib
import json
import queue
import subprocess
import sys
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
for _source in (ROOT / "components" / "integrity-client-memory" / "src", ROOT / "src"):
    if _source.is_dir() and str(_source) not in sys.path:
        sys.path.insert(0, str(_source))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from integrity_client_memory import doctor  # noqa: E402
from integrity_guardian.intent_custody import (  # noqa: E402
    IntentCustody,
    IntentReplayError,
    verify_consumption_receipt,
)
from integrity_guardian.reconciler import ObservedDelta, PostCheck, sign_change_intent  # noqa: E402
from integrity_guardian.seed_catalog import SeedCatalog  # noqa: E402
from integrity_guardian.signing import Ed25519Signer, TrustedKey, public_key_fingerprint  # noqa: E402
from integrity_guardian.turn_memory import (  # noqa: E402
    TurnMemoryStore,
    namespace_fingerprint,
    verify_turn_gap_receipt,
    verify_turn_terminal_receipt,
)

NAMESPACE = "seed://project/demo"
TENANT = "tenant:demo"
MACHINE = "machine:demo"
MEMORY_SERVER = ROOT / "examples" / "local-memory" / "memory_server.py"
DECISION = {
    "id": 1,
    "event_uid": "client:demo-decision-0001",
    "ts_utc": "2026-01-01T09:00:00Z",
    "actor": "agent-a",
    "action": "configuration_decision",
    "level": "info",
    "summary": "Keep the request timeout at 210 s; 180 s was too short for a cold start.",
    "details": {"task_id": "demo-task", "decision": {"timeout_sec": 210}},
    "tags": ["demo"],
}
GRANT_TIME = datetime(2026, 1, 1, 10, 5, tzinfo=UTC)
BEFORE = "sha256:" + "1" * 64
AFTER = "sha256:" + "2" * 64


class DemoFailure(RuntimeError):
    """A scene did not behave as the transcript says."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise DemoFailure(message)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def short(value: str) -> str:
    return value[:19] + "..."


def demo_signer(role: str) -> Ed25519Signer:
    # Demo keys are derived from a public string. They protect nothing.
    seed = hashlib.sha256(("integrity demo key: " + role).encode("utf-8")).digest()
    return Ed25519Signer("key:demo:" + role, Ed25519PrivateKey.from_private_bytes(seed))


def trusted(signer: Ed25519Signer) -> TrustedKey:
    return TrustedKey(signer.key_id, signer.public_key)


def turn_store(path: Path, *, create: bool) -> TurnMemoryStore:
    signer = demo_signer("turn-memory")
    namespace = namespace_fingerprint(source_namespace=NAMESPACE,
                                      trust_fingerprint=public_key_fingerprint(signer.public_key))
    return TurnMemoryStore(path, namespace=namespace, signer=signer, create=create)


def receipt_of(result: dict) -> dict:
    return result["receipt"] if isinstance(result.get("receipt"), dict) else result


class StdioClient:
    """A minimal JSON-RPC client for one MCP server process."""

    def __init__(self, command: list[str]) -> None:
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8", cwd=str(ROOT))
        self.lines: queue.Queue[str] = queue.Queue()
        self.errors: list[str] = []
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()
        self.ident = 0

    def _pump(self) -> None:
        for line in self.process.stdout:  # type: ignore[union-attr]
            self.lines.put(line)
        self.lines.put("")

    def _drain(self) -> None:
        for line in self.process.stderr:  # type: ignore[union-attr]
            self.errors.append(line)

    def request(self, method: str, params: dict) -> dict:
        self.ident += 1
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.ident, "method": method,
                                             "params": params}) + "\n")
        self.process.stdin.flush()
        try:
            line = self.lines.get(timeout=120)
        except queue.Empty:
            raise DemoFailure(method + ": no answer from the memory server") from None
        if not line:
            raise DemoFailure(method + ": the memory server stopped: " + "".join(self.errors)[-400:])
        reply = json.loads(line)
        expect("error" not in reply, method + ": " + str(reply.get("error")))
        return reply["result"]

    def tool(self, name: str, arguments: dict) -> dict:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        expect(result.get("isError") is not True, name + " was refused: " + str(result)[:300])
        return json.loads(result["content"][0]["text"])

    def close(self) -> None:
        try:
            if self.process.stdin:
                self.process.stdin.close()
            self.process.wait(timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()


def scene_record(work: Path) -> dict:
    """Scene 1. Agent A records a decision and closes its turn with a signed receipt."""
    catalog = SeedCatalog(work / "private" / "catalog.sqlite")
    report = catalog.import_events([DECISION], source_namespace=NAMESPACE)
    expect(report.result == "PASS" and catalog.verify()["ok"] is True, "the Seed catalog did not verify")
    store = turn_store(work / "private" / "turns.sqlite", create=True)
    opened = receipt_of(store.open_turn(machine_id=MACHINE, thread_id="agent-a-session-1", turn_id="turn-1",
                                        prompt_sha256=sha("Pick the request timeout."),
                                        opened_at="2026-01-01T09:00:00.000000Z"))
    closed = receipt_of(store.close_turn(
        registration_id=opened["receipt_id"], outcome="events",
        events=[{"event_uid": DECISION["event_uid"], "event_id": DECISION["id"],
                 "request_sha256": sha(json.dumps(DECISION, sort_keys=True))}],
        closed_at="2026-01-01T09:00:30.000000Z"))
    verify_turn_terminal_receipt(closed, trusted_key=trusted(store.signer))
    expect(closed["outcome"] == "events" and closed["events"][0]["event_id"] == 1, "the close receipt is wrong")
    return {
        "title": "agent A (vendor one) records a decision",
        "lines": [
            ("cmd", "agent-a  append  " + DECISION["event_uid"]),
            ("out", '         "' + DECISION["summary"] + '"'),
            ("ok", "seed     event 1 stored, catalog verified"),
            ("cmd", "agent-a  close turn-1  outcome=events [event 1]"),
            ("ok", "turn     close receipt " + short(closed["receipt_id"]) + "  signature ed25519: valid"),
        ],
    }


def scene_recall(work: Path) -> dict:
    """Scene 2. Another agent, in a new process, reads the decision through the memory server."""
    client = StdioClient([sys.executable, "-B", str(MEMORY_SERVER), "--catalog",
                          str(work / "private" / "catalog.sqlite"), "--snapshots", str(work / "snapshots")])
    try:
        client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "agent-b", "version": "1"}})
        client.tool("integrity_memory_capabilities", {})
        snapshot = client.tool("integrity_seed_snapshot", {})
        recall = client.tool("integrity_seed_recall",
                             {"snapshot_id": snapshot["snapshot_id"], "query": "request timeout"})
    finally:
        client.close()
    expect(len(recall["events"]) == 1, "the recall did not return exactly one event")
    hit, receipt = recall["events"][0], recall["receipt"]
    expect(hit["summary"] == DECISION["summary"] and hit["actor"] == "agent-a", "the recalled event differs")
    expect(receipt["event_ids"] == [1] and receipt["production_authority"] is False
           and receipt["snapshot_id"] == snapshot["snapshot_id"], "the recall receipt is wrong")
    return {
        "title": "agent B (vendor two), a new session, asks the memory",
        "lines": [
            ("cmd", 'agent-b  recall  "request timeout"'),
            ("ok", "memory   1 event  ->  event " + str(hit["event_id"]) + "  by " + hit["actor"]
                   + "  at " + hit["ts_utc"]),
            ("out", '         "' + hit["summary"] + '"'),
            ("out", "         event digest " + short(hit["event_digest"])),
            ("out", "         recall receipt: bound to one snapshot, production_authority=false"),
            ("note", "         What was read is evidence with its origin. It is not permission."),
        ],
    }


def scene_grant(work: Path) -> dict:
    """Scene 3. Acting on memory is refused; a one-use owner grant passes once."""
    owner, agent, custody_signer = demo_signer("owner"), demo_signer("agent-b"), demo_signer("custody")
    change = {
        "protocol": "integrity-guardian/change-intent/v1",
        "intent_id": "intent:demo-timeout",
        "tenant_id": TENANT,
        "actor": {"actor_id": "human:demo-owner", "kind": "human"},
        "target": {"node_id": "node:demo"},
        "scope": {"selectors": ["file:/demo/config.json"], "operations": ["update-content"]},
        "expected_changes": [{"selector": "file:/demo/config.json", "operation": "update-content",
                              "before_digest": BEFORE, "after_digest": AFTER}],
        "created_at": "2026-01-01T10:00:00Z",
        "valid_from": "2026-01-01T10:00:00Z",
        "valid_until": "2026-01-01T10:15:00Z",
        "authorization": {"authority_id": "human:demo-owner", "decision": "approved"},
    }
    observed = ObservedDelta(tenant_id=TENANT, node_id="node:demo", selector="file:/demo/config.json",
                             operation="update-content", observed_at="2026-01-01T10:06:00Z",
                             before_digest=BEFORE, after_digest=AFTER, post_check=PostCheck.PASS,
                             evidence_complete=True, source_event_id="event:demo-change")
    with IntentCustody(work / "custody.sqlite", tenant_id=TENANT, authority_key=trusted(owner),
                       signer=custody_signer) as custody:
        try:
            custody.reserve(sign_change_intent(change, agent), holder="agent:b", now=GRANT_TIME)
        except ValueError as exc:
            refused_memory = str(exc)
        else:
            raise DemoFailure("an intent signed by the agent itself was accepted")
        grant = sign_change_intent(change, owner)
        reservation = custody.reserve(grant, holder="agent:b", now=GRANT_TIME)
        receipt = custody.consume(reservation, grant, [observed], now=GRANT_TIME)
        verify_consumption_receipt(receipt, custody_key=trusted(custody_signer))
        expect(receipt["classifications"] == ["authorized_success"], "the granted change was not accepted")
        try:
            custody.reserve(grant, holder="agent:b", now=GRANT_TIME)
        except IntentReplayError as exc:
            refused_replay = str(exc)
        else:
            raise DemoFailure("a consumed grant was accepted a second time")
        expect(custody.status(grant["intent_id"])["status"] == "consumed", "the grant is not marked consumed")
    return {
        "title": "agent B wants to change a file",
        "lines": [
            ("cmd", 'agent-b  act  "memory says the owner approved this"  (signs the intent itself)'),
            ("deny", "custody  REFUSED  " + refused_memory),
            ("cmd", "owner    sign a one-use grant: update file:/demo/config.json, valid 15 minutes"),
            ("cmd", "agent-b  act  with the owner's grant"),
            ("ok", "custody  ALLOWED  authorized_success, consumption receipt signed"),
            ("cmd", "agent-b  act  with the same grant again"),
            ("deny", "custody  REFUSED  " + refused_replay),
        ],
    }


def scene_debt(work: Path) -> dict:
    """Scene 4. A turn that was never closed is a signed coverage gap the doctor reports."""
    path = work / "private" / "turns.sqlite"
    store = turn_store(path, create=False)
    opened = receipt_of(store.open_turn(machine_id=MACHINE, thread_id="agent-b-session-1", turn_id="turn-2",
                                        prompt_sha256=sha("Apply the timeout."),
                                        opened_at="2026-01-01T10:04:00.000000Z"))
    gap = receipt_of(store.observe_gap(registration_id=opened["receipt_id"], stage="stop",
                                       observed_at="2026-01-01T10:20:00.000000Z"))
    verify_turn_gap_receipt(gap, trusted_key=trusted(store.signer))
    transport = {"command": sys.executable,
                 "args": ["-B", str(Path(__file__).resolve()), "--serve-coverage", str(path)]}
    probe = doctor.probe(transport, coverage_limit=50, timeout=120)
    expect(probe.get("answered") is True and "coverage" in probe, "integrity-doctor got no answer: " + str(probe))
    coverage = probe["coverage"]
    expect((coverage["registered"], coverage["terminal"], coverage["unresolved"]) == (2, 1, 1),
           "the coverage counts are wrong: " + str(coverage))
    report = {"project": "demo", "hooks": [], "mcp": [], "turn_guard": [], "findings": [],
              "probes": [dict(probe, transport_file="demo")]}
    line = next(row.strip() for row in doctor.render(report).splitlines() if row.strip().startswith("coverage:"))
    return {
        "title": "agent B ends its turn without closing it",
        "lines": [
            ("cmd", "agent-b  open turn-2   ...and stops without a close"),
            ("deny", "stop     no close receipt  ->  coverage gap " + short(gap["receipt_id"])
                     + "  signature ed25519: valid"),
            ("cmd", "owner    integrity-doctor"),
            ("out", "doctor   " + line),
            ("note", "         The missing close is on record as a signed debt. It is not a silent no-event."),
        ],
    }


def run_scenes() -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="integrity-demo-") as temporary:
        work = Path(temporary)
        return [scene_record(work), scene_recall(work), scene_grant(work), scene_debt(work)]


def serve_coverage(path: Path) -> int:
    """A stand-in MCP server for scene 4: one tool, answered from the real turn store.

    The full memory server needs a signed write plane before it serves Turn
    Memory. This stand-in lets the real integrity-doctor probe read the same
    store without one.
    """
    store = turn_store(path, create=False)
    tool = {"name": "integrity_turn_memory_coverage", "description": "Turn coverage counts.",
            "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}}}
    for raw in sys.stdin:
        try:
            request = json.loads(raw)
        except ValueError:
            continue
        if "id" not in request:
            continue
        method, result = request.get("method"), {}
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "integrity-demo-coverage", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [tool]}
        elif method == "tools/call":
            limit = (request.get("params", {}).get("arguments") or {}).get("limit", 50)
            result = {"content": [{"type": "text", "text": json.dumps(store.coverage(limit=limit))}],
                      "isError": False}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
    return 0


def transcript(scenes: list[dict]) -> str:
    out = []
    for number, scene in enumerate(scenes, 1):
        out.append(f"== scene {number}: {scene['title']}")
        out += [("$ " if style == "cmd" else "  ") + text for style, text in scene["lines"]]
        out.append("")
    return "\n".join(out)


MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
SANS = "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
THEMES = {
    "light": {"canvas": "#FFFFFF", "edge": "#D0D7DE", "bar": "#F6F8FA", "ink": "#1F2328", "muted": "#59636E",
              "cmd": "#0969DA", "ok": "#0B7A5E", "deny": "#CF222E", "step": "#EEF1F4", "step_on": "#E2F5EE"},
    "dark": {"canvas": "#0D1117", "edge": "#30363D", "bar": "#161B22", "ink": "#E6EDF3", "muted": "#9198A1",
             "cmd": "#79B8FF", "ok": "#3FCF9F", "deny": "#FF7B72", "step": "#1C222B", "step_on": "#0E2A22"},
}
STEPS = ("1 record", "2 recall", "3 grant", "4 close")
WIDTH, LINE, TOP, SCENE_SECONDS, MAX_CHARS = 880, 22, 96, 9.0, 100


def _fade(start: float, end: float, total: float) -> str:
    """One SMIL animation: hidden, visible from start to end, hidden again; repeats."""
    edge = 0.25
    times = [0.0, start, start + edge, end, end + edge, total]
    keys = ";".join(f"{min(t / total, 1.0):.4f}" for t in times)
    return (f'<animate attributeName="opacity" dur="{total:g}s" repeatCount="indefinite" '
            f'keyTimes="{keys}" values="0;0;1;1;0;0"/>')


def render_svg(scenes: list[dict], theme: dict) -> str:
    total = SCENE_SECONDS * len(scenes)
    rows = max(len(scene["lines"]) for scene in scenes) + 1
    height = TOP + rows * LINE + 18
    colors = {"cmd": theme["cmd"], "out": theme["ink"], "ok": theme["ok"], "deny": theme["deny"],
              "note": theme["muted"]}
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" '
        f'height="{height}" role="img" aria-labelledby="t d" font-family="{MONO}">',
        '<title id="t">Integrity demo: four scenes</title>',
        '<desc id="d">' + escape(" ".join(f"Scene {n}: {s['title']}." for n, s in enumerate(scenes, 1))
                                 + " Recorded from demo/run.py.") + '</desc>',
        f'<rect x="1" y="1" width="{WIDTH - 2}" height="{height - 2}" rx="12" fill="{theme["canvas"]}" '
        f'stroke="{theme["edge"]}"/>',
        f'<path d="M1 13a12 12 0 0 1 12-12h{WIDTH - 26}a12 12 0 0 1 12 12v23H1z" fill="{theme["bar"]}"/>',
        f'<path d="M1 36.5h{WIDTH - 2}" stroke="{theme["edge"]}"/>',
    ]
    for index in range(3):
        parts.append(f'<circle cx="{22 + index * 18}" cy="19" r="5" fill="{theme["edge"]}"/>')
    parts.append(f'<text x="{WIDTH / 2:g}" y="23.5" text-anchor="middle" font-size="12.5" fill="{theme["muted"]}">'
                 'python demo/run.py</text>')
    step_width = (WIDTH - 48 - 3 * 10) / 4
    for index, label in enumerate(STEPS):
        x = 24 + index * (step_width + 10)
        start = index * SCENE_SECONDS
        parts.append(f'<rect x="{x:g}" y="48" width="{step_width:g}" height="24" rx="6" fill="{theme["step"]}"/>')
        parts.append(f'<rect x="{x:g}" y="48" width="{step_width:g}" height="24" rx="6" fill="{theme["step_on"]}" '
                     f'stroke="{theme["ok"]}" opacity="{1 if index == 0 else 0}">'
                     + _fade(start, start + SCENE_SECONDS - 0.25, total) + '</rect>')
        parts.append(f'<text x="{x + step_width / 2:g}" y="64.5" text-anchor="middle" font-size="12.5" '
                     f'font-family="{SANS}" fill="{theme["ink"]}">{escape(label)}</text>')
    for index, scene in enumerate(scenes):
        base, begin = (1 if index == 0 else 0), index * SCENE_SECONDS
        finish = begin + SCENE_SECONDS - 0.5
        heading = f"# scene {index + 1}: {scene['title']}"
        rows_of_scene = [("note", heading)] + list(scene["lines"])
        for row, (style, text) in enumerate(rows_of_scene):
            shown = ("$ " if style == "cmd" else "  ") + text if row else text
            if len(shown) > MAX_CHARS:
                raise DemoFailure(f"line too long for the picture ({len(shown)}): {shown}")
            appear = begin + 0.3 + row * 0.85
            parts.append(f'<text x="24" y="{TOP + row * LINE}" font-size="13" xml:space="preserve" '
                         f'fill="{colors[style]}" opacity="{base}">{escape(shown)}'
                         + _fade(appear, finish, total) + '</text>')
    parts.append('</svg>')
    return "\n".join(parts) + "\n"


def pictures(scenes: list[dict]) -> dict[str, bytes]:
    return {f"demo-{name}.svg": render_svg(scenes, theme).encode("utf-8") for name, theme in THEMES.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--svg", type=Path, metavar="DIR")
    parser.add_argument("--check", type=Path, metavar="DIR")
    parser.add_argument("--serve-coverage", type=Path, metavar="FILE", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.serve_coverage:
        return serve_coverage(args.serve_coverage)
    try:
        scenes = run_scenes()
    except DemoFailure as exc:
        print("demo failed: " + str(exc), file=sys.stderr)
        return 1
    print(transcript(scenes))
    if args.svg:
        args.svg.mkdir(parents=True, exist_ok=True)
        for name, data in pictures(scenes).items():
            (args.svg / name).write_bytes(data)
        print("pictures written to " + str(args.svg))
    if args.check:
        stale = [name for name, data in pictures(scenes).items()
                 if not (args.check / name).is_file() or (args.check / name).read_bytes() != data]
        if stale:
            print("out of date: " + ", ".join(stale) + " (run: python demo/run.py --svg " + str(args.check) + ")",
                  file=sys.stderr)
            return 1
        print("pictures in " + str(args.check) + " match this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
