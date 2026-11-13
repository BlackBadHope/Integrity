# SPDX-License-Identifier: BUSL-1.1
"""Three agents, one task, one memory: the record of a real run.

This script plays no agent. The agents are an agent client with its own
account and model; the memory is `guardian-local-memory` on the same machine.
`demo/README.md` has the commands and the three prompts. This script only
turns what the client printed into a record, and a record into text and
pictures.

    python demo/run.py                 print the two committed records
    python demo/run.py --svg DIR       also write demo-light.svg and demo-dark.svg to DIR
    python demo/run.py --check DIR     fail if the pictures in DIR differ from the records
    python demo/run.py record --client NAME --out FILE A.jsonl B.jsonl C.jsonl
                                       build a record from your own run; each file is
                                       what one client printed: Claude Code with
                                       `--output-format stream-json --verbose`, or
                                       Codex CLI with `exec --json`
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
RECORDS = {"closed": HERE / "recorded" / "closed.json", "broken-off": HERE / "recorded" / "broken-off.json"}
SCHEMA = "integrity-demo-record/v1"
SERVER = "integrity_local_memory"
SERVER_PREFIX = "mcp__" + SERVER + "__"
ROLES = ("A", "B", "C")
# How a scene shows the command of one agent; the key is the first word of the client name.
COMMANDS = {"claude": "claude -p < {prompt}", "codex": "codex exec - < {prompt}"}


class DemoFailure(RuntimeError):
    """A record does not hold what the demo shows."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise DemoFailure(message)


def prompt_digest(path: Path) -> str:
    """Digest of a prompt file with line endings normalised, so a checkout on any system agrees."""
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _codex_call(item: dict) -> dict:
    """One `mcp_tool_call` item of Codex CLI `exec --json`."""
    failed = item.get("error") is not None or item.get("status") != "completed"
    parts = (item.get("result") or {}).get("content") or []
    body = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
    result = {"error": str(item.get("error"))} if failed or not body else json.loads(body)
    return {"tool": item["tool"], "arguments": item.get("arguments") or {}, "is_error": failed, "result": result}


def read_client_output(path: Path) -> dict:
    """Server tool calls and the final answer from what one client printed.

    Two formats are read: Claude Code `--output-format stream-json`, and Codex
    CLI `exec --json`. Codex does not print the name of its model.
    """
    calls: list[dict] = []
    pending: dict[str, dict] = {}
    model, answer = "", ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip().startswith("{"):
            continue
        row = json.loads(line)
        kind = row.get("type")
        if kind == "item.completed":
            item = row.get("item") or {}
            if item.get("type") == "agent_message":
                answer = str(item.get("text", ""))
            elif item.get("type") == "mcp_tool_call" and item.get("server") == SERVER:
                calls.append(_codex_call(item))
        elif kind == "system" and row.get("subtype") == "init":
            model = str(row.get("model", ""))
        elif kind == "assistant":
            for part in row["message"]["content"]:
                if part.get("type") == "tool_use" and part["name"].startswith(SERVER_PREFIX):
                    entry = {"tool": part["name"][len(SERVER_PREFIX):], "arguments": part["input"]}
                    pending[part["id"]] = entry
                    calls.append(entry)
        elif kind == "user":
            for part in row["message"]["content"]:
                if isinstance(part, dict) and part.get("type") == "tool_result" and part.get("tool_use_id") in pending:
                    body = part.get("content")
                    if isinstance(body, list):
                        body = "".join(item.get("text", "") for item in body if isinstance(item, dict))
                    entry = pending.pop(part["tool_use_id"])
                    entry["is_error"] = bool(part.get("is_error"))
                    entry["result"] = json.loads(body)
        elif kind == "result":
            answer = str(row.get("result", ""))
    expect(not pending, f"{path.name}: a tool call has no result")
    expect(bool(calls), f"{path.name}: no call to the local memory server")
    return {"model": model, "calls": calls, "answer": answer.strip()}


def build_record(clients: list[str], recorded: str, platform: str, prompts: list[Path], outputs: list[Path]) -> dict:
    """`clients` is one name for all three agents, or one name for each of A, B and C."""
    expect(len(prompts) == len(outputs) == 3, "a record needs three prompts and three client outputs: A, B, C")
    expect(len(clients) in (1, 3), "give one client name, or three: for A, B and C")
    names = list(clients) * 3 if len(clients) == 1 else list(clients)
    agents = []
    for role, name, prompt, output in zip(ROLES, names, prompts, outputs, strict=True):
        parsed = read_client_output(output)
        agents.append({"role": role, "client": name, "prompt": prompt.resolve().relative_to(HERE.parent).as_posix(),
                       "prompt_sha256": prompt_digest(prompt), "model": parsed["model"],
                       "calls": parsed["calls"], "answer": parsed["answer"]})
    return {"schema": SCHEMA, "recorded": recorded, "client": ", ".join(dict.fromkeys(names)),
            "platform": platform, "agents": agents}


def client_of(record: dict, agent: dict) -> str:
    return agent.get("client") or record["client"]


def who(record: dict, agent: dict) -> str:
    """The client and, when the client printed it, the model."""
    return client_of(record, agent) + (", " + agent["model"] if agent.get("model") else "")


def command(record: dict, agent: dict) -> str:
    first = client_of(record, agent).split()[0].lower()
    return COMMANDS.get(first, "your-agent-client < {prompt}").format(prompt=agent["prompt"])


def load_record(path: Path) -> dict:
    record = json.loads(path.read_text(encoding="utf-8"))
    expect(record.get("schema") == SCHEMA, f"{path.name}: not a demo record")
    expect([agent["role"] for agent in record["agents"]] == list(ROLES), f"{path.name}: agents must be A, B, C")
    return record


def _result(agent: dict, tool: str) -> dict:
    """The result of the last successful call of one tool by one agent."""
    for call in reversed(agent["calls"]):
        if call["tool"] == tool and not call.get("is_error"):
            return call["result"]
    raise DemoFailure(f"agent {agent['role']} did not call {tool}")


def _called(agent: dict, tool: str) -> bool:
    return any(call["tool"] == tool and not call.get("is_error") for call in agent["calls"])


def short(value: str) -> str:
    return value[:19] + "..."


def clock(stamp: str) -> str:
    return stamp[11:19] + "Z"


def facts(record: dict) -> dict:
    """What agent C learned about agent B, taken from the tool results and not from C's prose."""
    writer, reader = record["agents"][1], record["agents"][2]
    written = _result(writer, "lm_append_event")
    recalled = _result(reader, "lm_seed_recall")["events"]
    found = _result(reader, "lm_turn_receipt_by_event")
    expect(found["event"]["event_uid"] == written["event_uid"], "agent C looked up another event than agent B wrote")
    turn = found["turn"]
    return {
        "recalled": [(event["actor"], event["summary"]) for event in recalled],
        "event_id": found["event"]["id"],
        "summary": found["event"]["summary"],
        "author": (found["author"]["declared_agent"], found["author"]["declared_client"],
                   found["author"]["declared_machine"]),
        "author_note": found["author"]["note"],
        "claim_kinds": [claim["kind"] for claim in found["claims"]],
        "claim_resources": found["claims"][0]["resources"] if found["claims"] else [],
        "claim_fence": max((claim["fence_token"] for claim in found["claims"]), default=0),
        "release_names_event": any(claim.get("outcome") == written["event_uid"] for claim in found["claims"]),
        "turn_status": turn["status"],
        "opened_at": turn["opened_at"],
        "closed_at": (turn.get("terminal_receipt") or {}).get("closed_at", ""),
        "listed": bool(turn.get("event_listed_in_terminal_receipt")),
        "gap_recorded": turn.get("gap_receipt") is not None,
    }


def writer_scene(record: dict, index: int) -> dict:
    agent = record["agents"][index]
    opened = _result(agent, "lm_turn_open")
    claim = _result(agent, "lm_work_claim")
    event = _result(agent, "lm_append_event")
    summary = next(call["arguments"]["summary"] for call in agent["calls"] if call["tool"] == "lm_append_event")
    receipt = _result(agent, "lm_turn_close")["receipt"]
    expect(claim["status"] == "acquired", f"agent {agent['role']} did not get the claim")
    expect(_called(agent, "lm_work_release"), f"agent {agent['role']} did not release the claim")
    expect([row["event_uid"] for row in receipt["events"]] == [event["event_uid"]],
           f"the receipt of agent {agent['role']} does not list its event")
    name = next(call["arguments"]["declared_agent"] for call in agent["calls"]
                if call["tool"] == "lm_turn_open")
    return {"title": f"agent {agent['role']} claims the task and writes ({who(record, agent)})",
            "lines": [
                ("cmd", command(record, agent)),
                ("out", f"lm_turn_open      turn of {name} registered, {short(opened['registration_id'])}"),
                ("out", f"lm_work_claim     {claim['resources'][0]}: acquired, fence {claim['fence_token']}"),
                ("out", f"lm_append_event   event {event['event_id']}: \"{summary}\""),
                ("out", f"lm_work_release   released, names event {event['event_id']}"),
                ("ok", f"lm_turn_close     signed receipt {short(receipt['receipt_id'])} lists event "
                       f"{event['event_id']}"),
            ]}


def reader_scene(record: dict, title: str) -> dict:
    agent, known = record["agents"][2], facts(record)
    recalled = ", ".join(f"\"{summary}\" by {actor}" for actor, summary in known["recalled"])
    released = "claim-released" in known["claim_kinds"]
    lines = [
        ("cmd", command(record, agent)),
        ("out", f"lm_seed_recall             {len(known['recalled'])} events: {recalled}"),
        ("out", f"lm_turn_receipt_by_event   event {known['event_id']}: \"{known['summary']}\""),
        ("out", "  author  " + " / ".join(known["author"]) + "   (" + known["author_note"] + ")"),
    ]
    resource = known["claim_resources"][0] if known["claim_resources"] else "?"
    if released and known["release_names_event"]:
        lines.append(("ok", f"  claim   {resource}, fence {known['claim_fence']}: acquired, then released "
                            f"naming event {known['event_id']}"))
    else:
        lines.append(("deny", f"  claim   {resource}, fence {known['claim_fence']}: acquired, never released"))
    if known["turn_status"] == "closed" and known["listed"]:
        lines.append(("ok", f"  turn    closed {clock(known['closed_at'])}: the signed receipt lists event "
                            f"{known['event_id']}"))
    else:
        gap = "a gap is recorded" if known["gap_recorded"] else "no gap recorded"
        lines.append(("deny", f"  turn    open since {clock(known['opened_at'])}: no closing receipt, {gap}"))
    return {"title": title, "lines": lines}


def scenes_of(closed: dict, broken: dict) -> list[dict]:
    known = facts(broken)
    expect(known["turn_status"] == "open" and "claim-released" not in known["claim_kinds"],
           "in the second record agent B must stop before the release and the close")
    expect(facts(closed)["turn_status"] == "closed", "in the first record agent B must close its turn")
    return [
        writer_scene(closed, 0),
        writer_scene(closed, 1),
        reader_scene(closed, "agent C continues; it reads the memory and does not ask agent B"),
        reader_scene(broken, "a second run: agent B stopped before the release and the close"),
    ]


def load_scenes() -> list[dict]:
    return scenes_of(load_record(RECORDS["closed"]), load_record(RECORDS["broken-off"]))


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
STEPS = ("1 A writes", "2 B writes", "3 C reads B from memory", "4 B broke off")
BAR = "three agents of one user, one local memory"
WIDTH, LINE, TOP, SCENE_SECONDS, LINE_SECONDS, MAX_CHARS = 880, 22, 96, 12.0, 0.7, 100


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
        '<title id="t">Integrity demo: three agents, one task, one memory</title>',
        '<desc id="d">' + escape(" ".join(f"Scene {n}: {s['title']}." for n, s in enumerate(scenes, 1))
                                 + " Drawn from the records in demo/recorded.") + '</desc>',
        f'<rect x="1" y="1" width="{WIDTH - 2}" height="{height - 2}" rx="12" fill="{theme["canvas"]}" '
        f'stroke="{theme["edge"]}"/>',
        f'<path d="M1 13a12 12 0 0 1 12-12h{WIDTH - 26}a12 12 0 0 1 12 12v23H1z" fill="{theme["bar"]}"/>',
        f'<path d="M1 36.5h{WIDTH - 2}" stroke="{theme["edge"]}"/>',
    ]
    for index in range(3):
        parts.append(f'<circle cx="{22 + index * 18}" cy="19" r="5" fill="{theme["edge"]}"/>')
    parts.append(f'<text x="{WIDTH / 2:g}" y="23.5" text-anchor="middle" font-size="12.5" fill="{theme["muted"]}">'
                 + escape(BAR) + '</text>')
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
            appear = begin + 0.3 + row * LINE_SECONDS
            parts.append(f'<text x="24" y="{TOP + row * LINE}" font-size="13" xml:space="preserve" '
                         f'fill="{colors[style]}" opacity="{base}">{escape(shown)}'
                         + _fade(appear, finish, total) + '</text>')
    parts.append('</svg>')
    return "\n".join(parts) + "\n"


def pictures(scenes: list[dict]) -> dict[str, bytes]:
    return {f"demo-{name}.svg": render_svg(scenes, theme).encode("utf-8") for name, theme in THEMES.items()}


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["record"]:
        parser = argparse.ArgumentParser(prog="run.py record", description="Build a record from your own run.")
        parser.add_argument("--client", required=True, nargs="+", metavar="NAME",
                            help='client name and version, for example "Claude Code 2.1"; one for all three '
                                 'agents, or three: for A, B and C')
        parser.add_argument("--platform", default=sys.platform)
        parser.add_argument("--recorded", required=True, metavar="DATE", help="the day of the run, YYYY-MM-DD")
        parser.add_argument("--prompts", nargs=3, type=Path, metavar="FILE",
                            default=[HERE / "prompts" / f"agent-{role.lower()}.txt" for role in ROLES])
        parser.add_argument("--out", required=True, type=Path)
        parser.add_argument("outputs", nargs=3, type=Path, metavar="CLIENT_OUTPUT")
        args = parser.parse_args(arguments[1:])
        try:
            record = build_record(args.client, args.recorded, args.platform, args.prompts, args.outputs)
        except DemoFailure as exc:
            print("record failed: " + str(exc), file=sys.stderr)
            return 1
        args.out.write_text(json.dumps(record, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                            encoding="utf-8", newline="\n")
        print("record written to " + str(args.out))
        return 0
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--svg", type=Path, metavar="DIR")
    parser.add_argument("--check", type=Path, metavar="DIR")
    args = parser.parse_args(arguments)
    try:
        scenes = load_scenes()
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
        print("pictures in " + str(args.check) + " match the records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
