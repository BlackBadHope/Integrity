# SPDX-License-Identifier: BUSL-1.1
"""ChatGPT Web adapter for LLM Bus (agent-bus/1).

Provides inbox reading, sending, reply_to handling, and status checks for
the ChatGPT Web participant (address: chatgpt-web) on the local LLM bus.
Stdlib only, safe read-only inbox queries (mode=ro + PRAGMA query_only=ON),
and full agent-bus/1 body validation.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import uuid

BUS_DIR = Path(__file__).resolve().parent

if str(BUS_DIR) not in sys.path:
    sys.path.insert(0, str(BUS_DIR))

import agent_registry
import agentbus_validate
import reachability
from bus import DELIVERY_MODES, MAX_BODY_BYTES, MessageStore, _row, _validate_message
from local_cli import open_store

DEFAULT_STATE_DIR = Path(_integrity_value('state_directory'))
DEFAULT_ADDRESS = "chatgpt-web"
DEFAULT_UUID = None  # the ChatGPT conversation UUID comes from configuration (chatgpt_thread_id)
DEFAULT_TOPIC = "ChatGPT Web participant / LLM Bus"
HARNESS = "chatgpt"
DISALLOWED_RECIPIENTS = frozenset({"owner", "bus-relay", DEFAULT_ADDRESS})
DELIVERY_ALIASES = {
    "followup": "queue",
    "auto": "steer",
}
ALLOWED_DELIVERY_MODES = tuple(DELIVERY_MODES) + tuple(DELIVERY_ALIASES.keys())


def normalize_delivery(delivery: str | None) -> str:
    """Normalize delivery aliases (followup -> queue, auto -> steer)."""
    if not delivery:
        return "steer"
    mode = str(delivery).strip().lower()
    canonical = DELIVERY_ALIASES.get(mode, mode)
    if canonical not in DELIVERY_MODES:
        raise ValueError(
            f"Invalid delivery mode {delivery!r}, must be one of {DELIVERY_MODES} or aliases {tuple(DELIVERY_ALIASES.keys())}"
        )
    return canonical


def ensure_registered(
    address: str = DEFAULT_ADDRESS,
    thread_uuid: str | None = DEFAULT_UUID,
    topic: str = DEFAULT_TOPIC,
    state_dir: Path | None = None,
) -> tuple[dict, bool]:
    """Register chatgpt-web in the bus registry if not already present."""
    sd = (state_dir or DEFAULT_STATE_DIR).resolve()
    return agent_registry.register(
        address=address,
        thread=thread_uuid or _integrity_value('chatgpt_thread_id'),
        harness=HARNESS,
        topic=topic,
        state_dir=sd,
    )


@contextlib.contextmanager
def _connect_ro(state_dir: Path):
    db_path = state_dir / "bus.sqlite3"
    if not db_path.is_file():
        raise FileNotFoundError(f"Bus database not found: {db_path}")
    con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only = ON")
    try:
        yield con
    finally:
        con.close()


def inbox(
    agent: str = DEFAULT_ADDRESS,
    status: str = "pending",
    limit: int = 20,
    state_dir: Path | None = None,
) -> list[dict]:
    """Read incoming messages for chatgpt-web in read-only mode."""
    if agent != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: chatgpt-web adapter cannot read inbox for {agent!r}")
    sd = (state_dir or DEFAULT_STATE_DIR).resolve()
    with _connect_ro(sd) as db:
        if status == "all":
            rows = db.execute(
                "SELECT seq, * FROM messages WHERE recipient=? ORDER BY seq ASC LIMIT ?",
                (DEFAULT_ADDRESS, limit),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT seq, * FROM messages WHERE recipient=? AND status=? ORDER BY seq ASC LIMIT ?",
                (DEFAULT_ADDRESS, status, limit),
            ).fetchall()
    res = []
    for r in rows:
        d = _row(r)
        if "seq" in r.keys():
            d["seq"] = r["seq"]
        res.append(d)
    return res


def get_message(
    msg_id: str,
    agent: str = DEFAULT_ADDRESS,
    state_dir: Path | None = None,
) -> dict | None:
    """Retrieve full message for chatgpt-web (only if chatgpt-web is recipient or sender)."""
    if agent != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: chatgpt-web adapter cannot inspect messages as {agent!r}")
    sd = (state_dir or DEFAULT_STATE_DIR).resolve()
    with _connect_ro(sd) as db:
        row = db.execute("SELECT seq, * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if row is None:
        return None
    m = _row(row)
    if m["to"] != DEFAULT_ADDRESS and m["from"] != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: message {msg_id} is neither to nor from {DEFAULT_ADDRESS}")
    return m


def _format_body(body: str | dict, topic: str = "chatgpt-task") -> str:
    """Ensure body conforms to agent-bus/1 schema string."""
    if isinstance(body, dict):
        if "v" not in body:
            body = {"v": 1, "k": "task", "th": topic, "need": "none", "data": body}
        return json.dumps(body, ensure_ascii=False)
    # Check if raw string is already valid JSON
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict) and "v" in parsed:
            return body
    except (ValueError, TypeError):
        pass
    # Plain text wrap
    wrapped = {"v": 1, "k": "task", "th": topic, "need": "none", "data": {"text": body}}
    return json.dumps(wrapped, ensure_ascii=False)


def send(
    to: str,
    body: str | dict,
    reply_to: str | None = None,
    msg_id: str | None = None,
    delivery: str = "steer",
    from_agent: str = DEFAULT_ADDRESS,
    state_dir: Path | None = None,
    strict: bool = True,
) -> dict:
    """Send a message from chatgpt-web to recipient."""
    if from_agent != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: sender identity spoofing disallowed (must be {DEFAULT_ADDRESS})")
    if to in DISALLOWED_RECIPIENTS:
        raise ValueError(f"Sending to {to!r} is disallowed for {DEFAULT_ADDRESS}")
    sd = (state_dir or DEFAULT_STATE_DIR).resolve()
    ensure_registered(DEFAULT_ADDRESS, state_dir=sd)

    known = agent_registry.all_agents(sd)
    if to not in known:
        raise ValueError(f"Unknown recipient {to!r}. Known agents: {known}")
    delivery = normalize_delivery(delivery)
    if to == "grok":
        # Grok Bot wakeup routing: Grok webhook endpoint requires continuation steer (wakeup).
        # Queue / followup is unsupported on the wire and rejected by the bus relay; always route to steer.
        delivery = "steer"
    elif delivery not in DELIVERY_MODES:
        raise ValueError(f"Invalid delivery mode {delivery!r}, must be one of {DELIVERY_MODES}")

    if msg_id is None:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        rand4 = uuid.uuid4().hex[:4]
        msg_id = f"{DEFAULT_ADDRESS}-{stamp}-{rand4}"

    body_str = _format_body(body, topic=f"bus-{DEFAULT_ADDRESS}")
    if len(body_str.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError(f"Body size exceeds maximum allowed ({MAX_BODY_BYTES} bytes)")

    if strict:
        errs = agentbus_validate.validate(body_str)
        if errs:
            raise ValueError(f"agent-bus/1 validation failed: {'; '.join(errs)}")

    msg = {
        "id": msg_id,
        "from": DEFAULT_ADDRESS,
        "to": to,
        "body": body_str,
        "reply_to": reply_to,
        "delivery": delivery,
    }
    _validate_message(msg, DEFAULT_ADDRESS, sd)

    store = open_store(sd)
    row, dup = store.post(msg)
    return {
        "id": row["id"],
        "from": row["from"],
        "to": row["to"],
        "reply_to": row["reply_to"],
        "delivery": row.get("delivery"),
        "status": row["status"],
        "created_at": row["created_at"],
        "duplicate": dup,
        "body_sha256": hashlib.sha256(body_str.encode("utf-8")).hexdigest(),
    }


def reply(
    to_msg_id: str,
    body: str | dict,
    msg_id: str | None = None,
    delivery: str = "steer",
    from_agent: str = DEFAULT_ADDRESS,
    state_dir: Path | None = None,
    strict: bool = True,
) -> dict:
    """Reply directly to an existing message addressed to chatgpt-web."""
    if from_agent != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: sender identity spoofing disallowed (must be {DEFAULT_ADDRESS})")
    delivery = normalize_delivery(delivery)
    parent = get_message(to_msg_id, agent=DEFAULT_ADDRESS, state_dir=state_dir)
    if parent is None:
        raise FileNotFoundError(f"Parent message {to_msg_id} not found")
    if parent["to"] != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: cannot reply to message addressed to {parent['to']!r}")
    recipient = parent["from"]
    if recipient == "grok":
        delivery = "steer"
    return send(
        to=recipient,
        body=body,
        reply_to=to_msg_id,
        msg_id=msg_id,
        delivery=delivery,
        from_agent=DEFAULT_ADDRESS,
        state_dir=state_dir,
        strict=strict,
    )


def ack(
    msg_id: str,
    agent: str = DEFAULT_ADDRESS,
    state_dir: Path | None = None,
) -> dict | None:
    """Acknowledge reading a message addressed to chatgpt-web."""
    if agent != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: cannot acknowledge on behalf of {agent!r}")
    sd = (state_dir or DEFAULT_STATE_DIR).resolve()
    with _connect_ro(sd) as db:
        row = db.execute("SELECT recipient, status FROM messages WHERE id=?", (msg_id,)).fetchone()
    if row is None:
        return None
    if row["recipient"] != DEFAULT_ADDRESS:
        raise PermissionError(f"Access denied: message {msg_id} is addressed to {row['recipient']!r}, not {DEFAULT_ADDRESS}")
    store = open_store(sd)
    res = store.ack(msg_id, DEFAULT_ADDRESS)
    return res if res else None


def message_status(
    msg_id: str,
    state_dir: Path | None = None,
) -> dict:
    """Query message status and any replies for chatgpt-web."""
    sd = (state_dir or DEFAULT_STATE_DIR).resolve()
    store = open_store(sd)
    with store._connection() as db:
        row = db.execute("SELECT seq, * FROM messages WHERE id=?", (msg_id,)).fetchone()
        if not row:
            return {"message": None, "replies": []}
        m = _row(row)
        if m["to"] != DEFAULT_ADDRESS and m["from"] != DEFAULT_ADDRESS:
            raise PermissionError(f"Access denied: message {msg_id} is neither to nor from {DEFAULT_ADDRESS}")
        replies = db.execute(
            "SELECT seq, * FROM messages WHERE reply_to=? ORDER BY seq ASC",
            (msg_id,),
        ).fetchall()
    return {
        "message": m,
        "replies": [_row(r) for r in replies],
    }


def list_agents(state_dir: Path | None = None) -> list[dict]:
    """List all registered agents and their reachability."""
    sd = (state_dir or DEFAULT_STATE_DIR).resolve()
    reg = agent_registry.load(sd)
    known = agent_registry.all_agents(sd)
    out = []
    for a in known:
        entry = reg.get(a, {})
        acc = reachability.assess(a, sd)
        if a in agent_registry.BUILTIN:
            harness = "codex" if a in agent_registry.BUILTIN_CODEX else a
        else:
            harness = entry.get("harness", "unknown")
        topic = entry.get("topic", "Grok Bot (xAI)" if a == "grok" else "")
        out.append({
            "address": a,
            "harness": harness,
            "topic": topic,
            "thread": entry.get("thread"),
            "deliverable": acc.get("deliverable"),
            "route": acc.get("route"),
        })
    return out


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="ChatGPT Web adapter for LLM Bus")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--address", default=DEFAULT_ADDRESS)
    parser.add_argument("--json", action="store_true", help="output raw JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # register
    sub.add_parser("register", help="ensure chatgpt-web is registered")

    # inbox
    inb = sub.add_parser("inbox", help="read inbox")
    inb.add_argument("--status", choices=("pending", "acked", "replied", "all"), default="pending")
    inb.add_argument("--limit", type=int, default=20)

    # get
    g = sub.add_parser("get", help="get full message")
    g.add_argument("id")

    # send
    s = sub.add_parser("send", help="send message")
    s.add_argument("--to", required=True)
    grp = s.add_mutually_exclusive_group(required=True)
    grp.add_argument("--body")
    grp.add_argument("--body-file", type=Path)
    s.add_argument("--reply-to")
    s.add_argument("--id")
    s.add_argument("--delivery", choices=ALLOWED_DELIVERY_MODES, default="steer")
    s.add_argument("--no-strict", dest="strict", action="store_false", default=True)

    # reply
    r = sub.add_parser("reply", help="reply to message")
    r.add_argument("--to-msg", required=True)
    rgrp = r.add_mutually_exclusive_group(required=True)
    rgrp.add_argument("--body")
    rgrp.add_argument("--body-file", type=Path)
    r.add_argument("--id")
    r.add_argument("--delivery", choices=ALLOWED_DELIVERY_MODES, default="steer")
    r.add_argument("--no-strict", dest="strict", action="store_false", default=True)

    # ack
    a = sub.add_parser("ack", help="acknowledge message")
    a.add_argument("id")

    # status
    st = sub.add_parser("status", help="check message status and replies")
    st.add_argument("id")

    # agents
    sub.add_parser("agents", help="list agents and reachability")

    args = parser.parse_args(argv)
    sd = args.state_dir.resolve()

    if args.cmd == "register":
        entry, again = ensure_registered(args.address, state_dir=sd)
        res = {"address": args.address, "already_registered": again, **entry}
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "inbox":
        msgs = inbox(agent=args.address, status=args.status, limit=args.limit, state_dir=sd)
        if args.json:
            print(json.dumps(msgs, ensure_ascii=False, indent=2))
        else:
            print(f"Inbox for {args.address} (status={args.status}, count={len(msgs)}):")
            for m in msgs:
                reply_part = f" (reply_to={m['reply_to']})" if m.get("reply_to") else ""
                print(f"  Seq {m.get('seq', '?')}: [{m['status']}] id={m['id']} from={m['from']}{reply_part}")
                print(f"    body: {m['body'][:120]}...")
        return 0

    if args.cmd == "get":
        m = get_message(args.id, agent=args.address, state_dir=sd)
        if m is None:
            print(f"Message {args.id} not found", file=sys.stderr)
            return 1
        print(json.dumps(m, ensure_ascii=False, indent=2))
        return 0

    if args.cmd in ("send", "reply"):
        body = args.body_file.read_text(encoding="utf-8") if getattr(args, "body_file", None) else args.body
        if args.cmd == "send":
            res = send(
                to=args.to,
                body=body,
                reply_to=args.reply_to,
                msg_id=args.id,
                delivery=args.delivery,
                from_agent=args.address,
                state_dir=sd,
                strict=args.strict,
            )
        else:
            res = reply(
                to_msg_id=args.to_msg,
                body=body,
                msg_id=args.id,
                delivery=args.delivery,
                from_agent=args.address,
                state_dir=sd,
                strict=args.strict,
            )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "ack":
        res = ack(args.id, agent=args.address, state_dir=sd)
        if res is None:
            print(f"Message {args.id} not found or not acked", file=sys.stderr)
            return 1
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "status":
        res = message_status(args.id, state_dir=sd)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "agents":
        res = list_agents(state_dir=sd)
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(f"Total reachable agents: {len(res)}")
            for a in res:
                harness_str = str(a.get("harness") or "")
                route_str = str(a.get("route") or "none")
                topic_str = str(a.get("topic") or "")
                print(f"  {a['address']:<24} harness={harness_str:<12} route={route_str:<8} topic={topic_str}")
        return 0

    return 0



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
