# SPDX-License-Identifier: BUSL-1.1
"""agent-mesh/1 CLI. Sends through the bus' own MessageStore.post; claims are decided by the mesh_store projection.

    python mesh_cli.py --from claude-x open  --work W-demo --title "..." [--cite OWNER_ROOT] --to grok
    python mesh_cli.py --from claude-x claim --work W-demo [--lease 1800] --to grok
    python mesh_cli.py --from claude-x post  --work W-demo --kind progress --body-file f.json [--parent ID] [--ev role=path] --to grok
    python mesh_cli.py show --work W-demo        python mesh_cli.py digest [--owner-root R]
    python mesh_cli.py rebuild [--apply]
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import uuid

import agentbus_validate
from bus import _validate_message
from local_cli import open_store
import mesh_store as ms
import mesh_validate as mv

HERE = Path(__file__).resolve().parent
OUTER_K = {"open": "task", "claim": "fyi", "release": "fyi", "assign": "task", "progress": "fyi", "review": "task",
           "verdict": "verdict", "artifact": "fyi", "blocked": "question", "decision-request": "question",
           "done": "report", "cancel": "cancel", "digest": "report"}
NEEDS = {"review": "answer", "decision-request": "answer", "assign": "answer"}


def _sync(store, limits):
    """Bring the projection up to date in one IMMEDIATE transaction (serialised across processes by SQLite)."""
    import bus_remote  # hub mode: the hub rebuilds the projection after each write; it arrives here with the replica
    if bus_remote.active(Path(store.path).parent):
        bus_remote.pull(Path(store.path).parent)
        return
    with store._connection() as db:
        db.execute("BEGIN IMMEDIATE")
        ms.project(db, limits)


@contextmanager
def _read(store):
    db = sqlite3.connect(store.path)
    try:
        ms.ensure_schema(db)
        yield db
    finally:
        db.close()


def _sha(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_body(kind, work, mesh_extra: dict) -> dict:
    mesh = {"p": mv.PROTOCOL, "kind": kind, "work": work, **{k: v for k, v in mesh_extra.items() if v not in (None, [], {})}}
    return {"v": 1, "k": OUTER_K[kind], "th": work, "need": NEEDS.get(kind, "none"), "data": {"mesh": mesh}}


DELIVERY = "steer"  # owner rule: every bus message is sent with explicit steer delivery; no queue option


def send(store, state_dir, sender, recipients, body, root_id, limits):
    text = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    errors = agentbus_validate.validate(text)
    if errors:
        raise ValueError("agent-bus/1 schema: " + "; ".join(errors))
    for recipient in recipients:
        mv.validate(body, sender, recipient)
    ids = [root_id] if len(recipients) == 1 else [f"{root_id}.{r}" for r in recipients]
    for mid, recipient in zip(ids, recipients):
        message = _validate_message({"id": mid, "from": sender, "to": recipient, "body": text, "reply_to": None,
                                     "delivery": DELIVERY}, sender, state_dir)
        store.post(message)
    _sync(store, limits)
    with _read(store) as db:
        copies = {mid: ms.outcome(db, mid) for mid in ids}
    # the first copy decides; the others are recorded as copy:<first> and reported here for transparency
    return {"ids": ids, "outcome": copies[ids[0]], "copies": copies}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="agent-mesh/1")
    ap.add_argument("--state-dir", type=Path, default=Path(_integrity_value('state_directory')))
    ap.add_argument("--from", dest="sender")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("open", "claim", "post"):
        p = sub.add_parser(name)
        p.add_argument("--work", required=True)
        p.add_argument("--to", action="append", required=True, help="recipient address (repeatable; copies share one eid)")
        p.add_argument("--id")
        p.add_argument("--parent", action="append", default=[])
        p.add_argument("--cite")
        if name == "open":
            p.add_argument("--title", required=True)
        if name == "claim":
            p.add_argument("--lease", type=int, default=1800)
            p.add_argument("--resource", action="append", default=[],
                           help="host:<h>, service:<h>/<name>, or file:<h>/<path>; repeatable")
        if name in ("claim", "post"):
            p.add_argument("--presence-until", type=int,
                           help="declared presence epoch; claim/progress only, independent of the work lease")
        if name == "post":
            p.add_argument("--kind", required=True, choices=[k for k in mv.KINDS if k not in ("open", "claim")])
            p.add_argument("--body-file", type=Path)
            p.add_argument("--ev", action="append", default=[], help="role=path (sha256 computed here)")
            p.add_argument("--sup")
    s = sub.add_parser("show"); s.add_argument("--work", required=True)
    s.add_argument("--now", type=int, help="observation epoch for read-only freshness")
    d = sub.add_parser("digest"); d.add_argument("--owner-root")
    d.add_argument("--now", type=int, help="observation epoch for read-only freshness")
    r = sub.add_parser("rebuild"); r.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    try:
        state_dir = a.state_dir.absolute()
        store = open_store(state_dir)
        limits = ms.load_limits(state_dir)
        _sync(store, limits)
        if a.cmd in ("show", "digest"):
            with _read(store) as db:
                out = (ms.show(db, a.work, now=a.now, stale_after_s=limits["stale_after_s"])
                       if a.cmd == "show" else
                       {"digest": ms.digest(db, a.owner_root, now=a.now, stale_after_s=limits["stale_after_s"])})
            if out is None:
                raise ValueError("unknown work node")
        elif a.cmd == "rebuild":
            import bus_remote  # hub mode
            if bus_remote.active(state_dir):
                raise ValueError("bus moved to the hub: mesh rebuild runs on the hub host")
            with store._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                out = ms.rebuild(db, limits, a.apply)
        else:
            if not a.sender:
                raise ValueError("--from is required")
            root = a.id or f"{a.sender}-mesh-{a.cmd if a.cmd != 'post' else a.kind}-{uuid.uuid4().hex[:12]}"
            extra = {"eid": root, "parents": a.parent, "cite": {"owner": a.cite} if a.cite else None}
            if a.cmd == "open":
                kind, extra["body"] = "open", {"title": a.title}
            elif a.cmd == "claim":
                with _read(store) as db:
                    view = ms.show(db, a.work)
                    node = view["node"] if view else None
                if node is None:
                    raise ValueError("unknown work node")
                expiring = node["state"] in ("claimed", "review") and view["freshness"]["expired"]
                if node["state"] != "open" and not expiring:
                    raise ValueError(f"not claimable: state={node['state']} claimant={node['claimant']}")
                kind = "claim"
                extra["claim"] = {"expect": node["version"] + int(expiring), "lease_s": a.lease}
                extra["body"] = {"resources": mv.normalize_resources(a.resource)}
            else:
                kind = a.kind
                extra["body"] = json.loads(a.body_file.read_text(encoding="utf-8")) if a.body_file else {}
                extra["ev"] = [{"role": spec.split("=", 1)[0], "p": spec.split("=", 1)[1], "sha256": _sha(spec.split("=", 1)[1])}
                               for spec in a.ev]
                extra["sup"] = a.sup
            if getattr(a, "presence_until", None) is not None:
                extra.setdefault("body", {})["presence_until"] = a.presence_until
            body = build_body(kind, a.work, extra)
            out = send(store, state_dir, a.sender, a.to, body, root, limits)
            if kind == "claim":
                out["claim"] = "won" if out["outcome"] == "accepted" else "lost:" + out["outcome"].split(":", 1)[-1]
    except (OSError, ValueError, mv.MeshError, sqlite3.Error, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return 0 if not (isinstance(out, dict) and str(out.get("outcome", "accepted")).startswith("rejected")) else 1



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
