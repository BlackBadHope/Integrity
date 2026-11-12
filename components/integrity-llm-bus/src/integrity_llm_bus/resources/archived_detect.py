# SPDX-License-Identifier: BUSL-1.1
"""Detect Codex recipients whose thread was archived and tell the sender at once.

Archived = rollout transcript exists only under ~/.codex/archived_sessions.
Instead of an opaque OSError/unknown batch, the relay marks the batch
`recipient_archived` (nothing sent), posts a bus notice back to each sender
(reply_to = original id, so the original leaves the pending queue) and records
the address in state/archived-recipients.json.

Design note: the notice is agent-bus/1 k=fyi and comes from the reserved system sender
SYSTEM_SENDER ("bus-relay"), never from the archived address (no impersonation). It carries no
reply_to; the original id goes in data.re and the original message stays pending (visible in
queue as relay_state=recipient_archived). bus-relay needs no registry entry (the relay posts
through MessageStore directly); agent_registry reserves the name so nobody can register it, and
nobody can address it (replies to bus-relay are rejected as unknown recipient).
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
import os
import time
from pathlib import Path

STATUS_FILE = "archived-recipients.json"
SYSTEM_SENDER = "bus-relay"


def codex_home() -> Path:
    return Path(os.environ.get("AGENTBUS_CODEX_HOME") or (Path.home() / ".codex"))


def _has(root: Path, thread_id: str) -> bool:
    return root.is_dir() and any(root.glob(f"**/rollout-*-{thread_id}.jsonl"))


def thread_archived(thread_id: str | None, home: Path | None = None) -> bool:
    if not thread_id:
        return False
    home = home or codex_home()
    return _has(home / "archived_sessions", thread_id) and not _has(home / "sessions", thread_id)


def load_status(state_dir: Path) -> dict:
    path = state_dir / STATUS_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and isinstance(data.get("archived"), dict) else {"version": 1, "archived": {}}
    except (OSError, ValueError):
        return {"version": 1, "archived": {}}


def mark(state_dir: Path, address: str, thread_id: str) -> dict:
    data = load_status(state_dir)
    entry = data["archived"].get(address) or {"thread": thread_id, "since": int(time.time())}
    entry["last_seen"] = int(time.time())
    data["archived"][address] = entry
    tmp = state_dir / (STATUS_FILE + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, state_dir / STATUS_FILE)
    return entry


def unmark_if_live(state_dir: Path, address: str) -> None:
    data = load_status(state_dir)
    if data["archived"].pop(address, None) is not None:
        tmp = state_dir / (STATUS_FILE + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, state_dir / STATUS_FILE)


def notify_senders(store, address: str, thread_id: str, messages: list[dict]) -> list[str]:
    """One fyi notice per original message from SYSTEM_SENDER; idempotent via deterministic id."""
    posted = []
    for m in messages:
        if m.get("from") in (address, SYSTEM_SENDER):
            continue
        nid = ("relay-archived-" + m["id"])[:120]
        body = json.dumps({"v": 1, "k": "fyi", "th": "BUS-DELIVERY", "need": "none", "st": "FAIL",
                           "note": f"recipient_archived: {address} is archived; {m['id']} not delivered. Readdress to a live thread."[:200],
                           "data": {"src": "relay", "re": m["id"], "delivery_status": "recipient_archived",
                                    "recipient": address, "thread": thread_id}},
                          ensure_ascii=True, separators=(",", ":"))
        try:
            store.post({"id": nid, "from": SYSTEM_SENDER, "to": m["from"], "body": body, "reply_to": None})
            posted.append(nid)
        except (ValueError, FileExistsError):
            pass
    return posted

if __name__ == "__main__":
    _integrity_require_config()
