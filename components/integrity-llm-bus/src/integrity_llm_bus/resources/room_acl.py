# SPDX-License-Identifier: BUSL-1.1
"""room_acl - the human-operator role (human-*) and its vendor room (room-*) in the LLM bus (agent-bus/1).

Rules are checked in MessageStore.post, in the same transaction as the owner gate:
  * a human-* address writes only to vendors of its room (room-*) and to the owner, never to the main agents;
  * room vendors answer only the human-* address and the owner; they cannot assign work to the main agents;
  * only a human-* address or the owner may write to room vendors;
  * messages from human-* and from room vendors never carry owner-signature fields (own/sig/cert/items):
    a GO from the room is impossible by schema; the only GO is the owner's signature (owner_verify.gate);
  * human-* and room-* addresses cannot be self-registered (reserved; the installer sets them).
This is the bus layer. The hard layer is executing room vendors in a read-only sandbox (OS, database, devices).

The room exists only when the installer enabled it with <state>/room.json:
    {"human": "human-<name>", "vendors": ["room-<name>-<vendor>", ...]}
Without that file the bus behaves as before this layer (the reserved prefixes still apply).
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import json

OWNER = "owner"
HUMAN_PREFIX = "human-"
WORKER_PREFIX = "room-"
ROOM_FILE = "room.json"
RESERVED_PREFIXES = (HUMAN_PREFIX, WORKER_PREFIX)
SIG_KEYS = {"own", "sig", "cert", "items"}


class RoomPolicyError(PermissionError):
    pass


def room_config(state_dir=None) -> dict:
    from pathlib import Path
    try:
        cfg = json.loads((Path(state_dir) / ROOM_FILE).read_text(encoding="utf-8")) if state_dir else None
    except (OSError, ValueError):
        cfg = None
    return cfg if isinstance(cfg, dict) else {}


def addresses(state_dir=None) -> tuple:
    """Room addresses exist only when the installer enabled the room (<state>/room.json)."""
    cfg = room_config(state_dir)
    human = cfg.get("human")
    if not isinstance(human, str) or not human.startswith(HUMAN_PREFIX):
        return ()
    vendors = tuple(v for v in cfg.get("vendors", ()) if isinstance(v, str) and v.startswith(WORKER_PREFIX))
    return (human,) + vendors


def reserved(name: str) -> bool:
    return isinstance(name, str) and name.startswith(RESERVED_PREFIXES)


def role(addr: str) -> str:
    if addr == OWNER:
        return "owner"
    if isinstance(addr, str) and addr.startswith(HUMAN_PREFIX):
        return "human"
    if isinstance(addr, str) and addr.startswith(WORKER_PREFIX):
        return "room-vendor"
    return "agent"


def _has_sig(obj, depth=0) -> bool:
    if depth > 8:
        return True
    if isinstance(obj, dict):
        return bool(SIG_KEYS & set(obj)) or any(_has_sig(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_sig(v, depth + 1) for v in obj)
    return False


def check(message: dict) -> None:
    s, t = message["from"], message["to"]
    rs, rt = role(s), role(t)
    try:
        body = json.loads(message["body"])
    except (ValueError, TypeError):
        body = None
    if rs == "human":
        if rt not in ("room-vendor", "owner"):
            raise RoomPolicyError("a human-* address may write only to room-* vendors or the owner")
        if _has_sig(body):
            raise RoomPolicyError("human-* messages cannot carry owner-signature fields: no GO from this role")
    if rs == "room-vendor":
        if rt not in ("human", "owner"):
            raise RoomPolicyError("room vendors reply only to the human-* address or the owner")
        if _has_sig(body):
            raise RoomPolicyError("room vendor messages cannot carry owner-signature fields")
    if rt == "room-vendor" and rs not in ("human", "owner"):
        raise RoomPolicyError("only the human-* address or the owner may write to room vendors")

if __name__ == "__main__":
    _integrity_require_config()
