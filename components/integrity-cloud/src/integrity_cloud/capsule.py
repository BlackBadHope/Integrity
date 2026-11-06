"""Read-only context capsules: the only memory a cloud agent receives.

A capsule is built on the trusted side from selected memory records. Only
``uid``, ``kind``, ``summary`` and ``tags`` survive; anything secret-like, any
non-documentation IP address and any owner-supplied denied literal refuses the
build. The capsule carries a random nonce: only whoever launched the task
knows it, so a journal that echoes it is bound to that launch.
"""
from __future__ import annotations

import json
import secrets
from pathlib import Path

from .journal import MAX_SUMMARY, MAX_TAG, MAX_TAGS, canonical, digest, utc_now
from .scan import scan

CAPSULE_FORMAT = "integrity-cloud-capsule/v1"
DEFAULT_MAX_ITEMS = 50
DEFAULT_MAX_BYTES = 32 * 1024


class CapsuleError(ValueError):
    pass


def _items(source: object) -> list[dict]:
    if isinstance(source, dict):
        for key in ("events", "items", "records"):
            if isinstance(source.get(key), list):
                return source[key]
        raise CapsuleError("input object has no events/items/records list")
    if isinstance(source, list):
        return source
    raise CapsuleError("input must be a JSON list or an object with an events list")


def _project(item: dict) -> dict:
    uid = item.get("event_uid") or item.get("uid") or item.get("id")
    summary = item.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise CapsuleError("every item needs a summary")
    tags = [str(t)[:MAX_TAG] for t in (item.get("tags") or [])][:MAX_TAGS]
    return {"uid": None if uid is None else str(uid), "kind": str(item.get("kind") or "note"),
            "summary": summary.strip()[:MAX_SUMMARY], "tags": tags}


def seal_capsule(body: dict) -> dict:
    body = {k: v for k, v in body.items() if k != "sha256"}
    return {**body, "sha256": digest(canonical(body))}


def build(source: object, *, purpose: str, max_items: int = DEFAULT_MAX_ITEMS,
          max_bytes: int = DEFAULT_MAX_BYTES, deny_literals: tuple[str, ...] = ()) -> dict:
    items = [_project(i) for i in _items(source) if isinstance(i, dict)]
    if not items:
        raise CapsuleError("no items selected")
    if len(items) > max_items:
        raise CapsuleError(f"{len(items)} items exceed --max-items {max_items}; select fewer")
    capsule = seal_capsule({"format": CAPSULE_FORMAT, "created_utc": utc_now(),
                            "nonce": secrets.token_hex(16), "purpose": purpose.strip(),
                            "read_only": True, "items": items})
    findings = scan(capsule, network=True, deny_literals=deny_literals)
    if findings:
        where = ", ".join(sorted({f"{f['path']}:{f['finding']}" for f in findings}))
        raise CapsuleError("refused: capsule would leak private content: " + where)
    if len(canonical(capsule)) > max_bytes:
        raise CapsuleError(f"capsule exceeds {max_bytes} bytes; select fewer items")
    return capsule


def load(path: Path) -> dict:
    capsule = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(capsule, dict) or capsule.get("format") != CAPSULE_FORMAT:
        raise CapsuleError("not an integrity-cloud capsule")
    if seal_capsule(capsule)["sha256"] != capsule.get("sha256"):
        raise CapsuleError("capsule digest mismatch: it was edited after it was built")
    if not isinstance(capsule.get("nonce"), str) or len(capsule["nonce"]) != 32:
        raise CapsuleError("capsule nonce is missing")
    return capsule
