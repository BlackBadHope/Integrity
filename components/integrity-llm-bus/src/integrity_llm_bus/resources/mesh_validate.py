# SPDX-License-Identifier: BUSL-1.1
"""agent-mesh/1 envelope validator (data.mesh inside an agent-bus/1 body). Strict: unknown keys are rejected."""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
import re

PROTOCOL = "agent-mesh/1"
KINDS = ("open", "claim", "release", "assign", "progress", "review", "verdict", "artifact",
         "blocked", "decision-request", "done", "cancel", "digest")
ROLES = ("candidate", "patch", "manifest", "log", "report", "bench", "fixture")
VERDICTS = ("PASS", "FAIL", "PARTIAL")
KEYS = {"p", "kind", "work", "eid", "parents", "sup", "claim", "ev", "cite", "body"}
REQUIRED = {"p", "kind", "work"}
WORK_RE = re.compile(r"W-[A-Za-z0-9._:-]{1,120}\Z")
ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
ADDR_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,63}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_BODY = 1536
OWNER = "owner"
RESOURCE_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
MAX_RESOURCES = 16
MAX_RESOURCE_LENGTH = 400


class MeshError(ValueError):
    pass


def resource_parts(resource: str) -> tuple[str, str, str]:
    """Parse a declared ID; host names are case-insensitive, paths/names are exact."""
    if (not isinstance(resource, str) or not resource or len(resource) > MAX_RESOURCE_LENGTH
            or resource != resource.strip() or any(ord(c) < 32 or ord(c) == 127 for c in resource)):
        raise MeshError("invalid resource string")
    kind, separator, value = resource.partition(":")
    if not separator or kind not in ("host", "service", "file"):
        raise MeshError("resource must be host:<h>, service:<h>/<name>, or file:<h>/<path>")
    if kind == "host":
        host, tail = value, ""
    else:
        host, separator, tail = value.partition("/")
        if not separator or not tail or not tail.strip():
            raise MeshError("service/file resource needs a host and non-empty name/path")
    if not RESOURCE_HOST_RE.fullmatch(host):
        raise MeshError("invalid resource host")
    return kind, host.lower(), tail


def normalize_resources(resources) -> list[str]:
    if not isinstance(resources, list) or len(resources) > MAX_RESOURCES:
        raise MeshError(f"resources must be a list of at most {MAX_RESOURCES} strings")
    normalized = []
    for item in resources:
        kind, host, tail = resource_parts(item)
        normalized.append(f"{kind}:{host}" + (f"/{tail}" if kind != "host" else ""))
    if len(set(normalized)) != len(normalized):
        raise MeshError("duplicate resource")
    return sorted(normalized)


def _id(value, what):
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise MeshError(f"invalid {what}")
    return value


def mesh_of(body: dict) -> dict | None:
    """The data.mesh object of an agent-bus/1 body, or None when the message is not a mesh message."""
    data = body.get("data") if isinstance(body, dict) else None
    return data.get("mesh") if isinstance(data, dict) and "mesh" in data else None


def validate(body: dict, sender: str, recipient: str) -> dict:
    """Validate an agent-bus/1 body carrying data.mesh. Returns the mesh dict or raises MeshError."""
    mesh = mesh_of(body)
    if not isinstance(mesh, dict):
        raise MeshError("data.mesh must be an object")
    if OWNER in (sender, recipient):
        raise MeshError("the owner is never part of agent-mesh")
    if set(mesh) - KEYS or REQUIRED - set(mesh):
        raise MeshError("data.mesh keys: required p, kind, work; allowed " + ", ".join(sorted(KEYS)))
    if mesh["p"] != PROTOCOL:
        raise MeshError("p must be agent-mesh/1")
    kind = mesh["kind"]
    if kind not in KINDS:
        raise MeshError("unknown kind")
    if not isinstance(mesh["work"], str) or not WORK_RE.fullmatch(mesh["work"]):
        raise MeshError("invalid work id")
    if body.get("th") != mesh["work"]:
        raise MeshError("outer th must equal data.mesh.work")
    if mesh.get("eid") is not None:
        _id(mesh["eid"], "eid")
    parents = mesh.get("parents", [])
    if not isinstance(parents, list) or len(parents) > 8:
        raise MeshError("parents must be a list of at most 8 ids")
    for parent in parents:
        _id(parent, "parent")
    if mesh.get("sup") is not None:
        _id(mesh["sup"], "sup")
    claim = mesh.get("claim")
    if kind == "claim":
        if not isinstance(claim, dict) or set(claim) != {"expect", "lease_s"}:
            raise MeshError("claim needs {expect, lease_s}")
        if not isinstance(claim["expect"], int) or isinstance(claim["expect"], bool) or claim["expect"] < 0:
            raise MeshError("claim.expect must be a non-negative integer")
        if not isinstance(claim["lease_s"], int) or isinstance(claim["lease_s"], bool) or not 60 <= claim["lease_s"] <= 7200:
            raise MeshError("claim.lease_s must be 60..7200")
    elif claim is not None:
        raise MeshError("claim is only allowed on kind=claim")
    ev = mesh.get("ev", [])
    if not isinstance(ev, list) or len(ev) > 16:
        raise MeshError("ev must be a list of at most 16 items")
    for item in ev:
        if not isinstance(item, dict) or set(item) != {"role", "p", "sha256"}:
            raise MeshError("ev items are {role, p, sha256}")
        if item["role"] not in ROLES or not isinstance(item["p"], str) or not item["p"] or len(item["p"]) > 400:
            raise MeshError("invalid ev role or path")
        if not isinstance(item["sha256"], str) or not SHA_RE.fullmatch(item["sha256"]):
            raise MeshError("ev sha256 must be 64 lowercase hex")
    candidates = [item for item in ev if item["role"] == "candidate"]
    if len(candidates) > 1:
        raise MeshError("at most one candidate per message")
    cite = mesh.get("cite")
    if cite is not None:
        if not isinstance(cite, dict) or set(cite) != {"owner"}:
            raise MeshError("cite must be {owner: <owner root id>}")
        _id(cite["owner"], "cite.owner")
    payload = mesh.get("body", {})
    if not isinstance(payload, dict):
        raise MeshError("body must be an object")
    if "resources" in payload:
        if kind != "claim":
            raise MeshError("body.resources is only allowed on claim")
        normalize_resources(payload["resources"])
    if "presence_until" in payload:
        if kind not in ("claim", "progress"):
            raise MeshError("body.presence_until is only allowed on claim/progress")
        until = payload["presence_until"]
        if isinstance(until, bool) or not isinstance(until, int) or not 0 <= until <= 2**63 - 1:
            raise MeshError("presence_until must be a non-negative SQLite integer epoch")
    if len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_BODY:
        raise MeshError(f"body exceeds {MAX_BODY} bytes")
    if kind in ("review", "verdict"):
        if payload.get("verdict") not in VERDICTS or not isinstance(payload.get("findings"), list):
            raise MeshError("review/verdict body needs verdict PASS|FAIL|PARTIAL and findings[]")
        if not candidates:
            raise MeshError("review/verdict must name the reviewed candidate sha in ev (role=candidate)")
    if kind == "decision-request":
        for field in ("text", "impact", "rollback"):
            if not isinstance(payload.get(field), str) or not payload[field].strip():
                raise MeshError(f"decision-request body needs {field}")
        if not isinstance(payload.get("sha256"), str) or not SHA_RE.fullmatch(payload["sha256"]):
            raise MeshError("decision-request body needs sha256 of the exact text/artifact")
        options = payload.get("options", ["approve", "reject", "defer"])
        if not isinstance(options, list) or not options or set(options) - {"approve", "reject", "defer"}:
            raise MeshError("decision-request options are a subset of approve, reject, defer")
    if kind == "assign":
        target = payload.get("for")
        if not isinstance(target, str) or not ADDR_RE.fullmatch(target) or target == OWNER:
            raise MeshError("assign body needs for=<agent address>")
    if kind == "open" and not isinstance(payload.get("title", ""), str):
        raise MeshError("open body title must be a string")
    return mesh

if __name__ == "__main__":
    _integrity_require_config()
