# SPDX-License-Identifier: BUSL-1.1
"""agent-bus/1 body validator (stdlib only, mirrors agent-bus-1.schema.json).

validate(text) -> list of "path: problem" strings; empty list means valid.
CLI: python agentbus_validate.py <body-file>  -> exit 0 if valid, 2 with one error per line otherwise.
Nothing is stripped or repaired: an invalid body is rejected as a whole.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

from datetime import datetime
import json
import math
import re
import sys
from pathlib import Path

MAX_BODY_BYTES = 4096
MAX_DEPTH = 32  # body object = level 1; generous for data{}, small enough to stop pathological input
KINDS = {"task", "report", "verdict", "ack", "question", "decision", "cancel", "fyi"}
NEEDS = {"none", "ack", "answer", "action", "go"}
STATUSES = ("PASS", "FAIL", "UNKNOWN", "NOT_RUN", "PARTIAL", "BLOCKED")
TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
SHA256 = re.compile(r"[0-9a-f]{64}")
DEADLINE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:\d{2})")
CHECK = re.compile(r"(%s)(:[\x20-\x7e]{1,160})?" % "|".join(STATUSES))
TOP_KEYS = {"v", "k", "th", "need", "st", "sup", "by", "dec", "chk", "ev", "ptr", "note", "data"}
DEC_KEYS = {"id", "src", "by", "ts", "text"}


def _fileref(value, path, errors):
    if not isinstance(value, dict):
        errors.append(f"{path}: must be an object {{p, sha256}}")
        return
    extra = set(value) - {"p", "sha256"}
    if extra:
        errors.append(f"{path}: unknown keys {sorted(extra)}")
    p = value.get("p")
    if not isinstance(p, str) or not 1 <= len(p) <= 400:
        errors.append(f"{path}.p: required string, 1-400 chars")
    sha = value.get("sha256")
    if not isinstance(sha, str) or not SHA256.fullmatch(sha):
        errors.append(f"{path}.sha256: required full lowercase 64-hex sha256")


class _StrictJsonError(ValueError):
    pass


def _no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise _StrictJsonError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _no_constants(name):
    raise _StrictJsonError(f"non-standard JSON constant {name}")


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise _StrictJsonError(f"number {text} is not finite")
    return value


def _structure_error(value, path="$"):
    """First structural problem: nesting deeper than MAX_DEPTH, or an unpaired UTF-16 surrogate
    (\\ud800 escapes) in a key or string. Iterative, so no depth can overflow the stack here."""
    stack = [(value, path, 1)]
    while stack:
        item, where, depth = stack.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                return f"{where}: unpaired UTF-16 surrogate; text must be valid Unicode"
        elif isinstance(item, (dict, list)):
            if depth > MAX_DEPTH:
                return f"{where}: nesting deeper than {MAX_DEPTH} levels"
            if isinstance(item, dict):
                for key, child in item.items():
                    stack.append((key, where, depth))
                    stack.append((child, f"{where}.{key}", depth + 1))
            else:
                stack.extend((child, f"{where}[{i}]", depth + 1) for i, child in enumerate(item))
    return None


def _valid_time(value):
    if not (isinstance(value, str) and DEADLINE.fullmatch(value)):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _enum(body, key, allowed):
    """Membership only for strings: an array or object must be rejected, not raise TypeError."""
    value = body.get(key)
    return isinstance(value, str) and value in allowed


def _ascii(value, path, errors):
    if isinstance(value, str) and not value.isascii():
        errors.append(f"{path}: non-ASCII text is allowed only in note, dec.text, paths and data")


def validate(text: str) -> list[str]:
    errors: list[str] = []
    size = len(text.encode("utf-8"))
    if size > MAX_BODY_BYTES:
        return [f"$: body is {size} bytes > {MAX_BODY_BYTES}; put the content in a file and send ptr {{p, sha256}}"]
    try:
        body = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants,
                          parse_float=_finite_float)
    except _StrictJsonError as exc:
        return [f"$: {exc}"]
    except ValueError as exc:
        return [f"$: not valid JSON ({getattr(exc, 'msg', exc)} at char {getattr(exc, 'pos', '?')})"]
    except RecursionError:
        return ["$: nesting too deep"]
    if not isinstance(body, dict):
        return ["$: body must be a JSON object"]
    structure = _structure_error(body)
    if structure:
        return [structure]
    extra = set(body) - TOP_KEYS
    if extra:
        errors.append(f"$: unknown keys {sorted(extra)}; put kind-specific fields under data")
    if type(body.get("v")) is not int or body["v"] != 1:  # bool is an int subclass: true must not pass as 1
        errors.append("$.v: required, must be the integer 1")
    if not _enum(body, "k", KINDS):
        errors.append(f"$.k: required, one of {sorted(KINDS)}")
    for key in ("th", "sup"):
        if key in body and not (isinstance(body[key], str) and TOKEN.fullmatch(body[key])):
            errors.append(f"$.{key}: token [A-Za-z0-9._:-]{{1,128}}")
    if "need" in body and not _enum(body, "need", NEEDS):
        errors.append(f"$.need: one of {sorted(NEEDS)}")
    if "st" in body and not _enum(body, "st", STATUSES):
        errors.append(f"$.st: one of {list(STATUSES)}")
    if "by" in body and not _valid_time(body["by"]):
        errors.append("$.by: real ISO time with zone, e.g. 2026-10-22T12:00+03:00")
    if "dec" in body:
        dec = body["dec"]
        if not isinstance(dec, dict):
            errors.append("$.dec: must be an object")
        else:
            if set(dec) - DEC_KEYS:
                errors.append(f"$.dec: unknown keys {sorted(set(dec) - DEC_KEYS)}")
            if not (isinstance(dec.get("src"), str) and 1 <= len(dec["src"]) <= 200):
                errors.append("$.dec.src: required string, 1-200 chars")
            if "id" in dec and not (isinstance(dec["id"], str) and TOKEN.fullmatch(dec["id"])):
                errors.append("$.dec.id: token")
            if "text" in dec and not (isinstance(dec["text"], str) and len(dec["text"]) <= 500):
                errors.append("$.dec.text: string <= 500 chars")
            if "by" in dec and not (isinstance(dec["by"], str) and len(dec["by"]) <= 64):
                errors.append("$.dec.by: string <= 64 chars")
            if "ts" in dec and not (isinstance(dec["ts"], str) and len(dec["ts"]) <= 40):
                errors.append("$.dec.ts: string <= 40 chars")
            for key in ("src", "by", "ts"):
                _ascii(dec.get(key), f"$.dec.{key}", errors)
    if "chk" in body:
        chk = body["chk"]
        if not isinstance(chk, dict):
            errors.append("$.chk: must be an object name -> STATUS[:detail]")
        else:
            for name, value in chk.items():
                if not TOKEN.fullmatch(name):
                    errors.append(f"$.chk.{name}: name must be a token")
                if not (isinstance(value, str) and CHECK.fullmatch(value)):
                    errors.append(f"$.chk.{name}: STATUS or STATUS:detail (ASCII, detail <= 160)")
    if "ev" in body:
        ev = body["ev"]
        if not isinstance(ev, list) or len(ev) > 8:
            errors.append("$.ev: array of at most 8 {p, sha256}; prefer one manifest")
        else:
            for i, item in enumerate(ev):
                _fileref(item, f"$.ev[{i}]", errors)
    if "ptr" in body:
        _fileref(body["ptr"], "$.ptr", errors)
    if "note" in body and not (isinstance(body["note"], str) and len(body["note"]) <= 200):
        errors.append("$.note: string <= 200 chars")
    if "data" in body and not isinstance(body["data"], dict):
        errors.append("$.data: must be an object")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: agentbus_validate.py <body-file>", file=sys.stderr)
        return 64
    errors = validate(Path(argv[1]).read_text(encoding="utf-8"))
    for error in errors:
        print(error)
    return 2 if errors else 0



if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
