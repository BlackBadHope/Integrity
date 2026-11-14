"""owner-rule/v1 selector for the admission capsule (stand build, Ultima Memory Core).

Pure functions, no I/O. Index: latest version per rule_id, superseded versions dropped.
Selection: `always` standing rules first (capped), then trigger matches by weight
(hosts 3, tools 3, subsystems 2, keyword 1), RU+EN keywords with a crude RU stem.
"""
from __future__ import annotations

import fnmatch
import json
import re
from typing import Any

PROTOCOL = "ultima-memory-core/owner-rules-block/v1"
WORD_RE = re.compile(r"[0-9a-zа-яё][0-9a-zа-яё._:*/-]*", re.IGNORECASE)
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _stem(word: str) -> str:
    w = word.lower().strip(".,:;!?()[]{}\"'")
    if re.search(r"[а-яё]", w) and len(w) >= 6:
        return w[:5]
    if len(w) >= 7:
        return w[:6]
    return w


def build_rule_index(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """records: owner-rule details (v1 fields) each with event_id. Returns active latest versions."""
    superseded: set[tuple[str, int]] = set()
    for r in records:
        sup = r.get("supersedes") or {}
        if sup.get("rule_id") and sup.get("version") is not None:
            superseded.add((sup["rule_id"], int(sup["version"])))
    latest: dict[str, dict[str, Any]] = {}
    for r in records:
        if r.get("rule_kind", "behavior") != "behavior" or r.get("state") == "superseded":
            continue
        key = (r["rule_id"], int(r.get("version", 1)))
        if key in superseded:
            continue
        cur = latest.get(r["rule_id"])
        if cur is None or int(r.get("version", 1)) > int(cur.get("version", 1)):
            latest[r["rule_id"]] = r
    return [latest[k] for k in sorted(latest)]


def _score(rule: dict[str, Any], stems: set[str], words: set[str], ips: list[str],
           hosts: list[str], tools: list[str]) -> int:
    t = rule.get("triggers") or {}
    score = 0
    targets = ips + [h.lower() for h in hosts]
    if any(fnmatch.fnmatch(x, pat.lower()) for pat in t.get("hosts", []) for x in targets):
        score += 3
    tool_words = words | {x.lower() for x in tools}
    if any(tl.lower() in tool_words or any(w.startswith(tl.lower()) for w in tool_words)
           for tl in t.get("tools", [])):
        score += 3
    if any(_stem(s) in stems for s in t.get("subsystems", [])):
        score += 2
    kws = list(t.get("keywords_ru", [])) + list(t.get("keywords_en", []))
    score += sum(1 for k in kws if all(_stem(p) in stems for p in k.split()))
    return score


def select_owner_rules(index: list[dict[str, Any]], query: str, *, hosts: list[str] | None = None,
                       tools: list[str] | None = None, max_rules: int = 8, max_bytes: int = 2048,
                       max_always: int = 4, lang: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    words = {w.lower() for w in WORD_RE.findall(query or "")}
    stems = {_stem(w) for w in words}
    ips = IP_RE.findall(query or "")
    lang = lang or ("ru" if re.search(r"[а-яё]", query or "", re.IGNORECASE) else "en")
    scored = []
    for r in index:
        s = _score(r, stems, words, ips, hosts or [], tools or [])
        always = bool(r.get("always")) and r.get("scope", "standing") == "standing"
        scored.append((s, always, int(r.get("violations", 0)), r["rule_id"], r))
    matched = sorted([x for x in scored if x[0] > 0], key=lambda x: (-x[0], -x[2], x[3]))
    always = sorted([x for x in scored if x[1] and x[0] == 0], key=lambda x: (-x[2], x[3]))[:max_always]
    # matched rules outrank pure-always rules; always fill only leftover slots
    order = matched + always
    out, used, dropped = [], 0, 0
    for s, alw, _v, rid, r in order:
        if len(out) >= max_rules:
            dropped += 1
            continue
        item = {"rule_id": rid, "version": int(r.get("version", 1)), "event_id": r.get("event_id"),
                "rule": r.get(f"rule_{lang}") or r.get("rule_en") or r.get("rule_ru", ""),
                "how": str(r.get("how", ""))[:240], "mode": (r.get("enforced_by") or [{}])[0].get("mode", "text"),
                "why": "always" if (alw and s == 0) else f"match:{s}"}
        b = len(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        if used + b > max_bytes:
            dropped += 1
            continue
        out.append(item)
        used += b
    receipt = {"protocol": PROTOCOL, "rules_considered": len(index), "rules_selected": len(out),
               "rules_truncated": dropped, "bytes": used, "lang": lang}
    return out, receipt


_INDEX_CACHE: dict[str, Any] = {}


def live_rules_request(source: dict[str, Any]) -> dict[str, Any] | None:
    """Server opt-in: INTEGRITY_OWNER_RULES=on and INTEGRITY_OWNER_RULES_INDEX=<json file>.

    Any problem (flag off, file missing, bad JSON) returns None, so admission is unchanged.
    The index file carries {"owner_rules": [owner-rule/v1 records]}; its sha256 is recorded in Seed.
    """
    import hashlib
    import os
    if os.environ.get("INTEGRITY_OWNER_RULES", "off") != "on":
        return None
    path = os.environ.get("INTEGRITY_OWNER_RULES_INDEX", "")
    try:
        with open(path, "rb") as stream:
            raw = stream.read()
        digest = hashlib.sha256(raw).hexdigest()
        if _INDEX_CACHE.get("digest") != digest:
            records = json.loads(raw.decode("utf-8")).get("owner_rules") or []
            _INDEX_CACHE.update(digest=digest, index=build_rule_index(records))
        aux = source.get("auxiliary_recall") if isinstance(source.get("auxiliary_recall"), dict) else {}
        rec = source.get("recall") if isinstance(source.get("recall"), dict) else {}
        terms = (aux.get("terms") if aux else None) or rec.get("terms") or []
        query = " ".join(str(t) for t in terms if isinstance(t, (str, int)))
        return {"enabled": True, "index": _INDEX_CACHE["index"], "query": query,
                "max_rules": int(os.environ.get("INTEGRITY_OWNER_RULES_MAX", "8")),
                "max_bytes": int(os.environ.get("INTEGRITY_OWNER_RULES_BYTES", "2048"))}
    except Exception:  # noqa: BLE001 - opt-in rules index: any fault means "no rules", never a failed admission
        return None
