#!/usr/bin/python3 -I
# SPDX-License-Identifier: BUSL-1.1
"""bus_quota_report - usage per account / subscription label from the bus journal (no bodies, no secrets).
  bus_quota_report.py <journal_dir> [--since YYYY-MM-DD]
Per label: requests, sends, body bytes, refusals (by reason), vendor keys. Verifies the journal chain first.
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import collections, glob, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bus_journal as J
d = sys.argv[1]; since = sys.argv[sys.argv.index("--since") + 1] if "--since" in sys.argv else ""
v = J.verify(d)
if not v["ok"]:
    print(json.dumps({"error": "journal chain broken", **v})); sys.exit(2)
acc = collections.defaultdict(lambda: {"requests": 0, "sends": 0, "body_bytes": 0, "denied": collections.Counter(), "keys": set()})
rt = collections.defaultdict(lambda: {"reports": 0, "with_route": 0, "routes": collections.Counter()})
rv = collections.defaultdict(lambda: {"reports": 0, "with_route": 0})
for f in sorted(glob.glob(os.path.join(d, "journal-*.jsonl"))):
    for line in open(f, encoding="utf-8"):
        r = json.loads(line)
        if r.get("ts", "") < since or "principal" not in r:
            continue
        a = acc[r.get("account") or "(no-account)"]
        a["requests"] += 1; a["keys"].add(r.get("principal"))
        if r.get("op") == "send" and r.get("verdict") == "ok":
            a["sends"] += 1; a["body_bytes"] += r.get("body_bytes", 0)
            if r.get("reply_to"):                      # a reply = a vendor report; route metric per key
                k = rt[r.get("principal")]; k["reports"] += 1; v = rv[r.get("vendor") or "?"]; v["reports"] += 1
                if r.get("route_used") and r["route_used"] != "none":
                    k["with_route"] += 1; k["routes"][r["route_used"]] += 1; v["with_route"] += 1
        if r.get("verdict") != "ok":
            a["denied"][r.get("reason", r.get("verdict"))[:60]] += 1
uro = {k: {"reports": x["reports"], "with_route": x["with_route"], "share": round(x["with_route"] / x["reports"], 3) if x["reports"] else None,
           "routes": dict(x["routes"])} for k, x in rt.items()}
uv = {k: {**x, "share": round(x["with_route"] / x["reports"], 3) if x["reports"] else None} for k, x in rv.items()}
print(json.dumps({"journal": v, "uroboros_by_vendor": uv, "uroboros_by_key": uro, "accounts": {k: {**x, "denied": dict(x["denied"]), "keys": sorted(map(str, x["keys"]))} for k, x in acc.items()}},
                 ensure_ascii=False, indent=1))
