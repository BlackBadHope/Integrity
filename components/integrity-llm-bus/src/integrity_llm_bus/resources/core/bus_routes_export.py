#!/usr/bin/python3 -I
# SPDX-License-Identifier: BUSL-1.1
"""bus_routes_export - route catalog for the bus. Source of truth: the action-log Seed; format uroboros-route/v1.

Runs as the action-log user (reads the Seed read-only) from a timer. It uses the INSTALLED
uroboros_routes.py module of integrity-action-log (the same one that produces ROUTE hints at admission)
and introduces no format of its own. Only safe fields enter the catalog: route_id, version, status, title,
triggers, scope, run, params names, safety, verified_at, event_id; params carry names and descriptions.
Records where validate_route_record/looks_secret detect a secret are dropped.
The catalog is a list of pseudo-events {id, ts_utc, details.uroboros_route}, so the bus daemon can call
build_known_routes(terms, catalog), the same matcher as admission. File mode 0444, atomic replace.

Paths: ROUTES_SEED, ROUTES_MODULE, ROUTES_OUT (environment) or the configuration values
routes_seed, routes_module, routes_catalog; ROUTES_SOURCE or routes_source_label names the catalog source.
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import hashlib, importlib.util, json, os, sqlite3, sys, tempfile, time

SRC = os.environ.get("ROUTES_SEED") or _integrity_value('routes_seed')
MOD = os.environ.get("ROUTES_MODULE") or _integrity_value('routes_module')
OUT = os.environ.get("ROUTES_OUT") or _integrity_value('routes_catalog')
SOURCE = os.environ.get("ROUTES_SOURCE") or _integrity_value('routes_source_label')
SAFE = ("route_id", "version", "status", "title", "triggers", "scope", "run", "safety", "verified_at")

spec = importlib.util.spec_from_file_location("uroboros_routes", MOD); U = importlib.util.module_from_spec(spec); spec.loader.exec_module(U)
db = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True)
rows = db.execute("SELECT id, ts_utc, details FROM events WHERE details LIKE '%uroboros_route%' ORDER BY id").fetchall()
latest, dropped = {}, 0
for eid, ts, det in rows:
    try:
        details = json.loads(det or "{}")
    except ValueError:
        continue
    recs = []
    if isinstance(details.get("uroboros_route"), dict):
        recs.append(details["uroboros_route"])
    if isinstance(details.get("uroboros_routes"), list):
        recs.extend(r for r in details["uroboros_routes"][:U.MAX_BUNDLE_ROUTES] if isinstance(r, dict))
    for rec in recs:
        try:
            r = U.validate_route_record(rec)
        except Exception:
            dropped += 1; continue
        safe = {k: r[k] for k in SAFE if k in r}
        if "params" in r:
            safe["params"] = dict(r["params"])                    # names and descriptions (already checked for secrets by the validator)
        text = " ".join(str(v) for v in safe.values())
        if U.looks_secret(text):
            dropped += 1; continue
        key = safe.get("route_id")
        prev = latest.get(key)
        if prev is None or int(safe.get("version", 0)) >= int(prev["details"]["uroboros_route"].get("version", 0)):
            latest[key] = {"id": eid, "ts_utc": ts, "details": {"uroboros_route": {"format": U.ROUTE_FORMAT, **safe}}}
catalog = sorted(latest.values(), key=lambda e: e["id"])
doc = {"format": "llm-bus-routes/v1", "source": SOURCE, "route_format": U.ROUTE_FORMAT,
       "module_sha256": hashlib.sha256(open(MOD, "rb").read()).hexdigest(), "seed_max_event_id": rows[-1][0] if rows else 0,
       "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "routes": catalog, "dropped": dropped}
d = os.path.dirname(OUT); fd, tmp = tempfile.mkstemp(dir=d, prefix=".catalog.")
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False)
os.chmod(tmp, 0o444); os.replace(tmp, OUT)
print(json.dumps({"routes": len(catalog), "dropped": dropped, "seed_max_event_id": doc["seed_max_event_id"]}))
