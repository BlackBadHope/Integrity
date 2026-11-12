#!/usr/bin/env bash
# Uroboros: run a compiled route in one call. Usage: uroboros-run.sh <route-id> key=value ...
#           uroboros-run.sh list [text]  - list compiled routes; filter by id, target host or summary words
# Read routes run directly; write routes need --apply and INTEGRITY_ROUTE_WRITE_GO=<route-id> (operator GO).
# Routes are read from INTEGRITY_COMPILED_ROUTES (or uroboros.compiled_routes in INTEGRITY_GUARDS_CONFIG).
py="${PYTHON:-python3}"
if [ "${1:-}" = "list" ] || [ "${1:-}" = "find" ]; then
  shift; exec "$py" -m integrity_guards uroboros list "$@"
fi
exec "$py" -m integrity_guards uroboros run "$@"
