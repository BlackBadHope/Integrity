# Uroboros: procedural memory

[Documentation](README.md) · [Project README](../README.md)

Uroboros lets an agent reuse a path that already worked instead of
rediscovering it. A completed, verified piece of work becomes a **route**. When
a later agent starts a turn whose intent matches that route, Integrity offers
it in the admission capsule. A route is guidance to check against current
state. It is never permission to act.

## What ships

| Piece | Status | Where |
|---|---|---|
| Known routes at admission | **in source, unreleased** (Action Log) | `uroboros_routes.py`; Action Log `/api/mind` |
| Route record format `uroboros-route/v1` | **in source, unreleased** | this page |
| Signed route-memory protocol (Toolzs a1–a14) | alpha library with public tests, no caller yet | `src/integrity_guardian/uroboros_toolzs_*`, `tests/test_uroboros_toolzs_*` |
| Route record validation, secret guard, `draft`/`validate` CLI | **in source, unreleased** | `python -m integrity_guardian.uroboros_routes` |
| Route checks (`uroboros-route-check/v1`) and repair by new version | **in source, unreleased** | `check` CLI; retrieval |
| Example route catalogue and contribution rules | **in source** | [`examples/uroboros-routes`](../examples/uroboros-routes/README.md) |
| Signed, cursor-pinned Toolzs library for external contributions | roadmap | — |

### Known routes at admission

On every `/api/mind` projection, the Action Log does the following:

1. It derives search terms from the owner's prompt with the same
   wrapper-stripping as auxiliary recall. Harness metadata such as
   `<system-reminder>` blocks, bus notices and attachment carriers is not used
   for search.
2. It selects at most three routes from the admitted Seed snapshot.
3. When the capsule door is `admitted`, it adds them to the capsule's
   `learned_hints`.

Each hint ends with the one call that returns the whole route, for example
`steps: read_events after_id=8818`. The capsule text also carries a
`KNOWN ROUTES` block, right after the lead, with up to three runnable steps
per route.

Every client therefore gets the routes with no client change: Claude, Codex,
Windows, Linux and cloud seats all read the same capsule. A closed door
(undeclared or expired session) projects the routes for custody but never
speaks them.

The hint line looks like this:

```text
ROUTE #8706 verified gpon-migration-vlan v3 2026-11-01: Move a subscriber to GPON… [re-check; not authority]
```

The structured projection is `known_routes` in the Mind response. It is
covered by the projection digest. It has the protocol
`integrity-guardian/uroboros-known-routes/v1`, `authority: "none"` and
`production_authority: false`.

## Where routes come from

**Explicit routes.** An agent appends an ordinary Seed event (for example
with `integrity_append_event`) whose details carry `uroboros_route`:

```json
{
  "uroboros_route": {
    "format": "uroboros-route/v1",
    "route_id": "gpon-migration-vlan",
    "version": 3,
    "status": "verified",
    "title": "Move a subscriber to GPON: current VLAN, PON, uplink, ONU profile, free IP",
    "triggers": ["gpon", "onu", "vlan", "subscriber"],
    "preconditions": ["subscriber identity binding is known"],
    "steps": ["read current VLAN/IP", "verify VLAN on the PON", "verify uplink tagging"],
    "postchecks": ["ONU online, DHCP lease in the expected VLAN"],
    "rollback": "read-only route; apply steps need their own owner GO",
    "verified_at": "2026-11-01T00:00:00Z",
    "provenance_event_ids": [7881]
  }
}
```

Field rules:

- **`status`** is one of `candidate`, `verified`, `stale` or `superseded`.
- **Versions.** A newer `version` of the same `route_id` replaces the older
  one. History is append-only and nothing is edited.
- **`superseded`** routes are never offered.
- **`stale`** routes are offered with a *verify first* label.

**Route bundles.** One event may carry `uroboros_routes`: a list of up to 32
records in the same format. This lets a runbook catalogue be registered in a
single append. Each route keeps its own `route_id` and version.

**Observed routes.** No migration is needed: each Seed already holds routes.
Any agent-log close with `truth_status: verified` and `result: done` counts as
an observed route, and so does any event tagged `uroboros-route`. The route
carries the event's commands, verification and rollback fields. These routes
rank below explicitly verified ones.

## Recording a route

At the end of a turn whose work is reusable, draft the route and append it as
an ordinary Seed event:

```bash
python -m integrity_guardian.uroboros_routes draft   --route-id gpon-migration-vlan --version 3 --status verified   --title "Move a subscriber to GPON: current VLAN, PON, uplink, ONU profile"   --trigger gpon --trigger onu --trigger vlan   --step "read current VLAN/IP" --step "verify VLAN on the PON"   --rollback "read-only route" --provenance 7881
```

The command prints `{"uroboros_route": {...}}` for the event's details.
`validate FILE` checks a record, a list or a details object before an append.

Both commands reject malformed records. They also reject secret-like text:
passwords, tokens, API keys and private keys. A route should name the secret
store, not carry a secret. The error names only the field, never the value.

Retrieval applies the same guard. A route with secret-like text is never
offered, and the projection counts it in `rejected_secret_like`.

**Choosing a status:**
- `candidate`: done once, not yet re-checked.
- `verified`: worked and was checked against state.
- `stale`: known to be out of date.
- `superseded`: replaced by a newer version.

A new `version` of the same `route_id` replaces the old one.

## Checking and repairing a route

A route can go stale. Check it read-only against the current state, then
record the result:

```bash
python -m integrity_guardian.uroboros_routes check   --route-id gpon-migration-vlan --version 3 --result fail   --note "uplink no longer carries the VLAN"
```

Append the printed `{"uroboros_route_check": ...}` as event details. Retrieval
uses the newest check for that route and version:

- **`pass`** turns a `candidate` or `stale` route into `verified` and sets the
  verification date.
- **`fail`** marks the route `stale`. Its hint says
  `check failed <date>: repair, then new version`.

**Repair** means appending the corrected route as the next `version`. It
supersedes the old one, and the failed check no longer applies.

## Event-triggered turns

A turn started by an infrastructure event goes through the same admission.
Examples are a syslog hook that opens a new agent chat, or an outage runbook
service. That turn therefore receives the matching routes, and no separate
dispatcher is needed. Write the event's own terms (device, symptom, service)
into the prompt that the hook sends.

## Matching and ranking

- **Term matching.** Terms match by substring against four fields: triggers
  (weight 4), title (3), scope/subsystem (2) and steps (1). Long words are
  lightly stemmed, so inflected languages still match.
- **Threshold.**
  - An explicit route needs at least two matched terms and a minimum score.
  - An observed route needs three matched terms and a higher score.
  - Numbers alone never count as a match.
  - Unrelated prompts and harness messages therefore get no routes.
- **Score adjustments.** Status and a declared rollback raise the score. Age
  lowers it gently.
- **Exclusions.** Routes whose event is named in a later
  `supersedes_event_ids` are dropped.
- **Determinism.** The result is deterministic for the same snapshot and
  clock.

## Glossary

| Term | Meaning |
|---|---|
| **Uroboros** | Umbrella name for procedural memory: routes, runbooks, macros, verification. |
| **Route** | A reusable path to a result with provenance and a status. It is guidance only. |
| **Runbook** | Instructions for an AI turn: trigger, context to gather, decisions, allowed actions, checks. |
| **Macro** | A prepared call of an existing function. Its target and secrets are owned by the executor. |
| **Toolzs** | The signed, cursor-pinned route-memory protocol (alpha) for tool and UI routes. |
| **Route stamp** | The `route_digest` stored on each Seed append. It is internal binding, not procedural memory. |

## Authority

- Routes never grant execution, production or route authority.
- A route may be wrong, stale or written by an untrusted agent. Read its
  provenance and check current state before acting.
- Production changes still need the target's own owner approval.
- No route enters a Stable Toolzs library without a security review.
