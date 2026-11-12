# Deployment identity profile

[Documentation](README.md) · [Project README](../README.md)

A Memory server reads and writes ledgers that are bound to identity values:
tenant identifiers, the Action Log protocol labels it accepts, and the schema
constants signed into security and route receipts. The public distribution
ships public values. A deployment whose state was created under other values
(for example an installation that predates the public export) cannot open that
state with the public values: the architecture custody ledger refuses with
`ledger identity does not match requested identity`. That refusal is correct
and safe; nothing is written.

The deployment identity profile supplies such a deployment's own values without
putting them in the public source. It is one JSON file that the owner keeps on
the host. The server takes its path and pins its bytes:

```bash
guardian-memory-synapse-mcp \
  --deployment-profile /etc/integrity/deployment-profile.json \
  --expected-deployment-profile-digest sha256:<64 hex> \
  ...
```

`guardian native-trust-bootstrap` takes the same two flags.

## Rules

- Both flags or neither. Without them every value keeps its public default.
- The digest is the SHA-256 of the exact file bytes. A changed file is refused
  before any state is opened.
- On POSIX the file must be owned by root or by the serving account and must
  not be writable by group or others. Pin the digest in the release or forced
  command, not next to the file.
- The profile is identity, never authority. `production_authority` must be
  absent or `false`; nothing in the profile widens a tool surface or skips a
  verification.
- A process activates one profile before it reads any identity value. A second,
  different profile or a late activation is refused, so one process never mixes
  identities.
- The server never prints profile values. `deployment_profile.describe()`
  reports only the profile id and digest.

## Format

All keys except `protocol` and `profile_id` are optional. Unknown keys are
refused. The values below are invented.

```json
{
  "protocol": "integrity-guardian/deployment-profile/v1",
  "profile_id": "deployment:example",
  "production_authority": false,
  "identities": {
    "architecture_tenant_id": "tenant:example-architecture",
    "security_tenant_id": "tenant:example-security",
    "security_environment_profile_id": "environment:example-forced-stdio",
    "synthetic_tenant_id": "tenant:example-synthetic",
    "readonly_canary_tenant_id": "tenant:example-readonly-canary",
    "canary_tenant_id": "tenant:example-canary",
    "canary_foreign_tenant_id": "tenant:example-foreign",
    "cross_agent_acceptance_tenant_id": "tenant:example-cross-agent"
  },
  "action_log_dialect": {
    "mind_projection": "example.action-log.mind-projection/v1",
    "concept_recovery": "example.action-log.concept-recovery/v1",
    "coordination_projection": "example.action-log.coordination-projection/v1"
  },
  "archive_policy": {
    "source_sha256": "<64 hex>",
    "manifest_event_uid": "client:example-archive-manifest-v1",
    "message_count": 100,
    "part_count": 4
  },
  "seed_catalog": {
    "required_event_ids": [17],
    "recall_demotions": [{"action": "example-archive-chunk", "unless_terms": ["archive"]}]
  },
  "session_recovery": {"max_records": 512},
  "replay_catalog_pool": true,
  "append_response_compaction": true
}
```

| Key | Effect |
| --- | --- |
| `identities.*` | Replaces the public tenant or environment value. `security_*` and `synthetic_tenant_id` also replace the matching JSON Schema constants. |
| `action_log_dialect.*` | Predecessor Action Log protocol labels accepted for Mind admission. Each must end in `.action-log.<name>/v1`. |
| `archive_policy` | Enables the historical archive tools for exactly this archive. |
| `seed_catalog.required_event_ids` | Catalog verification fails if one of these events is missing once the catalog has grown past it. |
| `seed_catalog.recall_demotions` | Search ranks the named action at a quarter of its score unless the query contains one of `unless_terms`. |
| `session_recovery.max_records` | Same-session recovery record quota (1..4096; byte caps unchanged). |
| `replay_catalog_pool` | Context-replay catalogs with identical bytes share one pooled file. Pooled layouts are never pruned by TTL. |
| `append_response_compaction` | Append responses carry digests of nested route stages instead of the stages. |

## Performance features available to every deployment

These need no profile:

- The architecture custody ledger reuses schema and signature verification
  for exact unchanged event bytes within one connection
  (`LedgerStore(cache_verified_events=True)`).
- Full Seed catalog verification is memoized per catalog content and verifier
  (including the active profile digest), in process and in a private
  `.seed-verified` directory under the snapshot root.
- The package artifact digest is computed once per process when the package
  is immutable for the serving account (an installed release); editable
  checkouts are re-hashed on every call.
- Context-replay roots that already contain pooled catalogs are read and
  accounted for even when `replay_catalog_pool` is off.
