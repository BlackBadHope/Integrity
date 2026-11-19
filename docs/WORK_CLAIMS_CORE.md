# Work claims across machines

[Documentation](README.md) · [Project README](../README.md) · [What is verified](STATUS.md)

A claims core is one claim database that agents on several machines share.
Each agent signs every claim operation with its own Ed25519 key, and the core
checks the signature before it acts. Clients on other machines reach the core
over the OpenSSH forced command of the
[two-machine quickstart](CROSS_MACHINE_QUICKSTART.md); clients on the same
machine start a session directly.

Checked: **CI**, on a loopback stand. It is not in daily use yet.

## What it guarantees

- **One writer per task.** Every session of the core writes the same SQLite
  database, and every decision runs in one `BEGIN IMMEDIATE` transaction.
  When two agents claim the same task at the same moment, one gets
  `acquired`, the other `waiting`.
- **Leases expire on the core's clock.** A claim lives for its `ttl_seconds`
  unless its holder renews it. An expired claim is closed, and the next
  waiting claim is promoted.
- **Fencing tokens only grow.** Each acquired claim gets a higher token than
  every claim before it, across all clients. A fenced write (`record`,
  `release`, `renew`, `handoff`) checks the token and writes in the same
  transaction, so a holder whose claim expired or was handed off cannot write
  a result afterwards.
- **A verified identity, not a declared name.** In strict mode every request
  must be signed by a key that the core operator enrolled. The core refuses a
  request when:

  | Code | Why |
  | --- | --- |
  | `unsigned-refused` | strict core, no signature |
  | `enrolled-agent-must-sign` | declared core, no signature, but a key was enrolled for this agent id (active or revoked) |
  | `bad-signature` | the signature does not cover the request with the enrolled key |
  | `unknown-key` | the key is not enrolled at this core |
  | `key-revoked` | the operator revoked the key, also while its session is open |
  | `agent-mismatch` | the key is enrolled for another agent id |
  | `device-mismatch` | the key is enrolled for other SSH devices than the one connected |
  | `wrong-core` | the request names another core |
  | `expired`, `not-yet-valid`, `bad-window` | the signed validity window (at most 300 s, 60 s clock tolerance) does not hold |
  | `replay` | this key and nonce were already used at this core, in any session |
  | `stale-fence` | the caller no longer holds the claim under that token |

  A request that passes the identity checks uses up its nonce even when the
  operation is then refused (for example `stale-fence`), and the refusal is
  logged as `claim-request-failed` in the same transaction.
- **An audit trail anyone can recheck.** Every event of the hash-chained claim
  log names the request that caused it: the agent id, the key id, the request
  digest and the SSH device. The core keeps each signed request.
  `guardian-claims-core verify` recomputes the chain and checks every stored
  signature against the enrolled keys.

Identity is not authority. A verified claim says who works on a task; it does
not allow any action on any system.

Strict mode protects the transport: requests that arrive over the forced
command. A process that can write to the core's database file is outside this
threat model, and the registry's `verified_request` context is not a boundary
inside a process.

## Identity modes

| Mode | Unsigned requests | Signed requests | How to get it |
| --- | --- | --- | --- |
| `declared` (default) | accepted under the agent id they name, unless a key was enrolled for that id; their events say `"requested_by": {"mode": "declared"}` | verified as in strict mode | `init` without `--identity` |
| `strict` | refused | verified | `init --identity strict` |

The mode is stored in the database. A strict core cannot be reopened as
declared. The work claims of the [local memory profile](LOCAL_MEMORY.md) stay
declared: their names are asserted by the caller, and their events say so.

## Set up a core

On the core machine, after installing this repository
(`python -m pip install .`):

```bash
guardian-claims-core init --home "$HOME/claims-core" --identity strict
```

On each agent's machine, make a key. The private key stays there:

```bash
guardian-claims keygen --out agent.key      # writes agent.key and agent.key.pub
```

Copy `agent.key.pub` to the core and enroll it. `--device` limits the key to
the `integrity-remote` device ids that may carry it:

```bash
guardian-claims-core enroll --home "$HOME/claims-core" --agent-id builder-1 \
  --public-key agent.key.pub --device laptop-b
guardian-claims-core keys --home "$HOME/claims-core"
guardian-claims-core revoke --home "$HOME/claims-core" --key-id sha256:...
```

On POSIX the core folder and the key files are private to their owner. On
Windows they inherit the folder's access rules.

## Connect a client on another machine

The core side of the transport needs Linux. Build an `integrity-remote`
release whose server is the claims core, then follow the
[two-machine quickstart](CROSS_MACHINE_QUICKSTART.md) from step 3: one key
and one `authorized_keys` line per device, the pinned host key, and
`integrity-remote client-upstream` on the client.

```bash
guardian-claims-core server-json --home "$HOME/claims-core" > claims-server.json
integrity-remote core init --root "$HOME/claims-core-release" --server-json claims-server.json
```

The forced command fixes the device id of each SSH key; the core reads it from
`INTEGRITY_REMOTE_DEVICE_ID` and checks it against the enrollment. On the
client:

```bash
guardian-claims hello --upstream upstream.json --agent-id builder-1 --key agent.key
guardian-claims claim --upstream upstream.json --agent-id builder-1 --key agent.key \
  --resource task:build-42 --ttl 600
guardian-claims record CLAIM_ID --fence 7 --result "built" \
  --upstream upstream.json --agent-id builder-1 --key agent.key
guardian-claims release CLAIM_ID --fence 7 --outcome "done" \
  --upstream upstream.json --agent-id builder-1 --key agent.key
```

On the core machine itself, use `--core-home "$HOME/claims-core"` instead of
`--upstream`. The other commands are `poll`, `renew`, `cancel`, `handoff`,
`status` and `events`. In Python, `integrity_guardian.claims_client.ClaimsClient`
keeps one session open.

## The wire

One JSON object per line on the session's stdin and stdout:

```text
-> {"id": 1, "method": "hello", "params": {}}
<- {"id": 1, "result": {"core_id": "claims-core:...", "identity_mode": "strict", ...}}
-> {"id": 2, "method": "request", "params": <signed request>}
<- {"id": 2, "result": {...}}   or   {"id": 2, "error": {"code": "...", "message": "..."}}
```

A signed request has exactly these fields:
`protocol` (`integrity-guardian/work-claim-request/v1`), `core_id`,
`agent_id`, `key_id` (the SHA-256 of the raw public key), `operation`,
`arguments`, `nonce`, `issued_at`, `expires_at` and `signature`. The
signature covers all other fields in the canonical JSON profile of this
project. The design note is [architecture/work-claims-identity.md](architecture/work-claims-identity.md).

## What is verified

- `tests/test_claims_core.py` runs in public CI on Ubuntu and Windows. Each
  client is its own `serve` process on stdio, writing the one database:
  a race of two agents with different keys for one task, five times; lease
  expiry with a stale holder refused; handoff; forged signatures; replay in
  the same and in a new session; a refused request consumed in the same
  transaction as its failure record; a key revoked while its session is open;
  strict and declared modes, and a declared core refusing unsigned requests
  for an enrolled agent; the validity window, the core binding and the
  device binding; a tampered stored request failing the audit; and the
  installed commands.
- `tests/test_networked_claims_ssh.py` runs the same checks through a real
  `sshd` with `integrity-remote` forced commands: two device keys, three agent
  keys each bound to one device, a strict core. It is required in the
  `Cross-machine SSH` workflow on Ubuntu, which also runs the installed
  commands.

Not verified:

- **Two physical hosts.** The SSH test reproduces two machines on one Linux
  host, with separate folders and keys and an `sshd` on loopback.
- **A real agent client.** No Claude Code, Codex or Antigravity session has
  used a claims core.
- **More than one core.** There is no replication, failover or consensus. If
  the core is down, nobody can claim.
- **Blast-radius coverage.** A claim covers the resources the agent names; it
  does not check that the agent's writes stay inside them.
- The hardened mode of `integrity-remote` with a claims core, long use, and
  backup and restore of the core folder.
- ChangeIntent custody and module-agent lease custody still run on one local
  database; they are not served by the claims core.
