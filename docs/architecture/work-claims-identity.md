# Design note: verified agent identity and one claims core

[Documentation](../README.md) · [Work claims across machines](../WORK_CLAIMS_CORE.md)

## Problem

Work claims were fenced and hash-chained, but on one machine only, and the
agent id in every claim was whatever the caller wrote. Any process could claim,
renew, release or hand off in another agent's name, and agents on different
machines had no shared claim database.

## Choice: every request signed with the agent's own Ed25519 key

- Each agent holds an Ed25519 key (`cryptography`, already a dependency).
  The core operator enrolls the public key under an agent id, optionally bound
  to the `integrity-remote` device ids that may carry it.
- Every operation is a signed request bound to one core (`core_id`), with a
  random nonce and a validity window of at most 300 s.
- The core checks, in this order: request shape, core binding, enrolled key,
  signature, key status, agent id, device, window. Then, in one write
  transaction, it stores the request under the unique pair (key id, nonce),
  checks the key status again and runs the operation. A second use of the pair
  fails the unique constraint: that is the replay check. Requests are kept, so
  it holds for as long as the database exists.
- The operation runs under the enrolled agent id, never under a name the
  request asserts. Every event it appends records the request digest, key id
  and device. Stored requests let a third party recheck every signature later.
- Strict mode is opt-in and sticky. Declared mode keeps today's behaviour for
  the local profile and labels it, so nothing silently claims verification it
  does not have.

## Alternative considered: identity from the forced-command key only

The `authorized_keys` line already fixes a device id that the core can read
from `INTEGRITY_REMOTE_DEVICE_ID`. Using it as the agent identity needs no new
keys. It was not chosen as the identity because:

- it names a device, not an agent: every agent on one laptop would share it;
- it exists only behind the SSH transport, so local sessions on the core would
  have no identity at all;
- it leaves nothing to verify afterwards: the log would hold the device name as
  the core asserted it, not a signature anyone can check;
- it gives no replay or freshness protection at the request level, only at
  the session level.

The device binding is kept as a second factor: an enrollment may name devices,
and then the key is accepted only through them.

## Why one core and not consensus

Atomic claims, expiring leases and monotonic fencing tokens need one
linearizable decision point. One SQLite database behind `BEGIN IMMEDIATE`
already is one, on one machine; serving it over stdio sessions extends it to
other machines without a new network listener. Replication or consensus
between several cores is a separate, larger problem and is not claimed.

## Limits

- The core is a single point of failure: when it is down, nobody claims.
- Clock tolerance is 60 s for `issued_at`; leases use the core's clock only.
- The private key file is unencrypted PEM, owner-only on POSIX.
- A revoked key stays revoked; a new key needs a new enrollment.
