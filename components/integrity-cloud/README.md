# integrity-cloud

Integrity memory for cloud agents that cannot run local hooks.

Local agents open and close every turn through Integrity hooks, and each turn ends
with a signed receipt. A cloud agent such as a Codex cloud task has no such
hooks. `integrity-cloud` gives it the same turn discipline inside its own
container:

- `open` creates a fresh Ed25519 key **per task**. The key lives outside the
  repository with owner-only permissions. `open` also records the launch
  nonce, the digest of the read-only context capsule and the base commit.
- `turn-open` / `event` / `turn-close` append hash-chained, signed records.
  A close is a receipt: it lists exactly the events of its turn, or gives a
  no-event reason. `--kind action` records a change to an external system,
  with its target and result.
- `seal --out integrity-journal/` writes a bundle and destroys the key. The
  agent commits the bundle with its work, so nothing goes over the network.
- On the trusted side, `verify` checks:
  - signatures, chain, sequence, turn balance, receipts and the seal;
  - optionally the expected nonce, capsule digest and base commit;
  - optionally a registry of journal ids already imported.

  `import-plan` turns a verified bundle into idempotent drafts for the ordinary
  client `append_event` path. Every draft is marked
  `provenance.trust = "reported"`.
- `capsule build` makes the read-only context that the agent receives. It keeps
  only uid, kind, summary and tags. It refuses secret-like text, private IP
  addresses and owner-supplied literals.
- `hook <Event>` is an optional Codex command-hook adapter. If cloud hooks run,
  it records tool-use observations as digests only and blocks one Stop while a
  turn is open. The journal does not depend on it.

## What a signature proves

A valid journal (`signed-chain-ok`) proves only that the records were not
changed, removed, reordered or extended after the agent sealed them, and, with
`--expect-nonce`, that the journal belongs to the task you launched. It does
**not** prove that the agent told the truth or recorded everything. The agent
controls its container and its key. Treat imported events as *reported*.
Promote a statement to *verified* only with evidence the agent did not
produce, such as the PR diff or the target system's own logs.

## Quick use

```bash
# cloud task (agent side)
integrity-cloud open --nonce "$NONCE" --label "fix flaky test"
integrity-cloud turn-open --intent "fix the flaky test"
integrity-cloud event --kind action --summary "re-ran the suite" \
  --target pytest --result "all passed" --exit-code 0
integrity-cloud turn-close --outcome events
integrity-cloud seal --out integrity-journal/

# trusted side
integrity-cloud verify integrity-journal/<id>.json --expect-nonce "$NONCE"
integrity-cloud import-plan integrity-journal/<id>.json --expect-nonce "$NONCE" \
  --seen imported-journals.txt --record-seen --out plan.json
```

See [docs/CLOUD_AGENTS.md](../../docs/CLOUD_AGENTS.md) for the Codex cloud
setup, the threat model and the planned append-only ingress.
