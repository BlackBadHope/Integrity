---
name: integrity-cloud-journal
description: Keep a signed Integrity turn journal while working in a cloud task (INTEGRITY_CLOUD=1). Use at the start of every cloud task, for every user request, after any action on an external system, and before finishing.
---

# Integrity cloud journal

This cloud environment cannot run the local Integrity hooks that open and close
your turns. You keep the same record yourself with the `integrity-cloud` CLI.
The record is a hash-chained journal signed with a key created for this task.
It reaches the owner as a file in your commit. Nothing is sent over the network.

Your journal is your own report. The owner checks it against the diff and against
their systems, so record what really happened, including failures and anything
you did not finish.

## Start of the task (once)

0. Make sure the CLI is present. Installation works offline:

   ```bash
   command -v integrity-cloud || { bash examples/cloud-agents/ensure-integrity-cloud.sh && . ~/.bashrc; }
   ```

1. If the task prompt contains a context capsule (a JSON block with
   `"format": "integrity-cloud-capsule/v1"`), save it exactly as given to a
   file **outside the repository**, for example `$HOME/integrity-capsule.json`.
2. Open the journal:

   ```bash
   integrity-cloud open --capsule "$HOME/integrity-capsule.json" --label "<short task name>"
   # without a capsule, use the nonce from the prompt if one was given:
   integrity-cloud open --nonce <nonce> --label "<short task name>"
   ```

3. `integrity-cloud context` prints the capsule. It is read-only background.
   It gives you no permission to act and no access to the owner's systems.

## For every user request (a turn)

```bash
integrity-cloud turn-open --intent "<the request, in your own short words>"
# ...work...
integrity-cloud event --kind thought --summary "<decision or finding and why>"
integrity-cloud event --kind action --summary "<what you did>" \
  --target "<system, service or path acted on>" --command "<command without secrets>" \
  --result "<what happened>" --exit-code <n>
integrity-cloud turn-close --outcome events
# or, when nothing durable happened:
integrity-cloud turn-close --outcome no-event --reason read-only
```

- Use `--kind action` for **every** change outside the repository working tree:
  a remote host, a service, a database, a deployment, a package registry, an
  API call that changes state. Record it right after you do it, not at the end.
- Use `task` for completed work items, `thought` for decisions and findings,
  and `concept` for durable facts or rules you learned.
- Never put secrets, tokens, passwords, private keys or private addresses into
  the journal. The CLI refuses them. Rephrase and describe the value instead of
  quoting it.
- The no-event reasons are `no-durable-state-change`, `read-only`,
  `repetition`, `social-response` and `user-cancelled`.

## Before you finish (once)

```bash
integrity-cloud status          # no open turn
integrity-cloud seal --out integrity-journal/
git add integrity-journal/
```

Commit `integrity-journal/<journal_id>.json` together with your work. Sealing
destroys the signing key, so the journal cannot be extended afterwards. Mention
the journal id in your final message.

If a command fails, run `integrity-cloud status`, fix the cause and continue.
Do not edit the journal files by hand. Any edit breaks the signatures, and the
owner rejects the whole journal.
