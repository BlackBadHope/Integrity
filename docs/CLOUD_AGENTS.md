# Cloud agents: Integrity memory without local hooks

Local Codex and Claude sessions take part in Integrity memory through hooks:
a context admission opens each turn and a signed receipt closes it. A cloud
agent such as a Codex cloud task runs in a container where these hooks cannot
be relied on. Its actions then leave no memory record. All that remains is the
agent's later account, which may be incomplete.

`integrity-cloud` (component [`components/integrity-cloud`](../components/integrity-cloud/README.md))
gives the cloud agent the same turn discipline. It does not open the owner's
network and does not give the agent live access to memory.

## What Codex cloud provides (checked 2026-11-04)

Sources: [Cloud environments](https://learn.chatgpt.com/docs/environments/cloud-environments),
[Codex Cloud (Legacy)](https://learn.chatgpt.com/docs/environments/cloud-environment),
[Internet access](https://learn.chatgpt.com/docs/cloud/internet-access),
[Hooks](https://learn.chatgpt.com/docs/hooks),
[MCP](https://learn.chatgpt.com/codex/extend/mcp?surface=cli),
[Build skills](https://learn.chatgpt.com/docs/build-skills).

| Capability | Status | Consequence |
| --- | --- | --- |
| Install script runs while the environment is prepared; the prepared filesystem is reused by new tasks | documented | Never create a signing key in the install script; `open` creates one per task |
| `AGENTS.md` and repository skills (`.agents/skills`) are used in cloud tasks | documented | The journal is driven from `AGENTS.md` and the `integrity-cloud-journal` skill |
| Environment variables reach the agent; network secrets are proxy-substituted for allowed HTTPS destinations; legacy secrets exist only during setup | documented | No secret is needed for (A); (B) would use a network secret |
| Agent internet is off by default, or restricted to an allowlist | documented | (A) needs no network; (B) needs exactly one allowlisted domain |
| Results come back as changed files, commits and pull requests | documented | The sealed journal is committed with the work |
| Command hooks (`hooks.json`) in cloud tasks | **not documented** | Optional observation layer only; a probe run shows whether they fire |
| MCP servers from `config.toml` in cloud tasks | **not documented** (the docs say local configuration and local MCP servers may not be available) | Not used |

## Flow (A): signed journal without opening the network

```text
trusted side                                   cloud task
capsule build ──(pasted into the task prompt)──▶ open --capsule  (new key, nonce, base commit)
                                                 turn-open / event / turn-close
                                                 hook <Event>     (only if hooks fire)
                                                 seal --out integrity-journal/   (key destroyed)
verify --expect-nonce ◀──────(commit in the PR)── integrity-journal/<id>.json
import-plan  → drafts for the ordinary client append path (trust = reported)
```

Environment setup: paste
[`examples/cloud-agents/codex-cloud-setup.sh`](../examples/cloud-agents/codex-cloud-setup.sh)
into the environment's install script. Also set the environment variable
`INTEGRITY_CLOUD=1`. The script writes it to `~/.bashrc` as well, but the
environment variable is the documented path. Keep agent internet off. Add no
secrets.

On a public repository the capsule must not be committed. Paste it into the task
prompt, and the agent saves it outside the repository. The capsule's random
nonce is known only to whoever launched the task, so `verify --expect-nonce`
binds the journal to that launch.

## Threat model

The agent controls its container, its key and the CLI.

| Threat | Detected? | How |
| --- | --- | --- |
| A record changed, removed, reordered or added after sealing (including edits to the committed file) | yes | Ed25519 signatures, hash chain, sequence, seal counts |
| Journal from another task or a replay | yes, with `--expect-nonce` and `--seen` | Launch nonce, registry of imported journal ids |
| Journal built against another capsule or base | yes, with `--expect-capsule` / `--expect-base-commit` | Digests recorded at `open` |
| The agent leaves an action out | **no** | Only form gaps are visible: no journal, unclosed turn, unsealed journal. Compare with the PR diff and the target systems' logs |
| The agent records something false | **no** | The signature binds the report to the task; it does not make the report true |
| Forged hook observations | **no** | Hooks and agent share the container and the key |
| Rewriting the whole journal before sealing | **no**, beyond the nonce | Needs an external witness, see (B) |
| Secret leaked into the journal or capsule | partly | Common secret formats and private addresses are refused, not masked |

Trust levels:

- **reported**: everything imported from a cloud journal, even when verification
  succeeds.
- **witnessed**: (B) only. A receiving service timestamped and countersigned each
  record as it arrived.
- **verified**: confirmed by evidence the agent did not produce, such as the
  PR diff or the target system's own logs. Promotion is a separate memory event
  that cites both sources. It is never a flag set by import.

Nothing in a cloud journal grants authority for production actions.

## Flow (B): append-only ingress (design only, not deployed)

For live reporting during the task:

- A small, separately hosted service is allowlisted as the task's only domain.
  It has no read path into memory and no route to the owner's network.
- A per-agent, per-task token is stored as a Codex network secret. The proxy
  substitutes it only for that domain. Its single scope is append to one
  journal, with a TTL and size and rate limits.
- The service accepts the same v1 records, verifies the signature and chain on
  arrival, and countersigns with its own key and receive time. This gives the
  *witnessed* level, and records arrive before the PR does.
- Import uses the same `import-plan` path. Rollback: remove the domain, revoke the
  tokens, stop the service. (A) keeps working.

(B) changes the owner's infrastructure and is deployed only on the owner's
explicit go-ahead.
