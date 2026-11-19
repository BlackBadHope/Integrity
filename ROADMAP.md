# Roadmap

[Project README](README.md) · [Documentation](docs/README.md) · [What is verified](docs/STATUS.md)

This page lists open work. It carries no dates: an item moves to the
[changelog](CHANGELOG.md) when it ships, and to
[what is verified](docs/STATUS.md) when something has checked it. A green
synthetic suite does not claim a production deployment or operational
acceptance.

## Where things stand

- **Stable:** `v7.0.1`, Guardian 7.0.0 with memory MCP facade API 2.11.0.
- **On `main`, not tagged:** core fixes carried over from a running release,
  agent bus 1.1.0 with a hub, `integrity-killswitch`, `integrity-guards`,
  `integrity-humanx`, and the Linux core deployment scripts.

## Verification still owed

These ship today. What is missing is evidence.

| Item | What is missing |
| --- | --- |
| Live acceptance on a fresh install | A run with a model on the core write path, for any vendor; Codex and Antigravity on the local memory profile. The local profile with Claude Code ran once ([report](docs/audits/live-acceptance-local-memory-20261114/REPORT.md)) |
| Codex Native on Windows, turn guard | A live Codex run of the `block` default |
| Cloud agents | A live Codex Cloud acceptance; CI covers the journal and the import |
| Agent bus hub | The socket handler, the systemd sandbox and operation across several hosts |
| Guards and kill switch | A live acceptance from this repository; both are alpha |
| Human operator room | A live run of the ported form; tests for the waker loops, the supervisor, Max Reasoning and the quota readers |
| Mode B tunnels | Whether a third party can connect through their own tunnel at all |
| macOS | 105 failing tests in the informational job (50 core, 55 client-memory); most need Linux `/proc` custody |

## Missing pieces

| Item | Today |
| --- | --- |
| One-command install of the Claude Code standalone hook | Wired into `.claude/settings.json` by hand |
| A command that merges hooks into user settings | Done by hand; tested on Linux |
| A guide for the Android setup | Tested once, not written up |
| Turn guard on the Claude Code Native route on Windows | That route has no guard and no admission-first gate |

## Next milestones

1. **Cross-machine coordination.** Memory access from other machines runs
   over an OpenSSH forced command (`integrity-remote`). Work claims now go to
   one [claims core](docs/WORK_CLAIMS_CORE.md) over the same transport, with
   every request signed by the agent's enrolled key (CI on a loopback stand).
   Still open: a run between two physical hosts, a real agent client on the
   claims core, and network custody for one-use ChangeIntents and module-agent
   leases, which are verified on one machine only.
2. **Event-driven runbooks.** *Alpha in source, CI on Linux and Windows.*
   Triggers and the dispatcher (`integrity-guards runbooks`, off by default)
   start a turn that follows a compiled route; write routes become proposals
   ([Uroboros](docs/UROBOROS.md#event-triggered-turns)). Still open: a run
   with a real model and a real log source, and the dispatcher as an
   installed service.
3. **Append-only ingress for cloud agents.** Designed in
   [cloud agents](docs/CLOUD_AGENTS.md), not deployed.
4. **Independent observer tooling.** Simpler verification and replay reports.
5. **Portable adapters.** Documented capability discovery without embedded
   credentials or production authority.
6. **Packaging.** Evaluated PyPI publication and reproducible release assets.

## Not claimed

- Replication, failover or consensus between claims cores: there is one
  authoritative core, and when it is down nobody can claim.
- Verified identity outside a strict claims core: the local memory profile and
  a declared core accept names asserted by the caller, and label them
  `declared`.
- Coordination between two physical hosts or with real agent clients: CI
  reproduces two machines on one Linux host with an `sshd` on loopback.
- Blast-radius coverage: a claim covers the resources the agent names, not the
  writes it actually makes.
- Production deployment or operational acceptance of any component.

`guardian capabilities` sets only `networked_claims_core_ci_proven`, with the
scope `ci-single-authoritative-claims-core-signed-requests-forced-command-loopback`.
It keeps the general `multi_agent_coordination_proven` false, as well as
`work_claim_consensus_proven`, `blast_radius_coverage_proven` and
`agent_handoff_distributed_consensus_proven`.
