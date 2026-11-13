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
| Live acceptance on a fresh install | A published run with a model, for any vendor |
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
   over an OpenSSH forced command (`integrity-remote`). Still open:
   authenticated agent identity for work claims and a networked claim backend.
   Claims, handoff fencing and one-use intent custody are verified on one
   machine only.
2. **Event-driven runbooks.** An infrastructure event starts an agent turn
   that follows a verified route. Known routes already reach every admitted
   turn ([Uroboros](docs/UROBOROS.md)); the triggers are not in this
   repository.
3. **Append-only ingress for cloud agents.** Designed in
   [cloud agents](docs/CLOUD_AGENTS.md), not deployed.
4. **Independent observer tooling.** Simpler verification and replay reports.
5. **Portable adapters.** Documented capability discovery without embedded
   credentials or production authority.
6. **Packaging.** Evaluated PyPI publication and reproducible release assets.

## Not claimed

- General coordination across machines, consensus, or a network claim backend.
- Authenticated agent identity for work claims: identities are asserted by the
  caller.
- Production deployment or operational acceptance of any component.

`guardian capabilities` keeps `multi_agent_coordination_proven` and
`blast_radius_coverage_proven` false for the same reason.
