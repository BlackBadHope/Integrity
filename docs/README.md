# Documentation

[Project README](../README.md) · [What is verified](STATUS.md) · [Changelog](../CHANGELOG.md)

Pick the row that matches what you want to do. Each page states what was run
and what was not.

## Start

| Page | What it gives you |
| --- | --- |
| [Project README](../README.md) | What Integrity is, the pictures, a five-minute first run |
| [Install and test](INSTALL.md) | Prerequisites, a source install, the checks that public CI runs |
| [Clean bootstrap](../BOOTSTRAP.md) | Optional components, wheels, an isolated local instance |
| [Read-only memory walkthrough](../examples/local-memory/README.md) | A disposable catalog connected to Codex, Claude Code and Antigravity without hooks |

## Connect an agent

| Page | What it gives you |
| --- | --- |
| [Native onboarding](native-onboarding.md) | Lifecycle hooks for Codex, Claude Code and Antigravity: install, connection, expected behavior, rollback |
| [Linux native clients](linux-native-clients.md) | Codex and Claude Code profiles under user custody on Linux |
| [Hooks troubleshooting](hooks-troubleshooting.md) | Where hooks apply, the turn-close guard, "memory unreachable" against "admission skipped" |
| [Cloud agents](CLOUD_AGENTS.md) | Signed turn journals for agents that cannot run local hooks |

## Deploy

| Page | What it gives you |
| --- | --- |
| [Two-machine quickstart](CROSS_MACHINE_QUICKSTART.md) | The core on machine A, clients on machine B, over an OpenSSH forced command |
| [Linux core scripts](../deploy/linux-core/README.md) | The server side of that transport, with the placeholders you fill |
| [Deployment identity profile](DEPLOYMENT_PROFILE.md) | A pinned JSON file with your deployment's own identity values, for state created under non-public values |
| [Team quickstart](QUICKSTART_TEAM.md) | One core for two to five people, each with their own model account |
| [Migrating to Integrity Seats](MIGRATION_INTEGRITY_SEATS.md) | Moving a single-user install to seats |
| [OpenAI tunnel seats](HOWTO_OPENAI_TUNNEL_SEATS.md) | Seats with each person's own OpenAI account: the OAuth gateway, and the optional personal tunnel (unverified) |

## Understand

| Page | What it gives you |
| --- | --- |
| [Architecture](../ARCHITECTURE.md) | Layers, boundaries, the authorization lifecycle, what the suite verifies |
| [What is verified](STATUS.md) | Each use case and how far it has been checked; platforms; known limitations |
| [Uroboros](UROBOROS.md) | Procedural memory: how verified work becomes a reusable route |
| [Expected test skips](expected-test-skips.md) | Test counts and skips per platform, measured in CI |
| [Roadmap](../ROADMAP.md) | What is next, and what is deliberately not claimed |

## Components

Each component has its own README with its interface, its limits and what was
run.

| Area | Components |
| --- | --- |
| Core and memory | [action-log](../components/integrity-action-log/README.md), [memory-plane](../components/integrity-memory-plane/README.md), [client-memory](../components/integrity-client-memory/README.md), [seed plugin](../components/integrity-seed/README.md) |
| Coordination and reach | [llm-bus](../components/integrity-llm-bus/README.md), [bridges](../components/integrity-bridges/README.md), [remote](../components/integrity-remote/README.md), [cloud](../components/integrity-cloud/README.md) |
| Safety on the agent's machine | [guards](../components/integrity-guards/README.md), [killswitch](../components/integrity-killswitch/README.md) |
| Execution and adapters | [adapter-sdk](../components/integrity-adapter-sdk/README.md), [execution-bridge](../components/integrity-execution-bridge/README.md), [agents-api](../components/integrity-agents-api/README.md), [codex-persistent](../components/integrity-codex-persistent/README.md), [claude-code](../components/integrity-claude-code/README.md), [active-inquiry](../components/integrity-active-inquiry/README.md), [experience-adapters](../components/integrity-experience-adapters/README.md) |
| Operator tools | [home](../components/integrity-home/README.md), [space](../components/integrity-space/README.md), [humanx](../components/integrity-humanx/README.md), [resource-advisor](../components/integrity-resource-advisor/README.md) |

## Design notes and history

These pages describe designs or past releases. They are not statements about
the current code.

| Page | Status |
| --- | --- |
| [Chronicle product brief](architecture/chronicle/PRODUCT-BRIEF.md) | Design only |
| [Chronicle sorting and indexing pipeline](architecture/chronicle/SORTING-AND-INDEXING-PIPELINE.md) | Design only |
| [Installation report for 6.1.0 / 6.1.1](audits/installation-6.1.1-20261017/REPORT_RU.md) | Historical, in Russian |
| [Runtime source consistency](runtime-source-sync.md) | Historical notes on the Linux client-memory repair chain |
| [Release notes](../RELEASE_NOTES.md) | Tagged releases |

## How these pages are written

- A statement is either covered by a test or a recorded run, or it is marked
  as not verified.
- Examples use invented names and reserved addresses. Nothing here describes a
  real network.
- The pictures are generated by `docs/assets/build_assets.py`, in a light and
  a dark variant.
