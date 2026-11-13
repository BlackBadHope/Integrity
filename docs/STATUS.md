# What is verified

[Documentation](README.md) · [Project README](../README.md)

Every statement about Integrity is one of these, and this page says which:

| Mark | Meaning |
| --- | --- |
| **daily use** | we run it in our own operations |
| **CI** | public CI covers it on every pull request |
| **once** | one recorded manual run |
| **not verified** | shipped, but nobody has checked it from this repository |
| **roadmap** | not in this repository yet |

A green suite is not a deployment. The tests use synthetic inputs; they do not
certify owner credentials, what reached a model, or a production installation.

## Use cases

### Windows desktop: Claude Code, Codex, Antigravity

*Claude Code: daily use, through the standalone hook. Codex: in regular use; on
Windows through managed hooks that have no turn guard. Antigravity lifecycle
hooks: CI, and tested live with a Claude model.*

`integrity-native-profile` generates the MCP registration and lifecycle hooks
for each client. The [native onboarding guide](native-onboarding.md) walks
through install, connection, expected hook behavior and rollback.

- **Codex and Antigravity** profiles build on a fresh Windows checkout.
  `native_runtime verify` and `probe` pass on the generated Codex profile. This
  was checked on a fresh clone on a development machine; the clean-VM result
  for 7.0.0 is in [RELEASE_NOTES.md](../RELEASE_NOTES.md).
- **Claude Code** Native profiles on Windows work only through the enrolled
  publisher route. A plain Claude Code install is refused with "requires its
  actual enrolled session ID". Our own Claude Code sessions use the standalone
  hook (`resources/claude/admission.py`), wired into a project
  `.claude/settings.json` by hand. There is no one-command install for it yet.
- **Hooks are project-scoped.** A session started in another folder runs
  without memory. `integrity-doctor` reports this.

To try memory without hooks, use the read-only
[local-memory walkthrough](../examples/local-memory/README.md). CI runs it on
Linux and Windows, and it prints PASS for all three clients.

To let your own agents write and claim tasks on one machine, use the
[local memory profile](LOCAL_MEMORY.md) (`guardian-local-memory`). CI runs its
tests and its `init`, `doctor` and `uninstall` on Linux and Windows. It is not
the core write path, agent names in it are declared and not verified, and it
has not been run with a real agent client yet.

The four-scene demo at the top of the [README](../README.md#the-demo-step-by-step)
(`demo/run.py`) is run by `tests/test_demo.py` in CI on Linux and Windows. It
runs no model, and its scene 2 is a recall, not the context a hooked client
receives.

### Linux workstations and servers

*CI. Also run on a clean Debian VM (beta.3).* Codex and Claude Code Native
profiles run under user custody. See [Linux native clients](linux-native-clients.md).

### Core on one machine, clients on another

*CI and daily use.* `integrity-remote` connects a client machine to the core
over an OpenSSH forced command with a pinned host key. CI tests unknown-key
denial, key revocation and lifecycle parity between local and SSH clients. See
the [two-machine quickstart](CROSS_MACHINE_QUICKSTART.md).

The server side of that transport is in
[`deploy/linux-core`](../deploy/linux-core/README.md). Its README lists what
was run; the scripts carry placeholders that you fill for your own host.

### A multi-vendor team on one infrastructure

*Daily use.* Our own setup: one operator, and agents from Claude Code and
Codex, with Antigravity in live tests, working on the same infrastructure. The
agents hand tasks to each other through a local bus. When one vendor hit a
quota, another continued from the same log. See the
[team quickstart](QUICKSTART_TEAM.md) and the
[agent bus](../components/integrity-llm-bus/README.md).

Of the bus, the local queue, registry and relay are in daily use on Windows.
The hub's socket handler, its systemd sandbox and operation across several
hosts are **not verified** from this repository.

### Cloud agents (Codex Cloud)

*CI; no live Codex Cloud acceptance yet.* An agent that cannot run local hooks
keeps a signed turn journal in its sandbox and commits it with its work. The
host verifies the chain before importing it as reported evidence, so no
inbound access to your network is needed. See [cloud agents](CLOUD_AGENTS.md)
and `examples/cloud-agents/codex-cloud-setup.sh`.

### CLI and headless agents

*Once.* A headless `claude -p` run in a project folder uses that project's
hooks. In a four-turn check on beta.3:

- admission worked;
- a read-only turn closed with `no-event`;
- a shell turn without a close was blocked once, then ended with the gap
  recorded;
- after two turns without admission the notice said `ADMISSION SKIPPED`.

### Android phone

*Once; no guide in this repository yet.* Our Android setup is a Linux userland
on the phone. On it, the Codex CLI writes to the same core over the SSH forced
command. Claude Code also runs there with Remote Control, so a prompt sent
from claude.ai ran on the phone. Two things we learned:

- Use the musl native Claude Code build. The glibc build aborted under the
  userland's preloaded library.
- Hard links are refused in that sandbox. Client Memory handles this since
  beta.2.

### Guards and the kill switch

*CI; both are alpha.* [`integrity-guards`](../components/integrity-guards/README.md)
and [`integrity-killswitch`](../components/integrity-killswitch/README.md)
come from a running deployment. Their tests run in public CI. CI also installs
the kill switch wheel alone, without any other Integrity package, and runs its
`doctor`, `uninstall` and `pip uninstall` on Ubuntu and Windows. The kill switch
is cooperative: it does not terminate processes. Host tables, device registries
and routes for the guards are yours to write; the shipped examples are
invented.

### A human operator room

*CI; alpha.* [`integrity-humanx`](../components/integrity-humanx/README.md) is a
port of a working pilot. A person writes in a small web page; a room agent of
one vendor is woken over the bus, held read-only by hooks, and reads
production through a read-only gateway. Its unit tests run in public CI with a
synthetic configuration. The port changes the bus addresses and takes every
site value from a configuration file, so the ported form has had no live run:
no real bus, agent, switch, database or browser took part. The waker loops,
the supervisor, the mode where several vendors answer together and the quota
readers have no tests. The component README lists the defects carried over
from the pilot.

### Event-driven runbooks

*Roadmap.* The plan is for an infrastructure event, such as a syslog line, to
start an agent turn that follows a verified runbook route. With an up-to-date
Action Log, known routes already reach every admitted turn, including turns
that a hook starts ([Uroboros](UROBOROS.md)). The hooks themselves are
deployment-specific.

## What the public suite verifies

The suite verifies the protocol core, the Ledger, one-use ChangeIntent custody,
index-backed Seed queries and fenced blast-radius claims between processes **on
one machine**. An end-to-end test enrolls two machines and rejects a stale
fence (`tests/e2e/test_two_machine_mesh.py`).

Not claimed: general coordination across machines, authenticated agent
identity for claims, and production operation.
[ARCHITECTURE.md](../ARCHITECTURE.md#what-the-public-suite-verifies) lists each
property with the test that covers it.

Test counts and the skips to expect on each platform are measured in CI and
kept in [expected test skips](expected-test-skips.md).

## Platform support

| Platform | Source and install | Public CI | Operational integration |
| --- | --- | --- | --- |
| Linux | Supported | Python 3.11 and 3.12, full suite | Requires an independently configured adapter |
| Windows | Portable core and client hooks supported | Python 3.11 and 3.12, full suite; POSIX-only tests skip | POSIX-only custody and Windows-only executors have separate gates |
| macOS | Not supported yet | Informational job: core and client-memory run, with known failures | Linux procfs custody (Toolzs authority ledger, Seed runtime recovery) does not work on macOS |

Platform support is a capability vector. An installation PASS does not imply
that host binding, credentials or production actions are configured.

- The portable core is verified on Python 3.11 and 3.12 in public CI, and on
  Python 3.12 in an independent clean-machine run.
- On macOS most failing tests need Linux `/proc` custody
  (`uroboros_toolzs_authority_ledger`, Seed sync and runtime recovery). Until
  they are ported, macOS is not a supported platform.
- The optional local adversarial rehearsal reported by `guardian
  platform-profile` needs `bubblewrap`, `prlimit` and a `python3.14` executable
  on `PATH`. Without them the profile reports `prerequisite-missing`; the rest
  of Guardian does not need them.
- Inside a nested Docker container, bubblewrap usually cannot create a user
  namespace. That is a limit of the container, not of Integrity: the sandboxed
  tests fail or skip there, and they pass on a host or VM.

## Known limitations

- Live acceptance with a model on a fresh install is not yet published for any
  vendor.
- macOS is not supported yet.
- Mode B tunnels are unverified.
- Hooks are project-scoped unless you merge them into user settings by hand.
  That merge is tested on Linux; there is no command for it yet.
- The Claude Code Native route on Windows has no turn guard and no
  admission-first gate. Antigravity's `Stop` cannot block. On Linux the guard
  only advises.
- Gemini Flash models in Antigravity may ignore MCP tool calls, so their turns
  get no memory. With the gate on, their other tools stay denied.
- Through `agentapi`, `new-conversation` creates owner turns for any local
  process that holds the hub CSRF token.
- Cloud agents do not share memory live. Their signed journals are imported as
  reported evidence.
- Five optional components have no behaviour tests: `integrity-active-inquiry`,
  `integrity-agents-api`, `integrity-codex-persistent`,
  `integrity-execution-bridge` and `integrity-experience-adapters`. CI only
  builds and installs them. `integrity-execution-bridge` does not run on
  Windows.
- The HumanX operator room and the agent-bus hub have had no live run in their
  published form.
- Seed events are not signed, and an incremental catalog sync does not re-read
  earlier events; see [ARCHITECTURE.md](../ARCHITECTURE.md#seed-service-and-plugin-boundaries).

## Historical evidence

The [6.1.0 / 6.1.1 isolated installation report](audits/installation-6.1.1-20261017/REPORT_RU.md)
(in Russian) keeps Linux and Windows results, single-run command timings,
preserved failures and evidence digests for that release. The timings are not
product-performance claims.
