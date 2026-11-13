# Linux core: release wrapper and forced-command transport

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

These files are the launch and verification scripts that run next to an
installed Guardian Memory & Synapse package on a Linux core host. MCP clients
reach the core over an OpenSSH forced command. The files are copied from a
running deployment. The only changes are the placeholders listed below, which
replace deployment-specific release paths and one deployment digest, and the
wording of two comment lines.

This is a reference layout, not an installer. Nothing in the repository
builds these directories or substitutes the placeholders yet. The
`integrity-remote` component (`components/integrity-remote`) is a separate,
generated design for the same job: it renders its own `run-mcp`,
`verify-release` and `supervisor.py` into a six-file release. The scripts here
are not produced by it, and the two release formats are not interchangeable.

## Files

| Path | Kind | Role |
| --- | --- | --- |
| `transport/run-mcp` | POSIX sh | Forced command. Checks the transport release with `verify-release --transport-only`, then execs the supervisor. |
| `transport/run-mcp-child` | POSIX sh | The one command the supervisor may start. Execs the facade release's `run-mcp`. |
| `transport/verify-release` | POSIX sh | Transport release check. With `--transport-only` it checks the transport release's own files; without arguments it also checks that the facade `run-mcp` is a regular file with the pinned digest and then runs the facade release's full `verify-release`. |
| `transport/transport-supervisor.py` | Python, Linux only | Per-connection stdio supervisor. Caps concurrent startups, relays bytes and cleans up the child's process tree. |
| `release/run-mcp` | POSIX sh | Facade entry point inside an immutable release. Runs the full `verify-release`, loads the reader environment and execs `guardian-memory-synapse-mcp`. |
| `release/verify-release` | Python | Builds (`build`) or checks (`verify`, or no arguments) the release's `release-inventory.json`: every file digest, mode and symlink, root ownership. |
| `release/action-log-passive-witness` | Python | Read-only, content-free witness. Reads one JSON line `{"event_uid", "request_sha256"}` and reports whether that Action Log event is `absent`, `exact` or a `collision`. |
| `release/action-log-witness.sudoers.in` | sudoers template | Lets the service principal run only the witness as the Action Log account. |
| `release/provision-state` | POSIX sh, root | One-time provisioning for a release: state directories, native trust bootstrap, Seed read ACL, witness sudoers and a witness health probe. |
| `release/refresh-seed-read-acl` | POSIX sh | Grants one `integrity-*` principal read-only ACLs on the Seed catalog and its WAL companions. |
| `host/integrity-custody-full-verify` | POSIX sh | Same as `release/run-mcp`, but bound to one fixed release directory and ending in `--custody-full-verify` (a scheduled full custody check). |
| `host/integrity-seed-wal-holder` | Python | Long-running holder. Keeps one idle `query_only` connection to the Seed catalog so its `-wal`/`-shm` files stay present for read-only readers, and reasserts read ACLs when the catalog is replaced. |
| `host/integrity-memory-mcp` | POSIX sh | Separate wrapper that starts `integrity-unified-mcp` from another release with an empty environment plus a fixed allowlist. |

## Start chain

```text
sshd (authorized_keys command=)
 └─ transport/run-mcp                      umask 077, clean Python env
     ├─ <transport release>/verify-release --transport-only
     └─ exec python3 -I transport-supervisor.py <transport release>/run-mcp-child
         │  waits for the first client bytes, then takes one of two flock slots
         │  in /dev/shm/integrity-transport-start-<uid>/
         └─ fork: keeper (child subreaper, watches the supervisor through a pidfd)
             └─ fork + setsid: /bin/sh run-mcp-child
                 └─ exec /bin/sh @FACADE_RELEASE_DIR@/run-mcp
                     ├─ @FACADE_RELEASE_DIR@/verify-release      (full inventory check)
                     ├─ . /etc/integrity-client-memory-lts.env   (reader token)
                     └─ exec venv/bin/guardian-memory-synapse-mcp --catalog ... \
                          --action-log-witness-helper @ACTION_LOG_WITNESS_HELPER@
```

The supervisor gives up the startup slot when the child writes its first
stdout bytes. When the connection ends, the keeper kills the child's process
group and every descendant it adopted. If no child slot frees up within the
queue wait (10 s), it exits with 75. If the client closes stdin before any
input arrives, it exits 0 and starts no child.

Provisioning chain (root, once per facade release):

```text
release/provision-state
 ├─ verify-release
 ├─ install -d state directories under /var/lib/integrity-client
 ├─ sudo -u integrity-client venv/bin/guardian native-trust-bootstrap ...
 ├─ refresh-seed-read-acl                       (default principal integrity-client)
 ├─ sed @ACTION_LOG_WITNESS@ action-log-witness.sudoers.in | visudo -c
 │    -> /etc/sudoers.d/integrity-client-action-log-witness-<release digest>
 └─ sudo -u integrity-client sudo -u codex-action-log action-log-passive-witness  (health probe)
```

## Placeholders

| Placeholder | Where | Live shape |
| --- | --- | --- |
| `@FACADE_RELEASE_DIR@` | `transport/run-mcp-child`, `transport/verify-release`, `host/integrity-custody-full-verify` | `/opt/integrity-client-memory-lts/releases/<64-hex digest>` |
| `@ACTION_LOG_WITNESS_HELPER@` | `release/run-mcp`, `host/integrity-custody-full-verify` | `/opt/integrity-client-memory-lts/releases/<64-hex digest>/action-log-passive-witness` |
| `@DEPLOYMENT_PROFILE_SHA256@` | `release/run-mcp`, `host/integrity-custody-full-verify` | 64-hex SHA-256 of `/etc/integrity-client-memory-lts.deployment-profile.json` (the script already writes the `sha256:` prefix) |
| `@MEMORY_RELEASE_DIR@` | `host/integrity-memory-mcp` (twice) | `/opt/integrity-memory/releases/<64-hex digest>` |
| `@ACTION_LOG_WITNESS@` | `release/action-log-witness.sudoers.in` | Already a template on the live host. `provision-state` substitutes it. |
| `@FACADE_RUN_MCP_SHA256@` | `transport/verify-release` | 64-hex SHA-256 of the facade release's `run-mcp` after its own placeholders are filled |

The release files are immutable and their digests are checked, so you must
substitute the placeholders before you compute `SHA256SUMS`, `artifact.sha256`
or `release-inventory.json`. Do not substitute them in an installed release.
`release/run-mcp` must stay byte-identical to the file whose digest the
transport `verify-release` pins.

## What must exist on the host

Accounts:

- `integrity-client`: the SSH login account for the forced command and the
  service principal. `HOME=/var/lib/integrity-client`.
- `codex-action-log`: owner of the Action Log database
  `/var/lib/codex-action-log/codex-action-log.sqlite3`. The witness runs as this
  account.
- `integrity-seed`: writer of the Seed catalog `/var/lib/integrity-seed/catalog.sqlite3`.
  Read-only readers are `integrity-*` accounts.

Files and directories (owner:group mode):

- `/opt/integrity-client-memory-lts/releases/<digest>/`: root-owned facade
  release with the `release/` scripts, `venv/` (the installed Guardian package
  with `bin/guardian` and `bin/guardian-memory-synapse-mcp`) and
  `release-inventory.json`. Nothing in it may be group- or world-writable.
- `/opt/integrity-client-memory-lts/transport-releases/<digest>/`: `root 0555`,
  with `run-mcp`, `run-mcp-child`, `transport-supervisor.py`, `verify-release`,
  `SHA256SUMS` and `artifact.sha256`, each `root 0444` or `0555`.
  `transport-supervisor.py` checks that `run-mcp-child` and its directory are
  owned by root and not group- or world-writable.
- `/etc/integrity-client-memory-lts.env`: `root:integrity-client 0640`. Its
  only key is `CODEX_LOG_TOKEN`. It may also set `INTEGRITY_TTT_PATH_CATALOG`
  and `INTEGRITY_TTT_PATH_CATALOG_SHA256`, but only together. Note that
  `provision-state` accepts only `CODEX_LOG_TOKEN`.
- `/etc/integrity-client-memory-lts.deployment-profile.json`: `root 0644`. See
  [docs/DEPLOYMENT_PROFILE.md](../../docs/DEPLOYMENT_PROFILE.md).
- `/var/lib/integrity-client/`: root-owned and not writable by
  `integrity-client`. `provision-state` creates `native-state/`,
  `architecture/` and `evidence/` (`integrity-client 0700`) and `provision/`
  (`root:integrity-client 0750`). `run-mcp` creates `seed-sessions/` (`0700`).
- `/dev/shm` must be a root-owned `1777` tmpfs. The supervisor creates its
  private gate directory there.
- Tools: `/bin/sh`, `/usr/bin/python3`, GNU coreutils `stat`, `sudo`,
  `visudo`, `setfacl`/`getfacl`, `getent`. The supervisor needs Linux with
  `pidfd_open`, `prctl(PR_SET_CHILD_SUBREAPER)` and `/proc/self/task/<tid>/children`
  (Python 3.9 or newer).

Forced-command line shape in `~integrity-client/.ssh/authorized_keys` (the
shape is an assumption; the live `authorized_keys` was not part of this batch):

```text
restrict,command="/opt/integrity-client-memory-lts/transport-releases/<transport-digest>/run-mcp" ssh-ed25519 AAAA... <device comment>
```

`transport/run-mcp` takes no arguments and ignores `SSH_ORIGINAL_COMMAND`.

`host/integrity-memory-mcp` expects `/etc/integrity-memory/memory-scopes.json`
and `/etc/integrity-memory/action-log-token`. `host/integrity-seed-wal-holder`
runs as `integrity-holder CATALOG [REFRESH_SCRIPT ...] [--refresh-command 'SCRIPT ARG ...']`,
for example under a service manager. The unit files that start it and the
scheduled full custody check are not included.

## Not included

- A separate host copy of the ACL refresher: on the live host the same script
  as `release/refresh-seed-read-acl` is also installed under a host-level name.
- `release-inventory.json`, `requirements.lock`, `SHA256SUMS`,
  `artifact.sha256`, wheels and the `venv/` itself. These are per-release
  build outputs.
- systemd units, timers and the live `authorized_keys`.

## Verified / not verified

Covered by `tests/test_linux_core_transport.py`. Public CI runs every case on
Ubuntu; on Windows the 19 POSIX-only and Linux-only cases skip. The cases use
temporary directories on a CI runner, and no real core host took part.

- On every platform:
  - Every file is UTF-8 with LF endings.
  - Shell scripts start with `#!/bin/sh` and `set -eu`.
  - The Python scripts compile.
  - No file contains a release-digest path, an IPv4 address or any 64-hex
    value other than the all-zero health-probe digest.
  - The placeholders are exactly the set documented above.
  - The start-chain references match between files.
  - `host/integrity-custody-full-verify` differs from `release/run-mcp` only
    in the fixed directory and the final flag.
  - `host/integrity-memory-mcp` has no command substitution in the argument
    list of `env -i`; the Action Log token is read by the child shell that
    `env` starts, so the value is never on any command line.
- The pure helpers, on every platform:
  - argument parsing in `integrity-seed-wal-holder`;
  - path and digest canonicalisation in `verify-release`;
  - the witness's `absent`, `exact` and `collision` answers, and its rejection
    of malformed requests, against a temporary SQLite database.
- POSIX only (skipped on Windows):
  - `sh -n` on every shell script;
  - `refresh-seed-read-acl` rejects bad principal names before it changes
    anything;
  - `provision-state` refuses arguments;
  - `release/run-mcp` refuses a directory whose name is not a digest;
  - a `verify-release` build, verify and tamper round trip in a temporary
    directory, without the root-ownership check.
  - `host/integrity-memory-mcp`, with its token file and program pointed at
    a temporary directory: the program receives the token in its
    environment, and the token appears in no recorded argument list.
- Linux only (skipped elsewhere):
  - `transport-supervisor.py` relays a request and response to a fake child,
    returns the child's exit status and creates a private `0700` gate with two
    slot files;
  - it starts no child when stdin closes before any input;
  - it rejects a wrong argument count.

Not verified here:

- Anything that needs root, real accounts, sudo, ACLs, a real Seed catalog,
  an Action Log database owned by another account or the Guardian package.
  This covers `provision-state` past its argument check,
  `refresh-seed-read-acl` past name validation, the full `run-mcp` path and
  `integrity-memory-mcp` against a real release and token file.
- The supervisor's `main()` custody checks on root-owned paths. Also its
  behaviour under SIGKILL, slot exhaustion, the queue-wait timeout and stuck
  children.
- An end-to-end SSH session through the forced command.
- Whether the placeholder substitution yields byte-identical files to a given
  live release. That depends on the values you substitute.
