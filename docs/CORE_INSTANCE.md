# A core instance on one Linux account

[Documentation](README.md) · [Project README](../README.md) · [What is verified](STATUS.md)

This is install stage 2: the core write path, kept in one private folder of
one Linux account. Clients on other machines reach it over the OpenSSH forced
command that the [two-machine quickstart](CROSS_MACHINE_QUICKSTART.md)
describes. Stage 1, the [local memory profile](LOCAL_MEMORY.md), needs no
Linux machine and is the faster start for one computer.

## What it is and what it is not

`guardian-core-instance init` creates one folder that holds:

- an Action Log database, where every event is written;
- a Seed catalog that is built from that database;
- native trust: the signing keys of the instance, as files;
- the custody ledger and the Turn Memory stores, with a signed registration
  for every turn and a signed receipt for how it ended.

Every session is one `guardian-core-instance serve` process. It is the
Guardian Memory MCP server on stdio, the same server that the two-machine test
runs. The process:

- starts the Action Log HTTP service on a loopback port that the system picks,
  with a token that exists only in that process and is never written to disk
  or passed on a command line;
- sends every append through admission, a one-use grant and that service;
- confirms the write by reading the Action Log database (the witness);
- imports new Action Log events into the catalog before every request, so a
  session sees what other sessions wrote.

Nothing here needs root, sudo, systemd or a listening network port.

It is **not** the hardened layout of
[`deploy/linux-core`](../deploy/linux-core/README.md):

- **Linux only.** On Windows and macOS `init` refuses and names the two ways
  forward: the local memory profile, or this machine as a client of a Linux
  core.
- **One account.** The folder and the keys belong to one account. Any process
  of that account can read the keys and sign with them. There is no separate
  service account and no systemd sandbox.
- **One device enrollment.** The `authorized_keys` line fixes the device id of
  an SSH client, but the instance writes under its own single device. It does
  not record which SSH device wrote an event.
- **The server of the core, not of the local profile.** The work-claim tools
  of stage 1 (`integrity_work_claim` and the others) are not part of this
  server.
- **Written for `integrity-action-log` 2.11.0.** With another version
  installed, `init` and `serve` refuse.
- **No production authority.** Memory is evidence for an agent, never
  permission to act.

## Install

On the Linux machine:

```bash
git clone https://github.com/BlackBadHope/Integrity.git
cd Integrity
python -m venv ../integrity-venv
. ../integrity-venv/bin/activate
python -m pip install . ./components/integrity-action-log ./components/integrity-remote
guardian-core-instance init
```

`init` prints the folder, the instance id and the server command. It writes
one event, "Integrity core instance created", so the catalog is not empty.

The folder is `$XDG_DATA_HOME/integrity-core`, or
`~/.local/share/integrity-core`. `--home PATH` or `INTEGRITY_CORE_HOME`
selects another folder; it must be empty or missing, and it must not be inside
a clone. The folder has mode 0700; the marker, the Action Log configuration,
the database and the key files are private to the account.

## Check

```bash
guardian-core-instance doctor
```

`doctor` only reads, and it starts no server. It checks that the Action Log
package has the expected version, that the folder and the key files are closed
to other accounts, that the Action Log database is readable, that the catalog
verifies, and that the native trust genesis verifies. A catalog that is behind
the Action Log is a warning: the next request imports the missing events.
`doctor` exits 1 when a check fails; `--json` prints the report as JSON.

## Connect clients

Build an `integrity-remote` release whose server is this instance:

```bash
guardian-core-instance server-json > server.json
integrity-remote core init --root "$HOME/integrity-core-release" --server-json server.json
```

`server.json` holds two paths from this machine, the Python of the
environment and the instance folder, and no secret. `core init` prints
`release` and `forced_command`. From here follow the
[two-machine quickstart](CROSS_MACHINE_QUICKSTART.md) from step 3: a key for
each device, one `authorized_keys` line for each device in this account, the
pinned host key, and `integrity-remote client-upstream` on the client. The
client can be any system with an OpenSSH client.

This is the user mode of that guide (step 2b): sessions run as the account
that owns the instance. A release allows two sessions at once by default
(`--max-sessions`).

## Remove

```bash
guardian-core-instance uninstall          # says what would be removed
guardian-core-instance uninstall --yes    # removes the instance folder
python -m pip uninstall integrity-guardian integrity-action-log integrity-remote
```

`uninstall --yes` deletes every event, receipt and key of the instance. It
refuses a folder that is not a core instance. Remove the `authorized_keys`
lines of its clients and the release folder yourself.

## What is verified

- `tests/test_core_instance.py` runs in public CI on Ubuntu. Every test starts
  the real `serve` process and talks to it over stdio:
  - `init` makes a private instance that `doctor` accepts, and a second `init`
    into the same folder changes nothing;
  - `doctor` fails when a key file is readable by other accounts;
  - a second session reads the event that the first one wrote, after the first
    server process has ended;
  - two sessions open at the same time both write;
  - `uninstall` is a dry run until `--yes`, and it refuses a foreign folder;
  - the instance is reached through an OpenSSH forced command: a device with
    only an SSH key runs a full turn, and a local session then reads its event.
- The `Cross-machine SSH` workflow runs these tests as required: a missing
  prerequisite fails the job. The main workflow fails on Ubuntu when one of
  three of them is skipped.
- CI also runs `init`, `doctor`, `server-json` and `uninstall` with the
  installed command on Ubuntu.
- On Windows, CI checks that `init` refuses and creates nothing.

Not verified:

- **A real agent client.** The producer envelope in the tests is synthetic, as
  in the other wire tests. No Claude Code, Codex or Antigravity session wrote
  to an instance made by this command.
- The install line above on its own. CI installs every public distribution,
  not only these three.
- Two separate hosts. The forced-command test reproduces two machines on one
  Linux host, with separate folders and keys and an `sshd` on loopback.
- The hardened mode of `integrity-remote` (a root-owned release and a service
  account) with this instance.
- More than two sessions at once, long use, backup and restore, and an upgrade
  of this command or of the Action Log over an existing instance.
- A core on Windows or macOS. This is a known limitation, not a planned part
  of this stage.
