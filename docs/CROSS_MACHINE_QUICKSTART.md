# Two machines: Integrity core on A, client on B

[Documentation](README.md) · [Project README](../README.md)

This guide runs an Integrity core on Linux machine **A** and connects an MCP
client (Codex, Claude Code, Antigravity, or the Native profiles) on machine
**B**. The transport is an OpenSSH **forced command**:

```text
B: MCP client ──stdio──▶ ssh -T … ──SSH──▶ A: sshd ─▶ authorized_keys command=
                                              └▶ run-mcp ─▶ verify-release ─▶ supervisor ─▶ your server
```

- **No new listener.** A runs only its existing `sshd`. Nothing else accepts
  connections and no port is opened for Integrity.
- **Same server, same guarantees.** A runs the server you would otherwise run
  locally, with the same arguments. SSH adds authentication and a channel. It
  does not change admission, signatures, receipts or append rules.
- **One key per device.** Every device gets its own key, and its
  `authorized_keys` line fixes that device's id. A client cannot choose a
  different device, server, catalog or command, and it cannot get a shell.
- **Pinned host key.** B checks A's host key against a dedicated
  `known_hosts` file. Nothing in this guide disables that check.
- **Immutable releases.** Each server configuration is a directory named after
  its digest. A changed, added, linked or writable file stops the session
  before any server code runs.

The `integrity-remote` component builds the release on A, prints
`authorized_keys` lines and generates the client command on B. It installs no
service, edits no `authorized_keys` file and never writes a private key.

## Prerequisites

- **A (core):** Linux with an OpenSSH server, GNU coreutils and Python 3.11+.
  The server you choose must already work there over local stdio.
- **B (client):** any OS with an OpenSSH client (`ssh`) and Python 3.11+.
  Windows 10/11 includes one.
- Both machines need a clone of this repository and a virtualenv outside it:

  ```bash
  python -m venv ../integrity-venv
  . ../integrity-venv/bin/activate            # Windows: ..\integrity-venv\Scripts\Activate.ps1
  python -m pip install . ./components/integrity-remote
  ```

The examples use `core-a.example.invalid` for A, the service account
`integrity-core` and the device id `laptop-b`. Replace them with your own.

## 1. On A: describe the server

Create `server.json` containing the exact stdio command. `argv[0]` must be an
absolute path. The literal `{device_id}` is replaced by the device id from the
`authorized_keys` line. The server also receives that value as
`INTEGRITY_REMOTE_DEVICE_ID`. You can write `{"argv": [...], "env": {...}}`
or the `{"command": ..., "args": [...]}` shape used by MCP configs.

**Quick try: the read-only example (4 tools).** Create its catalog on A as in
[examples/local-memory](../examples/local-memory/README.md). `setup.py` writes
a `server.json` in that shape:

```bash
python examples/local-memory/create_case.py --output ../integrity-local-memory/case
python examples/local-memory/setup.py --catalog ../integrity-local-memory/case/private/catalog.sqlite --output ../integrity-local-memory/clients
```

The service account in step 2 must be able to read the catalog. For a first
try, use **user mode** (step 2b) under your own account.

**Full Native lifecycle.** Point `argv` at your owner-operated Memory instance.
That is `guardian-memory-synapse-mcp --trust-profile personal-native …`, with
the paths described in [native-onboarding.md](native-onboarding.md#supported-owner-routes-and-prerequisites).
A source checkout is not such an instance. If each device has its own Native
device enrollment, pass it as, for example, `--native-device-id device:{device_id}`.

Do not put secrets in `server.json`. It is world-readable inside the release.
Let the server read its own protected credential file instead.

## 2. On A: build the release

**2a. Hardened (recommended).** Build a root-owned release and run sessions
under a dedicated account with `/bin/sh` as its shell:

```bash
sudo useradd --system --create-home --home-dir /var/lib/integrity-core --shell /bin/sh integrity-core
sudo ../integrity-venv/bin/integrity-remote core init --mode hardened --service-user integrity-core \
  --root /opt/integrity-core --server-json server.json
```

**2b. User mode (trying it out, CI).** The release is owned by your account and
sessions run as you:

```bash
integrity-remote core init --root "$HOME/integrity-core" --server-json server.json
```

Both commands print `release` (`…/releases/<digest>`) and `forced_command`.
Running the command again with identical input reuses that release. The
`--max-sessions` option (default 2) caps concurrent sessions. Extra sessions
wait up to `--queue-wait-seconds` and are then refused with exit code 75.

In user mode, the account that owns the release could still change it. SSH
clients cannot, because `restrict` and the forced command give them no shell.
Only hardened mode protects the release from the session account itself.

## 3. On B: create a device key

```bash
ssh-keygen -t ed25519 -f ~/.ssh/integrity_core_a -C laptop-b
```

Send the **public** half (`~/.ssh/integrity_core_a.pub`) to A by any channel.
The private key never leaves B. Use a passphrase together with an agent, or a
hardware key (`-t ed25519-sk`), if your client can unlock it non-interactively.
The transport runs with `BatchMode=yes`.

## 4. On A: authorize the device

```bash
integrity-remote authorize --release /opt/integrity-core/releases/<digest> \
  --device-id laptop-b --public-key laptop-b.pub > laptop-b.line
cat laptop-b.line
```

The line looks like this:

```text
restrict,no-user-rc,command="/opt/integrity-core/releases/<digest>/run-mcp --device laptop-b" ssh-ed25519 AAAA… integrity-remote:laptop-b
```

Review it, then append it to the service account's `authorized_keys`:

```bash
sudo install -d -m 0700 -o integrity-core -g integrity-core /var/lib/integrity-core/.ssh
sudo sh -c 'cat laptop-b.line >> /var/lib/integrity-core/.ssh/authorized_keys'
sudo chown integrity-core: /var/lib/integrity-core/.ssh/authorized_keys
sudo chmod 0600 /var/lib/integrity-core/.ssh/authorized_keys
```

`--from 192.0.2.0/24` adds an OpenSSH `from=` restriction. By default only
Ed25519, ECDSA and FIDO keys are accepted. `--allow-rsa` accepts RSA keys of
3072 bits or more.

## 5. On B: pin A's host key

```bash
ssh-keyscan -t ed25519 core-a.example.invalid > ~/.ssh/integrity_core_a_known_hosts
ssh-keygen -lf ~/.ssh/integrity_core_a_known_hosts
```

On A, print the real fingerprint and compare the two over a channel you trust:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

If they differ, stop and do not continue. For a non-default port, pass `-p PORT` to `ssh-keyscan`. The
file then holds a `[host]:port` entry.

## 6. On B: generate the client transport and check it

```bash
integrity-remote client-upstream --host core-a.example.invalid --user integrity-core \
  --identity ~/.ssh/integrity_core_a --known-hosts ~/.ssh/integrity_core_a_known_hosts \
  --output ../integrity-remote-b/upstream.json
integrity-remote check ../integrity-remote-b/upstream.json
```

`check` opens the real path: ssh, host key, device key, forced command,
release check, supervisor and server. It runs MCP `initialize` and
`tools/list` and prints the server name and tool names. It calls no tool.

Choose the output for your client with `--format`:

| Client | `--format` | Use it as |
| --- | --- | --- |
| Native profiles (Codex, Claude Code, Antigravity hooks) | `upstream-json` (default) | `--upstream-json` for `integrity_client_memory.native_install` |
| Claude Code, Antigravity (plain MCP) | `claude-mcp-json` | `claude --strict-mcp-config --mcp-config FILE` or the `mcpServers` table |
| Codex (plain MCP) | `codex-toml` | merge the `[mcp_servers.NAME]` table into a project config |

The generated command uses `-F none`, so your own `~/.ssh/config` cannot change
it. For a bastion host, add `--jump user@bastion.example.invalid`. Keep the
generated files outside the repository. They contain local paths.

## Revoke, rotate, upgrade, roll back

- **Revoke a device:** delete its line from `authorized_keys`. New sessions are
  refused at once. To end a session that is still open, stop its process on A
  (`pkill -u integrity-core -f 'run-mcp --device laptop-b'`).
- **Rotate a key:** authorize the new key under the same device id, check it
  from B, then delete the old line.
- **Change or upgrade the server:** run `core init` with the new `server.json`.
  You get a new digest, and the old release stays untouched. Point the lines
  at the new release one device at a time and check each device.
- **Roll back:** point the lines back at the previous release directory.
- **Verify a release at any time:**
  `integrity-remote core verify /opt/integrity-core/releases/<digest>`.

## Tested and not tested

`tests/test_two_machine_ssh.py` reproduces two machines on one Linux host.
They have separate directories, keys and `known_hosts`, and a non-root `sshd`
on loopback. The test runs the real Guardian Memory MCP server: NativeTrust,
signatures, Seed catalog, HTTP Action Log and witness. It runs admission,
open, append and close once over local stdio and once over SSH. Tool sequence,
receipt shapes and append outcome must match. It also checks four refusals: an
unknown key, a requested remote command, a changed host key and a revoked key.
The `Cross-machine SSH` workflow runs it on every pull request.

What it does not claim:

- The producer envelope is synthetic, as in the other wire tests. A live
  Codex, Claude Code or Antigravity owner route remains a separate acceptance,
  see [native-onboarding.md](native-onboarding.md).
- The core side is Linux only. macOS and Windows cores are not supported. The
  client side is tested on Linux, and the generated command is the standard
  OpenSSH client invocation used on Windows.
- The bus and seats hub are not carried by this transport. They keep their
  own token model. This transport also does not enroll hosts or grant action
  authority. Memory is evidence, not permission.
