# integrity-guards

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

Hook-side guards for coding agents: they read one tool call from a hook,
classify it, and answer with a warning or a refusal. They never run the
command themselves.

One entry point, `integrity-guards`, carries every guard:

| Command | Hook | What it checks |
|---|---|---|
| `lock-guard [--enforce] [--exit-code]` | PreToolUse | A shell call that **changes** a remote host (ssh, plink, scp, rsync, PowerShell remoting, Proxmox guest exec, ...) needs a live Integrity lock held by this session, and no lock of another session on that host. Only the part that runs on the remote side is classified; reads pass. `shadow` (default) warns, `--enforce` refuses. |
| `lock-guard record` | PostToolUse | Caches the `active_locks` of an Integrity admission and this session's own lock receipts, per session. |
| `rule-guard hook [--warn-only]` | PreToolUse | Rules that are easy to forget: device commands only in the exact syntax of a device registry profile; no CRLF scripts uploaded to Unix hosts; no reading of protected secret files except through the secret tool; no `BEGIN ... ROLLBACK` "dry run" against a database that cannot roll back; an optional browser-JavaScript warning. |
| `rule-guard validate --profile P --line L` | - | Checks device command lines against the registry by hand. |
| `rule-guard-antigravity` | PreToolUse | The rule guard with the Antigravity reply contract (always an explicit `allow`, with the warning as reason). |
| `rules-drift [--hook]` | SessionStart | Lists rule files that are new or changed since the last export of the rules. |
| `install-rule-guard install\|rollback` | - | Adds or removes the rule-guard entry in a Claude Code `settings.json` (warn-only), with a backup. It only runs when you call it. |
| `uroboros run\|validate\|list` | - | Runs a compiled route: a fixed, parameter-checked list of commands with expected output. Write routes are a dry run unless `--apply` **and** `INTEGRITY_ROUTE_WRITE_GO` names the route; a backup step runs before any write. |
| `uroboros-repeat-hook [--vendor V]` | PreToolUse | Notices the same remote command chain the second time in a session and points to a compiled route that covers it, or asks for one to be recorded. Optional pin guard: warns when a write touches files pinned by a release authority. Advisory only. |
| `uroboros-share hook [day]` / `transcripts [days]` | - | Daily share of remote production calls that went through a route. |
| `runbooks init\|doctor\|validate\|explain\|serve\|report\|proposals\|uninstall` | - | Event-driven runbooks, off by default: a log line, journald entry, loopback syslog datagram, loopback webhook or timer starts a turn that follows a compiled route. Read routes run; write routes become proposals that ask for an operator GO. See [Event-driven runbooks](#event-driven-runbooks). |

Every guard fails open on its own errors except the lock guard in enforce
mode, which refuses a remote change it could not classify. The rule guard has
a 0.9 s budget; past it, it allows.

## Configuration on a clean machine

Nothing names a particular network. Without configuration:

- the lock guard has no host table, so every remote host is "unknown" and a
  remote change is warned about (or refused with `--enforce`);
- the rule guard still warns about device CLI write lines sent over
  ssh/telnet-like tools without a declared `registry-profile:`, but a
  declared profile can only be checked once a registry is configured (until
  then it passes silently); the CRLF rule works; the secret, SQL and browser
  rules stay inactive;
- the repeat hook still fingerprints chains, with `?` as the host;
- route lists are empty.

Write a JSON file like [`configuration.example.json`](configuration.example.json)
and name it in `INTEGRITY_GUARDS_CONFIG`. All values in the example are
invented. Sections:

- `lock_guard`: `hosts_file` (see [`examples/hosts.example.json`](examples/hosts.example.json):
  canonical id -> aliases and addresses, plus Proxmox guest ids), `state_dir`,
  `server_lock_kind` (set `true` once your memory server accepts `kind=lock`;
  until then shadow mode stays silent unless a foreign lock is cached),
  `standard_ssh_configs` (regexes of `ssh -F` files you trust).
- `rule_guard`: `mode` (`off`, `warn`, `enforce`), `device_registry` (see
  [`examples/device-registry.example.json`](examples/device-registry.example.json)),
  `device_tool_patterns` and `device_address_patterns` (what marks a command
  as aimed at a device), `exempt_command_patterns` (runners that already use
  the registry), `protected_secret_paths`, `secret_tool`, `sql_write_targets`,
  `sql_write_marker` (a write to such a target needs this marker in the
  command), `browser_js_warning`.
- `rules_drift`: `memory_dir`, `export`.
- `uroboros`: `compiled_routes` (see [`examples/compiled-routes/`](examples/compiled-routes)),
  `hosts`, `aliases`, `host_patterns`, `host_route_markers`, `ignore_words`,
  `run_prefix`, `prod_patterns`, `timezone_offset_hours`, `transcripts_dir`,
  `state_dir`, `pin_guard`.

Environment variables win over the file: `INTEGRITY_LOCK_GUARD_HOSTS`,
`INTEGRITY_LOCK_GUARD_STATE`, `INTEGRITY_LOCK_GUARD_SERVER_LOCKS=1`,
`INTEGRITY_LOCK_GUARD_SSH_CONFIGS`, `INTEGRITY_RULE_GUARD_MODE`,
`INTEGRITY_RULE_GUARD_REGISTRY`, `INTEGRITY_COMPILED_ROUTES`,
`INTEGRITY_UROBOROS_STATE`, `INTEGRITY_UROBOROS_PINS`, `UROBOROS_RUN_PREFIX`.
State goes under `INTEGRITY_GUARDS_STATE_ROOT` (default `~/.integrity-guards`).

The device registry and the host table are yours to write. The examples
only show the format.

## Hook wiring (Claude Code)

```json
{"hooks": {
  "PreToolUse":  [{"matcher": "Bash|PowerShell", "hooks": [
    {"type": "command", "command": "python -m integrity_guards lock-guard"},
    {"type": "command", "command": "python -m integrity_guards rule-guard hook --warn-only"},
    {"type": "command", "command": "python -m integrity_guards uroboros-repeat-hook"}]}],
  "PostToolUse": [{"matcher": "mcp__.*integrity.*", "hooks": [
    {"type": "command", "command": "python -m integrity_guards lock-guard record"}]}]
}}
```

Other harnesses: `lock-guard --exit-code` exits 2 on a refusal;
`uroboros-repeat-hook --vendor codex|antigravity` adapts the reply.
`scripts/uroboros-run.sh` is a thin shell wrapper around `uroboros list|run`.

## Event-driven runbooks

`integrity-guards runbooks` is a small dispatcher: an infrastructure event
starts a turn that follows a compiled route. It is **off by default**. Nothing
is watched until you create an instance, add triggers and set
`"enabled": true`. The format and the order of the checks are described in
[Uroboros: event-triggered turns](../../docs/UROBOROS.md#event-triggered-turns);
[`examples/runbook-triggers`](../../examples/runbook-triggers/README.md) has a
configuration with one trigger of each source.

```bash
integrity-guards runbooks init                  # instance with "enabled": false
integrity-guards runbooks validate              # triggers against the compiled routes
integrity-guards runbooks explain TRIGGER --line "a log line"   # what it would do; runs nothing
integrity-guards runbooks doctor                # read-only self-check
integrity-guards runbooks serve                 # the loop (a service runs it)
integrity-guards runbooks report --hours 24     # turns, proposals, wall time, reported model cost
integrity-guards runbooks proposals             # write routes that wait for an operator GO
integrity-guards runbooks uninstall [--yes]     # dry run without --yes
```

The instance folder is `INTEGRITY_RUNBOOKS_HOME`, or `integrity-runbooks`
under `%LOCALAPPDATA%` on Windows and `$XDG_STATE_HOME` (or
`~/.local/state`) on Linux; `--home` selects another one. It holds
`runbooks.json`, the hash-chained `journal.jsonl` and `state.json` (file
offsets, journald cursors, dedup keys and rate windows, kept across a
restart).

Safety:

- Each value taken from a log line is checked with the route's own
  full-match parameter regex before anything starts. A rejected line is kept
  only as a SHA-256 hash.
- The kill switch is asked for the adapter's vendor on every match:
  `service` for the model-free `route` adapter, `claude` for `claude-p`,
  `codex` for `codex-exec`. With `killswitch.required` (the default) and no
  `integrity-killswitch` package, nothing runs.
- Only `safety: read` routes run. A `safety: write` route becomes a
  proposal: a journal record, the optional `notify` command (it reads the
  proposal as JSON on stdin), and the exact command an operator would run
  with a GO.
- Limits: a dedup key with a suppression window and an hourly limit per
  trigger; `max_turns_per_hour` and `max_concurrent` for the whole
  dispatcher. Proposals count against the same limits.
- Noise: `rejected`, `blocked`, `busy`, `suppressed` and `rate-limited`
  events are folded to one journal record (and at most one sink call) per
  trigger, kind and reason in each `limits.noise_window_s` (default 60 s);
  the next record carries the folded count in `repeats_before`, and
  `runbooks report` counts the folded events.
- Syslog and webhook listeners bind to loopback addresses only. A webhook
  can require a token header, `X-Integrity-Token`, whose value comes from the
  environment variable named in `listen.webhook_token_env`. Without it any
  local process can post an event; `runbooks doctor` warns about it.
- Adapters are argv lists, never a shell. An adapter that carries text that
  skips the client's permissions (`dangerously-...`, `bypassPermissions`,
  `danger-full-access`, `yolo`) anywhere in an argument, including
  `--flag=value` and `-c key=value` forms, is refused. A command adapter
  cannot use the `service` vendor; when any word of its argv (including a
  command string for `sh -c`, `cmd /c` or `pwsh -Command`) carries a kill
  switch vendor marker such as `claude` or `codex`, its vendor must be that
  one, and markers of two vendors are refused. This is a static check: a
  script that starts a model itself is not visible to it, so keep the kill
  switch's process-ancestry check in the client's hooks. A model turn runs in the folder
  named by the adapter's `cwd`, so that folder's hooks apply: point it at a
  project where Integrity admission and the guards are installed.

**Linux service.** `init --systemd-user` writes
`~/.config/systemd/user/integrity-runbooks.service` and does not start it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now integrity-runbooks.service
journalctl --user -u integrity-runbooks.service
```

A journald trigger needs read access to the journal it names (the user
journal, or membership of `systemd-journal` for the system journal).

**Windows.** `init --windows-task` prints a `schtasks /Create /SC ONLOGON`
command that runs `pythonw -m integrity_guards runbooks serve` at logon
under your account; init does not run it. Remove it with
`schtasks /Delete /TN IntegrityRunbooks /F`. journald sources are Linux only;
file, syslog, webhook and timer sources work on both systems.

## Known limits

- The lock guard cannot resolve a command name built at run time (`$(echo ssh)`,
  variables, aliases). On malformed hook input (not JSON) it exits with an error
  instead of answering.
- Under Antigravity the repeat hook only answers `allow`; its advice text is
  not delivered there.
- `uroboros-share hook` without a day uses the configured time zone, while the
  hook names its daily metric files by the machine's local date. Pass the day
  explicitly if the two differ.
- The runbook dispatcher reads a log file from the end when it first sees
  it; lines written while it was stopped are read on the next start, but a
  file rotated twice while it was stopped loses the lines of the first
  rotation. A turn that is refused as `busy` is not queued.
- `runbooks report` counts model cost only when the client prints it as
  JSON (`total_cost_usd`, as `claude -p --output-format json` does); other
  turns are listed as having no reported cost.

## What is verified

- The unit tests in `tests/` run in public CI on Ubuntu and Windows with
  Python 3.11 and 3.12. They use
  the invented examples, temporary configuration and a fake command runner;
  commands are parsed, never sent anywhere. The route CLI tests start only the
  current Python interpreter.
- `tests/test_runbooks.py` drives the dispatcher with invented routes that
  start only the current Python interpreter and a stub agent adapter; no model
  is called. CI also runs `runbooks init`, `doctor` and `uninstall` with the
  installed command on both systems.
- Nothing beyond these unit tests was run on Linux.
- There is **no live acceptance**: the guards were not exercised as installed
  hooks of a real agent as part of this package.

## License

Business Source License 1.1. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
