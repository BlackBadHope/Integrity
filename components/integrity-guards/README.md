# integrity-guards

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

## Known limits

- The lock guard cannot resolve a command name built at run time (`$(echo ssh)`,
  variables, aliases). On malformed hook input (not JSON) it exits with an error
  instead of answering.
- Under Antigravity the repeat hook only answers `allow`; its advice text is
  not delivered there.
- `uroboros-share hook` without a day uses the configured time zone, while the
  hook names its daily metric files by the machine's local date. Pass the day
  explicitly if the two differ.

## What is verified

- The unit tests in `tests/` were run on Windows with Python 3.12. They use
  the invented examples, temporary configuration and a fake command runner;
  commands are parsed, never sent anywhere. The route CLI tests start only the
  current Python interpreter.
- The tests are written to pass or skip on Linux, but **nothing was run on
  Linux**.
- There is **no live acceptance**: the guards were not exercised as installed
  hooks of a real agent as part of this package.

## License

Business Source License 1.1. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
