# integrity-killswitch

[Project README](../../README.md) · [Documentation](../../docs/README.md) · [What is verified](../../docs/STATUS.md)

A local switch that turns agent access off per vendor, or for all agents at
once, on one workstation.

Agents and the scripts they call ask the switch before acting:
`integrity-killswitch check` exits 0 when access is allowed and 3 when it is
blocked. The switch keeps its state in one JSON file and appends every change
to an audit log.

- `off VENDOR` and `panic` tighten access. Any caller may do this, including
  an agent that wants to stop itself.
- `on VENDOR` and `resume` restore access. Only the operator may do this: an
  interactive shell or a browser with no agent process among its ancestors.
- `serve` starts a dashboard on `127.0.0.1` (default port 8890) with the same
  controls. It checks the `Host` and `Origin` headers, and it finds which
  process opened the TCP connection to decide whether a request may restore
  access. Every value that a caller can set (titles, reasons, log lines) is
  HTML-escaped before it is shown.
- `sync-bus [--apply]` copies the switch state to the principals file of an
  agent bus on another host, over an ssh command that you configure. Without
  `--apply` it only shows what would change.

## What it does not do

This is a cooperative gate. It does **not** terminate processes. Any process
of the same user can edit the state file or simply not ask the switch. Real
enforcement is the revocation on the bus host, which `sync-bus --apply`
writes; that only works if the bus honours its principals file.

The caller is identified by its process ancestry. On Windows this uses the
Toolhelp32 snapshot; when Git for Windows' msys `ssh` breaks the Windows
parent chain, the msys `ps` table bridges it. **On other systems the
ancestry is not read**: every caller is classified as unknown, so `off`,
`panic` and `check` work, but `on` and `resume` are always refused (fail
closed) and the dashboard cannot identify the requesting process. Restoring
access there means editing the state file by hand.

## Install it on its own

The switch does not need the rest of Integrity. The package has no
dependencies and installs nothing else: no Guardian, no memory, no bus. It
needs Python 3.11 or newer.

From a clone of this repository:

```bash
python -m pip install ./components/integrity-killswitch
```

Without a clone (pip fetches the repository itself and builds only this
folder; it needs `git`):

```bash
python -m pip install "integrity-killswitch @ git+https://github.com/BlackBadHope/Integrity@main#subdirectory=components/integrity-killswitch"
```

To build a wheel that you can copy to another machine:

```bash
python -m pip wheel --no-deps -w dist ./components/integrity-killswitch
python -m pip install dist/integrity_killswitch-0.1.0a1-py3-none-any.whl
```

No release carries this wheel yet, and the package is not on PyPI. The tag
`v7.0.1` does not contain this component; use `main`.

## Check the installation

```bash
integrity-killswitch doctor
```

`doctor` only reads. It creates no state file, writes no log line and opens
no connection. It reports the package version, the configuration in use, the
state file and what it blocks now, whether the state folder is writable, the
audit log, how the caller is classified, and whether bus sync is configured.
It exits 0 when no check fails and 1 otherwise; `--json` prints the same
report as JSON.

On a system other than Windows the `caller` line is a warning, for the reason
given in "What it does not do".

## Remove it

```bash
integrity-killswitch uninstall          # lists the files, removes nothing
integrity-killswitch uninstall --yes    # removes them
python -m pip uninstall integrity-killswitch
```

`uninstall` removes the files the switch wrote for this user: the state file,
its temporary file, the audit log and the rotated log. It leaves your
configuration file alone. When the stored state blocks something (a vendor
that is off, a scope that is off, master panic, or a state file that cannot
be read), removing it would restore access, so `uninstall --yes` follows the
rule for `on` and `resume`: only the operator may run it. On a system other
than Windows it is then always refused and you delete the listed files by
hand.

## Configuration on a clean machine

Nothing is required. Without a configuration file the switch knows the
built-in vendors `claude`, `codex`, `antigravity` and `grok`, keeps its state
in the per-user state directory (`%LOCALAPPDATA%\integrity-killswitch` on
Windows, `$XDG_STATE_HOME/integrity-killswitch` or
`~/.local/state/integrity-killswitch` elsewhere) and has no bus sync.

To change that, write a JSON file like
[`configuration.example.json`](configuration.example.json) (all values in it
are invented) and point to it with `--config PATH` or
`INTEGRITY_KILLSWITCH_CONFIG`:

| Key | Meaning |
|---|---|
| `state_file`, `log_file` | Where the state and the audit log live. `INTEGRITY_KILLSWITCH_STATE` / `INTEGRITY_KILLSWITCH_LOG` and `--state` win over them. The log defaults to the state file's folder. |
| `dashboard_port` | Port for `serve` when `--port` is not given. |
| `vendors` | Extra vendors: `{"name": {"title": "...", "markers": ["process-name-part", ...]}}`. A process whose name contains a marker counts as that vendor. Built-in names cannot be redefined. |
| `msys_ps` | Path to the msys `ps.exe` used to bridge ssh process chains on Windows. |
| `bus_sync.ssh_command` | The ssh command as a list, ending with the destination. Required for `sync-bus` and `--sync`. |
| `bus_sync.principals_path` | Absolute path of the principals file on the bus host. Required. |
| `bus_sync.remote_command` | The interpreter started on the bus host; it reads the sync script from stdin. Default `sudo -n python3 -`. |
| `bus_sync.host_label` | A name for messages only. |

The sync script is sent over ssh stdin. Vendor names and the principals path
are checked against strict patterns before they are put into the remote
command line.

## Quick use

```bash
integrity-killswitch status
integrity-killswitch off codex --reason "stop for review"
integrity-killswitch panic --reason "stop everything"
integrity-killswitch check --vendor claude --action direct_ssh; echo $?
integrity-killswitch resume            # operator shell only
integrity-killswitch serve             # http://127.0.0.1:8890/
integrity-killswitch --config my.json sync-bus          # dry run
```

`scripts/windows/` holds three `.cmd` launchers (panic, dashboard, status)
that call `python -m integrity_killswitch`. The package must be installed in
the Python that `python` starts.

## What is verified

- The unit tests in `tests/` run in public CI on Ubuntu and Windows with
  Python 3.11 and 3.12. They use
  fake process ancestry, a fake TCP peer lookup and a stand-in ssh command;
  they never touch real processes, the network or a real bus.
- Public CI also installs the built wheel alone into an empty environment on
  both systems, checks that no other Integrity package came with it, and runs
  `doctor`, `off`, `check`, `uninstall` and `pip uninstall`
  (`.github/scripts/killswitch_standalone_check.py`).
- On Linux one case skips: it reads the Windows TCP owner table. Nothing
  beyond these unit tests and the install check was run on Linux.
- There is **no live acceptance**: the dashboard, the process-ancestry
  detection on a real agent and `sync-bus --apply` against a real bus host
  were not exercised as part of this package.

## License

Business Source License 1.1. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
