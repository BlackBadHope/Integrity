# Expected test skips

[Documentation](README.md) · [Project README](../README.md)

A full run of the public suite skips some tests on every platform. This page
lists the skips you should expect, so a first run can tell a normal result from
a broken one.

## Measured in CI

Measured by public CI on commit `2b7a0e0` (workflow run 43329223986). The test
reports are kept as `junit-*` artifacts of each run. Root is `pytest` in the
repository root; components are `components/*/tests`.

| Platform | Python | Root passed / failed / skipped | Components passed / failed / skipped |
| --- | --- | --- | --- |
| Ubuntu | 3.11 and 3.12 | 805 / 0 / 8 | 1202 / 0 / 10 |
| Windows | 3.11 and 3.12 | 657 / 0 / 156 | 1142 / 0 / 44 |
| macOS (informational) | 3.12 | 742 / 50 / 21 | 582 / 55 / 26 (client-memory only) |

The component totals differ between platforms: 1212 cases on Ubuntu and 1186
on Windows. The cause has not been looked into.

## Linux

| Skips | Reason |
| ---: | --- |
| 4 | `tests/test_windows_directory_custody.py`: needs the Windows DACL API. |
| 2 | `tests/test_seed_runtime_process_boundary.py`: Windows virtualenv redirector cases. |
| 1 | `tests/test_memory_ttt_review.py`: the private literal corpus is not part of the public export. |
| 1 | `tests/test_seed_startup_gate.py`: needs a copy of a running catalog, named by `K6_LIVE_CATALOG`. |
| 9 | client-memory: Antigravity and Claude sibling cases, the Windows `cmd` launcher and hook shell, one star-import static-analysis limit. |
| 1 | killswitch: the dashboard case that reads the Windows TCP owner table. |

On a machine without the OpenSSH client, `tests/test_two_machine_ssh.py` adds 6
skips, and without PowerShell `test_scope_wrappers.py` adds 2. Linux CI fails on
any client-memory skip outside the reviewed list
(`.github/scripts/native_skip_guard.py`). Skips in other suites are not guarded.

## Windows

The main reasons, from the CI reports:

- Root (156): POSIX custody roots with replay and recovery custody (about
  90), the Linux core transport scripts (19), the POSIX executor fixture
  `/usr/bin/printf` (12), Linux `flock`/`statvfs` and owner-lock boundaries
  (12), the Linux-only core side of the two-machine test (6), the Linux Native
  lifecycle (4), and POSIX file modes and symlinks.
- Components (44): Linux `/proc` custody primitives (20), POSIX
  custody/`flock` primitives (11), other vendors' parametrised cases (6), POSIX
  `sh` wrappers (2) and single POSIX file-mode cases.
- Privilege probes: without Developer Mode or elevation, symlink tests skip on
  `WinError 1314`, and seat tests skip on `WinError 5`.
- Added after the measured commit, not in the counts above: the kill switch's
  Linux ancestry cases. 3 read the real `/proc` and always skip on Windows;
  15 build an invented `/proc` with symbolic links and skip only where links
  cannot be made.

## macOS

macOS is not supported yet. The informational CI job runs the core and
client-memory suites. Most failures come from features that need Linux `/proc`
custody: the Toolzs authority ledger, Seed sync and runtime recovery.

A skip with any other reason, or any failure, is worth reporting. Run pytest
with `-rs` to print each skip reason.
