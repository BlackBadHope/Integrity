# Expected test skips

[Documentation](README.md) · [Project README](../README.md)

A full run of the public suite skips some tests on every platform. This page
lists the skips you should expect, so a first run can tell a normal result from
a broken one.

## Measured in CI

Measured by public CI on commit `9aec26b` (workflow run 42181602192). The test
reports are kept as `junit-*` artifacts of each run. Root is `pytest` in the
repository root; components are `components/*/tests`.

| Platform | Python | Root passed / failed / skipped | Components passed / failed / skipped |
| --- | --- | --- | --- |
| Ubuntu | 3.11 and 3.12 | 655 / 0 / 7 | 732 / 0 / 9 |
| Windows | 3.11 and 3.12 | 576 / 0 / 86 | 671 / 0 / 44 |
| macOS (informational) | 3.12 | 598 / 49 / 15 | 476 / 55 / 26 (client-memory only) |

## Linux

| Skips | Reason |
| ---: | --- |
| 4 | `tests/test_windows_directory_custody.py`: needs the Windows DACL API. |
| 2 | `tests/test_seed_runtime_process_boundary.py`: Windows virtualenv redirector cases. |
| 1 | `tests/test_memory_ttt_review.py`: the private literal corpus is not part of the public export. |
| 9 | client-memory: Antigravity and Claude sibling cases, the Windows `cmd` launcher and hook shell, one star-import static-analysis limit. |

On a machine without the OpenSSH client, `tests/test_two_machine_ssh.py` adds 6
skips, and without PowerShell `test_scope_wrappers.py` adds 2. Linux CI fails on
any client-memory skip outside the reviewed list
(`.github/scripts/native_skip_guard.py`). Skips in other suites are not guarded.

## Windows

The main reasons, from the CI reports:

- Root (86): POSIX replay and recovery custody (about 40), the POSIX executor
  fixture `/usr/bin/printf` (12), Linux `flock`/`statvfs` boundaries (9), the
  Linux-only core side of the two-machine test (6), and POSIX file modes and
  symlinks (5).
- Components (44): Linux `/proc` custody primitives (20), POSIX custody/`flock`
  primitives (11), POSIX `sh` wrappers and other vendors' parametrised cases.
- Privilege probes: without Developer Mode or elevation, symlink tests skip on
  `WinError 1314`, and seat tests skip on `WinError 5`.

## macOS

macOS is not supported yet. The informational CI job runs the core and
client-memory suites. Most failures come from features that need Linux `/proc`
custody: the Toolzs authority ledger, Seed sync and runtime recovery.

A skip with any other reason, or any failure, is worth reporting. Run pytest
with `-rs` to print each skip reason.
