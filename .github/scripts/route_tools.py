#!/usr/bin/env python3
"""Small shell-free helpers for the project's own compiled routes (.integrity/routes).

A compiled route runs argv lists without a shell, so it cannot expand a glob, set an
environment variable or redirect output. These subcommands do that one job each:

  absent PATH...                      prints "absent" when none of the paths exists
  unset NAME...                       prints "unset" when none of the environment variables
                                      is set (PYTHONPATH would let a source tree with build
                                      leftovers stand in for the wheels under test)
  not-ignored PATH...                 prints "not-ignored" when no path is ignored by git
                                      (git check-ignore) and none lies in .git, so a route
                                      cannot name build output or git's own files
  py-run [--venv DIR] [--exe NAME] [--glob PAT]... -- ARGS
                                      runs python (this one, or the venv's) or the venv's
                                      console script NAME with ARGS, with the environment the
                                      CI test steps set (PYTHONDONTWRITEBYTECODE=1,
                                      PYTEST_DISABLE_PLUGIN_AUTOLOAD=1) and the venv's script
                                      folder first on PATH (as CI's GITHUB_PATH does); each
                                      --glob adds its sorted matches after ARGS
  sha256 FILE                         prints the file's SHA-256, its size and how many
                                      files a git diff in it touches
  apply-check --base REF FILE         checks that a git diff applies to REF, in a temporary
                                      index outside the working tree; nothing in the
                                      repository changes

Nothing here pushes, opens a pull request or merges.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def cmd_absent(args: argparse.Namespace) -> int:
    present = [path for path in args.paths if os.path.lexists(path)]
    if present:
        print("present: " + ", ".join(present))
        return 1
    print("absent")
    return 0


def cmd_unset(args: argparse.Namespace) -> int:
    present = [name for name in args.names if os.environ.get(name)]
    if present:
        print("set: " + ", ".join(present))
        return 1
    print("unset")
    return 0


def cmd_not_ignored(args: argparse.Namespace) -> int:
    # git check-ignore does not see .git itself, and on a case-insensitive disk .GIT is .git.
    inside_git = [path for path in args.paths
                  if Path(path).parts[:1] and Path(path).parts[0].casefold() == ".git"]
    if inside_git:
        print("in .git: " + ", ".join(inside_git))
        return 1
    ignored = []
    for path in args.paths:
        check = subprocess.run(["git", "check-ignore", "-q", "--", path], check=False)
        if check.returncode == 0:
            ignored.append(path)
        elif check.returncode != 1:
            print(f"check-ignore FAILED on {path}")
            return 2
    if ignored:
        print("ignored: " + ", ".join(ignored))
        return 1
    print("not-ignored")
    return 0


def venv_program(venv: Path, name: str) -> tuple[Path, Path]:
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    return scripts, scripts / (name + ".exe" if os.name == "nt" else name)


def cmd_py_run(args: argparse.Namespace) -> int:
    env = dict(os.environ)
    if args.venv:
        scripts, program = venv_program(Path(args.venv), args.exe or "python")
        if not program.is_file():
            print(f"no {args.exe or 'python'} in {args.venv}", file=sys.stderr)
            return 127
        env["PATH"] = str(scripts.absolute()) + os.pathsep + env.get("PATH", "")
        env["VIRTUAL_ENV"] = str(Path(args.venv).absolute())
    elif args.exe:
        print("--exe needs --venv", file=sys.stderr)
        return 2
    else:
        program = Path(sys.executable)
    extra: list[str] = []
    for pattern in args.glob:
        matches = sorted(Path(p).as_posix() for p in glob.glob(pattern))
        if not matches:
            print(f"--glob {pattern} matched nothing", file=sys.stderr)
            return 2
        extra.extend(matches)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return subprocess.run([str(program), *command, *extra], env=env, check=False).returncode


def cmd_sha256(args: argparse.Namespace) -> int:
    data = Path(args.file).read_bytes()
    files = sum(1 for line in data.splitlines() if line.startswith(b"diff --git "))
    print(f"sha256 {hashlib.sha256(data).hexdigest()} bytes {len(data)} files {files}")
    return 0


def cmd_apply_check(args: argparse.Namespace) -> int:
    diff = Path(args.file).absolute()
    with tempfile.TemporaryDirectory(prefix="integrity-apply-check-") as tmp:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(tmp) / "index"))
        read = subprocess.run(["git", "read-tree", args.base], env=env, check=False)
        if read.returncode != 0:
            print(f"apply-check FAILED: cannot read {args.base}")
            return 1
        check = subprocess.run(["git", "apply", "--check", "--cached", str(diff)],
                               env=env, check=False)
    if check.returncode != 0:
        print(f"apply-check FAILED on {args.base}")
        return 1
    print(f"apply-check ok on {args.base}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command_name", required=True)
    absent = sub.add_parser("absent")
    absent.add_argument("paths", nargs="+")
    unset = sub.add_parser("unset")
    unset.add_argument("names", nargs="+")
    not_ignored = sub.add_parser("not-ignored")
    not_ignored.add_argument("paths", nargs="+")
    run = sub.add_parser("py-run")
    run.add_argument("--venv")
    run.add_argument("--exe")
    run.add_argument("--glob", action="append", default=[])
    run.add_argument("command", nargs=argparse.REMAINDER)
    digest = sub.add_parser("sha256")
    digest.add_argument("file")
    check = sub.add_parser("apply-check")
    check.add_argument("--base", required=True)
    check.add_argument("file")
    args = parser.parse_args(argv)
    handlers = {"absent": cmd_absent, "unset": cmd_unset, "not-ignored": cmd_not_ignored,
                "py-run": cmd_py_run, "sha256": cmd_sha256, "apply-check": cmd_apply_check}
    return handlers[args.command_name](args)


if __name__ == "__main__":
    raise SystemExit(main())
