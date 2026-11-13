# SPDX-License-Identifier: BUSL-1.1
"""Install the kill switch wheel alone in an empty environment and exercise it.

Proves that the switch works without any other Integrity package: install,
doctor, off, check, uninstall, pip uninstall. State and log stay in --work.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import venv
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--wheels", required=True, help="folder with the built integrity_killswitch wheel")
    parser.add_argument("--work", required=True, help="new folder for the environment, the state and the log")
    args = parser.parse_args()

    work = Path(args.work).resolve()
    work.mkdir(parents=True)
    venv.EnvBuilder(with_pip=True, clear=True).create(work / "venv")
    scripts = work / "venv" / ("Scripts" if os.name == "nt" else "bin")
    python = str(scripts / ("python.exe" if os.name == "nt" else "python"))
    tool = str(scripts / ("integrity-killswitch.exe" if os.name == "nt" else "integrity-killswitch"))

    state = work / "state" / "killswitch.json"
    env = {key: value for key, value in os.environ.items()
           if key not in ("INTEGRITY_KILLSWITCH_CONFIG", "LLM_VENDOR", "PYTHONPATH")}
    env["INTEGRITY_KILLSWITCH_STATE"] = str(state)
    env["INTEGRITY_KILLSWITCH_LOG"] = str(state.with_name("killswitch.log"))

    def run(command: list[str], expect: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
        done = subprocess.run(command, env=env, cwd=work, capture_output=True, text=True, timeout=300)
        if done.returncode not in expect:
            raise SystemExit(f"{command[1:]} exited {done.returncode}, expected {expect}\n{done.stdout}\n{done.stderr}")
        return done

    run([python, "-m", "pip", "install", "--no-index", "--find-links", str(Path(args.wheels).resolve()),
         "integrity-killswitch"])
    installed = {item["name"].lower().replace("_", "-")
                 for item in json.loads(run([python, "-m", "pip", "list", "--format", "json"]).stdout)}
    others = sorted(name for name in installed if name.startswith("integrity") and name != "integrity-killswitch")
    if "integrity-killswitch" not in installed or others:
        raise SystemExit(f"expected integrity-killswitch alone, found {sorted(installed)}")

    report = json.loads(run([tool, "doctor", "--json"]).stdout)
    if not report["passed"] or state.parent.exists():
        raise SystemExit("doctor on a clean machine must pass and must not create the state folder")

    run([tool, "status"])
    run([tool, "uninstall"])
    if not state.exists():
        raise SystemExit("uninstall without --yes must remove nothing")
    run([tool, "uninstall", "--yes"])
    if state.exists():
        raise SystemExit("uninstall --yes left the state file of a switch that blocks nothing")

    run([tool, "off", "codex", "--reason", "standalone check"])
    run([tool, "check", "--vendor", "codex", "--action", "direct_ssh"], expect=(3,))
    run([tool, "check", "--vendor", "claude", "--action", "direct_ssh"])
    detail = next(item["detail"] for item in json.loads(run([tool, "doctor", "--json"]).stdout)["checks"]
                  if item["check"] == "state")
    if "vendor codex" not in detail:
        raise SystemExit("doctor does not name the vendor that is off")
    # Removing a state that blocks something restores access: only the operator may do it.
    removal = run([tool, "uninstall", "--yes"], expect=(0, 3))
    if (removal.returncode == 3) != state.exists():
        raise SystemExit("uninstall --yes: the exit code and the state file disagree")

    run([python, "-m", "pip", "uninstall", "--yes", "integrity-killswitch"])
    if Path(tool).exists():
        raise SystemExit("pip uninstall left the command behind")
    print(json.dumps({"passed": True, "alone": True, "blocked_removal": "refused" if removal.returncode == 3
                      else "allowed (operator shell)", "platform": sys.platform}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
